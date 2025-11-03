// Package udpbridge provides UDP-to-QUIC bridging functionality.
// It handles UDP datagram encapsulation and forwarding through QUIC streams with session management.
package udpbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// bufferPool is a sync.Pool for UDP datagram buffers to reduce GC pressure
var bufferPool = sync.Pool{
	New: func() interface{} {
		// Max UDP datagram size is 65535 bytes
		buf := make([]byte, 65535)
		return &buf
	},
}

// SessionTimeout is the timeout for idle UDP sessions
const SessionTimeout = 2 * time.Minute

// UDPDatagram represents a UDP datagram in the stream
type UDPDatagram struct {
	Data   []byte
	Length uint16
}

// WriteUDPDatagram writes a UDP datagram to a writer
func WriteUDPDatagram(w io.Writer, datagram *UDPDatagram) error {
	// Write length (2 bytes, big-endian)
	if err := binary.Write(w, binary.BigEndian, datagram.Length); err != nil {
		return fmt.Errorf("failed to write datagram length: %w", err)
	}

	// Write data
	if _, err := w.Write(datagram.Data); err != nil {
		return fmt.Errorf("failed to write datagram data: %w", err)
	}

	return nil
}

// ReadUDPDatagram reads a UDP datagram from a reader
func ReadUDPDatagram(r io.Reader) (*UDPDatagram, error) {
	datagram := &UDPDatagram{}

	// Read length (2 bytes, big-endian)
	if err := binary.Read(r, binary.BigEndian, &datagram.Length); err != nil {
		return nil, fmt.Errorf("failed to read datagram length: %w", err)
	}

	// Read data
	datagram.Data = make([]byte, datagram.Length)
	if _, err := io.ReadFull(r, datagram.Data); err != nil {
		return nil, fmt.Errorf("failed to read datagram data: %w", err)
	}

	return datagram, nil
}

// UDPSession represents a UDP session with timeout tracking and stream reuse
type UDPSession struct {
	RemoteAddr  *net.UDPAddr
	LastSeen    time.Time
	Cancel      context.CancelFunc
	Stream      *quicgo.Stream
	StreamMutex sync.Mutex
}

// UDPToQUIC bridges UDP datagrams to a QUIC stream
func UDPToQUIC(ctx context.Context, udpConn *net.UDPConn, quicStream *quicgo.Stream) error {
	defer func() {
		if err := (*quicStream).Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC stream")
		}
	}()

	log.Debug().
		Str("local_addr", udpConn.LocalAddr().String()).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Bridging UDP to QUIC")

	// Get buffer from pool
	bufferPtr := bufferPool.Get().(*[]byte)
	buffer := *bufferPtr
	defer bufferPool.Put(bufferPtr)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		default:
		}

		// Read UDP datagram
		n, _, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read UDP datagram: %w", err)
		}

		// Create datagram wrapper
		datagram := &UDPDatagram{
			Length: uint16(n), // #nosec G115 -- n <= 65535 (max UDP size), safe for uint16
			Data:   buffer[:n],
		}

		// Write datagram to QUIC stream
		if err := WriteUDPDatagram(quicStream, datagram); err != nil {
			return fmt.Errorf("failed to write datagram to QUIC stream: %w", err)
		}

		log.Debug().
			Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
			Int("size", n).
			Msg("Sent UDP datagram over QUIC")
	}
}

// QUICToUDP bridges a QUIC stream to UDP datagrams
func QUICToUDP(ctx context.Context, quicStream *quicgo.Stream, targetAddr string) error {
	defer func() {
		if err := (*quicStream).Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC stream")
		}
	}()

	log.Debug().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Connecting to UDP target")

	// Resolve target address
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", targetAddr, err)
	}

	// Create UDP connection
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to UDP target %s: %w", targetAddr, err)
	}
	defer func() {
		if err := udpConn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close UDP connection")
		}
	}()

	log.Info().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Connected to UDP target, bridging QUIC to UDP")

	// Read datagrams from QUIC stream and forward to UDP
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		default:
		}

		// Read datagram from QUIC stream
		datagram, err := ReadUDPDatagram(quicStream)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read datagram from QUIC stream: %w", err)
		}

		// Write to UDP target
		_, err = udpConn.Write(datagram.Data)
		if err != nil {
			return fmt.Errorf("failed to write to UDP target: %w", err)
		}

		log.Debug().
			Str("target_addr", targetAddr).
			Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
			Int("size", len(datagram.Data)).
			Msg("Forwarded datagram to UDP target")
	}
}

// UDPListener listens for UDP datagrams and forwards them over QUIC
type UDPListener struct {
	ctx          context.Context
	conn         *net.UDPConn
	streamOpener func() (*quicgo.Stream, error)
	sessions     map[string]*UDPSession
	cancel       context.CancelFunc
	listenAddr   string
	targetAddr   string
	sessionMutex sync.RWMutex
}

// NewUDPListener creates a new UDP listener for forwarding
func NewUDPListener(listenAddr, targetAddr string, streamOpener func() (*quicgo.Stream, error)) *UDPListener {
	ctx, cancel := context.WithCancel(context.Background())

	return &UDPListener{
		listenAddr:   listenAddr,
		targetAddr:   targetAddr,
		streamOpener: streamOpener,
		sessions:     make(map[string]*UDPSession),
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start starts the UDP listener
func (l *UDPListener) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", l.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", l.listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", l.listenAddr, err)
	}

	l.conn = conn

	log.Info().
		Str("listen_addr", l.listenAddr).
		Str("target_addr", l.targetAddr).
		Msg("UDP listener started")

	return nil
}

// Serve receives and forwards UDP datagrams
// Returns an error if the read loop encounters a fatal error
// Individual datagram handling errors are logged but don't stop the listener
func (l *UDPListener) Serve() error {
	// Get buffer from pool
	bufferPtr := bufferPool.Get().(*[]byte)
	buffer := *bufferPtr
	defer bufferPool.Put(bufferPtr)

	// Start session cleanup goroutine
	go l.cleanupSessions()

	for {
		select {
		case <-l.ctx.Done():
			return nil
		default:
		}

		// Read UDP datagram
		n, remoteAddr, err := l.conn.ReadFromUDP(buffer)
		if err != nil {
			// Log the error and return it - persistent read errors indicate
			// a fatal problem with the listener
			log.Error().Err(err).Msg("Fatal error reading UDP datagram")
			return fmt.Errorf("failed to read UDP datagram: %w", err)
		}

		// Copy data since we need to pass it to goroutine and buffer will be reused
		dataCopy := make([]byte, n)
		copy(dataCopy, buffer[:n])

		// Handle datagram in goroutine
		go l.handleDatagram(dataCopy, remoteAddr)
	}
}

// handleDatagram handles a single UDP datagram
func (l *UDPListener) handleDatagram(data []byte, remoteAddr *net.UDPAddr) {
	sessionKey := remoteAddr.String()

	// Check if session exists
	l.sessionMutex.Lock()
	session, exists := l.sessions[sessionKey]
	if !exists {
		// Create new session
		ctx, cancel := context.WithCancel(l.ctx)
		session = &UDPSession{
			RemoteAddr: remoteAddr,
			LastSeen:   time.Now(),
			Cancel:     cancel,
			Stream:     nil, // Will be created on first use
		}
		l.sessions[sessionKey] = session
		l.sessionMutex.Unlock()

		log.Info().
			Str("remote_addr", remoteAddr.String()).
			Str("target_addr", l.targetAddr).
			Msg("New UDP session created")

		// Start session handler in background
		go l.handleSession(ctx, session)
	} else {
		// Update last seen
		session.LastSeen = time.Now()
		l.sessionMutex.Unlock()
	}

	// Forward datagram via session's reusable QUIC stream
	session.StreamMutex.Lock()
	defer session.StreamMutex.Unlock()

	// Create stream if it doesn't exist
	if session.Stream == nil {
		quicStream, err := l.streamOpener()
		if err != nil {
			log.Error().Err(err).Msg("Failed to open QUIC stream for UDP session")
			return
		}
		session.Stream = quicStream
		log.Debug().
			Str("remote_addr", remoteAddr.String()).
			Uint64("stream_id", uint64((*session.Stream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
			Msg("Created reusable QUIC stream for UDP session")
	}

	// Create datagram wrapper
	datagram := &UDPDatagram{
		Length: uint16(len(data)), // #nosec G115 -- UDP packet data is limited to 65535 bytes, safe for uint16
		Data:   data,
	}

	// Write datagram to QUIC stream
	if err := WriteUDPDatagram(session.Stream, datagram); err != nil {
		log.Warn().Err(err).Msg("Failed to write UDP datagram to QUIC stream, will recreate stream")

		// Close failed stream
		if closeErr := (*session.Stream).Close(); closeErr != nil {
			log.Debug().Err(closeErr).Msg("Failed to close failed QUIC stream")
		}

		// Try to create a new stream
		quicStream, err := l.streamOpener()
		if err != nil {
			log.Error().Err(err).Msg("Failed to recreate QUIC stream for UDP session")
			session.Stream = nil
			return
		}
		session.Stream = quicStream

		// Retry write with new stream
		if err := WriteUDPDatagram(session.Stream, datagram); err != nil {
			log.Error().Err(err).Msg("Failed to write UDP datagram after stream recreation")
			if closeErr := (*session.Stream).Close(); closeErr != nil {
				log.Debug().Err(closeErr).Msg("Failed to close QUIC stream after retry")
			}
			session.Stream = nil
			return
		}
		log.Debug().Msg("Successfully wrote datagram after stream recreation")
	}

	log.Debug().
		Str("remote_addr", remoteAddr.String()).
		Int("size", len(data)).
		Uint64("stream_id", uint64((*session.Stream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Forwarded UDP datagram over reused QUIC stream")
}

// handleSession handles a UDP session
func (l *UDPListener) handleSession(ctx context.Context, session *UDPSession) {
	<-ctx.Done()

	// Close the session's QUIC stream
	session.StreamMutex.Lock()
	if session.Stream != nil {
		if err := (*session.Stream).Close(); err != nil {
			log.Debug().Err(err).Msg("Failed to close QUIC stream during session cleanup")
		}
		session.Stream = nil
	}
	session.StreamMutex.Unlock()

	// Session ended, clean up
	l.sessionMutex.Lock()
	delete(l.sessions, session.RemoteAddr.String())
	l.sessionMutex.Unlock()

	log.Debug().
		Str("remote_addr", session.RemoteAddr.String()).
		Msg("UDP session closed")
}

// cleanupSessions periodically cleans up idle sessions
func (l *UDPListener) cleanupSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			l.sessionMutex.Lock()
			now := time.Now()
			for key, session := range l.sessions {
				if now.Sub(session.LastSeen) > SessionTimeout {
					// Close the session's QUIC stream
					session.StreamMutex.Lock()
					if session.Stream != nil {
						if err := (*session.Stream).Close(); err != nil {
							log.Debug().Err(err).Msg("Failed to close QUIC stream during timeout cleanup")
						}
						session.Stream = nil
					}
					session.StreamMutex.Unlock()

					session.Cancel()
					delete(l.sessions, key)
					log.Debug().
						Str("remote_addr", session.RemoteAddr.String()).
						Msg("UDP session timed out")
				}
			}
			l.sessionMutex.Unlock()
		}
	}
}

// Close closes the UDP listener
func (l *UDPListener) Close() error {
	l.cancel()

	// Cancel all sessions and close their streams
	l.sessionMutex.Lock()
	for _, session := range l.sessions {
		// Close the session's QUIC stream
		session.StreamMutex.Lock()
		if session.Stream != nil {
			if err := (*session.Stream).Close(); err != nil {
				log.Debug().Err(err).Msg("Failed to close QUIC stream during listener shutdown")
			}
			session.Stream = nil
		}
		session.StreamMutex.Unlock()

		session.Cancel()
	}
	l.sessionMutex.Unlock()

	if l.conn != nil {
		if err := l.conn.Close(); err != nil {
			return fmt.Errorf("failed to close UDP listener: %w", err)
		}
	}

	log.Info().
		Str("listen_addr", l.listenAddr).
		Msg("UDP listener closed")

	return nil
}
