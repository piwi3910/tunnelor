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

// UDPSession represents a UDP session with timeout tracking
type UDPSession struct {
	RemoteAddr *net.UDPAddr
	LastSeen   time.Time
	Cancel     context.CancelFunc
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

	buffer := make([]byte, 65535) // Max UDP datagram size

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
			Length: uint16(n),
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
func (l *UDPListener) Serve() error {
	buffer := make([]byte, 65535)

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
			log.Error().Err(err).Msg("Failed to read UDP datagram")
			continue
		}

		// Handle datagram
		go l.handleDatagram(buffer[:n], remoteAddr)
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

	// Forward datagram via session's QUIC stream
	// For simplicity, we'll open a new stream per datagram
	// A more sophisticated implementation could reuse streams
	quicStream, err := l.streamOpener()
	if err != nil {
		log.Error().Err(err).Msg("Failed to open QUIC stream for UDP datagram")
		return
	}
	defer func() {
		if err := (*quicStream).Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC stream")
		}
	}()

	// Create datagram wrapper
	datagram := &UDPDatagram{
		Length: uint16(len(data)),
		Data:   data,
	}

	// Write datagram to QUIC stream
	if err := WriteUDPDatagram(quicStream, datagram); err != nil {
		log.Error().Err(err).Msg("Failed to write UDP datagram to QUIC stream")
		return
	}

	log.Debug().
		Str("remote_addr", remoteAddr.String()).
		Int("size", len(data)).
		Msg("Forwarded UDP datagram over QUIC")
}

// handleSession handles a UDP session
func (l *UDPListener) handleSession(ctx context.Context, session *UDPSession) {
	<-ctx.Done()

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

	// Cancel all sessions
	l.sessionMutex.Lock()
	for _, session := range l.sessions {
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
