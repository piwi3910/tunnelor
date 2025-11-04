// Package tcpbridge provides TCP-to-QUIC bridging functionality.
// It handles bidirectional TCP connections and forwards them through QUIC streams.
package tcpbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// CopyBuffer is the buffer size for bidirectional copying
const CopyBuffer = 32 * 1024 // 32KB

// tcpBufferPool is a sync.Pool for TCP copy buffers to reduce GC pressure
var tcpBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, CopyBuffer)
		return &buf
	},
}

// copyWithBuffer copies data from src to dst using a pooled buffer and handles close
func copyWithBuffer(dst, src io.ReadWriteCloser, direction string, errChan chan<- error, wg *sync.WaitGroup) {
	defer wg.Done()

	// Get buffer from pool
	bufPtr, ok := tcpBufferPool.Get().(*[]byte)
	if !ok {
		errChan <- fmt.Errorf("buffer pool returned unexpected type")
		return
	}
	defer tcpBufferPool.Put(bufPtr)

	_, err := io.CopyBuffer(dst, src, *bufPtr)
	if err != nil && !errors.Is(err, io.EOF) {
		errChan <- fmt.Errorf("copy %s failed: %w", direction, err)
	}
	// Close write side to signal EOF
	if closer, ok := dst.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			errChan <- fmt.Errorf("failed to close %s write side: %w", direction, err)
		}
	}
}

// BidirectionalCopy copies data bidirectionally between two connections
func BidirectionalCopy(conn1, conn2 io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	wg.Add(2)

	errChan := make(chan error, 2)

	// Copy from conn1 to conn2
	go copyWithBuffer(conn2, conn1, "conn1->conn2", errChan, &wg)

	// Copy from conn2 to conn1
	go copyWithBuffer(conn1, conn2, "conn2->conn1", errChan, &wg)

	// Wait for both copies to complete
	wg.Wait()
	close(errChan)

	// Return first error if any
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// TCPToQUIC bridges a TCP connection to a QUIC stream
func TCPToQUIC(tcpConn net.Conn, quicStream *quicgo.Stream) error {
	defer func() {
		if err := tcpConn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close TCP connection")
		}
	}()
	defer func() {
		if err := (*quicStream).Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC stream")
		}
	}()

	log.Debug().
		Str("local_addr", tcpConn.LocalAddr().String()).
		Str("remote_addr", tcpConn.RemoteAddr().String()).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Bridging TCP to QUIC")

	// Perform bidirectional copy
	if err := BidirectionalCopy(tcpConn, quicStream); err != nil {
		return fmt.Errorf("bidirectional copy failed: %w", err)
	}

	log.Debug().
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("TCP to QUIC bridge closed")

	return nil
}

// QUICToTCP bridges a QUIC stream to a TCP connection
func QUICToTCP(quicStream *quicgo.Stream, targetAddr string) error {
	defer func() {
		if err := (*quicStream).Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC stream")
		}
	}()

	log.Debug().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Connecting to TCP target")

	// Connect to target TCP
	tcpConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
	}
	defer func() {
		if err := tcpConn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close TCP connection")
		}
	}()

	log.Info().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Connected to TCP target, bridging QUIC to TCP")

	// Perform bidirectional copy
	if err := BidirectionalCopy(quicStream, tcpConn); err != nil {
		return fmt.Errorf("bidirectional copy failed: %w", err)
	}

	log.Debug().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("QUIC to TCP bridge closed")

	return nil
}

// StreamWrapper wraps a QUIC stream to implement CloseWrite
type StreamWrapper struct {
	*quicgo.Stream
}

// CloseWrite closes the write side of the stream
func (sw *StreamWrapper) CloseWrite() error {
	if err := (*sw.Stream).Close(); err != nil {
		return fmt.Errorf("failed to close stream write side: %w", err)
	}
	return nil
}

// TCPListener listens for TCP connections and forwards them over QUIC
type TCPListener struct {
	listener     net.Listener
	ctx          context.Context
	streamOpener func() (*quicgo.Stream, error)
	cancel       context.CancelFunc
	listenAddr   string
	targetAddr   string
}

// NewTCPListener creates a new TCP listener for forwarding
func NewTCPListener(listenAddr, targetAddr string, streamOpener func() (*quicgo.Stream, error)) *TCPListener {
	ctx, cancel := context.WithCancel(context.Background())

	return &TCPListener{
		listenAddr:   listenAddr,
		targetAddr:   targetAddr,
		streamOpener: streamOpener,
		ctx:          ctx,
		cancel:       cancel,
	}
}

// Start starts the TCP listener
func (l *TCPListener) Start() error {
	listener, err := net.Listen("tcp", l.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", l.listenAddr, err)
	}

	l.listener = listener

	log.Info().
		Str("listen_addr", l.listenAddr).
		Str("target_addr", l.targetAddr).
		Msg("TCP listener started")

	return nil
}

// Serve accepts and handles TCP connections
// Returns an error if the accept loop encounters a fatal error
// Individual connection handling errors are logged but don't stop the listener
func (l *TCPListener) Serve() error {
	for {
		tcpConn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.ctx.Done():
				return nil
			default:
				// Log the error and return it - persistent accept errors indicate
				// a fatal problem with the listener
				log.Error().Err(err).Msg("Fatal error accepting TCP connection")
				return fmt.Errorf("failed to accept TCP connection: %w", err)
			}
		}

		// Handle connection in goroutine
		go l.handleConnection(tcpConn)
	}
}

// handleConnection handles a single TCP connection
func (l *TCPListener) handleConnection(tcpConn net.Conn) {
	log.Info().
		Str("local_addr", l.listenAddr).
		Str("remote_addr", tcpConn.RemoteAddr().String()).
		Str("target_addr", l.targetAddr).
		Msg("Accepted TCP connection, opening QUIC stream")

	// Open QUIC stream
	quicStream, err := l.streamOpener()
	if err != nil {
		log.Error().Err(err).Msg("Failed to open QUIC stream")
		if closeErr := tcpConn.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close TCP connection after stream open error")
		}
		return
	}

	// Bridge TCP to QUIC
	if err := TCPToQUIC(tcpConn, quicStream); err != nil {
		log.Error().
			Err(err).
			Str("target_addr", l.targetAddr).
			Msg("TCP to QUIC bridge error")
	}
}

// Close closes the TCP listener
func (l *TCPListener) Close() error {
	l.cancel()

	if l.listener != nil {
		if err := l.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}

	log.Info().
		Str("listen_addr", l.listenAddr).
		Msg("TCP listener closed")

	return nil
}
