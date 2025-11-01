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

// BidirectionalCopy copies data bidirectionally between two connections
func BidirectionalCopy(conn1 io.ReadWriteCloser, conn2 io.ReadWriteCloser) error {
	var wg sync.WaitGroup
	wg.Add(2)

	errChan := make(chan error, 2)

	// Copy from conn1 to conn2
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn2, conn1)
		if err != nil && !errors.Is(err, io.EOF) {
			errChan <- fmt.Errorf("copy conn1->conn2 failed: %w", err)
		}
		// Close write side to signal EOF
		if closer, ok := conn2.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
	}()

	// Copy from conn2 to conn1
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn1, conn2)
		if err != nil && !errors.Is(err, io.EOF) {
			errChan <- fmt.Errorf("copy conn2->conn1 failed: %w", err)
		}
		// Close write side to signal EOF
		if closer, ok := conn1.(interface{ CloseWrite() error }); ok {
			closer.CloseWrite()
		}
	}()

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
	defer tcpConn.Close()
	defer (*quicStream).Close()

	log.Debug().
		Str("local_addr", tcpConn.LocalAddr().String()).
		Str("remote_addr", tcpConn.RemoteAddr().String()).
		Uint64("stream_id", uint64((*quicStream).StreamID())).
		Msg("Bridging TCP to QUIC")

	// Perform bidirectional copy
	if err := BidirectionalCopy(tcpConn, quicStream); err != nil {
		return fmt.Errorf("bidirectional copy failed: %w", err)
	}

	log.Debug().
		Uint64("stream_id", uint64((*quicStream).StreamID())).
		Msg("TCP to QUIC bridge closed")

	return nil
}

// QUICToTCP bridges a QUIC stream to a TCP connection
func QUICToTCP(quicStream *quicgo.Stream, targetAddr string) error {
	defer (*quicStream).Close()

	log.Debug().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())).
		Msg("Connecting to TCP target")

	// Connect to target TCP
	tcpConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
	}
	defer tcpConn.Close()

	log.Info().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())).
		Msg("Connected to TCP target, bridging QUIC to TCP")

	// Perform bidirectional copy
	if err := BidirectionalCopy(quicStream, tcpConn); err != nil {
		return fmt.Errorf("bidirectional copy failed: %w", err)
	}

	log.Debug().
		Str("target_addr", targetAddr).
		Uint64("stream_id", uint64((*quicStream).StreamID())).
		Msg("QUIC to TCP bridge closed")

	return nil
}

// StreamWrapper wraps a QUIC stream to implement CloseWrite
type StreamWrapper struct {
	*quicgo.Stream
}

// CloseWrite closes the write side of the stream
func (sw *StreamWrapper) CloseWrite() error {
	return (*sw.Stream).Close()
}

// TCPListener listens for TCP connections and forwards them over QUIC
type TCPListener struct {
	listenAddr   string
	targetAddr   string
	listener     net.Listener
	streamOpener func() (*quicgo.Stream, error)
	ctx          context.Context
	cancel       context.CancelFunc
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
func (l *TCPListener) Serve() error {
	for {
		tcpConn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.ctx.Done():
				return nil
			default:
				log.Error().Err(err).Msg("Failed to accept TCP connection")
				continue
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
		tcpConn.Close()
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
