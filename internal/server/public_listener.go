// Package server provides server-side connection management and resource limiting.
package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/piwi3910/tunnelor/internal/mux"
)

// PublicListener listens for external connections and forwards them through the tunnel
type PublicListener struct {
	forwardInfo *ForwardInfo
	listener    net.Listener          // For TCP
	udpConn     *net.UDPConn          // For UDP
	multiplexer *mux.Multiplexer      // QUIC multiplexer to client
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// NewPublicListener creates a new public listener for a forward
func NewPublicListener(fwd *ForwardInfo, multiplexer *mux.Multiplexer) (*PublicListener, error) {
	ctx, cancel := context.WithCancel(context.Background())

	pl := &PublicListener{
		forwardInfo: fwd,
		multiplexer: multiplexer,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Create listener based on protocol
	switch fwd.Proto {
	case "tcp":
		listener, err := net.Listen("tcp", fwd.Local)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create TCP listener on %s: %w", fwd.Local, err)
		}
		pl.listener = listener
		log.Info().
			Str("forward_id", fwd.ID).
			Str("local", fwd.Local).
			Str("remote", fwd.Remote).
			Str("client_id", fwd.ClientID).
			Msg("TCP public listener created")

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", fwd.Local)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to resolve UDP address %s: %w", fwd.Local, err)
		}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create UDP listener on %s: %w", fwd.Local, err)
		}
		pl.udpConn = udpConn
		log.Info().
			Str("forward_id", fwd.ID).
			Str("local", fwd.Local).
			Str("remote", fwd.Remote).
			Str("client_id", fwd.ClientID).
			Msg("UDP public listener created")

	default:
		cancel()
		return nil, fmt.Errorf("unsupported protocol: %s", fwd.Proto)
	}

	return pl, nil
}

// Start begins accepting connections
func (pl *PublicListener) Start() error {
	switch pl.forwardInfo.Proto {
	case "tcp":
		return pl.serveTCP()
	case "udp":
		return pl.serveUDP()
	default:
		return fmt.Errorf("unsupported protocol: %s", pl.forwardInfo.Proto)
	}
}

// serveTCP accepts TCP connections and forwards them through QUIC
func (pl *PublicListener) serveTCP() error {
	log.Info().
		Str("forward_id", pl.forwardInfo.ID).
		Str("local", pl.forwardInfo.Local).
		Msg("Starting TCP public listener")

	for {
		select {
		case <-pl.ctx.Done():
			return nil
		default:
		}

		conn, err := pl.listener.Accept()
		if err != nil {
			select {
			case <-pl.ctx.Done():
				return nil
			default:
				log.Error().
					Err(err).
					Str("forward_id", pl.forwardInfo.ID).
					Msg("Failed to accept TCP connection")
				continue
			}
		}

		// Handle connection in goroutine
		pl.wg.Add(1)
		go func(c net.Conn) {
			defer pl.wg.Done()
			if err := pl.handleTCPConnection(c); err != nil {
				log.Error().
					Err(err).
					Str("forward_id", pl.forwardInfo.ID).
					Str("remote_addr", c.RemoteAddr().String()).
					Msg("Failed to handle TCP connection")
			}
		}(conn)
	}
}

// handleTCPConnection forwards a single TCP connection through QUIC
func (pl *PublicListener) handleTCPConnection(conn net.Conn) error {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close TCP connection")
		}
	}()

	log.Info().
		Str("forward_id", pl.forwardInfo.ID).
		Str("remote_addr", conn.RemoteAddr().String()).
		Str("target", pl.forwardInfo.Remote).
		Msg("Accepted TCP connection, opening QUIC stream")

	// Open QUIC stream to client
	stream, err := pl.multiplexer.OpenTCPStream(pl.forwardInfo.Remote, conn.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("failed to open QUIC stream: %w", err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC stream")
		}
	}()

	log.Debug().
		Str("forward_id", pl.forwardInfo.ID).
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("QUIC stream opened, starting bidirectional copy")

	// Bidirectional copy between TCP connection and QUIC stream
	errChan := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	// TCP -> QUIC
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, conn)
		if err != nil && !errors.Is(err, io.EOF) {
			errChan <- fmt.Errorf("TCP->QUIC copy failed: %w", err)
		} else {
			errChan <- nil
		}
		// Close write side to signal EOF
		if err := stream.Close(); err != nil {
			log.Debug().Err(err).Msg("Failed to close QUIC stream write side")
		}
	}()

	// QUIC -> TCP
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, stream)
		if err != nil && !errors.Is(err, io.EOF) {
			errChan <- fmt.Errorf("QUIC->TCP copy failed: %w", err)
		} else {
			errChan <- nil
		}
		// Close write side to signal EOF
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			if err := tcpConn.CloseWrite(); err != nil {
				log.Debug().Err(err).Msg("Failed to close TCP write side")
			}
		}
	}()

	// Wait for both directions to complete
	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	log.Debug().
		Str("forward_id", pl.forwardInfo.ID).
		Msg("TCP connection completed successfully")

	return nil
}

// serveUDP accepts UDP datagrams and forwards them through QUIC
func (pl *PublicListener) serveUDP() error {
	log.Info().
		Str("forward_id", pl.forwardInfo.ID).
		Str("local", pl.forwardInfo.Local).
		Msg("Starting UDP public listener")

	// For UDP, we need to track sessions per source address
	// This is a simplified implementation - production would need session management
	buf := make([]byte, 65535)

	for {
		select {
		case <-pl.ctx.Done():
			return nil
		default:
		}

		n, remoteAddr, err := pl.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-pl.ctx.Done():
				return nil
			default:
				log.Error().
					Err(err).
					Str("forward_id", pl.forwardInfo.ID).
					Msg("Failed to read UDP datagram")
				continue
			}
		}

		log.Debug().
			Str("forward_id", pl.forwardInfo.ID).
			Str("remote_addr", remoteAddr.String()).
			Int("bytes", n).
			Msg("Received UDP datagram")

		// For now, log that UDP is received but not fully implemented
		// Full implementation would require session tracking and UDP stream handling
		log.Warn().
			Str("forward_id", pl.forwardInfo.ID).
			Msg("UDP reverse tunnel not yet fully implemented")
	}
}

// Close stops the public listener
func (pl *PublicListener) Close() error {
	log.Info().
		Str("forward_id", pl.forwardInfo.ID).
		Msg("Closing public listener")

	pl.cancel()

	var err error
	if pl.listener != nil {
		err = pl.listener.Close()
	}
	if pl.udpConn != nil {
		if closeErr := pl.udpConn.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}

	// Wait for all connection handlers to finish
	pl.wg.Wait()

	log.Info().
		Str("forward_id", pl.forwardInfo.ID).
		Msg("Public listener closed")

	return err
}
