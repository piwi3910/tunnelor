package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// Server represents a QUIC server that accepts connections
type Server struct {
	ctx         context.Context
	listener    *quic.Listener
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	connections map[string]*Connection
	cancel      context.CancelFunc
	connMutex   sync.RWMutex
}

// ServerConfig holds configuration for the QUIC server
type ServerConfig struct {
	ListenAddr string
	TLSCert    string
	TLSKey     string
}

// NewServer creates a new QUIC server
func NewServer(cfg ServerConfig) (*Server, error) {
	// Load TLS configuration
	tlsConfig, err := LoadServerTLSConfig(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	// Create QUIC configuration
	quicConfig := &quic.Config{
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          1000,
		MaxIdleTimeout:                 0, // No timeout, keepalive on control stream
		KeepAlivePeriod:                0,
		InitialStreamReceiveWindow:     6 * 1024 * 1024,  // 6 MB
		MaxStreamReceiveWindow:         15 * 1024 * 1024, // 15 MB
		InitialConnectionReceiveWindow: 15 * 1024 * 1024, // 15 MB
		MaxConnectionReceiveWindow:     30 * 1024 * 1024, // 30 MB
		Allow0RTT:                      false,
		EnableDatagrams:                true,
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		tlsConfig:   tlsConfig,
		quicConfig:  quicConfig,
		connections: make(map[string]*Connection),
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

// Start starts the QUIC server and begins accepting connections
func (s *Server) Start(listenAddr string) error {
	// Parse listen address
	udpAddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve listen address: %w", err)
	}

	// Create UDP connection
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	// Create QUIC listener
	listener, err := quic.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close UDP connection after listener creation error")
		}
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	s.listener = listener

	log.Info().
		Str("addr", listenAddr).
		Msg("QUIC server started")

	return nil
}

// Accept waits for and returns the next QUIC connection
func (s *Server) Accept() (*Connection, error) {
	quicConn, err := s.listener.Accept(s.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	}

	// Create connection wrapper
	conn := &Connection{
		conn:       quicConn,
		streams:    make(map[uint64]*quic.Stream),
		ctx:        s.ctx,
		isServer:   true,
		remoteAddr: quicConn.RemoteAddr().String(),
	}

	// Store connection
	s.connMutex.Lock()
	s.connections[conn.remoteAddr] = conn
	s.connMutex.Unlock()

	log.Info().
		Str("remote_addr", conn.remoteAddr).
		Msg("Accepted new QUIC connection")

	return conn, nil
}

// GetConnection returns a connection by remote address
func (s *Server) GetConnection(remoteAddr string) (*Connection, bool) {
	s.connMutex.RLock()
	defer s.connMutex.RUnlock()
	conn, ok := s.connections[remoteAddr]
	return conn, ok
}

// RemoveConnection removes a connection from the server
func (s *Server) RemoveConnection(remoteAddr string) {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()
	delete(s.connections, remoteAddr)

	log.Debug().
		Str("remote_addr", remoteAddr).
		Msg("Removed connection from server")
}

// Close closes the QUIC server and all connections
func (s *Server) Close() error {
	s.cancel()

	// Close all connections
	s.connMutex.Lock()
	for remoteAddr, conn := range s.connections {
		if err := conn.Close(); err != nil {
			log.Warn().Err(err).Str("remote_addr", remoteAddr).Msg("Failed to close connection during server shutdown")
		}
	}
	s.connMutex.Unlock()

	// Close listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}

	log.Info().Msg("QUIC server closed")
	return nil
}

// Addr returns the listener's network address
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// ConnectionCount returns the number of active connections
func (s *Server) ConnectionCount() int {
	s.connMutex.RLock()
	defer s.connMutex.RUnlock()
	return len(s.connections)
}
