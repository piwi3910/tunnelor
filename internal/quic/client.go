// Package quic provides QUIC connection management for Tunnelor.
// It handles QUIC client/server connections, TLS configuration, and connection lifecycle.
package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// Client represents a QUIC client connection manager
type Client struct {
	ctx        context.Context
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	connection *Connection
	cancel     context.CancelFunc
	serverAddr string
}

// ClientConfig holds configuration for the QUIC client
type ClientConfig struct {
	ServerAddr         string
	ServerName         string
	CAFile             string
	InsecureSkipVerify bool
}

// NewClient creates a new QUIC client
func NewClient(cfg ClientConfig) (*Client, error) {
	// Parse server address (remove quic:// prefix if present)
	serverAddr := strings.TrimPrefix(cfg.ServerAddr, "quic://")

	// Extract server name from address if not provided
	serverName := cfg.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server address: %w", err)
		}
		serverName = host
	}

	// Load TLS configuration
	var tlsConfig *tls.Config
	var err error

	if cfg.CAFile != "" {
		tlsConfig, err = LoadClientTLSConfigWithCA(serverName, cfg.CAFile)
	} else {
		tlsConfig, err = LoadClientTLSConfig(serverName, cfg.InsecureSkipVerify)
	}

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

	return &Client{
		serverAddr: serverAddr,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
		ctx:        ctx,
		cancel:     cancel,
	}, nil
}

// Connect establishes a QUIC connection to the server
func (c *Client) Connect() error {
	return c.ConnectWithTimeout(10 * time.Second)
}

// ConnectWithTimeout establishes a QUIC connection with a timeout
func (c *Client) ConnectWithTimeout(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()

	log.Info().
		Str("server", c.serverAddr).
		Msg("Connecting to QUIC server...")

	// Dial QUIC connection
	quicConn, err := quic.DialAddr(ctx, c.serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		return fmt.Errorf("failed to dial QUIC server: %w", err)
	}

	// Create connection wrapper
	c.connection = &Connection{
		conn:       quicConn,
		streams:    make(map[uint64]*quic.Stream),
		ctx:        c.ctx,
		isServer:   false,
		remoteAddr: c.serverAddr,
	}

	log.Info().
		Str("server", c.serverAddr).
		Str("local_addr", quicConn.LocalAddr().String()).
		Msg("Connected to QUIC server")

	return nil
}

// Reconnect attempts to reconnect to the server
func (c *Client) Reconnect() error {
	log.Warn().
		Str("server", c.serverAddr).
		Msg("Attempting to reconnect to server...")

	// Close existing connection if any
	if c.connection != nil {
		if err := c.connection.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close existing connection during reconnect")
		}
		c.connection = nil
	}

	// Attempt reconnection with exponential backoff
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second
	attempts := 0
	maxAttempts := 10

	for attempts < maxAttempts {
		attempts++

		err := c.Connect()
		if err == nil {
			log.Info().
				Int("attempts", attempts).
				Msg("Reconnected successfully")
			return nil
		}

		log.Warn().
			Err(err).
			Int("attempt", attempts).
			Dur("backoff", backoff).
			Msg("Reconnection attempt failed, retrying...")

		// Wait before next attempt
		select {
		case <-time.After(backoff):
		case <-c.ctx.Done():
			return fmt.Errorf("reconnection canceled: %w", c.ctx.Err())
		}

		// Increase backoff exponentially
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}

	return fmt.Errorf("failed to reconnect after %d attempts", maxAttempts)
}

// Connection returns the active QUIC connection
func (c *Client) Connection() *Connection {
	return c.connection
}

// IsConnected returns true if the client has an active connection
func (c *Client) IsConnected() bool {
	return c.connection != nil && c.connection.Context().Err() == nil
}

// Close closes the QUIC client connection
func (c *Client) Close() error {
	c.cancel()

	if c.connection != nil {
		if err := c.connection.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	log.Info().Msg("QUIC client closed")
	return nil
}
