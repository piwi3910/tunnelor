// Package ipc provides inter-process communication for dynamic port forwarding.
// It uses Unix domain sockets for communication between the running client and CLI commands.
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/rs/zerolog/log"
)

// ForwardRequest represents a request to add a new forward
type ForwardRequest struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Proto  string `json:"proto"`
}

// ForwardResponse represents the response to a forward request
type ForwardResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

// GetSocketPath returns the path to the IPC socket
func GetSocketPath() string {
	// Use /tmp for Unix socket (could be made configurable)
	return filepath.Join(os.TempDir(), "tunnelorc.sock")
}

// Server represents an IPC server for accepting forward requests
type Server struct {
	listener     net.Listener
	socketPath   string
	forwardAdder func(ForwardRequest) error
	stopChan     chan struct{}
	closed       bool
	mu           sync.Mutex
}

// NewServer creates a new IPC server
func NewServer(forwardAdder func(ForwardRequest) error) (*Server, error) {
	socketPath := GetSocketPath()

	// Remove existing socket if it exists
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create Unix socket: %w", err)
	}

	log.Info().Str("socket", socketPath).Msg("IPC server listening")

	return &Server{
		listener:     listener,
		socketPath:   socketPath,
		forwardAdder: forwardAdder,
		stopChan:     make(chan struct{}),
	}, nil
}

// Serve starts accepting IPC connections
func (s *Server) Serve() error {
	defer func() {
		if err := s.Close(); err != nil {
			log.Warn().Err(err).Msg("Error closing IPC server")
		}
	}()

	for {
		select {
		case <-s.stopChan:
			return nil
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.stopChan:
				return nil
			default:
				log.Error().Err(err).Msg("Failed to accept IPC connection")
				return fmt.Errorf("failed to accept connection: %w", err)
			}
		}

		go s.handleConnection(conn)
	}
}

// handleConnection handles a single IPC connection
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Warn().Err(err).Msg("Error closing IPC connection")
		}
	}()

	// Read request
	reader := bufio.NewReader(conn)
	decoder := json.NewDecoder(reader)

	var req ForwardRequest
	if err := decoder.Decode(&req); err != nil {
		log.Error().Err(err).Msg("Failed to decode forward request")
		s.sendResponse(conn, ForwardResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid request: %v", err),
		})
		return
	}

	log.Info().
		Str("local", req.Local).
		Str("remote", req.Remote).
		Str("proto", req.Proto).
		Msg("Received forward request")

	// Add forward
	if err := s.forwardAdder(req); err != nil {
		log.Error().Err(err).Msg("Failed to add forward")
		s.sendResponse(conn, ForwardResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to add forward: %v", err),
		})
		return
	}

	// Send success response
	s.sendResponse(conn, ForwardResponse{
		Success: true,
		Message: fmt.Sprintf("Forward added: %s -> %s (%s)", req.Local, req.Remote, req.Proto),
	})
}

// sendResponse sends a JSON response over the connection
func (s *Server) sendResponse(conn net.Conn, resp ForwardResponse) {
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(resp); err != nil {
		log.Error().Err(err).Msg("Failed to send IPC response")
	}
}

// Close stops the IPC server
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Prevent double-close
	if s.closed {
		return nil
	}
	s.closed = true

	close(s.stopChan)

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return fmt.Errorf("failed to close listener: %w", err)
		}
	}

	// Clean up socket file
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		log.Warn().Err(err).Msg("Failed to remove socket file")
	}

	log.Info().Msg("IPC server closed")
	return nil
}

// SendForwardRequest sends a forward request to a running client
func SendForwardRequest(req ForwardRequest) (*ForwardResponse, error) {
	socketPath := GetSocketPath()

	// Check if socket exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("client not running (socket not found: %s)", socketPath)
	}

	// Connect to Unix socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to client: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Error closing IPC connection")
		}
	}()

	// Send request
	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp ForwardResponse
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
}
