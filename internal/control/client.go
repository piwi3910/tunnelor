package control

import (
	"fmt"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/piwi3910/tunnelor/internal/quic"
)

// ClientHandler handles control plane operations on the client side
type ClientHandler struct {
	clientID   string
	psk        string
	connection *quic.Connection
	sessionID  string
	lastPing   time.Time
}

// NewClientHandler creates a new client control handler
func NewClientHandler(clientID, psk string, conn *quic.Connection) *ClientHandler {
	return &ClientHandler{
		clientID:   clientID,
		psk:        psk,
		connection: conn,
	}
}

// Authenticate performs PSK authentication with the server
func (h *ClientHandler) Authenticate() error {
	log.Info().
		Str("client_id", h.clientID).
		Msg("Starting authentication...")

	// Open control stream
	stream, err := h.connection.OpenStream()
	if err != nil {
		return fmt.Errorf("failed to open control stream: %w", err)
	}

	// Generate nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Compute HMAC
	hmacValue, err := ComputeAuthHMAC(h.psk, h.clientID, nonce)
	if err != nil {
		return fmt.Errorf("failed to compute HMAC: %w", err)
	}

	// Create AUTH message
	authMsg := AuthMessage{
		ClientID: h.clientID,
		Nonce:    nonce,
		HMAC:     hmacValue,
	}

	msg, err := NewMessage(MessageTypeAuth, authMsg)
	if err != nil {
		return fmt.Errorf("failed to create AUTH message: %w", err)
	}

	// Send AUTH message
	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send AUTH message: %w", err)
	}

	log.Debug().
		Str("client_id", h.clientID).
		Msg("Sent AUTH message")

	// Wait for response
	respMsg, err := ReadMessage(stream)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	// Handle response
	switch respMsg.Type {
	case MessageTypeAuthOK:
		var authOK AuthOKMessage
		if err := respMsg.ParseData(&authOK); err != nil {
			return fmt.Errorf("failed to parse AUTH_OK message: %w", err)
		}

		h.sessionID = authOK.SessionID

		log.Info().
			Str("client_id", h.clientID).
			Str("session_id", h.sessionID).
			Msg("Authentication successful")

		return nil

	case MessageTypeAuthFail:
		var authFail AuthFailMessage
		if err := respMsg.ParseData(&authFail); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		log.Error().
			Str("reason", authFail.Reason).
			Msg("Authentication failed")

		return fmt.Errorf("authentication failed: %s", authFail.Reason)

	default:
		return fmt.Errorf("unexpected response type: %s", respMsg.Type)
	}
}

// SendPing sends a ping message to the server
func (h *ClientHandler) SendPing(stream *quicgo.Stream, seq uint64) error {
	pingMsg := PingMessage{
		Timestamp: time.Now().Unix(),
		Seq:       seq,
	}

	msg, err := NewMessage(MessageTypePing, pingMsg)
	if err != nil {
		return fmt.Errorf("failed to create PING message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send PING message: %w", err)
	}

	h.lastPing = time.Now()

	log.Debug().Uint64("seq", seq).Msg("Sent PING message")

	return nil
}

// SendOpen sends an OPEN message to request a new tunnel
func (h *ClientHandler) SendOpen(stream *quicgo.Stream, streamID uint64, protocol, localAddr, remoteAddr string) error {
	openMsg := OpenMessage{
		StreamID:   streamID,
		Protocol:   protocol,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
	}

	msg, err := NewMessage(MessageTypeOpen, openMsg)
	if err != nil {
		return fmt.Errorf("failed to create OPEN message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send OPEN message: %w", err)
	}

	log.Debug().
		Uint64("stream_id", streamID).
		Str("protocol", protocol).
		Str("local", localAddr).
		Str("remote", remoteAddr).
		Msg("Sent OPEN message")

	return nil
}

// SendClose sends a CLOSE message to close a stream
func (h *ClientHandler) SendClose(stream *quicgo.Stream, streamID uint64, reason string) error {
	closeMsg := CloseMessage{
		StreamID: streamID,
		Reason:   reason,
	}

	msg, err := NewMessage(MessageTypeClose, closeMsg)
	if err != nil {
		return fmt.Errorf("failed to create CLOSE message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send CLOSE message: %w", err)
	}

	log.Debug().
		Uint64("stream_id", streamID).
		Str("reason", reason).
		Msg("Sent CLOSE message")

	return nil
}

// GetSessionID returns the current session ID
func (h *ClientHandler) GetSessionID() string {
	return h.sessionID
}

// IsAuthenticated returns true if the client has authenticated
func (h *ClientHandler) IsAuthenticated() bool {
	return h.sessionID != ""
}
