package control

import (
	"fmt"
	"time"

	"github.com/piwi3910/tunnelor/internal/quic"
	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// ServerHandler handles control plane operations on the server side
type ServerHandler struct {
	pskMap     map[string]string
	sessions   map[string]*Session
	connection *quic.Connection
}

// Session represents an authenticated client session
type Session struct {
	SessionID  string
	ClientID   string
	RemoteAddr string
	AuthTime   time.Time
	LastSeen   time.Time
}

// NewServerHandler creates a new server control handler
func NewServerHandler(pskMap map[string]string, conn *quic.Connection) *ServerHandler {
	return &ServerHandler{
		pskMap:     pskMap,
		sessions:   make(map[string]*Session),
		connection: conn,
	}
}

// HandleControlStream handles the control stream for authentication and session management
func (h *ServerHandler) HandleControlStream(stream *quicgo.Stream) error {
	log.Info().
		Str("remote_addr", h.connection.RemoteAddr()).
		Msg("Control stream opened")

	// Read authentication message
	msg, err := ReadMessage(stream)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read auth message")
		return h.sendAuthFail(stream, "Failed to read authentication message")
	}

	// Verify message type
	if msg.Type != MessageTypeAuth {
		log.Warn().
			Str("type", string(msg.Type)).
			Msg("Expected AUTH message")
		return h.sendAuthFail(stream, "Expected AUTH message")
	}

	// Parse authentication data
	var authMsg AuthMessage
	if err := msg.ParseData(&authMsg); err != nil {
		log.Error().Err(err).Msg("Failed to parse auth message")
		return h.sendAuthFail(stream, "Invalid authentication data")
	}

	// Verify client has PSK
	psk, ok := h.pskMap[authMsg.ClientID]
	if !ok {
		log.Warn().
			Str("client_id", authMsg.ClientID).
			Msg("Unknown client ID")
		return h.sendAuthFail(stream, "Authentication failed")
	}

	// Verify HMAC
	valid, err := VerifyAuthHMAC(psk, authMsg.ClientID, authMsg.Nonce, authMsg.HMAC)
	if err != nil {
		log.Error().Err(err).Msg("Failed to verify HMAC")
		return h.sendAuthFail(stream, "Authentication failed")
	}

	if !valid {
		log.Warn().
			Str("client_id", authMsg.ClientID).
			Msg("Invalid HMAC")
		return h.sendAuthFail(stream, "Authentication failed")
	}

	// Create session
	sessionID := fmt.Sprintf("%s-%d", authMsg.ClientID, time.Now().Unix())
	session := &Session{
		SessionID:  sessionID,
		ClientID:   authMsg.ClientID,
		RemoteAddr: h.connection.RemoteAddr(),
		AuthTime:   time.Now(),
		LastSeen:   time.Now(),
	}

	h.sessions[sessionID] = session

	log.Info().
		Str("client_id", authMsg.ClientID).
		Str("session_id", sessionID).
		Str("remote_addr", h.connection.RemoteAddr()).
		Msg("Client authenticated successfully")

	// Send AUTH_OK response
	return h.sendAuthOK(stream, sessionID)
}

// sendAuthOK sends an AUTH_OK message to the client
func (h *ServerHandler) sendAuthOK(stream *quicgo.Stream, sessionID string) error {
	authOK := AuthOKMessage{
		SessionID: sessionID,
		Message:   "Authentication successful",
	}

	msg, err := NewMessage(MessageTypeAuthOK, authOK)
	if err != nil {
		return fmt.Errorf("failed to create AUTH_OK message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send AUTH_OK message: %w", err)
	}

	log.Debug().
		Str("session_id", sessionID).
		Msg("Sent AUTH_OK message")

	return nil
}

// sendAuthFail sends an AUTH_FAIL message to the client
func (h *ServerHandler) sendAuthFail(stream *quicgo.Stream, reason string) error {
	authFail := AuthFailMessage{
		Reason: reason,
	}

	msg, err := NewMessage(MessageTypeAuthFail, authFail)
	if err != nil {
		return fmt.Errorf("failed to create AUTH_FAIL message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send AUTH_FAIL message: %w", err)
	}

	log.Debug().Str("reason", reason).Msg("Sent AUTH_FAIL message")

	return nil
}

// GetSession returns a session by ID
func (h *ServerHandler) GetSession(sessionID string) (*Session, bool) {
	session, ok := h.sessions[sessionID]
	return session, ok
}

// RemoveSession removes a session
func (h *ServerHandler) RemoveSession(sessionID string) {
	delete(h.sessions, sessionID)
	log.Info().Str("session_id", sessionID).Msg("Session removed")
}

// SessionCount returns the number of active sessions
func (h *ServerHandler) SessionCount() int {
	return len(h.sessions)
}
