package control

import (
	"fmt"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/piwi3910/tunnelor/internal/quic"
)

// ServerHandler handles control plane operations on the server side
type ServerHandler struct {
	pskCacheMap map[string]*PSKCache
	sessions    map[string]*Session
	connection  *quic.Connection
	clientID    string // Authenticated client ID
}

// Session represents an authenticated client session
type Session struct {
	AuthTime   time.Time
	LastSeen   time.Time
	SessionID  string
	ClientID   string
	RemoteAddr string
}

// NewServerHandler creates a new server control handler
func NewServerHandler(pskMap map[string]string, conn *quic.Connection) (*ServerHandler, error) {
	// Pre-decode all PSKs into caches to avoid repeated base64 decoding
	pskCacheMap := make(map[string]*PSKCache, len(pskMap))
	for clientID, psk := range pskMap {
		cache, err := NewPSKCache(psk)
		if err != nil {
			return nil, fmt.Errorf("failed to create PSK cache for client %s: %w", clientID, err)
		}
		pskCacheMap[clientID] = cache
	}

	return &ServerHandler{
		pskCacheMap: pskCacheMap,
		sessions:    make(map[string]*Session),
		connection:  conn,
	}, nil
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

	// Verify client has PSK cache
	pskCache, ok := h.pskCacheMap[authMsg.ClientID]
	if !ok {
		log.Warn().
			Str("client_id", authMsg.ClientID).
			Msg("Unknown client ID")
		return h.sendAuthFail(stream, "Authentication failed")
	}

	// Verify HMAC using cached PSK (avoids repeated base64 decoding)
	valid := pskCache.VerifyAuthHMAC(authMsg.ClientID, authMsg.Nonce, authMsg.HMAC)
	if !valid {
		log.Warn().
			Str("client_id", authMsg.ClientID).
			Msg("HMAC verification failed")
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
	h.clientID = authMsg.ClientID // Store authenticated client ID

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

// GetClientID returns the authenticated client ID
func (h *ServerHandler) GetClientID() string {
	return h.clientID
}
