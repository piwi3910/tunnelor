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

// HandleCommandStream handles control plane commands after authentication
// This enables dynamic forward management and other runtime operations
func (h *ServerHandler) HandleCommandStream(stream *quicgo.Stream) error {
	log.Info().
		Str("client_id", h.clientID).
		Msg("Command stream opened")

	for {
		// Read command message
		msg, err := ReadMessage(stream)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read command message")
			return fmt.Errorf("failed to read command: %w", err)
		}

		// Handle command based on type
		switch msg.Type {
		case MessageTypeForwardAdd:
			if err := h.handleForwardAdd(stream, msg); err != nil {
				log.Error().Err(err).Msg("Failed to handle FORWARD_ADD")
			}

		case MessageTypeForwardRemove:
			if err := h.handleForwardRemove(stream, msg); err != nil {
				log.Error().Err(err).Msg("Failed to handle FORWARD_REMOVE")
			}

		case MessageTypeForwardList:
			if err := h.handleForwardList(stream, msg); err != nil {
				log.Error().Err(err).Msg("Failed to handle FORWARD_LIST")
			}

		case MessageTypePing:
			if err := h.handlePing(stream, msg); err != nil {
				log.Error().Err(err).Msg("Failed to handle PING")
			}

		default:
			log.Warn().
				Str("type", string(msg.Type)).
				Msg("Unknown command type")
			if err := h.sendForwardFail(stream, fmt.Sprintf("Unknown command type: %s", msg.Type)); err != nil {
				log.Error().Err(err).Msg("Failed to send FORWARD_FAIL")
			}
		}
	}
}

// handleForwardAdd handles dynamic forward addition requests
func (h *ServerHandler) handleForwardAdd(stream *quicgo.Stream, msg *Message) error {
	var addMsg ForwardAddMessage
	if err := msg.ParseData(&addMsg); err != nil {
		return h.sendForwardFail(stream, "Invalid FORWARD_ADD data")
	}

	log.Info().
		Str("type", addMsg.Type).
		Str("local", addMsg.Local).
		Str("remote", addMsg.Remote).
		Str("proto", addMsg.Proto).
		Msg("Received FORWARD_ADD request")

	// TODO: Integrate with ForwardRegistry and start listeners
	// For now, just acknowledge the request
	forwardID := fmt.Sprintf("%s-%s-%d", addMsg.Type, addMsg.Proto, time.Now().Unix())

	return h.sendForwardOK(stream, forwardID, "Forward added successfully")
}

// handleForwardRemove handles dynamic forward removal requests
func (h *ServerHandler) handleForwardRemove(stream *quicgo.Stream, msg *Message) error {
	var removeMsg ForwardRemoveMessage
	if err := msg.ParseData(&removeMsg); err != nil {
		return h.sendForwardFail(stream, "Invalid FORWARD_REMOVE data")
	}

	log.Info().
		Str("forward_id", removeMsg.ForwardID).
		Msg("Received FORWARD_REMOVE request")

	// TODO: Integrate with ForwardRegistry and stop listeners
	// For now, just acknowledge the request

	return h.sendForwardOK(stream, removeMsg.ForwardID, "Forward removed successfully")
}

// handleForwardList handles forward listing requests
func (h *ServerHandler) handleForwardList(stream *quicgo.Stream, msg *Message) error {
	var listMsg ForwardListMessage
	if err := msg.ParseData(&listMsg); err != nil {
		// Empty message is OK for list
		listMsg = ForwardListMessage{}
	}

	log.Info().
		Str("filter", listMsg.Type).
		Msg("Received FORWARD_LIST request")

	// TODO: Query ForwardRegistry for actual forwards
	// For now, return empty list
	forwards := []*ForwardInfo{}

	return h.sendForwardList(stream, forwards)
}

// handlePing handles ping messages in command stream
func (h *ServerHandler) handlePing(stream *quicgo.Stream, msg *Message) error {
	var pingMsg PingMessage
	if err := msg.ParseData(&pingMsg); err != nil {
		return fmt.Errorf("invalid PING data: %w", err)
	}

	// Send pong response
	pongMsg := PongMessage{
		Timestamp: time.Now().Unix(),
		Seq:       pingMsg.Seq,
	}

	pongMessage, err := NewMessage(MessageTypePong, pongMsg)
	if err != nil {
		return fmt.Errorf("failed to create PONG message: %w", err)
	}

	if err := WriteMessage(stream, pongMessage); err != nil {
		return fmt.Errorf("failed to send PONG message: %w", err)
	}

	log.Debug().Uint64("seq", pingMsg.Seq).Msg("Sent PONG message")
	return nil
}

// sendForwardOK sends a FORWARD_OK message
func (h *ServerHandler) sendForwardOK(stream *quicgo.Stream, forwardID, message string) error {
	okMsg := ForwardOKMessage{
		ForwardID: forwardID,
		Message:   message,
	}

	msg, err := NewMessage(MessageTypeForwardOK, okMsg)
	if err != nil {
		return fmt.Errorf("failed to create FORWARD_OK message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send FORWARD_OK message: %w", err)
	}

	log.Debug().
		Str("forward_id", forwardID).
		Str("message", message).
		Msg("Sent FORWARD_OK message")

	return nil
}

// sendForwardList sends a list of forwards
func (h *ServerHandler) sendForwardList(stream *quicgo.Stream, forwards []*ForwardInfo) error {
	listMsg := ForwardOKMessage{
		Forwards: forwards,
		Message:  fmt.Sprintf("Found %d forwards", len(forwards)),
	}

	msg, err := NewMessage(MessageTypeForwardOK, listMsg)
	if err != nil {
		return fmt.Errorf("failed to create FORWARD_OK message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send FORWARD_OK message: %w", err)
	}

	log.Debug().
		Int("count", len(forwards)).
		Msg("Sent forward list")

	return nil
}

// sendForwardFail sends a FORWARD_FAIL message
func (h *ServerHandler) sendForwardFail(stream *quicgo.Stream, reason string) error {
	failMsg := ForwardFailMessage{
		Reason: reason,
	}

	msg, err := NewMessage(MessageTypeForwardFail, failMsg)
	if err != nil {
		return fmt.Errorf("failed to create FORWARD_FAIL message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return fmt.Errorf("failed to send FORWARD_FAIL message: %w", err)
	}

	log.Debug().Str("reason", reason).Msg("Sent FORWARD_FAIL message")

	return nil
}
