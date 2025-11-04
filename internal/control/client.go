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
	lastPing   time.Time
	connection *quic.Connection
	clientID   string
	pskCache   *PSKCache
	sessionID  string
}

// NewClientHandler creates a new client control handler
func NewClientHandler(clientID, psk string, conn *quic.Connection) (*ClientHandler, error) {
	// Cache the decoded PSK to avoid repeated base64 decoding
	pskCache, err := NewPSKCache(psk)
	if err != nil {
		return nil, fmt.Errorf("failed to create PSK cache: %w", err)
	}

	return &ClientHandler{
		clientID:   clientID,
		pskCache:   pskCache,
		connection: conn,
	}, nil
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

	// Compute HMAC using cached PSK (avoids repeated base64 decoding)
	hmacValue := h.pskCache.ComputeAuthHMAC(h.clientID, nonce)

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

// AddForward sends a FORWARD_ADD message to request adding a new forward
func (h *ClientHandler) AddForward(stream *quicgo.Stream, local, remote, proto, forwardType string) (*ForwardOKMessage, error) {
	addMsg := ForwardAddMessage{
		Local:    local,
		Remote:   remote,
		Proto:    proto,
		ClientID: h.clientID,
		Type:     forwardType,
	}

	msg, err := NewMessage(MessageTypeForwardAdd, addMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to create FORWARD_ADD message: %w", err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return nil, fmt.Errorf("failed to send FORWARD_ADD message: %w", err)
	}

	log.Debug().
		Str("local", local).
		Str("remote", remote).
		Str("proto", proto).
		Str("type", forwardType).
		Msg("Sent FORWARD_ADD message")

	// Wait for response
	respMsg, err := ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read forward add response: %w", err)
	}

	return h.handleForwardResponse(respMsg)
}

// RemoveForward sends a FORWARD_REMOVE message to request removing a forward
func (h *ClientHandler) RemoveForward(stream *quicgo.Stream, forwardID string) (*ForwardOKMessage, error) {
	removeMsg := ForwardRemoveMessage{
		ForwardID: forwardID,
	}

	return h.sendForwardCommand(stream, MessageTypeForwardRemove, removeMsg, "FORWARD_REMOVE", forwardID)
}

// ListForwards sends a FORWARD_LIST message to request listing active forwards
func (h *ClientHandler) ListForwards(stream *quicgo.Stream, filterType string) (*ForwardOKMessage, error) {
	listMsg := ForwardListMessage{
		Type: filterType,
	}

	return h.sendForwardCommand(stream, MessageTypeForwardList, listMsg, "FORWARD_LIST", filterType)
}

// sendForwardCommand is a helper to send forward management commands and handle responses
func (h *ClientHandler) sendForwardCommand(stream *quicgo.Stream, msgType MessageType, data interface{}, cmdName, logValue string) (*ForwardOKMessage, error) {
	msg, err := NewMessage(msgType, data)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s message: %w", cmdName, err)
	}

	if err := WriteMessage(stream, msg); err != nil {
		return nil, fmt.Errorf("failed to send %s message: %w", cmdName, err)
	}

	log.Debug().
		Str("value", logValue).
		Msgf("Sent %s message", cmdName)

	// Wait for response
	respMsg, err := ReadMessage(stream)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s response: %w", cmdName, err)
	}

	return h.handleForwardResponse(respMsg)
}

// handleForwardResponse handles responses to forward management commands
func (h *ClientHandler) handleForwardResponse(msg *Message) (*ForwardOKMessage, error) {
	switch msg.Type {
	case MessageTypeForwardOK:
		var okMsg ForwardOKMessage
		if err := msg.ParseData(&okMsg); err != nil {
			return nil, fmt.Errorf("failed to parse FORWARD_OK message: %w", err)
		}

		log.Info().
			Str("forward_id", okMsg.ForwardID).
			Str("message", okMsg.Message).
			Msg("Forward operation successful")

		return &okMsg, nil

	case MessageTypeForwardFail:
		var failMsg ForwardFailMessage
		if err := msg.ParseData(&failMsg); err != nil {
			return nil, fmt.Errorf("forward operation failed: %w", err)
		}

		log.Error().
			Str("reason", failMsg.Reason).
			Msg("Forward operation failed")

		return nil, fmt.Errorf("forward operation failed: %s", failMsg.Reason)

	default:
		return nil, fmt.Errorf("unexpected response type: %s", msg.Type)
	}
}
