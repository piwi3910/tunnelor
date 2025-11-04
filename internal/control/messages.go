package control

import (
	"encoding/json"
	"fmt"
)

// MessageType represents the type of control message
type MessageType string

const (
	// MessageTypeAuth is sent by client to authenticate
	MessageTypeAuth MessageType = "AUTH"

	// MessageTypeAuthOK is sent by server on successful authentication
	MessageTypeAuthOK MessageType = "AUTH_OK"

	// MessageTypeAuthFail is sent by server on failed authentication
	MessageTypeAuthFail MessageType = "AUTH_FAIL"

	// MessageTypeOpen is sent to request opening a new tunnel
	MessageTypeOpen MessageType = "OPEN"

	// MessageTypeClose is sent to close a stream
	MessageTypeClose MessageType = "CLOSE"

	// MessageTypeMetrics is sent to share metrics
	MessageTypeMetrics MessageType = "METRICS"

	// MessageTypePing is sent for keepalive
	MessageTypePing MessageType = "PING"

	// MessageTypePong is sent in response to ping
	MessageTypePong MessageType = "PONG"

	// MessageTypeForwardAdd is sent to request adding a new forward
	MessageTypeForwardAdd MessageType = "FORWARD_ADD"

	// MessageTypeForwardRemove is sent to request removing a forward
	MessageTypeForwardRemove MessageType = "FORWARD_REMOVE"

	// MessageTypeForwardList is sent to request listing active forwards
	MessageTypeForwardList MessageType = "FORWARD_LIST"

	// MessageTypeForwardOK is sent when forward operation succeeds
	MessageTypeForwardOK MessageType = "FORWARD_OK"

	// MessageTypeForwardFail is sent when forward operation fails
	MessageTypeForwardFail MessageType = "FORWARD_FAIL"
)

// Message represents a control plane message
type Message struct {
	Type MessageType     `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// AuthMessage is sent by client to authenticate with PSK
type AuthMessage struct {
	ClientID string `json:"client_id"`
	Nonce    string `json:"nonce"`
	HMAC     string `json:"hmac"`
}

// AuthOKMessage is sent by server on successful authentication
type AuthOKMessage struct {
	SessionID string `json:"session_id"`
	Message   string `json:"message,omitempty"`
}

// AuthFailMessage is sent by server on failed authentication
type AuthFailMessage struct {
	Reason string `json:"reason"`
}

// OpenMessage requests opening a new tunnel
type OpenMessage struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	StreamID   uint64 `json:"stream_id"`
}

// CloseMessage requests closing a stream
type CloseMessage struct {
	Reason   string `json:"reason,omitempty"`
	StreamID uint64 `json:"stream_id"`
}

// MetricsMessage contains session metrics
type MetricsMessage struct {
	ActiveStreams int    `json:"active_streams"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
	StreamsOpened uint64 `json:"streams_opened"`
	StreamsClosed uint64 `json:"streams_closed"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// PingMessage is sent for keepalive
type PingMessage struct {
	Timestamp int64  `json:"timestamp"`
	Seq       uint64 `json:"seq"`
}

// PongMessage is sent in response to ping
type PongMessage struct {
	Timestamp int64  `json:"timestamp"`
	Seq       uint64 `json:"seq"`
}

// ForwardAddMessage requests adding a new forward tunnel
type ForwardAddMessage struct {
	Local    string `json:"local"`     // Local address to listen on (forward) or public address (reverse)
	Remote   string `json:"remote"`    // Remote address to connect to
	Proto    string `json:"proto"`     // Protocol: "tcp" or "udp"
	ClientID string `json:"client_id"` // Client ID (for server-side reverse tunnels)
	Type     string `json:"type"`      // "forward" or "reverse"
}

// ForwardRemoveMessage requests removing a forward tunnel
type ForwardRemoveMessage struct {
	ForwardID string `json:"forward_id"` // ID of the forward to remove
}

// ForwardListMessage requests listing active forwards
type ForwardListMessage struct {
	Type string `json:"type,omitempty"` // Optional filter: "forward", "reverse", or empty for all
}

// ForwardInfo represents information about an active forward
type ForwardInfo struct {
	ID       string `json:"id"`        // Unique identifier
	Local    string `json:"local"`     // Local/public address
	Remote   string `json:"remote"`    // Remote address
	Proto    string `json:"proto"`     // Protocol
	ClientID string `json:"client_id"` // Client ID (for reverse tunnels)
	Type     string `json:"type"`      // "forward" or "reverse"
	Active   bool   `json:"active"`    // Whether the forward is currently active
}

// ForwardOKMessage indicates successful forward operation
type ForwardOKMessage struct {
	ForwardID string         `json:"forward_id,omitempty"`
	Message   string         `json:"message,omitempty"`
	Forwards  []*ForwardInfo `json:"forwards,omitempty"`
}

// ForwardFailMessage indicates failed forward operation
type ForwardFailMessage struct {
	Reason string `json:"reason"` // Error reason
}

// NewMessage creates a new control message
func NewMessage(msgType MessageType, data interface{}) (*Message, error) {
	var rawData json.RawMessage
	if data != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal message data: %w", err)
		}
		rawData = jsonData
	}

	return &Message{
		Type: msgType,
		Data: rawData,
	}, nil
}

// ParseData parses the message data into the given structure
func (m *Message) ParseData(v interface{}) error {
	if m.Data == nil {
		return fmt.Errorf("message has no data")
	}

	if err := json.Unmarshal(m.Data, v); err != nil {
		return fmt.Errorf("failed to unmarshal message data: %w", err)
	}

	return nil
}

// Marshal serializes the message to JSON
func (m *Message) Marshal() ([]byte, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message: %w", err)
	}
	return data, nil
}

// UnmarshalMessage deserializes a message from JSON
func UnmarshalMessage(data []byte) (*Message, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return &msg, nil
}
