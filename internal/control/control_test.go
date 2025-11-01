package control

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Test auth.go functions

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}

	if len(nonce1) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("GenerateNonce() length = %d, want 32", len(nonce1))
	}

	// Generate another and ensure they're different
	nonce2, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}

	if nonce1 == nonce2 {
		t.Error("GenerateNonce() generated same nonce twice")
	}
}

func TestComputeHMAC(t *testing.T) {
	// Create a base64-encoded test key
	key := base64.StdEncoding.EncodeToString([]byte("test-secret-key"))
	message := "test message"

	hmac1, err := ComputeHMAC(key, message)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	if len(hmac1) == 0 {
		t.Error("ComputeHMAC() returned empty string")
	}

	// Computing same HMAC should give same result
	hmac2, err := ComputeHMAC(key, message)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	if hmac1 != hmac2 {
		t.Error("ComputeHMAC() not deterministic")
	}

	// Different message should give different HMAC
	hmac3, err := ComputeHMAC(key, "different message")
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	if hmac1 == hmac3 {
		t.Error("ComputeHMAC() same for different messages")
	}
}

func TestComputeHMACInvalidKey(t *testing.T) {
	_, err := ComputeHMAC("invalid-base64!!!", "message")
	if err == nil {
		t.Error("ComputeHMAC() expected error for invalid base64 key")
	}
}

func TestVerifyHMAC(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("test-secret-key"))
	message := "test message"

	hmac, err := ComputeHMAC(key, message)
	if err != nil {
		t.Fatalf("ComputeHMAC() error = %v", err)
	}

	// Verify should succeed with correct HMAC
	valid, err := VerifyHMAC(key, message, hmac)
	if err != nil {
		t.Fatalf("VerifyHMAC() error = %v", err)
	}
	if !valid {
		t.Error("VerifyHMAC() = false, want true")
	}

	// Verify should fail with incorrect HMAC
	valid, err = VerifyHMAC(key, message, "wrong-hmac")
	if err != nil {
		t.Fatalf("VerifyHMAC() error = %v", err)
	}
	if valid {
		t.Error("VerifyHMAC() = true for wrong HMAC, want false")
	}

	// Verify should fail with different message
	valid, err = VerifyHMAC(key, "different message", hmac)
	if err != nil {
		t.Fatalf("VerifyHMAC() error = %v", err)
	}
	if valid {
		t.Error("VerifyHMAC() = true for different message, want false")
	}
}

func TestCreateAuthPayload(t *testing.T) {
	clientID := "test-client"
	nonce := "abc123"

	payload := CreateAuthPayload(clientID, nonce)
	expected := "test-client|abc123"

	if payload != expected {
		t.Errorf("CreateAuthPayload() = %v, want %v", payload, expected)
	}
}

func TestComputeAuthHMAC(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString([]byte("test-secret"))
	clientID := "test-client"
	nonce := "abc123"

	hmac, err := ComputeAuthHMAC(psk, clientID, nonce)
	if err != nil {
		t.Fatalf("ComputeAuthHMAC() error = %v", err)
	}

	if len(hmac) == 0 {
		t.Error("ComputeAuthHMAC() returned empty string")
	}
}

func TestVerifyAuthHMAC(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString([]byte("test-secret"))
	clientID := "test-client"
	nonce := "abc123"

	hmac, err := ComputeAuthHMAC(psk, clientID, nonce)
	if err != nil {
		t.Fatalf("ComputeAuthHMAC() error = %v", err)
	}

	// Verify should succeed
	valid, err := VerifyAuthHMAC(psk, clientID, nonce, hmac)
	if err != nil {
		t.Fatalf("VerifyAuthHMAC() error = %v", err)
	}
	if !valid {
		t.Error("VerifyAuthHMAC() = false, want true")
	}

	// Verify should fail with wrong HMAC
	valid, err = VerifyAuthHMAC(psk, clientID, nonce, "wrong-hmac")
	if err != nil {
		t.Fatalf("VerifyAuthHMAC() error = %v", err)
	}
	if valid {
		t.Error("VerifyAuthHMAC() = true for wrong HMAC, want false")
	}

	// Verify should fail with wrong client ID
	valid, err = VerifyAuthHMAC(psk, "wrong-client", nonce, hmac)
	if err != nil {
		t.Fatalf("VerifyAuthHMAC() error = %v", err)
	}
	if valid {
		t.Error("VerifyAuthHMAC() = true for wrong client ID, want false")
	}
}

// Test messages.go functions

func TestNewMessage(t *testing.T) {
	tests := []struct {
		name    string
		msgType MessageType
		data    interface{}
		wantErr bool
	}{
		{
			name:    "message without data",
			msgType: MessageTypePing,
			data:    nil,
			wantErr: false,
		},
		{
			name:    "message with struct data",
			msgType: MessageTypeAuth,
			data: &AuthMessage{
				ClientID: "test",
				Nonce:    "abc123",
				HMAC:     "hmac-value",
			},
			wantErr: false,
		},
		{
			name:    "message with map data",
			msgType: MessageTypeMetrics,
			data: map[string]interface{}{
				"active_streams": 5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := NewMessage(tt.msgType, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if msg.Type != tt.msgType {
					t.Errorf("NewMessage() type = %v, want %v", msg.Type, tt.msgType)
				}
			}
		})
	}
}

func TestMessageParseData(t *testing.T) {
	authData := &AuthMessage{
		ClientID: "test-client",
		Nonce:    "abc123",
		HMAC:     "hmac-value",
	}

	msg, err := NewMessage(MessageTypeAuth, authData)
	if err != nil {
		t.Fatalf("NewMessage() error = %v", err)
	}

	var parsed AuthMessage
	err = msg.ParseData(&parsed)
	if err != nil {
		t.Fatalf("ParseData() error = %v", err)
	}

	if parsed.ClientID != authData.ClientID {
		t.Errorf("ParseData() ClientID = %v, want %v", parsed.ClientID, authData.ClientID)
	}
	if parsed.Nonce != authData.Nonce {
		t.Errorf("ParseData() Nonce = %v, want %v", parsed.Nonce, authData.Nonce)
	}
	if parsed.HMAC != authData.HMAC {
		t.Errorf("ParseData() HMAC = %v, want %v", parsed.HMAC, authData.HMAC)
	}
}

func TestMessageParseDataNoData(t *testing.T) {
	msg, err := NewMessage(MessageTypePing, nil)
	if err != nil {
		t.Fatalf("NewMessage() error = %v", err)
	}

	var parsed PingMessage
	err = msg.ParseData(&parsed)
	if err == nil {
		t.Error("ParseData() expected error for message with no data")
	}
}

func TestMessageMarshalUnmarshal(t *testing.T) {
	authData := &AuthMessage{
		ClientID: "test-client",
		Nonce:    "abc123",
		HMAC:     "hmac-value",
	}

	msg, err := NewMessage(MessageTypeAuth, authData)
	if err != nil {
		t.Fatalf("NewMessage() error = %v", err)
	}

	// Marshal
	data, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Marshal() returned empty data")
	}

	// Unmarshal
	msg2, err := UnmarshalMessage(data)
	if err != nil {
		t.Fatalf("UnmarshalMessage() error = %v", err)
	}

	if msg2.Type != msg.Type {
		t.Errorf("UnmarshalMessage() Type = %v, want %v", msg2.Type, msg.Type)
	}

	// Parse data
	var parsed AuthMessage
	err = msg2.ParseData(&parsed)
	if err != nil {
		t.Fatalf("ParseData() error = %v", err)
	}

	if parsed.ClientID != authData.ClientID {
		t.Errorf("Parsed ClientID = %v, want %v", parsed.ClientID, authData.ClientID)
	}
}

func TestUnmarshalMessageInvalid(t *testing.T) {
	_, err := UnmarshalMessage([]byte("invalid json"))
	if err == nil {
		t.Error("UnmarshalMessage() expected error for invalid JSON")
	}
}

func TestAllMessageTypes(t *testing.T) {
	messageTypes := []MessageType{
		MessageTypeAuth,
		MessageTypeAuthOK,
		MessageTypeAuthFail,
		MessageTypeOpen,
		MessageTypeClose,
		MessageTypeMetrics,
		MessageTypePing,
		MessageTypePong,
	}

	for _, msgType := range messageTypes {
		msg, err := NewMessage(msgType, nil)
		if err != nil {
			t.Errorf("NewMessage(%v) error = %v", msgType, err)
		}
		if msg.Type != msgType {
			t.Errorf("NewMessage(%v) Type = %v", msgType, msg.Type)
		}
	}
}

// Test framing.go functions using bufio (avoiding QUIC stream dependency)

func TestWriteReadMessageBuffered(t *testing.T) {
	authData := &AuthMessage{
		ClientID: "test-client",
		Nonce:    "abc123",
		HMAC:     "hmac-value",
	}

	msg, err := NewMessage(MessageTypeAuth, authData)
	if err != nil {
		t.Fatalf("NewMessage() error = %v", err)
	}

	// Create buffer
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	reader := bufio.NewReader(&buf)

	// Write message
	err = WriteMessageBuffered(writer, msg)
	if err != nil {
		t.Fatalf("WriteMessageBuffered() error = %v", err)
	}

	// Read message
	msg2, err := ReadMessageBuffered(reader)
	if err != nil {
		t.Fatalf("ReadMessageBuffered() error = %v", err)
	}

	if msg2.Type != msg.Type {
		t.Errorf("ReadMessageBuffered() Type = %v, want %v", msg2.Type, msg.Type)
	}

	// Parse data
	var parsed AuthMessage
	err = msg2.ParseData(&parsed)
	if err != nil {
		t.Fatalf("ParseData() error = %v", err)
	}

	if parsed.ClientID != authData.ClientID {
		t.Errorf("Parsed ClientID = %v, want %v", parsed.ClientID, authData.ClientID)
	}
}

func TestWriteMessageBufferedTooLarge(t *testing.T) {
	// Create message with data larger than MaxMessageSize
	largeData := make([]byte, MaxMessageSize+1)
	for i := range largeData {
		largeData[i] = 'a'
	}

	msg := &Message{
		Type: MessageTypeAuth,
		Data: json.RawMessage(largeData),
	}

	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	err := WriteMessageBuffered(writer, msg)
	if err == nil {
		t.Error("WriteMessageBuffered() expected error for message too large")
	}
}

func TestReadMessageBufferedTooLarge(t *testing.T) {
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	// Write a length that exceeds MaxMessageSize
	largeLength := uint32(MaxMessageSize + 1)
	writer.Write([]byte{
		byte(largeLength >> 24),
		byte(largeLength >> 16),
		byte(largeLength >> 8),
		byte(largeLength),
	})
	writer.Flush()

	reader := bufio.NewReader(&buf)
	_, err := ReadMessageBuffered(reader)
	if err == nil {
		t.Error("ReadMessageBuffered() expected error for message too large")
	}
}

func TestReadMessageBufferedEOF(t *testing.T) {
	var buf bytes.Buffer
	reader := bufio.NewReader(&buf)

	_, err := ReadMessageBuffered(reader)
	if err == nil {
		t.Error("ReadMessageBuffered() expected EOF error")
	}
}

func TestMultipleMessagesBuffered(t *testing.T) {
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	// Write multiple messages
	messages := []MessageType{
		MessageTypeAuth,
		MessageTypeAuthOK,
		MessageTypePing,
	}

	for _, msgType := range messages {
		msg, err := NewMessage(msgType, nil)
		if err != nil {
			t.Fatalf("NewMessage() error = %v", err)
		}
		err = WriteMessageBuffered(writer, msg)
		if err != nil {
			t.Fatalf("WriteMessageBuffered() error = %v", err)
		}
	}

	// Read messages back
	reader := bufio.NewReader(&buf)
	for i, expectedType := range messages {
		msg, err := ReadMessageBuffered(reader)
		if err != nil {
			t.Fatalf("ReadMessageBuffered() message %d error = %v", i, err)
		}
		if msg.Type != expectedType {
			t.Errorf("Message %d Type = %v, want %v", i, msg.Type, expectedType)
		}
	}
}

// TestNewClientHandler tests the ClientHandler constructor
func TestNewClientHandler(t *testing.T) {
	clientID := "test-client"
	psk := "test-psk"

	handler := NewClientHandler(clientID, psk, nil)

	if handler == nil {
		t.Fatal("NewClientHandler() returned nil")
	}
	if handler.clientID != clientID {
		t.Errorf("clientID = %v, want %v", handler.clientID, clientID)
	}
	if handler.psk != psk {
		t.Errorf("psk = %v, want %v", handler.psk, psk)
	}
	if handler.sessionID != "" {
		t.Errorf("sessionID should be empty, got %v", handler.sessionID)
	}
}

// TestClientHandlerGetSessionID tests GetSessionID method
func TestClientHandlerGetSessionID(t *testing.T) {
	handler := NewClientHandler("test", "psk", nil)

	// Initially should be empty
	if sid := handler.GetSessionID(); sid != "" {
		t.Errorf("GetSessionID() = %v, want empty string", sid)
	}

	// Set session ID directly for testing
	handler.sessionID = "test-session-123"
	if sid := handler.GetSessionID(); sid != "test-session-123" {
		t.Errorf("GetSessionID() = %v, want test-session-123", sid)
	}
}

// TestClientHandlerIsAuthenticated tests IsAuthenticated method
func TestClientHandlerIsAuthenticated(t *testing.T) {
	handler := NewClientHandler("test", "psk", nil)

	// Initially should be false
	if handler.IsAuthenticated() {
		t.Error("IsAuthenticated() = true, want false")
	}

	// Set session ID to simulate authentication
	handler.sessionID = "test-session-123"
	if !handler.IsAuthenticated() {
		t.Error("IsAuthenticated() = false, want true after setting sessionID")
	}
}

// TestNewServerHandler tests the ServerHandler constructor
func TestNewServerHandler(t *testing.T) {
	pskMap := map[string]string{
		"client1": "psk1",
		"client2": "psk2",
	}

	handler := NewServerHandler(pskMap, nil)

	if handler == nil {
		t.Fatal("NewServerHandler() returned nil")
	}
	if len(handler.pskMap) != 2 {
		t.Errorf("pskMap length = %v, want 2", len(handler.pskMap))
	}
	if handler.sessions == nil {
		t.Error("sessions map should be initialized")
	}
	if len(handler.sessions) != 0 {
		t.Errorf("sessions should be empty initially, got %v", len(handler.sessions))
	}
}

// TestServerHandlerSessionManagement tests session management methods
func TestServerHandlerSessionManagement(t *testing.T) {
	handler := NewServerHandler(map[string]string{"client1": "psk1"}, nil)

	// Initially should have no sessions
	if count := handler.SessionCount(); count != 0 {
		t.Errorf("SessionCount() = %v, want 0", count)
	}

	// Add a session manually for testing
	session := &Session{
		SessionID:  "session-123",
		ClientID:   "client1",
		RemoteAddr: "127.0.0.1:12345",
	}
	handler.sessions["session-123"] = session

	// Test SessionCount
	if count := handler.SessionCount(); count != 1 {
		t.Errorf("SessionCount() = %v, want 1", count)
	}

	// Test GetSession
	retrieved, ok := handler.GetSession("session-123")
	if !ok {
		t.Error("GetSession() should return true for existing session")
	}
	if retrieved.SessionID != "session-123" {
		t.Errorf("GetSession() SessionID = %v, want session-123", retrieved.SessionID)
	}

	// Test GetSession for non-existent session
	_, ok = handler.GetSession("nonexistent")
	if ok {
		t.Error("GetSession() should return false for non-existent session")
	}

	// Test RemoveSession
	handler.RemoveSession("session-123")
	if count := handler.SessionCount(); count != 0 {
		t.Errorf("SessionCount() after removal = %v, want 0", count)
	}

	// Verify session is actually removed
	_, ok = handler.GetSession("session-123")
	if ok {
		t.Error("GetSession() should return false after RemoveSession()")
	}
}

// TestServerHandlerMultipleSessions tests managing multiple sessions
func TestServerHandlerMultipleSessions(t *testing.T) {
	handler := NewServerHandler(map[string]string{
		"client1": "psk1",
		"client2": "psk2",
	}, nil)

	// Add multiple sessions
	sessions := []*Session{
		{SessionID: "session-1", ClientID: "client1", RemoteAddr: "127.0.0.1:1001"},
		{SessionID: "session-2", ClientID: "client1", RemoteAddr: "127.0.0.1:1002"},
		{SessionID: "session-3", ClientID: "client2", RemoteAddr: "127.0.0.1:1003"},
	}

	for _, s := range sessions {
		handler.sessions[s.SessionID] = s
	}

	// Verify count
	if count := handler.SessionCount(); count != 3 {
		t.Errorf("SessionCount() = %v, want 3", count)
	}

	// Verify each session can be retrieved
	for _, s := range sessions {
		retrieved, ok := handler.GetSession(s.SessionID)
		if !ok {
			t.Errorf("GetSession(%s) should exist", s.SessionID)
		}
		if retrieved.ClientID != s.ClientID {
			t.Errorf("GetSession(%s).ClientID = %v, want %v", s.SessionID, retrieved.ClientID, s.ClientID)
		}
	}

	// Remove one session
	handler.RemoveSession("session-2")
	if count := handler.SessionCount(); count != 2 {
		t.Errorf("SessionCount() after one removal = %v, want 2", count)
	}

	// Verify removed session is gone
	_, ok := handler.GetSession("session-2")
	if ok {
		t.Error("Removed session should not be retrievable")
	}

	// Other sessions should still exist
	_, ok = handler.GetSession("session-1")
	if !ok {
		t.Error("session-1 should still exist")
	}
	_, ok = handler.GetSession("session-3")
	if !ok {
		t.Error("session-3 should still exist")
	}
}
