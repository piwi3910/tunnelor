package control

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testClientID  = "test-client"
	testPSK       = "abc123"
	testSessionID = "test-session-123"
)

// Test auth.go functions

func TestGenerateNonce(t *testing.T) {
	nonce1, err := GenerateNonce()
	require.NoError(t, err, "GenerateNonce() should not return error")
	assert.Equal(t, 32, len(nonce1), "GenerateNonce() length should be 32") // 16 bytes = 32 hex chars

	// Generate another and ensure they're different
	nonce2, err := GenerateNonce()
	require.NoError(t, err, "GenerateNonce() should not return error")
	assert.NotEqual(t, nonce1, nonce2, "GenerateNonce() should generate different nonces")
}

func TestComputeHMAC(t *testing.T) {
	// Create a base64-encoded test key
	key := base64.StdEncoding.EncodeToString([]byte("test-secret-key"))
	message := "test message"

	hmac1, err := ComputeHMAC(key, message)
	require.NoError(t, err, "ComputeHMAC() should not return error")
	assert.NotEmpty(t, hmac1, "ComputeHMAC() should not return empty string")

	// Computing same HMAC should give same result
	hmac2, err := ComputeHMAC(key, message)
	require.NoError(t, err, "ComputeHMAC() should not return error")
	assert.Equal(t, hmac1, hmac2, "ComputeHMAC() should be deterministic")

	// Different message should give different HMAC
	hmac3, err := ComputeHMAC(key, "different message")
	require.NoError(t, err, "ComputeHMAC() should not return error")
	assert.NotEqual(t, hmac1, hmac3, "ComputeHMAC() should differ for different messages")
}

func TestComputeHMACInvalidKey(t *testing.T) {
	_, err := ComputeHMAC("invalid-base64!!!", "message")
	assert.Error(t, err, "ComputeHMAC() should return error for invalid base64 key")
}

func TestVerifyHMAC(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("test-secret-key"))
	message := "test message"

	hmac, err := ComputeHMAC(key, message)
	require.NoError(t, err, "ComputeHMAC() should not return error")

	// Verify should succeed with correct HMAC
	valid, err := VerifyHMAC(key, message, hmac)
	require.NoError(t, err, "VerifyHMAC() should not return error")
	assert.True(t, valid, "VerifyHMAC() should return true for correct HMAC")

	// Verify should fail with incorrect HMAC
	valid, err = VerifyHMAC(key, message, "wrong-hmac")
	require.NoError(t, err, "VerifyHMAC() should not return error")
	assert.False(t, valid, "VerifyHMAC() should return false for wrong HMAC")

	// Verify should fail with different message
	valid, err = VerifyHMAC(key, "different message", hmac)
	require.NoError(t, err, "VerifyHMAC() should not return error")
	assert.False(t, valid, "VerifyHMAC() should return false for different message")
}

func TestCreateAuthPayload(t *testing.T) {
	clientID := testClientID
	nonce := testPSK

	payload := CreateAuthPayload(clientID, nonce)
	expected := testClientID + "|" + testPSK

	assert.Equal(t, expected, payload, "CreateAuthPayload() should return expected value")
}

func TestComputeAuthHMAC(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString([]byte("test-secret"))
	clientID := testClientID
	nonce := testPSK

	hmac, err := ComputeAuthHMAC(psk, clientID, nonce)
	require.NoError(t, err, "ComputeAuthHMAC() should not return error")
	assert.NotEmpty(t, hmac, "ComputeAuthHMAC() should not return empty string")
}

func TestVerifyAuthHMAC(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString([]byte("test-secret"))
	clientID := testClientID
	nonce := testPSK

	hmac, err := ComputeAuthHMAC(psk, clientID, nonce)
	require.NoError(t, err, "ComputeAuthHMAC() should not return error")

	// Verify should succeed
	valid, err := VerifyAuthHMAC(psk, clientID, nonce, hmac)
	require.NoError(t, err, "VerifyAuthHMAC() should not return error")
	assert.True(t, valid, "VerifyAuthHMAC() should return true for correct HMAC")

	// Verify should fail with wrong HMAC
	valid, err = VerifyAuthHMAC(psk, clientID, nonce, "wrong-hmac")
	require.NoError(t, err, "VerifyAuthHMAC() should not return error")
	assert.False(t, valid, "VerifyAuthHMAC() should return false for wrong HMAC")

	// Verify should fail with wrong client ID
	valid, err = VerifyAuthHMAC(psk, "wrong-client", nonce, hmac)
	require.NoError(t, err, "VerifyAuthHMAC() should not return error")
	assert.False(t, valid, "VerifyAuthHMAC() should return false for wrong client ID")
}

// Test messages.go functions

func TestNewMessage(t *testing.T) {
	tests := []struct {
		data    interface{}
		name    string
		msgType MessageType
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
			if tt.wantErr {
				assert.Fail(t, "NewMessage() should return error")
			} else {
				require.NoError(t, err, "NewMessage() should not return error")
				assert.Equal(t, tt.msgType, msg.Type, "NewMessage() type should match")
			}
		})
	}
}

func TestMessageParseData(t *testing.T) {
	authData := &AuthMessage{
		ClientID: testClientID,
		Nonce:    "abc123",
		HMAC:     "hmac-value",
	}

	msg, err := NewMessage(MessageTypeAuth, authData)
	require.NoError(t, err, "NewMessage() should not return error")

	var parsed AuthMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")

	assert.Equal(t, authData.ClientID, parsed.ClientID, "ParseData() ClientID should match")
	assert.Equal(t, authData.Nonce, parsed.Nonce, "ParseData() Nonce should match")
	assert.Equal(t, authData.HMAC, parsed.HMAC, "ParseData() HMAC should match")
}

func TestMessageParseDataNoData(t *testing.T) {
	msg, err := NewMessage(MessageTypePing, nil)
	if err != nil {
		require.NoError(t, err, "NewMessage() should not return error")
	}

	var parsed PingMessage
	err = msg.ParseData(&parsed)
	if err == nil {
		assert.Fail(t, "ParseData() expected error for message with no data")
	}
}

func TestMessageMarshalUnmarshal(t *testing.T) {
	authData := &AuthMessage{
		ClientID: testClientID,
		Nonce:    "abc123",
		HMAC:     "hmac-value",
	}

	msg, err := NewMessage(MessageTypeAuth, authData)
	if err != nil {
		require.NoError(t, err, "NewMessage() should not return error")
	}

	// Marshal
	data, err := msg.Marshal()
	if err != nil {
		require.NoError(t, err, "Marshal() should not return error")
	}

	if len(data) == 0 {
		assert.Fail(t, "Marshal() returned empty data")
	}

	// Unmarshal
	msg2, err := UnmarshalMessage(data)
	if err != nil {
		require.NoError(t, err, "UnmarshalMessage() should not return error")
	}

	if msg2.Type != msg.Type {
		assert.Equal(t, msg.Type, msg2.Type, "UnmarshalMessage() Type should match expected value")
	}

	// Parse data
	var parsed AuthMessage
	err = msg2.ParseData(&parsed)
	if err != nil {
		require.NoError(t, err, "ParseData() should not return error")
	}

	if parsed.ClientID != authData.ClientID {
		assert.Equal(t, authData.ClientID, parsed.ClientID, "Parsed ClientID should match expected value")
	}
}

func TestUnmarshalMessageInvalid(t *testing.T) {
	_, err := UnmarshalMessage([]byte("invalid json"))
	if err == nil {
		assert.Fail(t, "UnmarshalMessage() expected error for invalid JSON")
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
		ClientID: testClientID,
		Nonce:    "abc123",
		HMAC:     "hmac-value",
	}

	msg, err := NewMessage(MessageTypeAuth, authData)
	if err != nil {
		require.NoError(t, err, "NewMessage() should not return error")
	}

	// Create buffer
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	reader := bufio.NewReader(&buf)

	// Write message
	err = WriteMessageBuffered(writer, msg)
	if err != nil {
		require.NoError(t, err, "WriteMessageBuffered() should not return error")
	}

	// Read message
	msg2, err := ReadMessageBuffered(reader)
	if err != nil {
		require.NoError(t, err, "ReadMessageBuffered() should not return error")
	}

	if msg2.Type != msg.Type {
		assert.Equal(t, msg.Type, msg2.Type, "ReadMessageBuffered() Type should match expected value")
	}

	// Parse data
	var parsed AuthMessage
	err = msg2.ParseData(&parsed)
	if err != nil {
		require.NoError(t, err, "ParseData() should not return error")
	}

	if parsed.ClientID != authData.ClientID {
		assert.Equal(t, authData.ClientID, parsed.ClientID, "Parsed ClientID should match expected value")
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
		assert.Fail(t, "WriteMessageBuffered() expected error for message too large")
	}
}

func TestReadMessageBufferedTooLarge(t *testing.T) {
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)

	// Write a length that exceeds MaxMessageSize
	largeLength := uint32(MaxMessageSize + 1)
	if _, err := writer.Write([]byte{
		byte(largeLength >> 24),
		byte(largeLength >> 16),
		byte(largeLength >> 8),
		byte(largeLength),
	}); err != nil {
		t.Fatalf("Failed to write test data: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Failed to flush writer: %v", err)
	}

	reader := bufio.NewReader(&buf)
	_, err := ReadMessageBuffered(reader)
	if err == nil {
		assert.Fail(t, "ReadMessageBuffered() expected error for message too large")
	}
}

func TestReadMessageBufferedEOF(t *testing.T) {
	var buf bytes.Buffer
	reader := bufio.NewReader(&buf)

	_, err := ReadMessageBuffered(reader)
	if err == nil {
		assert.Fail(t, "ReadMessageBuffered() expected EOF error")
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
			require.NoError(t, err, "NewMessage() should not return error")
		}
		err = WriteMessageBuffered(writer, msg)
		if err != nil {
			require.NoError(t, err, "WriteMessageBuffered() should not return error")
		}
	}

	// Read messages back
	reader := bufio.NewReader(&buf)
	for i, expectedType := range messages {
		msg, err := ReadMessageBuffered(reader)
		if err != nil {
			require.NoErrorf(t, err, "ReadMessageBuffered() message %d should not error", i)
		}
		if msg.Type != expectedType {
			assert.Equal(t, msg.Type, expectedType, i, "Message %d Type should match expected value")
		}
	}
}

// TestNewClientHandler tests the ClientHandler constructor
func TestNewClientHandler(t *testing.T) {
	clientID := testClientID
	psk := base64.StdEncoding.EncodeToString([]byte("test-psk"))

	handler, err := NewClientHandler(clientID, psk, nil)
	require.NoError(t, err, "NewClientHandler() should not return error")
	require.NotNil(t, handler, "NewClientHandler() returned nil")

	if handler.clientID != clientID {
		assert.Equal(t, clientID, handler.clientID, "clientID should match expected value")
	}
	if handler.pskCache == nil {
		assert.Fail(t, "pskCache should be initialized")
	}
	if handler.sessionID != "" {
		t.Errorf("sessionID should be empty, got %v", handler.sessionID)
	}
}

// TestClientHandlerGetSessionID tests GetSessionID method
func TestClientHandlerGetSessionID(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString([]byte("test-psk"))
	handler, err := NewClientHandler("test", psk, nil)
	require.NoError(t, err, "NewClientHandler() should not return error")

	// Initially should be empty
	if sid := handler.GetSessionID(); sid != "" {
		t.Errorf("GetSessionID() = %v, want empty string", sid)
	}

	// Set session ID directly for testing
	handler.sessionID = testSessionID
	if sid := handler.GetSessionID(); sid != testSessionID {
		t.Errorf("GetSessionID() = %v, want %s", sid, testSessionID)
	}
}

// TestClientHandlerIsAuthenticated tests IsAuthenticated method
func TestClientHandlerIsAuthenticated(t *testing.T) {
	psk := base64.StdEncoding.EncodeToString([]byte("test-psk"))
	handler, err := NewClientHandler("test", psk, nil)
	require.NoError(t, err, "NewClientHandler() should not return error")

	// Initially should be false
	assert.False(t, handler.IsAuthenticated(), "IsAuthenticated() should be false initially")

	// Set session ID to simulate authentication
	handler.sessionID = testSessionID
	assert.True(t, handler.IsAuthenticated(), "IsAuthenticated() should be true after setting sessionID")
}

// TestNewServerHandler tests the ServerHandler constructor
func TestNewServerHandler(t *testing.T) {
	pskMap := map[string]string{
		"client1": base64.StdEncoding.EncodeToString([]byte("psk1")),
		"client2": base64.StdEncoding.EncodeToString([]byte("psk2")),
	}

	handler, err := NewServerHandler(pskMap, nil)
	require.NoError(t, err, "NewServerHandler() should not return error")
	require.NotNil(t, handler, "NewServerHandler() returned nil")

	if len(handler.pskCacheMap) != 2 {
		t.Errorf("pskCacheMap length = %v, want 2", len(handler.pskCacheMap))
	}
	if handler.sessions == nil {
		assert.Fail(t, "sessions map should be initialized")
	}
	if len(handler.sessions) != 0 {
		t.Errorf("sessions should be empty initially, got %v", len(handler.sessions))
	}
}

// TestServerHandlerSessionManagement tests session management methods
func TestServerHandlerSessionManagement(t *testing.T) {
	pskMap := map[string]string{
		"client1": base64.StdEncoding.EncodeToString([]byte("psk1")),
	}
	handler, err := NewServerHandler(pskMap, nil)
	require.NoError(t, err, "NewServerHandler() should not return error")

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
		assert.Fail(t, "GetSession() should return true for existing session")
	}
	if retrieved.SessionID != "session-123" {
		t.Errorf("GetSession() SessionID = %v, want session-123", retrieved.SessionID)
	}

	// Test GetSession for non-existent session
	_, ok = handler.GetSession("nonexistent")
	if ok {
		assert.Fail(t, "GetSession() should return false for non-existent session")
	}

	// Test RemoveSession
	handler.RemoveSession("session-123")
	if count := handler.SessionCount(); count != 0 {
		t.Errorf("SessionCount() after removal = %v, want 0", count)
	}

	// Verify session is actually removed
	_, ok = handler.GetSession("session-123")
	if ok {
		assert.Fail(t, "GetSession() should return false after RemoveSession()")
	}
}

// TestServerHandlerMultipleSessions tests managing multiple sessions
func TestServerHandlerMultipleSessions(t *testing.T) {
	pskMap := map[string]string{
		"client1": base64.StdEncoding.EncodeToString([]byte("psk1")),
		"client2": base64.StdEncoding.EncodeToString([]byte("psk2")),
	}
	handler, err := NewServerHandler(pskMap, nil)
	require.NoError(t, err, "NewServerHandler() should not return error")

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
			assert.Equal(t, retrieved.ClientID, s.ClientID, s.SessionID, "GetSession(%s).ClientID should match expected value")
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
		assert.Fail(t, "Removed session should not be retrievable")
	}

	// Other sessions should still exist
	_, ok = handler.GetSession("session-1")
	if !ok {
		assert.Fail(t, "session-1 should still exist")
	}
	_, ok = handler.GetSession("session-3")
	if !ok {
		assert.Fail(t, "session-3 should still exist")
	}
}

// Test forward management messages

func TestForwardAddMessage(t *testing.T) {
	addMsg := ForwardAddMessage{
		Local:    "127.0.0.1:8080",
		Remote:   "10.0.0.5:9000",
		Proto:    "tcp",
		ClientID: testClientID,
		Type:     "forward",
	}

	msg, err := NewMessage(MessageTypeForwardAdd, addMsg)
	require.NoError(t, err, "NewMessage() should not return error")
	assert.Equal(t, MessageTypeForwardAdd, msg.Type, "Message type should be FORWARD_ADD")

	// Parse back
	var parsed ForwardAddMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, addMsg.Local, parsed.Local, "Local address should match")
	assert.Equal(t, addMsg.Remote, parsed.Remote, "Remote address should match")
	assert.Equal(t, addMsg.Proto, parsed.Proto, "Protocol should match")
	assert.Equal(t, addMsg.ClientID, parsed.ClientID, "Client ID should match")
	assert.Equal(t, addMsg.Type, parsed.Type, "Type should match")
}

func TestForwardRemoveMessage(t *testing.T) {
	removeMsg := ForwardRemoveMessage{
		ForwardID: "fwd-123",
	}

	msg, err := NewMessage(MessageTypeForwardRemove, removeMsg)
	require.NoError(t, err, "NewMessage() should not return error")
	assert.Equal(t, MessageTypeForwardRemove, msg.Type, "Message type should be FORWARD_REMOVE")

	// Parse back
	var parsed ForwardRemoveMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, removeMsg.ForwardID, parsed.ForwardID, "Forward ID should match")
}

func TestForwardListMessage(t *testing.T) {
	listMsg := ForwardListMessage{
		Type: "forward",
	}

	msg, err := NewMessage(MessageTypeForwardList, listMsg)
	require.NoError(t, err, "NewMessage() should not return error")
	assert.Equal(t, MessageTypeForwardList, msg.Type, "Message type should be FORWARD_LIST")

	// Parse back
	var parsed ForwardListMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, listMsg.Type, parsed.Type, "Filter type should match")
}

func TestForwardOKMessage(t *testing.T) {
	okMsg := ForwardOKMessage{
		ForwardID: "fwd-123",
		Message:   "Forward added successfully",
		Forwards:  nil,
	}

	msg, err := NewMessage(MessageTypeForwardOK, okMsg)
	require.NoError(t, err, "NewMessage() should not return error")
	assert.Equal(t, MessageTypeForwardOK, msg.Type, "Message type should be FORWARD_OK")

	// Parse back
	var parsed ForwardOKMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, okMsg.ForwardID, parsed.ForwardID, "Forward ID should match")
	assert.Equal(t, okMsg.Message, parsed.Message, "Message should match")
}

func TestForwardOKMessageWithList(t *testing.T) {
	forwards := []*ForwardInfo{
		{
			ID:       "fwd-1",
			Local:    "127.0.0.1:8080",
			Remote:   "10.0.0.5:9000",
			Proto:    "tcp",
			ClientID: testClientID,
			Type:     "forward",
			Active:   true,
		},
		{
			ID:       "fwd-2",
			Local:    "127.0.0.1:5432",
			Remote:   "db.internal:5432",
			Proto:    "tcp",
			ClientID: testClientID,
			Type:     "forward",
			Active:   false,
		},
	}

	okMsg := ForwardOKMessage{
		Forwards: forwards,
		Message:  "Found 2 forwards",
	}

	msg, err := NewMessage(MessageTypeForwardOK, okMsg)
	require.NoError(t, err, "NewMessage() should not return error")

	// Parse back
	var parsed ForwardOKMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Len(t, parsed.Forwards, 2, "Should have 2 forwards")
	assert.Equal(t, forwards[0].ID, parsed.Forwards[0].ID, "First forward ID should match")
	assert.Equal(t, forwards[1].ID, parsed.Forwards[1].ID, "Second forward ID should match")
}

func TestForwardFailMessage(t *testing.T) {
	failMsg := ForwardFailMessage{
		Reason: "Invalid forward configuration",
	}

	msg, err := NewMessage(MessageTypeForwardFail, failMsg)
	require.NoError(t, err, "NewMessage() should not return error")
	assert.Equal(t, MessageTypeForwardFail, msg.Type, "Message type should be FORWARD_FAIL")

	// Parse back
	var parsed ForwardFailMessage
	err = msg.ParseData(&parsed)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, failMsg.Reason, parsed.Reason, "Reason should match")
}

// Test forward management message serialization
func TestForwardMessagesRoundTrip(t *testing.T) {
	tests := []struct {
		data    interface{}
		msgType MessageType
		name    string
	}{
		{
			name:    "FORWARD_ADD",
			msgType: MessageTypeForwardAdd,
			data: ForwardAddMessage{
				Local:    "127.0.0.1:8080",
				Remote:   "10.0.0.5:9000",
				Proto:    "tcp",
				ClientID: testClientID,
				Type:     "forward",
			},
		},
		{
			name:    "FORWARD_REMOVE",
			msgType: MessageTypeForwardRemove,
			data: ForwardRemoveMessage{
				ForwardID: "fwd-123",
			},
		},
		{
			name:    "FORWARD_LIST",
			msgType: MessageTypeForwardList,
			data: ForwardListMessage{
				Type: "forward",
			},
		},
		{
			name:    "FORWARD_OK",
			msgType: MessageTypeForwardOK,
			data: ForwardOKMessage{
				ForwardID: "fwd-123",
				Message:   "Success",
			},
		},
		{
			name:    "FORWARD_FAIL",
			msgType: MessageTypeForwardFail,
			data: ForwardFailMessage{
				Reason: "Error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create message
			msg, err := NewMessage(tt.msgType, tt.data)
			require.NoError(t, err, "NewMessage() should not return error")

			// Marshal to JSON
			jsonData, err := msg.Marshal()
			require.NoError(t, err, "Marshal() should not return error")

			// Unmarshal from JSON
			parsed, err := UnmarshalMessage(jsonData)
			require.NoError(t, err, "UnmarshalMessage() should not return error")
			assert.Equal(t, tt.msgType, parsed.Type, "Message type should match after round trip")
		})
	}
}

// Test buffered forward message exchange
func TestForwardMessageExchange(t *testing.T) {
	var buf bytes.Buffer
	writer := bufio.NewWriter(&buf)
	reader := bufio.NewReader(&buf)

	// Client sends FORWARD_ADD
	addMsg := ForwardAddMessage{
		Local:    "127.0.0.1:8080",
		Remote:   "10.0.0.5:9000",
		Proto:    "tcp",
		ClientID: testClientID,
		Type:     "forward",
	}
	addMessage, err := NewMessage(MessageTypeForwardAdd, addMsg)
	require.NoError(t, err, "NewMessage() should not return error")

	err = WriteMessageBuffered(writer, addMessage)
	require.NoError(t, err, "WriteMessageBuffered() should not return error")
	err = writer.Flush()
	require.NoError(t, err, "Flush() should not return error")

	// Server reads FORWARD_ADD
	receivedAdd, err := ReadMessageBuffered(reader)
	require.NoError(t, err, "ReadMessageBuffered() should not return error")
	assert.Equal(t, MessageTypeForwardAdd, receivedAdd.Type, "Should receive FORWARD_ADD")

	var parsedAdd ForwardAddMessage
	err = receivedAdd.ParseData(&parsedAdd)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, addMsg.Local, parsedAdd.Local, "Local address should match")

	// Server sends FORWARD_OK
	okMsg := ForwardOKMessage{
		ForwardID: "fwd-new-123",
		Message:   "Forward added successfully",
	}
	okMessage, err := NewMessage(MessageTypeForwardOK, okMsg)
	require.NoError(t, err, "NewMessage() should not return error")

	err = WriteMessageBuffered(writer, okMessage)
	require.NoError(t, err, "WriteMessageBuffered() should not return error")
	err = writer.Flush()
	require.NoError(t, err, "Flush() should not return error")

	// Client reads FORWARD_OK
	receivedOK, err := ReadMessageBuffered(reader)
	require.NoError(t, err, "ReadMessageBuffered() should not return error")
	assert.Equal(t, MessageTypeForwardOK, receivedOK.Type, "Should receive FORWARD_OK")

	var parsedOK ForwardOKMessage
	err = receivedOK.ParseData(&parsedOK)
	require.NoError(t, err, "ParseData() should not return error")
	assert.Equal(t, okMsg.ForwardID, parsedOK.ForwardID, "Forward ID should match")
	assert.Equal(t, okMsg.Message, parsedOK.Message, "Message should match")
}
