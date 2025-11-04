package ipc

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSocketPath(t *testing.T) {
	path := GetSocketPath()
	assert.NotEmpty(t, path, "GetSocketPath should return non-empty string")
	assert.True(t, filepath.IsAbs(path), "GetSocketPath should return absolute path")
}

func TestNewServer(t *testing.T) {
	// Create a mock forward adder
	adder := func(_ ForwardRequest) error {
		return nil
	}

	server, err := NewServer(adder)
	require.NoError(t, err, "NewServer should not fail")
	require.NotNil(t, server, "NewServer should return non-nil server")

	// Clean up
	err = server.Close()
	assert.NoError(t, err, "Server.Close should not fail")
}

func TestServerServeAndClose(t *testing.T) {
	// Create a mock forward adder
	adder := func(_ ForwardRequest) error {
		return nil
	}

	server, err := NewServer(adder)
	require.NoError(t, err, "NewServer should not fail")

	// Start server in background
	done := make(chan error, 1)
	go func() {
		done <- server.Serve()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Close server
	err = server.Close()
	assert.NoError(t, err, "Server.Close should not fail")

	// Wait for Serve to return
	select {
	case err := <-done:
		assert.NoError(t, err, "Serve should not return error")
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestForwardRequestResponse(t *testing.T) {
	// Create a mock forward adder that succeeds and validates request
	successAdder := func(req ForwardRequest) error {
		assert.Equal(t, "127.0.0.1:8080", req.Local, "Local address should match")
		assert.Equal(t, "10.0.0.1:9000", req.Remote, "Remote address should match")
		assert.Equal(t, "tcp", req.Proto, "Protocol should match")
		return nil
	}

	server, err := NewServer(successAdder)
	require.NoError(t, err, "NewServer should not fail")
	defer func() {
		err := server.Close()
		assert.NoError(t, err, "Server.Close should not fail")
	}()

	// Start server in background
	go func() {
		_ = server.Serve()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Send request
	req := ForwardRequest{
		Local:  "127.0.0.1:8080",
		Remote: "10.0.0.1:9000",
		Proto:  "tcp",
	}

	resp, err := SendForwardRequest(req)
	require.NoError(t, err, "SendForwardRequest should not fail")
	assert.True(t, resp.Success, "Response should indicate success")
	assert.NotEmpty(t, resp.Message, "Response should have non-empty message")
}

func TestSendForwardRequestNoServer(t *testing.T) {
	// Try to send request when no server is running
	req := ForwardRequest{
		Local:  "127.0.0.1:8080",
		Remote: "10.0.0.1:9000",
		Proto:  "tcp",
	}

	// Make sure socket doesn't exist
	socketPath := GetSocketPath()
	_ = os.Remove(socketPath)

	resp, err := SendForwardRequest(req)
	assert.Error(t, err, "SendForwardRequest should fail when no server running")
	assert.Nil(t, resp, "Response should be nil when request fails")
}

func TestForwardRequestJSON(t *testing.T) {
	req := ForwardRequest{
		Local:  "127.0.0.1:8080",
		Remote: "10.0.0.1:9000",
		Proto:  "tcp",
	}

	// Marshal to JSON
	data, err := json.Marshal(req)
	require.NoError(t, err, "Marshal should not fail")

	// Unmarshal from JSON
	var req2 ForwardRequest
	err = json.Unmarshal(data, &req2)
	require.NoError(t, err, "Unmarshal should not fail")

	// Verify fields match
	assert.Equal(t, req, req2, "Marshaled and unmarshaled request should be equal")
}

func TestForwardResponseJSON(t *testing.T) {
	resp := ForwardResponse{
		Success: true,
		Message: "Forward added successfully",
	}

	// Marshal to JSON
	data, err := json.Marshal(resp)
	require.NoError(t, err, "Marshal should not fail")

	// Unmarshal from JSON
	var resp2 ForwardResponse
	err = json.Unmarshal(data, &resp2)
	require.NoError(t, err, "Unmarshal should not fail")

	// Verify fields match
	assert.Equal(t, resp, resp2, "Marshaled and unmarshaled response should be equal")
}

func TestServerHandleInvalidJSON(t *testing.T) {
	// Create a mock forward adder
	adder := func(_ ForwardRequest) error {
		return nil
	}

	server, err := NewServer(adder)
	require.NoError(t, err, "NewServer should not fail")
	defer func() {
		err := server.Close()
		assert.NoError(t, err, "Server.Close should not fail")
	}()

	// Start server in background
	go func() {
		_ = server.Serve()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect and send invalid JSON
	conn, err := net.Dial("unix", GetSocketPath())
	require.NoError(t, err, "Should connect to server")
	defer func() {
		_ = conn.Close()
	}()

	// Send invalid JSON
	_, err = conn.Write([]byte("{invalid json"))
	require.NoError(t, err, "Write should not fail")

	// Read response
	decoder := json.NewDecoder(conn)
	var resp ForwardResponse
	err = decoder.Decode(&resp)
	require.NoError(t, err, "Should decode error response")

	// Should get error response
	assert.False(t, resp.Success, "Response should indicate failure for invalid JSON")
	assert.NotEmpty(t, resp.Error, "Response should contain error message")
}
