package ipc

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetSocketPath(t *testing.T) {
	path := GetSocketPath()
	if path == "" {
		t.Error("GetSocketPath returned empty string")
	}
	if !filepath.IsAbs(path) {
		t.Error("GetSocketPath did not return absolute path")
	}
}

func TestNewServer(t *testing.T) {
	// Create a mock forward adder
	adder := func(req ForwardRequest) error {
		return nil
	}

	server, err := NewServer(adder)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if server == nil {
		t.Fatal("NewServer returned nil server")
	}

	// Clean up
	if err := server.Close(); err != nil {
		t.Errorf("Server.Close failed: %v", err)
	}
}

func TestServerServeAndClose(t *testing.T) {
	// Create a mock forward adder
	adder := func(req ForwardRequest) error {
		return nil
	}

	server, err := NewServer(adder)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Start server in background
	done := make(chan error, 1)
	go func() {
		done <- server.Serve()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Close server
	if err := server.Close(); err != nil {
		t.Errorf("Server.Close failed: %v", err)
	}

	// Wait for Serve to return
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestForwardRequestResponse(t *testing.T) {
	// Create a mock forward adder that succeeds
	successAdder := func(req ForwardRequest) error {
		if req.Local != "127.0.0.1:8080" {
			t.Errorf("Unexpected local address: %s", req.Local)
		}
		if req.Remote != "10.0.0.1:9000" {
			t.Errorf("Unexpected remote address: %s", req.Remote)
		}
		if req.Proto != "tcp" {
			t.Errorf("Unexpected protocol: %s", req.Proto)
		}
		return nil
	}

	server, err := NewServer(successAdder)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Errorf("Server.Close failed: %v", err)
		}
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
	if err != nil {
		t.Fatalf("SendForwardRequest failed: %v", err)
	}

	if !resp.Success {
		t.Errorf("Expected success, got failure: %s", resp.Error)
	}
	if resp.Message == "" {
		t.Error("Expected non-empty message")
	}
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
	if err == nil {
		t.Error("Expected error when no server running, got nil")
	}
	if resp != nil {
		t.Error("Expected nil response when no server running")
	}
}

func TestForwardRequestJSON(t *testing.T) {
	req := ForwardRequest{
		Local:  "127.0.0.1:8080",
		Remote: "10.0.0.1:9000",
		Proto:  "tcp",
	}

	// Marshal to JSON
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal ForwardRequest: %v", err)
	}

	// Unmarshal from JSON
	var req2 ForwardRequest
	if err := json.Unmarshal(data, &req2); err != nil {
		t.Fatalf("Failed to unmarshal ForwardRequest: %v", err)
	}

	// Verify fields
	if req2.Local != req.Local {
		t.Errorf("Local mismatch: got %s, want %s", req2.Local, req.Local)
	}
	if req2.Remote != req.Remote {
		t.Errorf("Remote mismatch: got %s, want %s", req2.Remote, req.Remote)
	}
	if req2.Proto != req.Proto {
		t.Errorf("Proto mismatch: got %s, want %s", req2.Proto, req.Proto)
	}
}

func TestForwardResponseJSON(t *testing.T) {
	resp := ForwardResponse{
		Success: true,
		Message: "Forward added successfully",
	}

	// Marshal to JSON
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal ForwardResponse: %v", err)
	}

	// Unmarshal from JSON
	var resp2 ForwardResponse
	if err := json.Unmarshal(data, &resp2); err != nil {
		t.Fatalf("Failed to unmarshal ForwardResponse: %v", err)
	}

	// Verify fields
	if resp2.Success != resp.Success {
		t.Errorf("Success mismatch: got %v, want %v", resp2.Success, resp.Success)
	}
	if resp2.Message != resp.Message {
		t.Errorf("Message mismatch: got %s, want %s", resp2.Message, resp.Message)
	}
}

func TestServerHandleInvalidJSON(t *testing.T) {
	// Create a mock forward adder
	adder := func(req ForwardRequest) error {
		return nil
	}

	server, err := NewServer(adder)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer func() {
		if err := server.Close(); err != nil {
			t.Errorf("Server.Close failed: %v", err)
		}
	}()

	// Start server in background
	go func() {
		_ = server.Serve()
	}()

	// Give server time to start
	time.Sleep(50 * time.Millisecond)

	// Connect and send invalid JSON
	conn, err := net.Dial("unix", GetSocketPath())
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			t.Errorf("Failed to close connection: %v", closeErr)
		}
	}()

	// Send invalid JSON
	_, err = conn.Write([]byte("{invalid json"))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Read response
	decoder := json.NewDecoder(conn)
	var resp ForwardResponse
	if err := decoder.Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should get error response
	if resp.Success {
		t.Error("Expected failure for invalid JSON, got success")
	}
	if resp.Error == "" {
		t.Error("Expected error message for invalid JSON")
	}
}
