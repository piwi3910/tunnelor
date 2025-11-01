package mux

import (
	"context"
	"testing"

	quicgo "github.com/quic-go/quic-go"
)

// TestNewMultiplexer tests the Multiplexer constructor
func TestNewMultiplexer(t *testing.T) {
	mux := NewMultiplexer(nil)

	if mux == nil {
		t.Fatal("NewMultiplexer() returned nil")
	}
	if mux.handlers == nil {
		t.Error("handlers map should be initialized")
	}
	if mux.streams == nil {
		t.Error("streams map should be initialized")
	}
	if mux.ctx == nil {
		t.Error("context should be initialized")
	}
	if mux.cancel == nil {
		t.Error("cancel function should be initialized")
	}
	if len(mux.handlers) != 0 {
		t.Errorf("handlers should be empty initially, got %d", len(mux.handlers))
	}
	if len(mux.streams) != 0 {
		t.Errorf("streams should be empty initially, got %d", len(mux.streams))
	}
}

// TestRegisterHandler tests handler registration
func TestRegisterHandler(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Test handler function
	testHandler := func(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
		return nil
	}

	// Register handler
	mux.RegisterHandler(ProtocolTCP, testHandler)

	// Verify handler was registered
	mux.mu.RLock()
	handler, ok := mux.handlers[ProtocolTCP]
	mux.mu.RUnlock()

	if !ok {
		t.Error("Handler should be registered for ProtocolTCP")
	}
	if handler == nil {
		t.Error("Registered handler should not be nil")
	}
}

// TestRegisterMultipleHandlers tests registering multiple handlers
func TestRegisterMultipleHandlers(t *testing.T) {
	mux := NewMultiplexer(nil)

	handler := func(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
		return nil
	}

	// Register handlers for different protocols
	protocols := []ProtocolID{ProtocolTCP, ProtocolUDP, ProtocolControl, ProtocolRaw}
	for _, protocol := range protocols {
		mux.RegisterHandler(protocol, handler)
	}

	// Verify all handlers were registered
	mux.mu.RLock()
	defer mux.mu.RUnlock()

	if len(mux.handlers) != len(protocols) {
		t.Errorf("Expected %d handlers, got %d", len(protocols), len(mux.handlers))
	}

	for _, protocol := range protocols {
		if _, ok := mux.handlers[protocol]; !ok {
			t.Errorf("Handler for protocol %s not registered", protocol.String())
		}
	}
}

// TestGetStream tests stream lookup
func TestGetStream(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Test getting non-existent stream
	_, ok := mux.GetStream(123)
	if ok {
		t.Error("GetStream should return false for non-existent stream")
	}

	// Add a mock stream manually for testing
	mockMuxStream := &MuxStream{
		Stream:   nil, // We don't have a real stream for unit test
		Header:   &StreamHeader{Protocol: ProtocolTCP},
		StreamID: 456,
	}

	mux.mu.Lock()
	mux.streams[456] = mockMuxStream
	mux.mu.Unlock()

	// Test getting existing stream
	retrieved, ok := mux.GetStream(456)
	if !ok {
		t.Error("GetStream should return true for existing stream")
	}
	if retrieved.StreamID != 456 {
		t.Errorf("GetStream returned wrong stream ID: got %d, want 456", retrieved.StreamID)
	}
	if retrieved.Header.Protocol != ProtocolTCP {
		t.Errorf("GetStream returned wrong protocol: got %s, want TCP", retrieved.Header.Protocol.String())
	}
}

// TestStreamCount tests stream counting
func TestStreamCount(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Initially should be 0
	if count := mux.StreamCount(); count != 0 {
		t.Errorf("StreamCount() = %d, want 0", count)
	}

	// Add some mock streams
	for i := uint64(1); i <= 5; i++ {
		mux.mu.Lock()
		mux.streams[i] = &MuxStream{
			StreamID: i,
			Header:   &StreamHeader{Protocol: ProtocolTCP},
		}
		mux.mu.Unlock()
	}

	// Verify count
	if count := mux.StreamCount(); count != 5 {
		t.Errorf("StreamCount() = %d, want 5", count)
	}

	// Remove a stream
	mux.mu.Lock()
	delete(mux.streams, 3)
	mux.mu.Unlock()

	// Verify count updated
	if count := mux.StreamCount(); count != 4 {
		t.Errorf("StreamCount() after deletion = %d, want 4", count)
	}
}

// TestClose tests multiplexer cleanup
func TestClose(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Close empty multiplexer
	if err := mux.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Verify context was cancelled
	select {
	case <-mux.ctx.Done():
		// Expected - context should be cancelled
	default:
		t.Error("Context should be cancelled after Close()")
	}

	// Verify streams were cleared
	if count := mux.StreamCount(); count != 0 {
		t.Errorf("StreamCount() after Close = %d, want 0", count)
	}
}

// TestCloseIdempotent tests that Close can be called multiple times
func TestCloseIdempotent(t *testing.T) {
	mux := NewMultiplexer(nil)

	// First close
	if err := mux.Close(); err != nil {
		t.Errorf("First Close() returned error: %v", err)
	}

	// Second close should also work
	if err := mux.Close(); err != nil {
		t.Errorf("Second Close() returned error: %v", err)
	}

	// Verify state
	if count := mux.StreamCount(); count != 0 {
		t.Errorf("StreamCount() = %d, want 0", count)
	}
}
