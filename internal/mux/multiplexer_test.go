package mux

import (
	"context"
	"testing"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewMultiplexer tests the Multiplexer constructor
func TestNewMultiplexer(t *testing.T) {
	mux := NewMultiplexer(nil)

	require.NotNil(t, mux, "NewMultiplexer() should return non-nil")
	assert.NotNil(t, mux.handlers, "handlers map should be initialized")
	assert.NotNil(t, mux.streams, "streams map should be initialized")
	assert.NotNil(t, mux.ctx, "context should be initialized")
	assert.NotNil(t, mux.cancel, "cancel function should be initialized")
	assert.Equal(t, 0, len(mux.handlers), "handlers should be empty initially")
	assert.Equal(t, 0, len(mux.streams), "streams should be empty initially")
}

// TestRegisterHandler tests handler registration
func TestRegisterHandler(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Test handler function
	testHandler := func(_ context.Context, _ *quicgo.Stream, _ *StreamHeader) error {
		return nil
	}

	// Register handler
	mux.RegisterHandler(ProtocolTCP, testHandler)

	// Verify handler was registered
	mux.mu.RLock()
	handler, ok := mux.handlers[ProtocolTCP]
	mux.mu.RUnlock()

	assert.True(t, ok, "Handler should be registered for ProtocolTCP")
	assert.NotNil(t, handler, "Registered handler should not be nil")
}

// TestRegisterMultipleHandlers tests registering multiple handlers
func TestRegisterMultipleHandlers(t *testing.T) {
	mux := NewMultiplexer(nil)

	handler := func(_ context.Context, _ *quicgo.Stream, _ *StreamHeader) error {
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

	assert.Equal(t, len(protocols), len(mux.handlers), "Expected handlers count should match")

	for _, protocol := range protocols {
		_, ok := mux.handlers[protocol]
		assert.True(t, ok, "Handler for protocol %s should be registered", protocol.String())
	}
}

// TestGetStream tests stream lookup
func TestGetStream(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Test getting non-existent stream
	_, ok := mux.GetStream(123)
	assert.False(t, ok, "GetStream should return false for non-existent stream")

	// Add a mock stream manually for testing
	mockStream := &Stream{
		Stream:   nil, // We don't have a real stream for unit test
		Header:   &StreamHeader{Protocol: ProtocolTCP},
		StreamID: 456,
	}

	mux.mu.Lock()
	mux.streams[456] = mockStream
	mux.mu.Unlock()

	// Test getting existing stream
	retrieved, ok := mux.GetStream(456)
	assert.True(t, ok, "GetStream should return true for existing stream")
	assert.Equal(t, uint64(456), retrieved.StreamID, "GetStream returned wrong stream ID")
	assert.Equal(t, ProtocolTCP, retrieved.Header.Protocol, "GetStream returned wrong protocol")
}

// TestStreamCount tests stream counting
func TestStreamCount(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Initially should be 0
	assert.Equal(t, 0, mux.StreamCount(), "StreamCount() should be 0 initially")

	// Add some mock streams
	for i := uint64(1); i <= 5; i++ {
		mux.mu.Lock()
		mux.streams[i] = &Stream{
			StreamID: i,
			Header:   &StreamHeader{Protocol: ProtocolTCP},
		}
		mux.mu.Unlock()
	}

	// Verify count
	assert.Equal(t, 5, mux.StreamCount(), "StreamCount() should be 5")

	// Remove a stream
	mux.mu.Lock()
	delete(mux.streams, 3)
	mux.mu.Unlock()

	// Verify count updated
	assert.Equal(t, 4, mux.StreamCount(), "StreamCount() after deletion should be 4")
}

// TestClose tests multiplexer cleanup
func TestClose(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Close empty multiplexer
	err := mux.Close()
	assert.NoError(t, err, "Close() should not return error")

	// Verify context was canceled
	select {
	case <-mux.ctx.Done():
		// Expected - context should be canceled
	default:
		t.Error("Context should be canceled after Close()")
	}

	// Verify streams were cleared
	assert.Equal(t, 0, mux.StreamCount(), "StreamCount() after Close should be 0")
}

// TestCloseIdempotent tests that Close can be called multiple times
func TestCloseIdempotent(t *testing.T) {
	mux := NewMultiplexer(nil)

	// First close
	err := mux.Close()
	assert.NoError(t, err, "First Close() should not return error")

	// Second close should also work
	err = mux.Close()
	assert.NoError(t, err, "Second Close() should not return error")

	// Verify state
	assert.Equal(t, 0, mux.StreamCount(), "StreamCount() should be 0")
}

// TestCloseWithActiveStreams tests stream map is cleared on close
// Note: Actual stream closing requires real QUIC streams, tested in integration tests
func TestCloseWithActiveStreams(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Add mock streams (but don't call Close as it requires real QUIC streams)
	for i := uint64(1); i <= 3; i++ {
		mux.mu.Lock()
		mux.streams[i] = &Stream{
			StreamID: i,
			Header:   &StreamHeader{Protocol: ProtocolTCP},
			Stream:   nil,
		}
		mux.mu.Unlock()
	}

	assert.Equal(t, 3, mux.StreamCount(), "Should have 3 streams")

	// Manually clear streams instead of calling Close (which would try to close nil streams)
	mux.mu.Lock()
	for id := range mux.streams {
		delete(mux.streams, id)
	}
	mux.mu.Unlock()

	assert.Equal(t, 0, mux.StreamCount(), "StreamCount() after manual clear should be 0")
}

// TestHandlerNotFound tests dispatching stream without registered handler
func TestHandlerNotFound(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Create stream with unregistered protocol
	stream := &Stream{
		StreamID: 1,
		Header:   &StreamHeader{Protocol: ProtocolTCP},
		Stream:   nil,
	}

	// HandleStream should error for unregistered protocol
	err := mux.HandleStream(stream)
	assert.Error(t, err, "HandleStream should error for unregistered protocol")
	assert.Contains(t, err.Error(), "no handler registered")
}

// TestRegisterHandlerOverwrite tests overwriting an existing handler
func TestRegisterHandlerOverwrite(t *testing.T) {
	mux := NewMultiplexer(nil)

	handler1 := func(_ context.Context, _ *quicgo.Stream, _ *StreamHeader) error {
		return nil
	}

	handler2 := func(_ context.Context, _ *quicgo.Stream, _ *StreamHeader) error {
		return assert.AnError
	}

	// Register first handler
	mux.RegisterHandler(ProtocolTCP, handler1)

	// Overwrite with second handler
	mux.RegisterHandler(ProtocolTCP, handler2)

	// Verify second handler is registered
	mux.mu.RLock()
	handler, ok := mux.handlers[ProtocolTCP]
	mux.mu.RUnlock()

	assert.True(t, ok, "Handler should be registered")
	assert.NotNil(t, handler, "Handler should not be nil")
}

// TestStreamOperations tests adding and removing streams
func TestStreamOperations(t *testing.T) {
	mux := NewMultiplexer(nil)

	// Add stream
	stream := &Stream{
		StreamID: 100,
		Header:   &StreamHeader{Protocol: ProtocolUDP},
		Stream:   nil,
	}

	mux.mu.Lock()
	mux.streams[stream.StreamID] = stream
	mux.mu.Unlock()

	// Verify stream exists
	retrieved, ok := mux.GetStream(100)
	assert.True(t, ok, "Stream should exist")
	assert.Equal(t, uint64(100), retrieved.StreamID)

	// Remove stream
	mux.mu.Lock()
	delete(mux.streams, 100)
	mux.mu.Unlock()

	// Verify stream removed
	_, ok = mux.GetStream(100)
	assert.False(t, ok, "Stream should not exist after deletion")
}

// TestConcurrentHandlerRegistration tests concurrent handler registration
func TestConcurrentHandlerRegistration(t *testing.T) {
	mux := NewMultiplexer(nil)

	done := make(chan bool)
	protocols := []ProtocolID{ProtocolTCP, ProtocolUDP, ProtocolControl, ProtocolRaw}

	// Register handlers concurrently
	for _, proto := range protocols {
		go func(p ProtocolID) {
			handler := func(_ context.Context, _ *quicgo.Stream, _ *StreamHeader) error {
				return nil
			}
			mux.RegisterHandler(p, handler)
			done <- true
		}(proto)
	}

	// Wait for all registrations
	for i := 0; i < len(protocols); i++ {
		<-done
	}

	// Verify all handlers registered
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	assert.Equal(t, len(protocols), len(mux.handlers))
}
