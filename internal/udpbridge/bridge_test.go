package udpbridge

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionTimeout(t *testing.T) {
	expectedTimeout := 2 * time.Minute
	if SessionTimeout != expectedTimeout {
		assert.Equal(t, expectedTimeout, SessionTimeout, "SessionTimeout should match")
	}
}

func TestWriteReadUDPDatagram(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "small datagram",
			data: []byte("hello world"),
		},
		{
			name: "empty datagram",
			data: []byte{},
		},
		{
			name: "large datagram",
			data: make([]byte, 65000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			datagram := &UDPDatagram{
				Length: uint16(len(tt.data)), // #nosec G115 -- Test data is small, fits in uint16
				Data:   tt.data,
			}

			var buf bytes.Buffer

			// Write datagram
			err := WriteUDPDatagram(&buf, datagram)
			if err != nil {
				require.NoError(t, err, "WriteUDPDatagram() should not return error")
			}

			// Read datagram
			datagram2, err := ReadUDPDatagram(&buf)
			if err != nil {
				require.NoError(t, err, "ReadUDPDatagram() should not return error")
			}

			// Verify
			if datagram2.Length != datagram.Length {
				assert.Equal(t, datagram.Length, datagram2.Length, "ReadUDPDatagram() Length should match")
			}

			if !bytes.Equal(datagram2.Data, datagram.Data) {
				assert.Fail(t, "ReadUDPDatagram() Data mismatch")
			}
		})
	}
}

func TestWriteUDPDatagramMaxSize(t *testing.T) {
	// Test with maximum UDP datagram size
	maxData := make([]byte, 65535)
	for i := range maxData {
		maxData[i] = byte(i % 256)
	}

	datagram := &UDPDatagram{
		Length: uint16(len(maxData)), // #nosec G115 -- maxData is 65535 bytes, safe for uint16
		Data:   maxData,
	}

	var buf bytes.Buffer
	err := WriteUDPDatagram(&buf, datagram)
	if err != nil {
		require.NoError(t, err, "WriteUDPDatagram() should not return error")
	}

	// Read back
	datagram2, err := ReadUDPDatagram(&buf)
	if err != nil {
		require.NoError(t, err, "ReadUDPDatagram() should not return error")
	}

	if !bytes.Equal(datagram2.Data, maxData) {
		assert.Fail(t, "ReadUDPDatagram() max size data mismatch")
	}
}

func TestReadUDPDatagramEOF(t *testing.T) {
	var buf bytes.Buffer

	_, err := ReadUDPDatagram(&buf)
	if err == nil {
		assert.Fail(t, "ReadUDPDatagram() expected error for empty buffer, got nil")
	}
}

func TestReadUDPDatagramIncompleteLength(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00}) // Only 1 byte instead of 2

	_, err := ReadUDPDatagram(buf)
	if err == nil {
		assert.Fail(t, "ReadUDPDatagram() expected error for incomplete length")
	}
}

func TestReadUDPDatagramIncompleteData(t *testing.T) {
	var buf bytes.Buffer

	// Write length indicating 100 bytes
	buf.Write([]byte{0x00, 0x64}) // 100 in big-endian
	// But only write 10 bytes
	buf.Write(make([]byte, 10))

	_, err := ReadUDPDatagram(&buf)
	if err == nil {
		assert.Fail(t, "ReadUDPDatagram() expected error for incomplete data")
	}
}

func TestMultipleDatagrams(t *testing.T) {
	var buf bytes.Buffer

	// Write multiple datagrams
	datagrams := [][]byte{
		[]byte("first datagram"),
		[]byte("second datagram"),
		[]byte("third datagram"),
	}

	for _, data := range datagrams {
		dg := &UDPDatagram{
			Length: uint16(len(data)), // #nosec G115 -- Test data is small, fits in uint16 // #nosec G115 -- Test data is small, fits in uint16
			Data:   data,
		}
		err := WriteUDPDatagram(&buf, dg)
		if err != nil {
			require.NoError(t, err, "WriteUDPDatagram() should not return error")
		}
	}

	// Read them back
	for i, expectedData := range datagrams {
		dg, err := ReadUDPDatagram(&buf)
		if err != nil {
			t.Fatalf("ReadUDPDatagram() datagram %d error = %v", i, err)
		}

		if !bytes.Equal(dg.Data, expectedData) {
			t.Errorf("Datagram %d data mismatch: got %q, want %q", i, dg.Data, expectedData)
		}
	}
}

func TestUDPSession(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	if err != nil {
		require.NoError(t, err, "ResolveUDPAddr() should not return error")
	}

	// Create a dummy cancel function
	cancelCalled := false
	cancel := func() {
		cancelCalled = true
	}

	session := &UDPSession{
		RemoteAddr: addr,
		LastSeen:   time.Now(),
		Cancel:     cancel,
	}

	// Verify fields
	if session.RemoteAddr.String() != "127.0.0.1:12345" {
		t.Errorf("UDPSession RemoteAddr = %v, want 127.0.0.1:12345", session.RemoteAddr)
	}

	if time.Since(session.LastSeen) > time.Second {
		assert.Fail(t, "UDPSession LastSeen not set correctly")
	}

	// Call cancel
	session.Cancel()
	if !cancelCalled {
		assert.Fail(t, "UDPSession Cancel not called")
	}
}

func TestNewUDPListener(t *testing.T) {
	listenAddr := "127.0.0.1:0"
	targetAddr := "10.0.0.5:53"

	// Note: In real code streamOpener would return *quicgo.Stream
	listener := &UDPListener{
		listenAddr: listenAddr,
		targetAddr: targetAddr,
		sessions:   make(map[string]*UDPSession),
	}

	if listener.listenAddr != listenAddr {
		assert.Equal(t, listenAddr, listener.listenAddr, "UDPListener listenAddr should match")
	}

	if listener.targetAddr != targetAddr {
		assert.Equal(t, targetAddr, listener.targetAddr, "UDPListener targetAddr should match")
	}

	if listener.sessions == nil {
		assert.Fail(t, "UDPListener sessions map not initialized")
	}
}

func TestDatagramSizeEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		length uint16
	}{
		{"zero length", 0},
		{"one byte", 1},
		{"max uint16", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.length)
			datagram := &UDPDatagram{
				Length: tt.length,
				Data:   data,
			}

			var buf bytes.Buffer
			err := WriteUDPDatagram(&buf, datagram)
			if err != nil {
				require.NoError(t, err, "WriteUDPDatagram() should not return error")
			}

			dg2, err := ReadUDPDatagram(&buf)
			if err != nil {
				require.NoError(t, err, "ReadUDPDatagram() should not return error")
			}

			if dg2.Length != tt.length {
				t.Errorf("Length mismatch: got %d, want %d", dg2.Length, tt.length)
			}
		})
	}
}

func TestDatagramWithVariousDataPatterns(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "all zeros",
			data: make([]byte, 100),
		},
		{
			name: "all 0xFF",
			data: bytes.Repeat([]byte{0xFF}, 100),
		},
		{
			name: "sequential pattern",
			data: func() []byte {
				d := make([]byte, 256)
				for i := range d {
					d[i] = byte(i)
				}
				return d
			}(),
		},
		{
			name: "alternating pattern",
			data: bytes.Repeat([]byte{0xAA, 0x55}, 50),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			datagram := &UDPDatagram{
				Length: uint16(len(tt.data)), // #nosec G115 -- Test data is small, fits in uint16
				Data:   tt.data,
			}

			var buf bytes.Buffer
			if err := WriteUDPDatagram(&buf, datagram); err != nil {
				require.NoError(t, err, "WriteUDPDatagram() should not return error")
			}
			dg2, err := ReadUDPDatagram(&buf)

			if err != nil {
				require.NoError(t, err, "ReadUDPDatagram() should not return error")
			}

			if !bytes.Equal(dg2.Data, tt.data) {
				assert.Fail(t, "Data pattern not preserved")
			}
		})
	}
}

// Benchmark tests
func BenchmarkWriteUDPDatagram(b *testing.B) {
	data := make([]byte, 1400) // Typical MTU size
	datagram := &UDPDatagram{
		Length: uint16(len(data)), // #nosec G115 -- Test data is small, fits in uint16
		Data:   data,
	}

	var buf bytes.Buffer
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = WriteUDPDatagram(&buf, datagram)
	}
}

func BenchmarkReadUDPDatagram(b *testing.B) {
	data := make([]byte, 1400)
	datagram := &UDPDatagram{
		Length: uint16(len(data)), // #nosec G115 -- Test data is small, fits in uint16
		Data:   data,
	}

	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		_ = WriteUDPDatagram(&buf, datagram)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf2 := bytes.NewBuffer(buf.Bytes())
		_, _ = ReadUDPDatagram(buf2)
	}
}

// Note: UDPToQUIC and QUICToUDP use concrete quic.Stream types which are difficult to mock
// for unit tests. These functions are better tested in integration tests.
// Here we test the supporting components that can be unit tested.

// Test session timeout constant
func TestSessionTimeoutValue(t *testing.T) {
	expected := 2 * time.Minute
	assert.Equal(t, expected, SessionTimeout, "SessionTimeout should be 2 minutes")
}

// Test buffer pool
func TestBufferPool(t *testing.T) {
	// Get buffer from pool
	bufPtr1 := bufferPool.Get().(*[]byte)
	assert.NotNil(t, bufPtr1, "Buffer pool should return buffer")
	assert.Equal(t, 65535, len(*bufPtr1), "Buffer should be max UDP size")

	// Put it back
	bufferPool.Put(bufPtr1)

	// Get another buffer
	bufPtr2 := bufferPool.Get().(*[]byte)
	assert.NotNil(t, bufPtr2, "Buffer pool should return buffer")

	bufferPool.Put(bufPtr2)
}

// Test UDPDatagram struct
func TestUDPDatagramStruct(t *testing.T) {
	data := []byte("test data")
	datagram := &UDPDatagram{
		Length: uint16(len(data)), // #nosec G115 -- Test data is small
		Data:   data,
	}

	assert.Equal(t, uint16(len(data)), datagram.Length)
	assert.Equal(t, data, datagram.Data)
}

// Test UDPSession struct fields
func TestUDPSessionFields(t *testing.T) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:54321")
	require.NoError(t, err)

	cancel := func() {}
	now := time.Now()

	session := &UDPSession{
		RemoteAddr:  addr,
		LastSeen:    now,
		Cancel:      cancel,
		Stream:      nil, // Stream is nil until first datagram
		StreamMutex: sync.Mutex{},
	}

	assert.Equal(t, addr, session.RemoteAddr)
	assert.Equal(t, now, session.LastSeen)
	assert.NotNil(t, session.Cancel)
	assert.Nil(t, session.Stream, "Stream should be nil initially")
}

// Test UDPListener creation and field initialization
func TestNewUDPListenerCreation(t *testing.T) {
	// Create a simple stream opener that returns nil (won't be called in this test)
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("127.0.0.1:8080", "10.0.0.5:53", streamOpener)

	assert.NotNil(t, listener, "Listener should not be nil")
	assert.Equal(t, "127.0.0.1:8080", listener.listenAddr)
	assert.Equal(t, "10.0.0.5:53", listener.targetAddr)
	assert.NotNil(t, listener.sessions, "Sessions map should be initialized")
	assert.NotNil(t, listener.ctx, "Context should be initialized")
	assert.NotNil(t, listener.cancel, "Cancel function should be initialized")
	assert.Equal(t, 0, len(listener.sessions), "Sessions should start empty")
}

// Test context cancellation propagation
func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	// Check that context is done
	select {
	case <-ctx.Done():
		assert.NotNil(t, ctx.Err(), "Context should have error after cancellation")
	default:
		assert.Fail(t, "Context should be cancelled")
	}
}

// Test UDPListener Start method
func TestUDPListenerStartMethod(t *testing.T) {
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("127.0.0.1:0", "10.0.0.5:53", streamOpener)

	err := listener.Start()
	require.NoError(t, err, "Start should succeed with port 0 (random port)")
	assert.NotNil(t, listener.conn, "UDP connection should be created after Start")

	// Verify we can get the local address
	localAddr := listener.conn.LocalAddr()
	assert.NotNil(t, localAddr, "Local address should be available")

	// Clean up
	err = listener.Close()
	assert.NoError(t, err, "Close should succeed")
}

// Test UDPListener Start with invalid address
func TestUDPListenerStartInvalid(t *testing.T) {
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("invalid:address:port", "10.0.0.5:53", streamOpener)

	err := listener.Start()
	assert.Error(t, err, "Start should fail with invalid address")
	assert.Contains(t, err.Error(), "failed to resolve UDP address", "Error should mention address resolution")
}

// Test UDPListener Close method
func TestUDPListenerCloseMethod(t *testing.T) {
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("127.0.0.1:0", "10.0.0.5:53", streamOpener)

	err := listener.Start()
	require.NoError(t, err)

	err = listener.Close()
	assert.NoError(t, err, "Close should succeed")

	// Verify context is canceled
	select {
	case <-listener.ctx.Done():
		// Expected - context should be done
	default:
		assert.Fail(t, "Context should be canceled after Close")
	}
}

// Test UDPListener Close without Start
func TestUDPListenerCloseBeforeStart(t *testing.T) {
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("127.0.0.1:0", "10.0.0.5:53", streamOpener)

	// Close without Start should not panic
	err := listener.Close()
	assert.NoError(t, err, "Close without Start should not error")
}

// Test UDPListener double Close
func TestUDPListenerDoubleClose(t *testing.T) {
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("127.0.0.1:0", "10.0.0.5:53", streamOpener)

	err := listener.Start()
	require.NoError(t, err)

	// First close
	err = listener.Close()
	assert.NoError(t, err, "First Close should succeed")

	// Second close (may error since connection is already closed)
	err = listener.Close()
	// We don't assert error here because second close on nil connection is handled
	_ = err
}

// Test UDPListener Serve cancellation
func TestUDPListenerServeCancellation(t *testing.T) {
	streamOpener := func() (*quicgo.Stream, error) {
		return nil, nil
	}

	listener := NewUDPListener("127.0.0.1:0", "10.0.0.5:53", streamOpener)

	err := listener.Start()
	require.NoError(t, err)

	// Start Serve in background
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- listener.Serve()
	}()

	// Give Serve time to start
	time.Sleep(50 * time.Millisecond)

	// Cancel and close
	err = listener.Close()
	assert.NoError(t, err)

	// Serve should return (may be error or nil depending on timing)
	select {
	case err := <-serveDone:
		// When Close() is called, it closes the UDP connection which causes
		// the blocking ReadFromUDP to fail with "use of closed network connection"
		// This is expected behavior, not a test failure
		if err != nil {
			assert.Contains(t, err.Error(), "closed network connection",
				"Error should be due to closed connection")
		}
	case <-time.After(2 * time.Second):
		assert.Fail(t, "Serve did not return after Close")
	}
}
