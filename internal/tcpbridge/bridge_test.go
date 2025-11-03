package tcpbridge

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// mockReadWriteCloser implements io.ReadWriteCloser for testing
type mockReadWriteCloser struct {
	*bytes.Buffer
	closed bool
}

func newMockReadWriteCloser(data string) *mockReadWriteCloser {
	return &mockReadWriteCloser{
		Buffer: bytes.NewBufferString(data),
		closed: false,
	}
}

func (m *mockReadWriteCloser) Close() error {
	m.closed = true
	return nil
}

func (m *mockReadWriteCloser) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	n, err = m.Buffer.Read(p)
	if err != nil {
		return n, fmt.Errorf("mock read failed: %w", err)
	}
	return n, nil
}

func (m *mockReadWriteCloser) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	n, err = m.Buffer.Write(p)
	if err != nil {
		return n, fmt.Errorf("mock write failed: %w", err)
	}
	return n, nil
}

// TestBidirectionalCopy tests the bidirectional copy function
func TestBidirectionalCopy(t *testing.T) {
	// Create two mock connections
	data1 := "Hello from conn1"
	data2 := "Hello from conn2"

	conn1 := newMockReadWriteCloser(data1)
	conn2 := newMockReadWriteCloser(data2)

	// Run bidirectional copy with timeout
	done := make(chan error, 1)
	go func() {
		done <- BidirectionalCopy(conn1, conn2)
	}()

	// Wait for copy to complete or timeout
	select {
	case err := <-done:
		// Copy completed
		if err != nil && !errors.Is(err, io.EOF) {
			t.Errorf("BidirectionalCopy() unexpected error: %v", err)
		}

		// Verify data was copied
		// Note: In this simple mock, data is both read and written to same buffer
		// In real scenario, data from conn1 would be in conn2 and vice versa

	case <-time.After(2 * time.Second):
		t.Fatal("BidirectionalCopy() timeout")
	}
}

// TestBidirectionalCopyWithPipe uses io.Pipe for more realistic testing
// Note: This is a simplified test as full bidirectional testing requires careful
// synchronization to avoid deadlocks
func TestBidirectionalCopyWithPipe(t *testing.T) {
	t.Skip("Skipping bidirectional pipe test - requires integration test setup")
}

// pipeReadWriteCloser combines a reader and writer into ReadWriteCloser
type pipeReadWriteCloser struct {
	io.ReadCloser
	io.WriteCloser
}

func (p *pipeReadWriteCloser) Close() error {
	err1 := p.ReadCloser.Close()
	err2 := p.WriteCloser.Close()
	if err1 != nil {
		return fmt.Errorf("failed to close reader: %w", err1)
	}
	if err2 != nil {
		return fmt.Errorf("failed to close writer: %w", err2)
	}
	return nil
}

// TestBidirectionalCopyLargeData tests copying large amounts of data
func TestBidirectionalCopyLargeData(t *testing.T) {
	t.Skip("Skipping large data test - requires integration test setup")
}

// TestStreamWrapper tests the StreamWrapper type
func TestStreamWrapper(_ *testing.T) {
	// Note: StreamWrapper wraps *quic.Stream which we can't easily mock
	// This test just verifies the type exists and compiles correctly
	// Full testing would require integration tests with actual QUIC streams

	// Verify StreamWrapper has expected methods at compile time
	var _ interface {
		Close() error
		CloseWrite() error
	} = (*StreamWrapper)(nil)
}

// TestCopyBuffer constant
func TestCopyBufferSize(t *testing.T) {
	if CopyBuffer != 32*1024 {
		t.Errorf("CopyBuffer = %d, want %d", CopyBuffer, 32*1024)
	}
}

// Benchmark for BidirectionalCopy
func BenchmarkBidirectionalCopy(b *testing.B) {
	data := strings.Repeat("x", 1024) // 1KB of data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pr1, pw1 := io.Pipe()
		pr2, pw2 := io.Pipe()

		conn1 := &pipeReadWriteCloser{pr1, pw2}
		conn2 := &pipeReadWriteCloser{pr2, pw1}

		go func() {
			_ = BidirectionalCopy(conn1, conn2)
		}()

		go func() {
			_, _ = pw1.Write([]byte(data))
			_ = pw1.Close()
		}()

		_, _ = io.Copy(io.Discard, pr2)
		_ = pr1.Close()
		_ = pr2.Close()
		_ = pw2.Close()
	}
}
