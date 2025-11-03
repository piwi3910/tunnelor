package udpbridge

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestSessionTimeout(t *testing.T) {
	expectedTimeout := 2 * time.Minute
	if SessionTimeout != expectedTimeout {
		t.Errorf("SessionTimeout = %v, want %v", SessionTimeout, expectedTimeout)
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
				t.Fatalf("WriteUDPDatagram() error = %v", err)
			}

			// Read datagram
			datagram2, err := ReadUDPDatagram(&buf)
			if err != nil {
				t.Fatalf("ReadUDPDatagram() error = %v", err)
			}

			// Verify
			if datagram2.Length != datagram.Length {
				t.Errorf("ReadUDPDatagram() Length = %v, want %v", datagram2.Length, datagram.Length)
			}

			if !bytes.Equal(datagram2.Data, datagram.Data) {
				t.Error("ReadUDPDatagram() Data mismatch")
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
		Length: uint16(len(maxData)),
		Data:   maxData,
	}

	var buf bytes.Buffer
	err := WriteUDPDatagram(&buf, datagram)
	if err != nil {
		t.Fatalf("WriteUDPDatagram() error = %v", err)
	}

	// Read back
	datagram2, err := ReadUDPDatagram(&buf)
	if err != nil {
		t.Fatalf("ReadUDPDatagram() error = %v", err)
	}

	if !bytes.Equal(datagram2.Data, maxData) {
		t.Error("ReadUDPDatagram() max size data mismatch")
	}
}

func TestReadUDPDatagramEOF(t *testing.T) {
	var buf bytes.Buffer

	_, err := ReadUDPDatagram(&buf)
	if err == nil {
		t.Error("ReadUDPDatagram() expected error for empty buffer, got nil")
	}
}

func TestReadUDPDatagramIncompleteLength(t *testing.T) {
	buf := bytes.NewBuffer([]byte{0x00}) // Only 1 byte instead of 2

	_, err := ReadUDPDatagram(buf)
	if err == nil {
		t.Error("ReadUDPDatagram() expected error for incomplete length")
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
		t.Error("ReadUDPDatagram() expected error for incomplete data")
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
			Length: uint16(len(data)), // #nosec G115 -- Test data is small, fits in uint16
			Data:   data,
		}
		err := WriteUDPDatagram(&buf, dg)
		if err != nil {
			t.Fatalf("WriteUDPDatagram() error = %v", err)
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
		t.Fatalf("ResolveUDPAddr() error = %v", err)
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
		t.Error("UDPSession LastSeen not set correctly")
	}

	// Call cancel
	session.Cancel()
	if !cancelCalled {
		t.Error("UDPSession Cancel not called")
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
		t.Errorf("UDPListener listenAddr = %v, want %v", listener.listenAddr, listenAddr)
	}

	if listener.targetAddr != targetAddr {
		t.Errorf("UDPListener targetAddr = %v, want %v", listener.targetAddr, targetAddr)
	}

	if listener.sessions == nil {
		t.Error("UDPListener sessions map not initialized")
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
				t.Fatalf("WriteUDPDatagram() error = %v", err)
			}

			dg2, err := ReadUDPDatagram(&buf)
			if err != nil {
				t.Fatalf("ReadUDPDatagram() error = %v", err)
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
				t.Fatalf("WriteUDPDatagram() error = %v", err)
			}
			dg2, err := ReadUDPDatagram(&buf)

			if err != nil {
				t.Fatalf("ReadUDPDatagram() error = %v", err)
			}

			if !bytes.Equal(dg2.Data, tt.data) {
				t.Error("Data pattern not preserved")
			}
		})
	}
}

// Benchmark tests
func BenchmarkWriteUDPDatagram(b *testing.B) {
	data := make([]byte, 1400) // Typical MTU size
	datagram := &UDPDatagram{
		Length: uint16(len(data)),
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
		Length: uint16(len(data)),
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
