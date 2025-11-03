package mux

import (
	"bytes"
	"testing"


	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require")

func TestProtocolID_String(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		protocol ProtocolID
	}{
		{name: "TCP", protocol: ProtocolTCP, expected: "TCP"},
		{name: "UDP", protocol: ProtocolUDP, expected: "UDP"},
		{name: "Control", protocol: ProtocolControl, expected: "CONTROL"},
		{name: "Raw", protocol: ProtocolRaw, expected: "RAW"},
		{name: "Unknown", protocol: ProtocolID(0xFF), expected: "UNKNOWN(0xff)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.protocol.String()
			if result != tt.expected {
				assert.Equal(t, tt.expected, result, "ProtocolID.String() should match")
			}
		})
	}
}

func TestNewStreamHeader(t *testing.T) {
	tests := []struct {
		name     string
		metadata []byte
		protocol ProtocolID
		wantErr  bool
	}{
		{
			name:     "valid header with metadata",
			protocol: ProtocolTCP,
			metadata: []byte("test metadata"),
			wantErr:  false,
		},
		{
			name:     "valid header without metadata",
			protocol: ProtocolUDP,
			metadata: nil,
			wantErr:  false,
		},
		{
			name:     "metadata at max size",
			protocol: ProtocolTCP,
			metadata: make([]byte, MaxMetadataSize),
			wantErr:  false,
		},
		{
			name:     "metadata too large",
			protocol: ProtocolTCP,
			metadata: make([]byte, MaxMetadataSize+1),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, err := NewStreamHeader(tt.protocol, tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewStreamHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if header.Version != StreamVersion {
					assert.Equal(t, StreamVersion, header.Version, "NewStreamHeader() Version should match")
				}
				if header.Protocol != tt.protocol {
					assert.Equal(t, tt.protocol, header.Protocol, "NewStreamHeader() Protocol should match")
				}
				if !bytes.Equal(header.Metadata, tt.metadata) {
					assert.Fail(t, "NewStreamHeader() Metadata mismatch")
				}
			}
		})
	}
}

func TestWriteReadHeader(t *testing.T) {
	tests := []struct {
		header *StreamHeader
		name   string
	}{
		{
			name: "header with metadata",
			header: &StreamHeader{
				Version:  StreamVersion,
				Protocol: ProtocolTCP,
				Flags:    0,
				Metadata: []byte("test metadata"),
			},
		},
		{
			name: "header without metadata",
			header: &StreamHeader{
				Version:  StreamVersion,
				Protocol: ProtocolUDP,
				Flags:    0,
				Metadata: nil,
			},
		},
		{
			name: "header with flags",
			header: &StreamHeader{
				Version:  StreamVersion,
				Protocol: ProtocolRaw,
				Flags:    FlagCompressed | FlagPriority,
				Metadata: []byte("data"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Write header
			err := WriteHeader(&buf, tt.header)
			if err != nil {
				require.NoError(t, err, "WriteHeader() should not return error")
			}

			// Read header
			header2, err := ReadHeader(&buf)
			if err != nil {
				require.NoError(t, err, "ReadHeader() should not return error")
			}

			// Compare
			if header2.Version != tt.header.Version {
				assert.Equal(t, tt.header.Version, header2.Version, "ReadHeader() Version should match")
			}
			if header2.Protocol != tt.header.Protocol {
				assert.Equal(t, tt.header.Protocol, header2.Protocol, "ReadHeader() Protocol should match")
			}
			if header2.Flags != tt.header.Flags {
				assert.Equal(t, tt.header.Flags, header2.Flags, "ReadHeader() Flags should match")
			}
			if !bytes.Equal(header2.Metadata, tt.header.Metadata) {
				assert.Equal(t, tt.header.Metadata, header2.Metadata, "ReadHeader() Metadata should match")
			}
		})
	}
}

func TestReadHeaderInvalidVersion(t *testing.T) {
	header := &StreamHeader{
		Version:  0xFF, // Invalid version
		Protocol: ProtocolTCP,
		Flags:    0,
		Metadata: nil,
	}

	var buf bytes.Buffer
	if err := WriteHeader(&buf, header); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	_, err := ReadHeader(&buf)
	if err == nil {
		assert.Fail(t, "ReadHeader() expected error for invalid version")
	}
}

func TestHeaderSize(t *testing.T) {
	tests := []struct {
		name         string
		metadata     []byte
		expectedSize int
	}{
		{"no metadata", nil, 4},
		{"with metadata", []byte("test"), 8},        // 4 + 4 bytes metadata
		{"larger metadata", make([]byte, 100), 104}, // 4 + 100 bytes metadata
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, _ := NewStreamHeader(ProtocolTCP, tt.metadata)
			size := header.HeaderSize()
			if size != tt.expectedSize {
				assert.Equal(t, tt.expectedSize, size, "HeaderSize() should match")
			}
		})
	}
}

func TestHeaderFlags(t *testing.T) {
	header, _ := NewStreamHeader(ProtocolTCP, nil)

	// Initially no flags
	if header.HasFlag(FlagCompressed) {
		assert.Fail(t, "HasFlag(FlagCompressed) = true, want false")
	}

	// Set flag
	header.SetFlag(FlagCompressed)
	if !header.HasFlag(FlagCompressed) {
		assert.Fail(t, "HasFlag(FlagCompressed) = false after SetFlag, want true")
	}

	// Set another flag
	header.SetFlag(FlagPriority)
	if !header.HasFlag(FlagPriority) {
		assert.Fail(t, "HasFlag(FlagPriority) = false after SetFlag, want true")
	}
	if !header.HasFlag(FlagCompressed) {
		assert.Fail(t, "HasFlag(FlagCompressed) = false, should still be true")
	}

	// Clear flag
	header.ClearFlag(FlagCompressed)
	if header.HasFlag(FlagCompressed) {
		assert.Fail(t, "HasFlag(FlagCompressed) = true after ClearFlag, want false")
	}
	if !header.HasFlag(FlagPriority) {
		assert.Fail(t, "HasFlag(FlagPriority) = false, should still be true")
	}
}

func TestEncodeTCPMetadata(t *testing.T) {
	meta := TCPMetadata{
		SourceAddr: "127.0.0.1:8080",
		TargetAddr: "10.0.0.5:9000",
	}

	data, err := EncodeTCPMetadata(meta)
	if err != nil {
		require.NoError(t, err, "EncodeTCPMetadata() should not return error")
	}

	if len(data) == 0 {
		assert.Fail(t, "EncodeTCPMetadata() returned empty data")
	}
}

func TestDecodeTCPMetadata(t *testing.T) {
	original := TCPMetadata{
		SourceAddr: "127.0.0.1:8080",
		TargetAddr: "10.0.0.5:9000",
	}

	// Encode
	data, err := EncodeTCPMetadata(original)
	if err != nil {
		require.NoError(t, err, "EncodeTCPMetadata() should not return error")
	}

	// Decode
	decoded, err := DecodeTCPMetadata(data)
	if err != nil {
		require.NoError(t, err, "DecodeTCPMetadata() should not return error")
	}

	if decoded.SourceAddr != original.SourceAddr {
		assert.Equal(t, original.SourceAddr, decoded.SourceAddr, "DecodeTCPMetadata() SourceAddr should match")
	}
	if decoded.TargetAddr != original.TargetAddr {
		assert.Equal(t, original.TargetAddr, decoded.TargetAddr, "DecodeTCPMetadata() TargetAddr should match")
	}
}

func TestDecodeTCPMetadataInvalid(t *testing.T) {
	_, err := DecodeTCPMetadata([]byte("invalid json"))
	if err == nil {
		assert.Fail(t, "DecodeTCPMetadata() expected error for invalid JSON")
	}
}

func TestEncodeUDPMetadata(t *testing.T) {
	meta := UDPMetadata{
		SourceAddr: "127.0.0.1:5353",
		TargetAddr: "10.0.0.5:53",
	}

	data, err := EncodeUDPMetadata(meta)
	if err != nil {
		require.NoError(t, err, "EncodeUDPMetadata() should not return error")
	}

	if len(data) == 0 {
		assert.Fail(t, "EncodeUDPMetadata() returned empty data")
	}
}

func TestDecodeUDPMetadata(t *testing.T) {
	original := UDPMetadata{
		SourceAddr: "127.0.0.1:5353",
		TargetAddr: "10.0.0.5:53",
	}

	// Encode
	data, err := EncodeUDPMetadata(original)
	if err != nil {
		require.NoError(t, err, "EncodeUDPMetadata() should not return error")
	}

	// Decode
	decoded, err := DecodeUDPMetadata(data)
	if err != nil {
		require.NoError(t, err, "DecodeUDPMetadata() should not return error")
	}

	if decoded.SourceAddr != original.SourceAddr {
		assert.Equal(t, original.SourceAddr, decoded.SourceAddr, "DecodeUDPMetadata() SourceAddr should match")
	}
	if decoded.TargetAddr != original.TargetAddr {
		assert.Equal(t, original.TargetAddr, decoded.TargetAddr, "DecodeUDPMetadata() TargetAddr should match")
	}
}

func TestDecodeUDPMetadataInvalid(t *testing.T) {
	_, err := DecodeUDPMetadata([]byte("invalid json"))
	if err == nil {
		assert.Fail(t, "DecodeUDPMetadata() expected error for invalid JSON")
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	// TCP metadata round trip
	tcpMeta := TCPMetadata{
		SourceAddr: "192.168.1.1:1234",
		TargetAddr: "10.0.0.1:5678",
	}

	tcpData, _ := EncodeTCPMetadata(tcpMeta)
	tcpDecoded, err := DecodeTCPMetadata(tcpData)
	if err != nil {
		t.Errorf("TCP metadata round trip failed: %v", err)
	}
	if tcpDecoded.SourceAddr != tcpMeta.SourceAddr || tcpDecoded.TargetAddr != tcpMeta.TargetAddr {
		assert.Fail(t, "TCP metadata round trip data mismatch")
	}

	// UDP metadata round trip
	udpMeta := UDPMetadata{
		SourceAddr: "192.168.1.1:53",
		TargetAddr: "8.8.8.8:53",
	}

	udpData, _ := EncodeUDPMetadata(udpMeta)
	udpDecoded, err := DecodeUDPMetadata(udpData)
	if err != nil {
		t.Errorf("UDP metadata round trip failed: %v", err)
	}
	if udpDecoded.SourceAddr != udpMeta.SourceAddr || udpDecoded.TargetAddr != udpMeta.TargetAddr {
		assert.Fail(t, "UDP metadata round trip data mismatch")
	}
}

// Test ReadHeader with EOF
func TestReadHeaderEOF(t *testing.T) {
	var buf bytes.Buffer

	_, err := ReadHeader(&buf)
	assert.Error(t, err, "ReadHeader should fail with EOF on empty buffer")
}

// Test ReadHeader with incomplete header
func TestReadHeaderIncomplete(t *testing.T) {
	var buf bytes.Buffer

	// Write only first two bytes
	buf.WriteByte(StreamVersion)
	buf.WriteByte(byte(ProtocolTCP))

	_, err := ReadHeader(&buf)
	assert.Error(t, err, "ReadHeader should fail with incomplete header")
}

// Test ReadHeader with incomplete metadata
func TestReadHeaderIncompleteMetadata(t *testing.T) {
	var buf bytes.Buffer

	// Write header indicating metadata exists
	buf.WriteByte(StreamVersion)
	buf.WriteByte(byte(ProtocolTCP))
	buf.WriteByte(0)    // flags
	buf.WriteByte(10)   // metadata length = 10 bytes

	// But only write 5 bytes of metadata
	buf.Write([]byte("hello"))

	_, err := ReadHeader(&buf)
	assert.Error(t, err, "ReadHeader should fail with incomplete metadata")
}

// Test WriteHeader error path
func TestWriteHeaderError(t *testing.T) {
	header := &StreamHeader{
		Version:  StreamVersion,
		Protocol: ProtocolTCP,
		Flags:    0,
		Metadata: []byte("test"),
	}

	// Create a writer that fails
	failWriter := &failingWriter{}

	err := WriteHeader(failWriter, header)
	assert.Error(t, err, "WriteHeader should fail with failing writer")
}

// failingWriter is a writer that always fails
type failingWriter struct{}

func (f *failingWriter) Write(p []byte) (n int, err error) {
	return 0, bytes.ErrTooLarge
}

// Test encoding empty metadata
func TestEncodeEmptyMetadata(t *testing.T) {
	// TCP with empty addresses
	tcpMeta := TCPMetadata{
		SourceAddr: "",
		TargetAddr: "",
	}
	tcpData, err := EncodeTCPMetadata(tcpMeta)
	require.NoError(t, err, "EncodeTCPMetadata should handle empty addresses")
	assert.NotNil(t, tcpData)

	decoded, err := DecodeTCPMetadata(tcpData)
	require.NoError(t, err)
	assert.Equal(t, "", decoded.SourceAddr)
	assert.Equal(t, "", decoded.TargetAddr)

	// UDP with empty addresses
	udpMeta := UDPMetadata{
		SourceAddr: "",
		TargetAddr: "",
	}
	udpData, err := EncodeUDPMetadata(udpMeta)
	require.NoError(t, err, "EncodeUDPMetadata should handle empty addresses")
	assert.NotNil(t, udpData)

	decodedUDP, err := DecodeUDPMetadata(udpData)
	require.NoError(t, err)
	assert.Equal(t, "", decodedUDP.SourceAddr)
	assert.Equal(t, "", decodedUDP.TargetAddr)
}

// Test decoding empty data
func TestDecodeEmptyData(t *testing.T) {
	_, err := DecodeTCPMetadata([]byte{})
	assert.Error(t, err, "DecodeTCPMetadata should fail with empty data")

	_, err = DecodeUDPMetadata([]byte{})
	assert.Error(t, err, "DecodeUDPMetadata should fail with empty data")
}

// Test header with maximum metadata size
func TestHeaderWithMaxMetadata(t *testing.T) {
	maxMeta := make([]byte, MaxMetadataSize)
	for i := range maxMeta {
		maxMeta[i] = byte(i % 256)
	}

	header, err := NewStreamHeader(ProtocolTCP, maxMeta)
	require.NoError(t, err)

	var buf bytes.Buffer
	err = WriteHeader(&buf, header)
	require.NoError(t, err)

	readHeader, err := ReadHeader(&buf)
	require.NoError(t, err)
	assert.Equal(t, MaxMetadataSize, len(readHeader.Metadata))
	assert.Equal(t, maxMeta, readHeader.Metadata)
}

// Test all protocol IDs
func TestAllProtocolIDs(t *testing.T) {
	protocols := []ProtocolID{ProtocolTCP, ProtocolUDP, ProtocolControl, ProtocolRaw}

	for _, proto := range protocols {
		header, err := NewStreamHeader(proto, []byte("test"))
		require.NoError(t, err)
		assert.Equal(t, proto, header.Protocol)

		// Test string representation
		str := proto.String()
		assert.NotEmpty(t, str)
		assert.NotContains(t, str, "UNKNOWN")
	}
}

// Test multiple flags
func TestMultipleFlags(t *testing.T) {
	header, _ := NewStreamHeader(ProtocolTCP, nil)

	// Set multiple flags
	header.SetFlag(FlagCompressed)
	header.SetFlag(FlagPriority)
	header.SetFlag(FlagEncrypted)

	// Verify all are set
	assert.True(t, header.HasFlag(FlagCompressed))
	assert.True(t, header.HasFlag(FlagPriority))
	assert.True(t, header.HasFlag(FlagEncrypted))

	// Clear one flag
	header.ClearFlag(FlagPriority)

	// Verify state
	assert.True(t, header.HasFlag(FlagCompressed))
	assert.False(t, header.HasFlag(FlagPriority))
	assert.True(t, header.HasFlag(FlagEncrypted))
}
