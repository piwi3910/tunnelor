package mux

import (
	"bytes"
	"testing"
)

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
				t.Errorf("ProtocolID.String() = %v, want %v", result, tt.expected)
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
					t.Errorf("NewStreamHeader() Version = %v, want %v", header.Version, StreamVersion)
				}
				if header.Protocol != tt.protocol {
					t.Errorf("NewStreamHeader() Protocol = %v, want %v", header.Protocol, tt.protocol)
				}
				if !bytes.Equal(header.Metadata, tt.metadata) {
					t.Error("NewStreamHeader() Metadata mismatch")
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
				t.Fatalf("WriteHeader() error = %v", err)
			}

			// Read header
			header2, err := ReadHeader(&buf)
			if err != nil {
				t.Fatalf("ReadHeader() error = %v", err)
			}

			// Compare
			if header2.Version != tt.header.Version {
				t.Errorf("ReadHeader() Version = %v, want %v", header2.Version, tt.header.Version)
			}
			if header2.Protocol != tt.header.Protocol {
				t.Errorf("ReadHeader() Protocol = %v, want %v", header2.Protocol, tt.header.Protocol)
			}
			if header2.Flags != tt.header.Flags {
				t.Errorf("ReadHeader() Flags = %v, want %v", header2.Flags, tt.header.Flags)
			}
			if !bytes.Equal(header2.Metadata, tt.header.Metadata) {
				t.Errorf("ReadHeader() Metadata = %v, want %v", header2.Metadata, tt.header.Metadata)
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
		t.Error("ReadHeader() expected error for invalid version")
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
				t.Errorf("HeaderSize() = %v, want %v", size, tt.expectedSize)
			}
		})
	}
}

func TestHeaderFlags(t *testing.T) {
	header, _ := NewStreamHeader(ProtocolTCP, nil)

	// Initially no flags
	if header.HasFlag(FlagCompressed) {
		t.Error("HasFlag(FlagCompressed) = true, want false")
	}

	// Set flag
	header.SetFlag(FlagCompressed)
	if !header.HasFlag(FlagCompressed) {
		t.Error("HasFlag(FlagCompressed) = false after SetFlag, want true")
	}

	// Set another flag
	header.SetFlag(FlagPriority)
	if !header.HasFlag(FlagPriority) {
		t.Error("HasFlag(FlagPriority) = false after SetFlag, want true")
	}
	if !header.HasFlag(FlagCompressed) {
		t.Error("HasFlag(FlagCompressed) = false, should still be true")
	}

	// Clear flag
	header.ClearFlag(FlagCompressed)
	if header.HasFlag(FlagCompressed) {
		t.Error("HasFlag(FlagCompressed) = true after ClearFlag, want false")
	}
	if !header.HasFlag(FlagPriority) {
		t.Error("HasFlag(FlagPriority) = false, should still be true")
	}
}

func TestEncodeTCPMetadata(t *testing.T) {
	meta := TCPMetadata{
		SourceAddr: "127.0.0.1:8080",
		TargetAddr: "10.0.0.5:9000",
	}

	data, err := EncodeTCPMetadata(meta)
	if err != nil {
		t.Fatalf("EncodeTCPMetadata() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("EncodeTCPMetadata() returned empty data")
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
		t.Fatalf("EncodeTCPMetadata() error = %v", err)
	}

	// Decode
	decoded, err := DecodeTCPMetadata(data)
	if err != nil {
		t.Fatalf("DecodeTCPMetadata() error = %v", err)
	}

	if decoded.SourceAddr != original.SourceAddr {
		t.Errorf("DecodeTCPMetadata() SourceAddr = %v, want %v", decoded.SourceAddr, original.SourceAddr)
	}
	if decoded.TargetAddr != original.TargetAddr {
		t.Errorf("DecodeTCPMetadata() TargetAddr = %v, want %v", decoded.TargetAddr, original.TargetAddr)
	}
}

func TestDecodeTCPMetadataInvalid(t *testing.T) {
	_, err := DecodeTCPMetadata([]byte("invalid json"))
	if err == nil {
		t.Error("DecodeTCPMetadata() expected error for invalid JSON")
	}
}

func TestEncodeUDPMetadata(t *testing.T) {
	meta := UDPMetadata{
		SourceAddr: "127.0.0.1:5353",
		TargetAddr: "10.0.0.5:53",
	}

	data, err := EncodeUDPMetadata(meta)
	if err != nil {
		t.Fatalf("EncodeUDPMetadata() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("EncodeUDPMetadata() returned empty data")
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
		t.Fatalf("EncodeUDPMetadata() error = %v", err)
	}

	// Decode
	decoded, err := DecodeUDPMetadata(data)
	if err != nil {
		t.Fatalf("DecodeUDPMetadata() error = %v", err)
	}

	if decoded.SourceAddr != original.SourceAddr {
		t.Errorf("DecodeUDPMetadata() SourceAddr = %v, want %v", decoded.SourceAddr, original.SourceAddr)
	}
	if decoded.TargetAddr != original.TargetAddr {
		t.Errorf("DecodeUDPMetadata() TargetAddr = %v, want %v", decoded.TargetAddr, original.TargetAddr)
	}
}

func TestDecodeUDPMetadataInvalid(t *testing.T) {
	_, err := DecodeUDPMetadata([]byte("invalid json"))
	if err == nil {
		t.Error("DecodeUDPMetadata() expected error for invalid JSON")
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
		t.Error("TCP metadata round trip data mismatch")
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
		t.Error("UDP metadata round trip data mismatch")
	}
}
