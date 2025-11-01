package mux

import (
	"encoding/json"
	"fmt"
	"io"
)

// ProtocolID represents the protocol type for a stream
type ProtocolID byte

const (
	// ProtocolTCP indicates a TCP stream
	ProtocolTCP ProtocolID = 0x01

	// ProtocolUDP indicates a UDP datagram stream
	ProtocolUDP ProtocolID = 0x02

	// ProtocolControl indicates a control stream
	ProtocolControl ProtocolID = 0x03

	// ProtocolRaw indicates a raw framed data stream
	ProtocolRaw ProtocolID = 0x04
)

// String returns the string representation of the protocol ID
func (p ProtocolID) String() string {
	switch p {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolControl:
		return "CONTROL"
	case ProtocolRaw:
		return "RAW"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", byte(p))
	}
}

// StreamHeader represents the header of a multiplexed stream
// Format: version(1B) | proto_id(1B) | flags(1B) | meta_len(1B) | meta(...)
type StreamHeader struct {
	Version  byte       // Protocol version
	Protocol ProtocolID // Protocol type
	Flags    byte       // Protocol-specific flags
	Metadata []byte     // Protocol-specific metadata
}

// StreamVersion is the current protocol version
const StreamVersion byte = 0x01

// Header flags
const (
	// FlagCompressed indicates the stream data is compressed
	FlagCompressed byte = 0x01

	// FlagEncrypted indicates the stream data is encrypted
	FlagEncrypted byte = 0x02

	// FlagPriority indicates this is a high-priority stream
	FlagPriority byte = 0x04
)

// MaxMetadataSize is the maximum size of metadata in bytes
const MaxMetadataSize = 255

// NewStreamHeader creates a new stream header
func NewStreamHeader(protocol ProtocolID, metadata []byte) (*StreamHeader, error) {
	if len(metadata) > MaxMetadataSize {
		return nil, fmt.Errorf("metadata too large: %d bytes (max %d)", len(metadata), MaxMetadataSize)
	}

	return &StreamHeader{
		Version:  StreamVersion,
		Protocol: protocol,
		Flags:    0,
		Metadata: metadata,
	}, nil
}

// WriteHeader writes the stream header to a writer
func WriteHeader(w io.Writer, header *StreamHeader) error {
	// Write version
	if _, err := w.Write([]byte{header.Version}); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}

	// Write protocol ID
	if _, err := w.Write([]byte{byte(header.Protocol)}); err != nil {
		return fmt.Errorf("failed to write protocol: %w", err)
	}

	// Write flags
	if _, err := w.Write([]byte{header.Flags}); err != nil {
		return fmt.Errorf("failed to write flags: %w", err)
	}

	// Write metadata length
	metaLen := byte(len(header.Metadata))
	if _, err := w.Write([]byte{metaLen}); err != nil {
		return fmt.Errorf("failed to write metadata length: %w", err)
	}

	// Write metadata if present
	if metaLen > 0 {
		if _, err := w.Write(header.Metadata); err != nil {
			return fmt.Errorf("failed to write metadata: %w", err)
		}
	}

	return nil
}

// ReadHeader reads a stream header from a reader
func ReadHeader(r io.Reader) (*StreamHeader, error) {
	header := &StreamHeader{}

	// Read version
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, versionBuf); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	header.Version = versionBuf[0]

	// Validate version
	if header.Version != StreamVersion {
		return nil, fmt.Errorf("unsupported protocol version: 0x%02x (expected 0x%02x)", header.Version, StreamVersion)
	}

	// Read protocol ID
	protocolBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, protocolBuf); err != nil {
		return nil, fmt.Errorf("failed to read protocol: %w", err)
	}
	header.Protocol = ProtocolID(protocolBuf[0])

	// Read flags
	flagsBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, flagsBuf); err != nil {
		return nil, fmt.Errorf("failed to read flags: %w", err)
	}
	header.Flags = flagsBuf[0]

	// Read metadata length
	metaLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, metaLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read metadata length: %w", err)
	}
	metaLen := metaLenBuf[0]

	// Read metadata if present
	if metaLen > 0 {
		header.Metadata = make([]byte, metaLen)
		if _, err := io.ReadFull(r, header.Metadata); err != nil {
			return nil, fmt.Errorf("failed to read metadata: %w", err)
		}
	}

	return header, nil
}

// HeaderSize returns the total size of the header in bytes
func (h *StreamHeader) HeaderSize() int {
	return 4 + len(h.Metadata) // version + protocol + flags + meta_len + metadata
}

// HasFlag checks if a flag is set
func (h *StreamHeader) HasFlag(flag byte) bool {
	return (h.Flags & flag) != 0
}

// SetFlag sets a flag
func (h *StreamHeader) SetFlag(flag byte) {
	h.Flags |= flag
}

// ClearFlag clears a flag
func (h *StreamHeader) ClearFlag(flag byte) {
	h.Flags &^= flag
}

// TCPMetadata contains metadata for TCP streams
type TCPMetadata struct {
	SourceAddr string `json:"source_addr"`
	TargetAddr string `json:"target_addr"`
}

// UDPMetadata contains metadata for UDP streams
type UDPMetadata struct {
	SourceAddr string `json:"source_addr"`
	TargetAddr string `json:"target_addr"`
}

// EncodeTCPMetadata encodes TCP metadata to bytes
func EncodeTCPMetadata(meta TCPMetadata) ([]byte, error) {
	data, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TCP metadata: %w", err)
	}
	return data, nil
}

// DecodeTCPMetadata decodes TCP metadata from bytes
func DecodeTCPMetadata(data []byte) (*TCPMetadata, error) {
	var meta TCPMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to decode TCP metadata: %w", err)
	}
	return &meta, nil
}

// EncodeUDPMetadata encodes UDP metadata to bytes
func EncodeUDPMetadata(meta UDPMetadata) ([]byte, error) {
	data, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to encode UDP metadata: %w", err)
	}
	return data, nil
}

// DecodeUDPMetadata decodes UDP metadata from bytes
func DecodeUDPMetadata(data []byte) (*UDPMetadata, error) {
	var meta UDPMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("failed to decode UDP metadata: %w", err)
	}
	return &meta, nil
}
