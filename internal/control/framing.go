package control

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	quicgo "github.com/quic-go/quic-go"
)

// MaxMessageSize is the maximum size of a control message
const MaxMessageSize = 64 * 1024 // 64KB

// WriteMessage writes a framed message to the stream
// Frame format: [4-byte length][message data]
func WriteMessage(stream *quicgo.Stream, msg *Message) error {
	// Marshal message to JSON
	data, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Check message size
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", len(data), MaxMessageSize)
	}

	// Write length prefix (4 bytes, big-endian)
	length := uint32(len(data))
	if err := binary.Write(stream, binary.BigEndian, length); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	// Write message data
	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	return nil
}

// ReadMessage reads a framed message from the stream
func ReadMessage(stream *quicgo.Stream) (*Message, error) {
	// Read length prefix (4 bytes, big-endian)
	var length uint32
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	// Validate message size
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, MaxMessageSize)
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(stream, data); err != nil {
		return nil, fmt.Errorf("failed to read message data: %w", err)
	}

	// Unmarshal message
	msg, err := UnmarshalMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return msg, nil
}

// WriteMessageBuffered writes a framed message using a buffered writer
func WriteMessageBuffered(writer *bufio.Writer, msg *Message) error {
	// Marshal message to JSON
	data, err := msg.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	// Check message size
	if len(data) > MaxMessageSize {
		return fmt.Errorf("message too large: %d bytes (max %d)", len(data), MaxMessageSize)
	}

	// Write length prefix (4 bytes, big-endian)
	length := uint32(len(data))
	if err := binary.Write(writer, binary.BigEndian, length); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}

	// Write message data
	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}

	// Flush buffer
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush writer: %w", err)
	}

	return nil
}

// ReadMessageBuffered reads a framed message using a buffered reader
func ReadMessageBuffered(reader *bufio.Reader) (*Message, error) {
	// Read length prefix (4 bytes, big-endian)
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	// Validate message size
	if length > MaxMessageSize {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", length, MaxMessageSize)
	}

	// Read message data
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read message data: %w", err)
	}

	// Unmarshal message
	msg, err := UnmarshalMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal message: %w", err)
	}

	return msg, nil
}
