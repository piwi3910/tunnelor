package quic

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
)

// Connection represents a QUIC connection with stream management
type Connection struct {
	ctx          context.Context
	conn         *quic.Conn
	streams      map[uint64]*quic.Stream
	remoteAddr   string
	streamsMutex sync.RWMutex
	isServer     bool
}

// OpenStream opens a new bidirectional stream
func (c *Connection) OpenStream() (*quic.Stream, error) {
	stream, err := c.conn.OpenStreamSync(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Register stream
	streamID := stream.StreamID()
	c.streamsMutex.Lock()
	c.streams[uint64(streamID)] = stream
	c.streamsMutex.Unlock()

	log.Debug().
		Uint64("stream_id", uint64(streamID)).
		Str("remote_addr", c.remoteAddr).
		Msg("Opened new stream")

	return stream, nil
}

// AcceptStream waits for and accepts an incoming stream
func (c *Connection) AcceptStream() (*quic.Stream, error) {
	stream, err := c.conn.AcceptStream(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}

	// Register stream
	streamID := stream.StreamID()
	c.streamsMutex.Lock()
	c.streams[uint64(streamID)] = stream
	c.streamsMutex.Unlock()

	log.Debug().
		Uint64("stream_id", uint64(streamID)).
		Str("remote_addr", c.remoteAddr).
		Msg("Accepted new stream")

	return stream, nil
}

// GetStream returns a stream by ID
func (c *Connection) GetStream(streamID uint64) (*quic.Stream, bool) {
	c.streamsMutex.RLock()
	defer c.streamsMutex.RUnlock()
	stream, ok := c.streams[streamID]
	return stream, ok
}

// CloseStream closes and removes a stream
func (c *Connection) CloseStream(streamID uint64) error {
	c.streamsMutex.Lock()
	stream, ok := c.streams[streamID]
	if ok {
		delete(c.streams, streamID)
	}
	c.streamsMutex.Unlock()

	if !ok {
		return fmt.Errorf("stream %d not found", streamID)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	log.Debug().
		Uint64("stream_id", streamID).
		Str("remote_addr", c.remoteAddr).
		Msg("Closed stream")

	return nil
}

// StreamCount returns the number of active streams
func (c *Connection) StreamCount() int {
	c.streamsMutex.RLock()
	defer c.streamsMutex.RUnlock()
	return len(c.streams)
}

// SendDatagram sends a datagram over the QUIC connection
func (c *Connection) SendDatagram(data []byte) error {
	if err := c.conn.SendDatagram(data); err != nil {
		return fmt.Errorf("failed to send datagram: %w", err)
	}
	return nil
}

// ReceiveDatagram receives a datagram from the QUIC connection
func (c *Connection) ReceiveDatagram() ([]byte, error) {
	data, err := c.conn.ReceiveDatagram(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive datagram: %w", err)
	}
	return data, nil
}

// Context returns the connection context
func (c *Connection) Context() context.Context {
	return c.conn.Context()
}

// RemoteAddr returns the remote address of the connection
func (c *Connection) RemoteAddr() string {
	return c.remoteAddr
}

// LocalAddr returns the local address of the connection
func (c *Connection) LocalAddr() string {
	return c.conn.LocalAddr().String()
}

// Close closes the QUIC connection and all streams
func (c *Connection) Close() error {
	// Close all streams
	c.streamsMutex.Lock()
	for streamID, stream := range c.streams {
		stream.Close()
		delete(c.streams, streamID)
	}
	c.streamsMutex.Unlock()

	// Close connection
	if err := c.conn.CloseWithError(0, "connection closed"); err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}

	log.Info().
		Str("remote_addr", c.remoteAddr).
		Msg("Connection closed")

	return nil
}

// CloseWithError closes the connection with an error code and message
func (c *Connection) CloseWithError(code uint64, msg string) error {
	if err := c.conn.CloseWithError(quic.ApplicationErrorCode(code), msg); err != nil {
		return fmt.Errorf("failed to close connection with error: %w", err)
	}

	log.Warn().
		Str("remote_addr", c.remoteAddr).
		Uint64("error_code", code).
		Str("error_msg", msg).
		Msg("Connection closed with error")

	return nil
}

// StreamReader wraps a QUIC stream for easier reading
type StreamReader struct {
	stream *quic.Stream
}

// Read reads data from the stream
func (sr *StreamReader) Read(p []byte) (int, error) {
	n, err := sr.stream.Read(p)
	if err != nil {
		return n, fmt.Errorf("failed to read from stream: %w", err)
	}
	return n, nil
}

// Close closes the read side of the stream
func (sr *StreamReader) Close() error {
	sr.stream.CancelRead(0)
	return nil
}

// StreamWriter wraps a QUIC stream for easier writing
type StreamWriter struct {
	stream *quic.Stream
}

// Write writes data to the stream
func (sw *StreamWriter) Write(p []byte) (int, error) {
	n, err := sw.stream.Write(p)
	if err != nil {
		return n, fmt.Errorf("failed to write to stream: %w", err)
	}
	return n, nil
}

// Close closes the write side of the stream
func (sw *StreamWriter) Close() error {
	if err := sw.stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}
	return nil
}

// NewStreamReader creates a new StreamReader for the given stream
func NewStreamReader(stream *quic.Stream) io.ReadCloser {
	return &StreamReader{stream: stream}
}

// NewStreamWriter creates a new StreamWriter for the given stream
func NewStreamWriter(stream *quic.Stream) io.WriteCloser {
	return &StreamWriter{stream: stream}
}
