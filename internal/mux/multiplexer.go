package mux

import (
	"context"
	"fmt"
	"sync"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/piwi3910/tunnelor/internal/quic"
)

// StreamHandler is a function that handles a multiplexed stream
type StreamHandler func(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error

// Multiplexer manages stream multiplexing and dispatching
type Multiplexer struct {
	ctx        context.Context
	connection *quic.Connection
	handlers   map[ProtocolID]StreamHandler
	streams    map[uint64]*Stream
	cancel     context.CancelFunc
	mu         sync.RWMutex
}

// Stream represents a multiplexed stream with its header
type Stream struct {
	Stream   *quicgo.Stream
	Header   *StreamHeader
	StreamID uint64
}

// NewMultiplexer creates a new multiplexer for a connection
func NewMultiplexer(conn *quic.Connection) *Multiplexer {
	ctx, cancel := context.WithCancel(context.Background())

	return &Multiplexer{
		connection: conn,
		handlers:   make(map[ProtocolID]StreamHandler),
		streams:    make(map[uint64]*Stream),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// RegisterHandler registers a handler for a protocol type
func (m *Multiplexer) RegisterHandler(protocol ProtocolID, handler StreamHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.handlers[protocol] = handler

	log.Debug().
		Str("protocol", protocol.String()).
		Msg("Registered stream handler")
}

// OpenStream opens a new multiplexed stream with the given protocol
func (m *Multiplexer) OpenStream(protocol ProtocolID, metadata []byte) (*Stream, error) {
	// Open QUIC stream
	stream, err := m.connection.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	// Create stream header
	header, err := NewStreamHeader(protocol, metadata)
	if err != nil {
		if closeErr := stream.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close stream after header creation error")
		}
		return nil, fmt.Errorf("failed to create stream header: %w", err)
	}

	// Write header to stream
	if err := WriteHeader(stream, header); err != nil {
		if closeErr := stream.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close stream after header write error")
		}
		return nil, fmt.Errorf("failed to write stream header: %w", err)
	}

	// Create mux stream
	muxStream := &Stream{
		Stream:   stream,
		Header:   header,
		StreamID: uint64(stream.StreamID()), // #nosec G115 -- QUIC stream IDs are always non-negative
	}

	// Register stream
	m.mu.Lock()
	m.streams[muxStream.StreamID] = muxStream
	m.mu.Unlock()

	log.Debug().
		Uint64("stream_id", muxStream.StreamID).
		Str("protocol", protocol.String()).
		Msg("Opened multiplexed stream")

	return muxStream, nil
}

// OpenTCPStream opens a new TCP stream with the given target address
func (m *Multiplexer) OpenTCPStream(targetAddr, sourceAddr string) (*quicgo.Stream, error) {
	// Encode TCP metadata
	meta := TCPMetadata{
		SourceAddr: sourceAddr,
		TargetAddr: targetAddr,
	}
	metaBytes, err := EncodeTCPMetadata(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to encode TCP metadata: %w", err)
	}

	return m.openProtocolStream(ProtocolTCP, metaBytes, targetAddr, sourceAddr, "TCP")
}

// OpenUDPStream opens a new UDP stream with the given target address
func (m *Multiplexer) OpenUDPStream(targetAddr, sourceAddr string) (*quicgo.Stream, error) {
	// Encode UDP metadata
	meta := UDPMetadata{
		SourceAddr: sourceAddr,
		TargetAddr: targetAddr,
	}
	metaBytes, err := EncodeUDPMetadata(meta)
	if err != nil {
		return nil, fmt.Errorf("failed to encode UDP metadata: %w", err)
	}

	return m.openProtocolStream(ProtocolUDP, metaBytes, targetAddr, sourceAddr, "UDP")
}

// openProtocolStream is a helper to open streams for different protocols
func (m *Multiplexer) openProtocolStream(protocol ProtocolID, metadata []byte, targetAddr, sourceAddr, protocolName string) (*quicgo.Stream, error) {
	// Open stream
	muxStream, err := m.OpenStream(protocol, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s stream: %w", protocolName, err)
	}

	log.Debug().
		Str("target", targetAddr).
		Str("source", sourceAddr).
		Uint64("stream_id", muxStream.StreamID).
		Msgf("Opened %s stream", protocolName)

	return muxStream.Stream, nil
}

// AcceptStream accepts an incoming multiplexed stream
func (m *Multiplexer) AcceptStream() (*Stream, error) {
	// Accept QUIC stream
	stream, err := m.connection.AcceptStream()
	if err != nil {
		return nil, fmt.Errorf("failed to accept stream: %w", err)
	}

	// Read stream header
	header, err := ReadHeader(stream)
	if err != nil {
		if closeErr := stream.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close stream after header read error")
		}
		return nil, fmt.Errorf("failed to read stream header: %w", err)
	}

	// Create mux stream
	muxStream := &Stream{
		Stream:   stream,
		Header:   header,
		StreamID: uint64(stream.StreamID()), // #nosec G115 -- QUIC stream IDs are always non-negative
	}

	// Register stream
	m.mu.Lock()
	m.streams[muxStream.StreamID] = muxStream
	m.mu.Unlock()

	log.Debug().
		Uint64("stream_id", muxStream.StreamID).
		Str("protocol", header.Protocol.String()).
		Msg("Accepted multiplexed stream")

	return muxStream, nil
}

// HandleStream dispatches a stream to the appropriate handler
func (m *Multiplexer) HandleStream(muxStream *Stream) error {
	m.mu.RLock()
	handler, ok := m.handlers[muxStream.Header.Protocol]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no handler registered for protocol: %s", muxStream.Header.Protocol.String())
	}

	// Call handler
	if err := handler(m.ctx, muxStream.Stream, muxStream.Header); err != nil {
		return fmt.Errorf("handler failed for protocol %s: %w", muxStream.Header.Protocol.String(), err)
	}

	return nil
}

// ServeStreams accepts and handles incoming streams
// Returns an error if the accept loop encounters a fatal error
// Individual stream handling errors are logged but don't stop the server
func (m *Multiplexer) ServeStreams() error {
	for {
		// Accept stream
		muxStream, err := m.AcceptStream()
		if err != nil {
			// Check if context was canceled
			select {
			case <-m.ctx.Done():
				return nil
			default:
				// Log the error and return it - this is a fatal accept error
				// that indicates the connection is no longer accepting streams
				log.Error().Err(err).Msg("Fatal error accepting stream")
				return fmt.Errorf("failed to accept stream: %w", err)
			}
		}

		// Handle stream in goroutine
		go func(ms *Stream) {
			defer func() {
				if err := m.CloseStream(ms.StreamID); err != nil {
					log.Error().Err(err).Uint64("stream_id", ms.StreamID).Msg("Failed to close stream")
				}
			}()

			if err := m.HandleStream(ms); err != nil {
				log.Error().
					Err(err).
					Uint64("stream_id", ms.StreamID).
					Str("protocol", ms.Header.Protocol.String()).
					Msg("Failed to handle stream")
			}
		}(muxStream)
	}
}

// GetStream returns a stream by ID
func (m *Multiplexer) GetStream(streamID uint64) (*Stream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stream, ok := m.streams[streamID]
	return stream, ok
}

// CloseStream closes and removes a stream
func (m *Multiplexer) CloseStream(streamID uint64) error {
	m.mu.Lock()
	muxStream, ok := m.streams[streamID]
	if ok {
		delete(m.streams, streamID)
	}
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("stream %d not found", streamID)
	}

	if err := muxStream.Stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	log.Debug().
		Uint64("stream_id", streamID).
		Msg("Closed multiplexed stream")

	return nil
}

// StreamCount returns the number of active streams
func (m *Multiplexer) StreamCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// Close closes the multiplexer and all streams
func (m *Multiplexer) Close() error {
	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Close all streams
	for streamID, muxStream := range m.streams {
		if err := muxStream.Stream.Close(); err != nil {
			log.Warn().Err(err).Uint64("stream_id", streamID).Msg("Failed to close stream during multiplexer shutdown")
		}
		delete(m.streams, streamID)
	}

	log.Info().Msg("Multiplexer closed")
	return nil
}
