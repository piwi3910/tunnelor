// Package mux provides stream multiplexing and protocol handling for QUIC connections.
// It manages stream headers, protocol routing, and default handlers for TCP/UDP/control protocols.
package mux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"

	"github.com/piwi3910/tunnelor/internal/tcpbridge"
	"github.com/piwi3910/tunnelor/internal/udpbridge"
)

// CopyBuffer is the size of the buffer used for raw stream copying
const CopyBuffer = 32 * 1024 // 32KB

// rawBufferPool is a sync.Pool for raw stream copy buffers to reduce GC pressure
var rawBufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, CopyBuffer)
		return &buf
	},
}

// DefaultControlHandler is a default handler for control streams
func DefaultControlHandler(_ context.Context, stream *quicgo.Stream, _ *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Control stream handler called")

	// Control streams are typically handled by the control package
	// This is just a placeholder
	return nil
}

// DefaultTCPHandler is a default handler for TCP streams
func DefaultTCPHandler(_ context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("TCP stream handler called")

	// Parse TCP metadata
	if len(header.Metadata) == 0 {
		return fmt.Errorf("TCP stream missing metadata")
	}

	meta, err := DecodeTCPMetadata(header.Metadata)
	if err != nil {
		return fmt.Errorf("failed to decode TCP metadata: %w", err)
	}

	log.Info().
		Str("source", meta.SourceAddr).
		Str("target", meta.TargetAddr).
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("TCP stream opened, forwarding to target")

	// Forward QUIC stream to TCP target
	if err := tcpbridge.QUICToTCP(stream, meta.TargetAddr); err != nil {
		return fmt.Errorf("TCP bridge failed: %w", err)
	}
	return nil
}

// DefaultUDPHandler is a default handler for UDP streams
func DefaultUDPHandler(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("UDP stream handler called")

	// Parse UDP metadata
	if len(header.Metadata) == 0 {
		return fmt.Errorf("UDP stream missing metadata")
	}

	meta, err := DecodeUDPMetadata(header.Metadata)
	if err != nil {
		return fmt.Errorf("failed to decode UDP metadata: %w", err)
	}

	log.Info().
		Str("source", meta.SourceAddr).
		Str("target", meta.TargetAddr).
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("UDP stream opened, forwarding to target")

	// Forward QUIC stream to UDP target
	if err := udpbridge.QUICToUDP(ctx, stream, meta.TargetAddr); err != nil {
		return fmt.Errorf("UDP bridge failed: %w", err)
	}
	return nil
}

// DefaultRawHandler is a default handler for raw streams
// It provides a length-prefixed message framing protocol for arbitrary byte streams
// Message format: [4-byte length (big-endian)][message data]
func DefaultRawHandler(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Raw stream handler called")

	// Check if metadata specifies a target for forwarding
	// If no target is specified, default to echo mode for testing
	if len(header.Metadata) == 0 {
		log.Debug().
			Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
			Msg("No target specified, using echo mode")
		return echoStream(ctx, stream)
	}

	// Parse target from metadata (format: "host:port")
	target := string(header.Metadata)
	log.Info().
		Str("target", target).
		Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
		Msg("Forwarding raw stream to target")

	// Forward to target using raw stream protocol
	return forwardRawStream(ctx, stream, target)
}

// forwardRawStream forwards a raw stream to a TCP target with message framing
func forwardRawStream(ctx context.Context, stream *quicgo.Stream, targetAddr string) error {
	// Connect to target
	conn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to target %s: %w", targetAddr, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close target connection")
		}
	}()

	log.Debug().
		Str("target", targetAddr).
		Msg("Connected to raw stream target")

	// Bidirectional copy with context using pooled buffers
	errChan := make(chan error, 2)

	// Stream -> Target
	go func() {
		bufPtr, ok := rawBufferPool.Get().(*[]byte)
		if !ok {
			errChan <- fmt.Errorf("buffer pool returned unexpected type")
			return
		}
		defer rawBufferPool.Put(bufPtr)

		_, err := io.CopyBuffer(conn, stream, *bufPtr)
		if err != nil && !errors.Is(err, io.EOF) {
			errChan <- fmt.Errorf("stream->target copy failed: %w", err)
		} else {
			errChan <- nil
		}
	}()

	// Target -> Stream
	go func() {
		bufPtr, ok := rawBufferPool.Get().(*[]byte)
		if !ok {
			errChan <- fmt.Errorf("buffer pool returned unexpected type")
			return
		}
		defer rawBufferPool.Put(bufPtr)

		_, err := io.CopyBuffer(stream, conn, *bufPtr)
		if err != nil && !errors.Is(err, io.EOF) {
			errChan <- fmt.Errorf("target->stream copy failed: %w", err)
		} else {
			errChan <- nil
		}
	}()

	// Wait for either copy to complete or context cancellation
	select {
	case <-ctx.Done():
		return fmt.Errorf("context canceled: %w", ctx.Err())
	case err := <-errChan:
		// One direction completed, close and wait for the other
		if closeErr := conn.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Msg("Error closing connection during shutdown")
		}
		if closeErr := stream.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Msg("Error closing stream during shutdown")
		}
		// Wait for second goroutine
		<-errChan
		return err
	}
}

// echoStream echoes data back on the stream (for testing/debugging)
// This is useful for protocol testing and verification
func echoStream(ctx context.Context, stream *quicgo.Stream) error {
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled: %w", ctx.Err())
		default:
		}

		n, err := stream.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read from stream: %w", err)
		}

		if _, err := stream.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write to stream: %w", err)
		}

		log.Debug().
			Int("bytes", n).
			Uint64("stream_id", uint64(stream.StreamID())). // #nosec G115 -- QUIC stream IDs are always non-negative
			Msg("Echoed data on raw stream")
	}
}

// RegisterDefaultHandlers registers default handlers for all protocol types
func RegisterDefaultHandlers(mux *Multiplexer) {
	mux.RegisterHandler(ProtocolControl, DefaultControlHandler)
	mux.RegisterHandler(ProtocolTCP, DefaultTCPHandler)
	mux.RegisterHandler(ProtocolUDP, DefaultUDPHandler)
	mux.RegisterHandler(ProtocolRaw, DefaultRawHandler)

	log.Info().Msg("Registered default stream handlers")
}
