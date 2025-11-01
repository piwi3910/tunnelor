package mux

import (
	"context"
	"fmt"
	"io"

	quicgo "github.com/quic-go/quic-go"
	"github.com/piwi3910/tunnelor/internal/tcpbridge"
	"github.com/piwi3910/tunnelor/internal/udpbridge"
	"github.com/rs/zerolog/log"
)

// DefaultControlHandler is a default handler for control streams
func DefaultControlHandler(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())).
		Msg("Control stream handler called")

	// Control streams are typically handled by the control package
	// This is just a placeholder
	return nil
}

// DefaultTCPHandler is a default handler for TCP streams
func DefaultTCPHandler(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())).
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
		Uint64("stream_id", uint64(stream.StreamID())).
		Msg("TCP stream opened, forwarding to target")

	// Forward QUIC stream to TCP target
	return tcpbridge.QUICToTCP(stream, meta.TargetAddr)
}

// DefaultUDPHandler is a default handler for UDP streams
func DefaultUDPHandler(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())).
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
		Uint64("stream_id", uint64(stream.StreamID())).
		Msg("UDP stream opened, forwarding to target")

	// Forward QUIC stream to UDP target
	return udpbridge.QUICToUDP(stream, meta.TargetAddr, ctx)
}

// DefaultRawHandler is a default handler for raw streams
func DefaultRawHandler(ctx context.Context, stream *quicgo.Stream, header *StreamHeader) error {
	log.Debug().
		Uint64("stream_id", uint64(stream.StreamID())).
		Msg("Raw stream handler called")

	// TODO: Implement raw stream handling
	return echoStream(ctx, stream)
}

// echoStream echoes data back on the stream (for testing)
func echoStream(ctx context.Context, stream *quicgo.Stream) error {
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := stream.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("failed to read from stream: %w", err)
		}

		if _, err := stream.Write(buf[:n]); err != nil {
			return fmt.Errorf("failed to write to stream: %w", err)
		}
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
