// +build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"io"

	quicgo "github.com/quic-go/quic-go"

	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/tcpbridge"
)

// TestBasicConnection tests basic QUIC connection establishment
func (suite *TunnelorIntegrationSuite) TestBasicConnection() {
	// Connection and authentication already done in SetupTest
	suite.Assert().NotNil(suite.client.Connection(), "Client connection should exist")
	suite.Assert().NotNil(suite.serverConn, "Server connection should exist")
	suite.T().Log("✅ Basic QUIC connection successful")
}

// TestAuthentication tests PSK-based authentication
func (suite *TunnelorIntegrationSuite) TestAuthentication() {
	// Authentication already done in SetupTest
	suite.Assert().NotEmpty(suite.clientHandler.GetSessionID(), "Client should have session ID")
	suite.T().Log("✅ Authentication successful")
}

// TestStreamMultiplexing tests opening and using multiplexed streams
func (suite *TunnelorIntegrationSuite) TestStreamMultiplexing() {
	// Register echo handler on server
	suite.serverMux.RegisterHandler(mux.ProtocolRaw, func(_ context.Context, stream *quicgo.Stream, _ *mux.StreamHeader) error {
		// Echo back whatever is sent
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("stream read error: %w", err)
		}
		if _, err = stream.Write(buf[:n]); err != nil {
			return fmt.Errorf("stream write error: %w", err)
		}
		return nil
	})

	// Server accepts streams
	go func() {
		for i := 0; i < 3; i++ {
			stream, err := suite.serverConn.AcceptStream()
			if err != nil {
				return
			}

			// Read and parse stream header
			headerBuf := make([]byte, 4)
			if _, err := io.ReadFull(stream, headerBuf); err != nil {
				continue
			}

			header := &mux.StreamHeader{
				Version:  headerBuf[0],
				Protocol: mux.ProtocolID(headerBuf[1]),
				Flags:    headerBuf[2],
			}

			if header.Protocol == mux.ProtocolControl {
				continue
			}

			muxStream := &mux.Stream{
				StreamID: uint64(stream.StreamID()),
				Stream:   stream,
				Header:   header,
			}
			go func(ms *mux.Stream) {
				_ = suite.serverMux.HandleStream(ms)
			}(muxStream)
		}
	}()

	// Client opens 3 streams and sends data
	testMessages := []string{
		"Hello from stream 1",
		"Message from stream 2",
		"Stream 3 data",
	}

	for i, msg := range testMessages {
		// Open stream
		muxStream, err := suite.clientMux.OpenStream(mux.ProtocolRaw, nil)
		suite.Require().NoError(err, "Stream %d: should open successfully", i+1)

		// Send data
		_, err = muxStream.Stream.Write([]byte(msg))
		suite.Require().NoError(err, "Stream %d: should write successfully", i+1)

		// Read echo
		buf := make([]byte, len(msg))
		_, err = io.ReadFull(muxStream.Stream, buf)
		suite.Require().NoError(err, "Stream %d: should read successfully", i+1)

		suite.Assert().Equal(msg, string(buf), "Stream %d: data should match", i+1)
		suite.T().Logf("Stream %d: ✅ %s", i+1, msg)
	}

	suite.T().Log("✅ Stream multiplexing successful (3 streams tested)")
}

// TestTCPForwarding tests end-to-end TCP forwarding through QUIC tunnel
func (suite *TunnelorIntegrationSuite) TestTCPForwarding() {
	// Start TCP echo server
	echoAddr := suite.startTCPEchoServer()

	// Register TCP handler on server that forwards to echo server
	mux.RegisterDefaultHandlers(suite.serverMux)

	// Server accepts and handles streams
	go func() {
		for i := 0; i < 3; i++ {
			muxStream, err := suite.serverMux.AcceptStream()
			if err != nil {
				return
			}
			go func(ms *mux.Stream) {
				_ = suite.serverMux.HandleStream(ms)
			}(muxStream)
		}
	}()

	// Test messages
	testMessages := []string{
		"Hello, TCP tunnel!",
		"Second message through tunnel",
		"Final test message",
	}

	for i, msg := range testMessages {
		// Encode metadata
		metadata, err := mux.EncodeTCPMetadata(mux.TCPMetadata{
			SourceAddr: "client",
			TargetAddr: echoAddr,
		})
		suite.Require().NoError(err, "Test %d: should encode metadata", i+1)

		// Open stream
		muxStream, err := suite.clientMux.OpenStream(mux.ProtocolTCP, metadata)
		suite.Require().NoError(err, "Test %d: should open stream", i+1)

		// Send data
		_, err = muxStream.Stream.Write([]byte(msg))
		suite.Require().NoError(err, "Test %d: should write data", i+1)

		// Read echo response
		buf := make([]byte, len(msg))
		_, err = io.ReadFull(muxStream.Stream, buf)
		suite.Require().NoError(err, "Test %d: should read response", i+1)

		// Verify echo
		suite.Assert().Equal(msg, string(buf), "Test %d: data should match", i+1)

		// Close stream
		_ = muxStream.Stream.Close()

		suite.T().Logf("Test %d: ✅ %s", i+1, msg)
	}

	suite.T().Log("✅ TCP forwarding successful (3 messages echoed)")
}

// TestTCPBridge tests the TCP bridge directly
func (suite *TunnelorIntegrationSuite) TestTCPBridge() {
	// Start TCP echo server
	echoAddr := suite.startTCPEchoServer()

	// Test data
	testData := "Hello from TCP bridge test"

	// Open QUIC stream
	quicStream, err := suite.client.Connection().OpenStream()
	suite.Require().NoError(err, "Should open QUIC stream")

	// Server side: forward QUIC stream to TCP target
	go func() {
		stream, _ := suite.serverConn.AcceptStream()
		_ = tcpbridge.QUICToTCP(stream, echoAddr)
	}()

	// Client side: write data to stream
	_, err = quicStream.Write([]byte(testData))
	suite.Require().NoError(err, "Should write to stream")

	// Read response
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(quicStream, buf)
	suite.Require().NoError(err, "Should read from stream")

	suite.Assert().Equal(testData, string(buf), "Data should match")
	suite.T().Log("✅ TCP bridge test successful")
}

// TestUDPBridge tests UDP bridge functionality with real QUIC streams
func (suite *TunnelorIntegrationSuite) TestUDPBridge() {
	// Start UDP echo server
	udpEchoAddr := suite.startUDPEchoServer()

	// Test data
	testMessages := []string{
		"UDP message 1",
		"UDP message 2",
		"UDP message 3",
	}

	for i, msg := range testMessages {
		// Open QUIC stream for UDP forwarding
		quicStream, err := suite.client.Connection().OpenStream()
		suite.Require().NoError(err, "Test %d: Should open QUIC stream", i+1)

		// Server side: forward QUIC stream to UDP target
		go func() {
			stream, _ := suite.serverConn.AcceptStream()
			_ = suite.handleUDPToQUIC(stream, udpEchoAddr)
		}()

		// Client side: Send UDP datagram through QUIC
		err = suite.sendUDPDatagramOverQUIC(quicStream, []byte(msg))
		suite.Require().NoError(err, "Test %d: Should send UDP datagram", i+1)

		// Read UDP response through QUIC
		response, err := suite.receiveUDPDatagramFromQUIC(quicStream)
		suite.Require().NoError(err, "Test %d: Should receive UDP datagram", i+1)

		suite.Assert().Equal(msg, string(response), "Test %d: UDP data should match", i+1)
		suite.T().Logf("Test %d: ✅ %s", i+1, msg)

		_ = quicStream.Close()
	}

	suite.T().Log("✅ UDP bridge test successful (3 datagrams tested)")
}
