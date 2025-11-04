//go:build integration
// +build integration

package integration

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/piwi3910/tunnelor/internal/config"
	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/quic"
	"github.com/piwi3910/tunnelor/internal/server"
)

// TestReverseTunnel tests end-to-end reverse tunnel functionality
// Flow: External User → Server (public port) → QUIC → Client → Local Service
func TestReverseTunnel(t *testing.T) {
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	t.Log("=== Starting Reverse Tunnel Integration Test ===")

	// Step 1: Create a local service on the "client" side
	// This simulates a service running on localhost that we want to expose
	localService := createLocalHTTPService(t)
	defer func() { _ = localService.Close() }()

	localAddr := localService.Addr().String()
	t.Logf("✓ Local service listening on %s", localAddr)

	// Step 2: Generate TLS certificates for QUIC
	certFile, keyFile := generateTestCerts(t)

	// Step 3: Create and start QUIC server
	quicServer, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	require.NoError(t, err, "Failed to create QUIC server")

	serverStarted := make(chan error, 1)
	go func() {
		serverStarted <- quicServer.Start("127.0.0.1:0")
	}()

	select {
	case err := <-serverStarted:
		require.NoError(t, err, "Server failed to start")
	case <-time.After(500 * time.Millisecond):
		// Server started successfully
	}
	defer func() { _ = quicServer.Close() }()

	quicAddr := quicServer.Addr().String()
	t.Logf("✓ QUIC server listening on %s", quicAddr)

	// Step 4: Setup server-side forward registry
	forwardRegistry := server.NewForwardRegistry()

	// Choose a random available port for the public listener
	publicPort, err := getFreePort()
	require.NoError(t, err, "Failed to get free port")

	publicAddr := fmt.Sprintf("127.0.0.1:%d", publicPort)

	// Configure reverse tunnel: public port → local service
	forwardConfig := []config.ServerForwardConfig{
		{
			Local:    publicAddr,     // Server will listen here (public)
			Remote:   localAddr,      // Client will connect here (local)
			Proto:    "tcp",
			ClientID: testClientID,
		},
	}

	err = forwardRegistry.LoadFromConfig(forwardConfig)
	require.NoError(t, err, "Failed to load forward config")
	t.Logf("✓ Forward registry configured: %s → %s", publicAddr, localAddr)

	// Step 5: Setup PSK authentication
	pskEncoded := base64.StdEncoding.EncodeToString([]byte(testPSK))
	pskMap := map[string]string{testClientID: pskEncoded}

	// Step 6: Accept QUIC connection from client (background)
	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		conn, err := quicServer.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			return
		}
		connectionAccepted <- conn
	}()

	// Step 7: Create QUIC client
	quicClient, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         quicAddr,
		InsecureSkipVerify: true, // OK for tests
	})
	require.NoError(t, err, "Failed to create QUIC client")
	defer func() { _ = quicClient.Close() }()

	err = quicClient.Connect()
	require.NoError(t, err, "Failed to connect QUIC client")
	t.Log("✓ Client connected to server")

	// Step 8: Wait for server to accept connection
	var serverConn *quic.Connection
	select {
	case serverConn = <-connectionAccepted:
		t.Log("✓ Server accepted client connection")
	case <-time.After(2 * time.Second):
		require.Fail(t, "Timeout waiting for server to accept connection")
	}

	// Step 9: Authenticate client
	clientHandler, err := control.NewClientHandler(testClientID, pskEncoded, quicClient.Connection())
	require.NoError(t, err, "Failed to create client handler")

	serverHandler, err := control.NewServerHandler(pskMap, serverConn)
	require.NoError(t, err, "Failed to create server handler")

	// Server accepts and handles control stream
	authResult := make(chan error, 1)
	go func() {
		stream, err := serverConn.AcceptStream()
		if err != nil {
			authResult <- fmt.Errorf("accept stream failed: %w", err)
			return
		}
		authResult <- serverHandler.HandleControlStream(stream)
	}()

	// Client authenticates
	err = clientHandler.Authenticate()
	require.NoError(t, err, "Client authentication failed")

	// Wait for server authentication
	select {
	case err := <-authResult:
		require.NoError(t, err, "Server authentication failed")
		t.Log("✓ Authentication successful")
	case <-time.After(3 * time.Second):
		require.Fail(t, "Timeout waiting for authentication")
	}

	// Step 10: Create multiplexers
	clientMux := mux.NewMultiplexer(quicClient.Connection())
	serverMux := mux.NewMultiplexer(serverConn)

	// Step 11: Register default handlers on client
	// This allows the client to handle incoming streams from the server
	mux.RegisterDefaultHandlers(clientMux)

	// Step 12: Start client serving streams (critical for reverse tunnels!)
	go func() {
		if err := clientMux.ServeStreams(); err != nil {
			t.Logf("Client ServeStreams error: %v", err)
		}
	}()
	t.Log("✓ Client stream server started")

	// Step 13: Start public listener on server
	forwards := forwardRegistry.GetForwardsByClient(testClientID)
	require.Len(t, forwards, 1, "Expected 1 forward for test client")

	publicListener, err := server.NewPublicListener(forwards[0], serverMux)
	require.NoError(t, err, "Failed to create public listener")
	defer func() { _ = publicListener.Close() }()

	// Start listener in background
	go func() {
		if err := publicListener.Start(); err != nil {
			t.Logf("Public listener error: %v", err)
		}
	}()

	// Give listener time to start
	time.Sleep(200 * time.Millisecond)
	t.Logf("✓ Public listener started on %s", publicAddr)

	// Step 14: Simulate external user connecting to public port
	t.Log("=== Testing External Connection ===")

	testMessages := []string{
		"GET / HTTP/1.0\r\n\r\n",
		"GET /test HTTP/1.0\r\n\r\n",
		"GET /another HTTP/1.0\r\n\r\n",
	}

	for i, msg := range testMessages {
		t.Logf("Test %d: Connecting to public port...", i+1)

		// Connect to public port (as external user would)
		externalConn, err := net.DialTimeout("tcp", publicAddr, 2*time.Second)
		require.NoError(t, err, "Failed to connect to public port")

		// Send HTTP request
		_, err = externalConn.Write([]byte(msg))
		require.NoError(t, err, "Failed to write to public port")

		// Read response
		buf := make([]byte, 1024)
		err = externalConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		require.NoError(t, err, "Failed to set read deadline")

		n, err := externalConn.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			require.NoError(t, err, "Failed to read response")
		}

		response := string(buf[:n])
		t.Logf("Test %d: Received response (%d bytes)", i+1, n)

		// Verify we got a response from local service
		require.Contains(t, response, "HTTP/1.0 200 OK", "Expected HTTP 200 OK response")
		require.Contains(t, response, "Hello from local service!", "Expected service response")

		err = externalConn.Close()
		require.NoError(t, err, "Failed to close connection")

		t.Logf("Test %d: ✅ Success", i+1)
	}

	t.Log("=== All Tests Passed ===")
	t.Log("✅ Reverse tunnel working correctly!")
	t.Log("✅ External User → Server → Client → Local Service flow verified")
}

// TestMultipleReverseTunnels tests multiple reverse tunnels for the same client
func TestMultipleReverseTunnels(t *testing.T) {
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	t.Log("=== Testing Multiple Reverse Tunnels ===")

	// Create two local services
	localService1 := createLocalHTTPService(t)
	defer func() { _ = localService1.Close() }()

	localService2 := createLocalHTTPService(t)
	defer func() { _ = localService2.Close() }()

	local1Addr := localService1.Addr().String()
	local2Addr := localService2.Addr().String()

	t.Logf("✓ Local service 1 on %s", local1Addr)
	t.Logf("✓ Local service 2 on %s", local2Addr)

	// Setup QUIC server
	certFile, keyFile := generateTestCerts(t)
	quicServer, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	require.NoError(t, err)

	go func() { _ = quicServer.Start("127.0.0.1:0") }()
	time.Sleep(200 * time.Millisecond)
	defer func() { _ = quicServer.Close() }()

	// Get two free public ports
	publicPort1, _ := getFreePort()
	publicPort2, _ := getFreePort()
	publicAddr1 := fmt.Sprintf("127.0.0.1:%d", publicPort1)
	publicAddr2 := fmt.Sprintf("127.0.0.1:%d", publicPort2)

	// Configure two reverse tunnels
	forwardRegistry := server.NewForwardRegistry()
	forwardConfigs := []config.ServerForwardConfig{
		{
			Local:    publicAddr1,
			Remote:   local1Addr,
			Proto:    "tcp",
			ClientID: testClientID,
		},
		{
			Local:    publicAddr2,
			Remote:   local2Addr,
			Proto:    "tcp",
			ClientID: testClientID,
		},
	}

	err = forwardRegistry.LoadFromConfig(forwardConfigs)
	require.NoError(t, err)
	t.Logf("✓ Two forwards configured")

	// Setup and connect client
	pskEncoded := base64.StdEncoding.EncodeToString([]byte(testPSK))
	pskMap := map[string]string{testClientID: pskEncoded}

	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		conn, _ := quicServer.Accept()
		connectionAccepted <- conn
	}()

	quicClient, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         quicServer.Addr().String(),
		InsecureSkipVerify: true,
	})
	require.NoError(t, err)
	defer func() { _ = quicClient.Close() }()

	err = quicClient.Connect()
	require.NoError(t, err)

	serverConn := <-connectionAccepted

	// Authenticate
	clientHandler, _ := control.NewClientHandler(testClientID, pskEncoded, quicClient.Connection())
	serverHandler, _ := control.NewServerHandler(pskMap, serverConn)

	go func() {
		stream, _ := serverConn.AcceptStream()
		_ = serverHandler.HandleControlStream(stream)
	}()

	_ = clientHandler.Authenticate()
	time.Sleep(100 * time.Millisecond)

	// Create multiplexers
	clientMux := mux.NewMultiplexer(quicClient.Connection())
	serverMux := mux.NewMultiplexer(serverConn)

	mux.RegisterDefaultHandlers(clientMux)
	go func() { _ = clientMux.ServeStreams() }()

	// Start both public listeners
	forwards := forwardRegistry.GetForwardsByClient(testClientID)
	require.Len(t, forwards, 2, "Expected 2 forwards")

	listener1, _ := server.NewPublicListener(forwards[0], serverMux)
	listener2, _ := server.NewPublicListener(forwards[1], serverMux)

	defer func() {
		_ = listener1.Close()
		_ = listener2.Close()
	}()

	go func() { _ = listener1.Start() }()
	go func() { _ = listener2.Start() }()

	time.Sleep(200 * time.Millisecond)
	t.Log("✓ Both public listeners started")

	// Test both tunnels
	testTunnel := func(addr, name string) {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		require.NoError(t, err, "Failed to connect to "+name)
		defer func() { _ = conn.Close() }()

		_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)

		response := string(buf[:n])
		require.Contains(t, response, "HTTP/1.0 200 OK")
		t.Logf("✓ %s working", name)
	}

	testTunnel(publicAddr1, "Tunnel 1")
	testTunnel(publicAddr2, "Tunnel 2")

	t.Log("✅ Multiple reverse tunnels working correctly!")
}

// Helper function to create a simple HTTP service for testing
func createLocalHTTPService(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Failed to create local service")

	// Start simple HTTP server
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				// Read request (we don't parse it, just respond)
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)

				// Send HTTP response
				response := "HTTP/1.0 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					"Content-Length: 27\r\n" +
					"\r\n" +
					"Hello from local service!\n"

				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	return listener
}

// Helper function to get a free port
func getFreePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("failed to listen on free port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port, nil
}
