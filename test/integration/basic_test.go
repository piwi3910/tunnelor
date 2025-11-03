// +build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"

	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/quic"
)

const (
	testClientID = "test-client"
	testPSK      = "test-secret-key-1234567890"
)

// generateTestCerts creates self-signed certificates for testing
func generateTestCerts(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	tmpDir := t.TempDir()
	certFile = filepath.Join(tmpDir, "server.crt")
	keyFile = filepath.Join(tmpDir, "server.key")

	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Tunnelor Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Write certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	// Write private key
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	return certFile, keyFile
}

// acceptAndHandleStreams accepts incoming streams and dispatches them to the multiplexer
func acceptAndHandleStreams(serverConn *quic.Connection, serverMux *mux.Multiplexer, count int) {
	go func() {
		for i := 0; i < count; i++ {
			stream, err := serverConn.AcceptStream()
			if err != nil {
				return
			}

			// Read stream header
			headerBuf := make([]byte, 4)
			if _, err := io.ReadFull(stream, headerBuf); err != nil {
				continue
			}

			header := &mux.StreamHeader{
				Version:  headerBuf[0],
				Protocol: mux.ProtocolID(headerBuf[1]),
				Flags:    headerBuf[2],
			}

			metaLen := int(headerBuf[3])
			if metaLen > 0 {
				metadata := make([]byte, metaLen)
				if _, err := io.ReadFull(stream, metadata); err != nil {
					continue
				}
				header.Metadata = metadata
			}

			if header.Protocol == mux.ProtocolControl {
				continue
			}

			muxStream := &mux.Stream{
				StreamID: uint64(stream.StreamID()),
				Stream:   stream,
				Header:   header,
			}
			go serverMux.HandleStream(muxStream)
		}
	}()
}

// testEchoMessages tests sending and receiving echo messages through a multiplexed stream
func testEchoMessages(t *testing.T, clientMux *mux.Multiplexer, protocol mux.ProtocolID, echoAddr string, messages []string) {
	t.Helper()

	for i, msg := range messages {
		// Create metadata based on protocol
		var metadata []byte
		var err error

		switch protocol {
		case mux.ProtocolTCP:
			metadata, err = mux.EncodeTCPMetadata(mux.TCPMetadata{
				SourceAddr: "client",
				TargetAddr: echoAddr,
			})
		case mux.ProtocolUDP:
			metadata, err = mux.EncodeUDPMetadata(mux.UDPMetadata{
				SourceAddr: "client",
				TargetAddr: echoAddr,
			})
		default:
			t.Fatalf("unsupported protocol: %s", protocol)
		}

		if err != nil {
			t.Fatalf("Test %d: failed to encode metadata: %v", i+1, err)
		}

		// Open stream through multiplexer
		muxStream, err := clientMux.OpenStream(protocol, metadata)
		if err != nil {
			t.Fatalf("Test %d: failed to open stream: %v", i+1, err)
		}

		// Send data
		if _, err := muxStream.Stream.Write([]byte(msg)); err != nil {
			t.Fatalf("Test %d: failed to write: %v", i+1, err)
		}

		// Read echo response
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(muxStream.Stream, buf); err != nil {
			t.Fatalf("Test %d: failed to read: %v", i+1, err)
		}

		// Verify echo
		if string(buf) != msg {
			t.Fatalf("Test %d: data mismatch: got %q, want %q", i+1, buf, msg)
		}

		// Close stream
		if err := muxStream.Stream.Close(); err != nil {
			t.Logf("Test %d: warning closing stream: %v", i+1, err)
		}

		t.Logf("Test %d: ✅ %s", i+1, msg)
	}
}

// TestBasicConnection tests basic QUIC connection establishment
func TestBasicConnection(t *testing.T) {
	// Setup quiet logging
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	// Generate test certificates
	certFile, keyFile := generateTestCerts(t)

	// Create server with port 0 (OS assigns random available port)
	server, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start("127.0.0.1:0"); err != nil {
			errChan <- err
		}
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Check if server failed to start
	select {
	case err := <-errChan:
		t.Fatalf("Server failed to start: %v", err)
	default:
	}

	defer server.Close()

	// Get actual server address
	serverAddr := server.Addr().String()
	t.Logf("Server listening on %s", serverAddr)

	// Create client
	client, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         serverAddr,
		InsecureSkipVerify: true, // OK for tests
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Connect to server
	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Verify connection
	if client.Connection() == nil {
		t.Fatal("Client connection is nil")
	}

	t.Log("✅ Basic QUIC connection successful")
}

// TestAuthentication tests PSK-based authentication
func TestAuthentication(t *testing.T) {
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	certFile, keyFile := generateTestCerts(t)

	// Create and start server with port 0
	server, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server and wait for it to be ready
	serverStarted := make(chan error, 1)
	go func() {
		serverStarted <- server.Start("127.0.0.1:0")
	}()

	// Wait for server to start or fail
	select {
	case err := <-serverStarted:
		if err != nil {
			t.Fatalf("Server failed to start: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		// Server started successfully (Start is blocking)
	}
	defer server.Close()

	// Get actual server address
	serverAddr := server.Addr().String()
	t.Logf("Server listening on %s", serverAddr)

	// Setup PSK map
	pskEncoded := base64.StdEncoding.EncodeToString([]byte(testPSK))
	pskMap := map[string]string{
		testClientID: pskEncoded,
	}

	// Accept connection in background
	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond) // Give server time to fully initialize
		conn, err := server.Accept()
		if err != nil {
			t.Logf("Accept error: %v", err)
			return
		}
		connectionAccepted <- conn
	}()

	// Create and connect client
	client, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         serverAddr,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Wait for server to accept connection
	var serverConn *quic.Connection
	select {
	case serverConn = <-connectionAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for server to accept connection")
	}

	// Setup control handlers
	clientHandler := control.NewClientHandler(testClientID, pskEncoded, client.Connection())
	serverHandler := control.NewServerHandler(pskMap, serverConn)

	// Server accepts control stream
	authResult := make(chan error, 1)
	go func() {
		stream, err := serverConn.AcceptStream()
		if err != nil {
			authResult <- fmt.Errorf("accept stream failed: %w", err)
			return
		}
		if err := serverHandler.HandleControlStream(stream); err != nil {
			authResult <- fmt.Errorf("handle control stream failed: %w", err)
			return
		}
		authResult <- nil
	}()

	// Client authenticates
	if err := clientHandler.Authenticate(); err != nil {
		t.Fatalf("Client authentication failed: %v", err)
	}

	// Wait for server authentication result
	select {
	case err := <-authResult:
		if err != nil {
			t.Fatalf("Server authentication failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for authentication")
	}

	// Verify client got session ID
	if clientHandler.GetSessionID() == "" {
		t.Fatal("Client did not receive session ID")
	}

	t.Logf("✅ Authentication successful (session: %s)", clientHandler.GetSessionID())
}

// TestStreamMultiplexing tests opening and using multiplexed streams
func TestStreamMultiplexing(t *testing.T) {
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	certFile, keyFile := generateTestCerts(t)

	// Create and start server with port 0
	server, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Start server and wait for it to be ready
	serverStarted := make(chan error, 1)
	go func() {
		serverStarted <- server.Start("127.0.0.1:0")
	}()

	select {
	case err := <-serverStarted:
		if err != nil {
			t.Fatalf("Server failed to start: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		// Server started successfully
	}
	defer server.Close()

	// Get actual server address
	serverAddr := server.Addr().String()
	t.Logf("Server listening on %s", serverAddr)

	// Setup PSK
	pskEncoded := base64.StdEncoding.EncodeToString([]byte(testPSK))
	pskMap := map[string]string{testClientID: pskEncoded}

	// Accept connection in background
	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond) // Give server time to initialize
		conn, err := server.Accept()
		if err != nil {
			return
		}
		connectionAccepted <- conn
	}()

	// Create and connect client
	client, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         serverAddr,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Wait for connection
	var serverConn *quic.Connection
	select {
	case serverConn = <-connectionAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for connection")
	}

	// Authenticate first
	clientHandler := control.NewClientHandler(testClientID, pskEncoded, client.Connection())
	serverHandler := control.NewServerHandler(pskMap, serverConn)

	go func() {
		stream, _ := serverConn.AcceptStream()
		serverHandler.HandleControlStream(stream)
	}()

	if err := clientHandler.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Create multiplexers
	clientMux := mux.NewMultiplexer(client.Connection())
	serverMux := mux.NewMultiplexer(serverConn)

	// Register echo handler on server
	serverMux.RegisterHandler(mux.ProtocolRaw, func(_ context.Context, stream *quicgo.Stream, _ *mux.StreamHeader) error {
		// Echo back whatever is sent
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
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
			stream, err := serverConn.AcceptStream()
			if err != nil {
				return
			}

			// Read and parse stream header
			headerBuf := make([]byte, 4) // Version, Protocol, Flags, MetaLen
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
			go serverMux.HandleStream(muxStream)
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
		muxStream, err := clientMux.OpenStream(mux.ProtocolRaw, nil)
		if err != nil {
			t.Fatalf("Stream %d: failed to open: %v", i+1, err)
		}

		// Send data
		if _, err := muxStream.Stream.Write([]byte(msg)); err != nil {
			t.Fatalf("Stream %d: failed to write: %v", i+1, err)
		}

		// Read echo
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(muxStream.Stream, buf); err != nil {
			t.Fatalf("Stream %d: failed to read: %v", i+1, err)
		}

		if string(buf) != msg {
			t.Fatalf("Stream %d: data mismatch: got %q, want %q", i+1, buf, msg)
		}

		t.Logf("Stream %d: ✅ %s", i+1, msg)
	}

	t.Log("✅ Stream multiplexing successful (3 streams tested)")
}

// TestTCPForwarding tests end-to-end TCP forwarding through QUIC tunnel
func TestTCPForwarding(t *testing.T) {
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	certFile, keyFile := generateTestCerts(t)

	// Create echo TCP server (this simulates the remote service we want to reach)
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create echo server: %v", err)
	}
	defer echoListener.Close()

	echoAddr := echoListener.Addr().String()
	t.Logf("Echo server listening on %s", echoAddr)

	// Start echo server
	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	// Create QUIC server
	server, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC server: %v", err)
	}

	serverStarted := make(chan error, 1)
	go func() {
		serverStarted <- server.Start("127.0.0.1:0")
	}()

	select {
	case err := <-serverStarted:
		if err != nil {
			t.Fatalf("Server failed to start: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
	}
	defer server.Close()

	serverAddr := server.Addr().String()
	t.Logf("QUIC server listening on %s", serverAddr)

	// Setup PSK
	pskEncoded := base64.StdEncoding.EncodeToString([]byte(testPSK))
	pskMap := map[string]string{testClientID: pskEncoded}

	// Accept QUIC connection in background
	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		conn, err := server.Accept()
		if err != nil {
			return
		}
		connectionAccepted <- conn
	}()

	// Create QUIC client
	client, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         serverAddr,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect QUIC client: %v", err)
	}

	// Wait for server to accept connection
	var serverConn *quic.Connection
	select {
	case serverConn = <-connectionAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for QUIC connection")
	}

	// Authenticate
	clientHandler := control.NewClientHandler(testClientID, pskEncoded, client.Connection())
	serverHandler := control.NewServerHandler(pskMap, serverConn)

	go func() {
		stream, _ := serverConn.AcceptStream()
		serverHandler.HandleControlStream(stream)
	}()

	if err := clientHandler.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Create multiplexers
	serverMux := mux.NewMultiplexer(serverConn)
	clientMux := mux.NewMultiplexer(client.Connection())

	// Register TCP handler on server that forwards to echo server
	serverMux.RegisterHandler(mux.ProtocolTCP, func(_ context.Context, stream *quicgo.Stream, header *mux.StreamHeader) error {
		// Parse TCP metadata
		metadata, err := mux.DecodeTCPMetadata(header.Metadata)
		if err != nil {
			return fmt.Errorf("failed to decode TCP metadata: %w", err)
		}

		t.Logf("Server forwarding to %s", metadata.TargetAddr)

		// Connect to echo server
		targetConn, err := net.Dial("tcp", echoAddr)
		if err != nil {
			return fmt.Errorf("failed to connect to target: %w", err)
		}
		defer targetConn.Close()

		// Bidirectional copy
		errChan := make(chan error, 2)

		go func() {
			_, err := io.Copy(targetConn, stream)
			errChan <- err
		}()

		go func() {
			_, err := io.Copy(stream, targetConn)
			errChan <- err
		}()

		// Wait for either direction to complete
		return <-errChan
	})

	// Server accepts and handles streams
	acceptAndHandleStreams(serverConn, serverMux, 3)

	// Client opens TCP stream and sends test data
	testData := []string{
		"Hello, TCP tunnel!",
		"Second message through tunnel",
		"Final test message",
	}

	testEchoMessages(t, clientMux, mux.ProtocolTCP, echoAddr, testData)

	t.Log("✅ TCP forwarding successful (3 messages echoed)")
}

// TestUDPForwarding tests end-to-end UDP forwarding through QUIC tunnel
func TestUDPForwarding(t *testing.T) {
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	certFile, keyFile := generateTestCerts(t)

	// Create echo UDP server (this simulates the remote service we want to reach)
	echoConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP echo server: %v", err)
	}
	defer echoConn.Close()

	echoAddr := echoConn.LocalAddr().String()
	t.Logf("UDP echo server listening on %s", echoAddr)

	// Start UDP echo server
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Echo back
			if _, err := echoConn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	// Create QUIC server
	server, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    certFile,
		TLSKey:     keyFile,
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC server: %v", err)
	}

	serverStarted := make(chan error, 1)
	go func() {
		serverStarted <- server.Start("127.0.0.1:0")
	}()

	select {
	case err := <-serverStarted:
		if err != nil {
			t.Fatalf("Server failed to start: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
	}
	defer server.Close()

	serverAddr := server.Addr().String()
	t.Logf("QUIC server listening on %s", serverAddr)

	// Setup PSK
	pskEncoded := base64.StdEncoding.EncodeToString([]byte(testPSK))
	pskMap := map[string]string{testClientID: pskEncoded}

	// Accept QUIC connection in background
	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		conn, err := server.Accept()
		if err != nil {
			return
		}
		connectionAccepted <- conn
	}()

	// Create QUIC client
	client, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         serverAddr,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("Failed to create QUIC client: %v", err)
	}
	defer client.Close()

	if err := client.Connect(); err != nil {
		t.Fatalf("Failed to connect QUIC client: %v", err)
	}

	// Wait for server to accept connection
	var serverConn *quic.Connection
	select {
	case serverConn = <-connectionAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for QUIC connection")
	}

	// Authenticate
	clientHandler := control.NewClientHandler(testClientID, pskEncoded, client.Connection())
	serverHandler := control.NewServerHandler(pskMap, serverConn)

	go func() {
		stream, _ := serverConn.AcceptStream()
		serverHandler.HandleControlStream(stream)
	}()

	if err := clientHandler.Authenticate(); err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Create multiplexers
	serverMux := mux.NewMultiplexer(serverConn)
	clientMux := mux.NewMultiplexer(client.Connection())

	// Register UDP handler on server that forwards to echo server
	serverMux.RegisterHandler(mux.ProtocolUDP, func(_ context.Context, stream *quicgo.Stream, header *mux.StreamHeader) error {
		// Parse UDP metadata
		metadata, err := mux.DecodeUDPMetadata(header.Metadata)
		if err != nil {
			return fmt.Errorf("failed to decode UDP metadata: %w", err)
		}

		t.Logf("Server forwarding UDP to %s", metadata.TargetAddr)

		// Create UDP connection to target
		targetAddr, err := net.ResolveUDPAddr("udp", echoAddr)
		if err != nil {
			return fmt.Errorf("failed to resolve target address: %w", err)
		}

		udpConn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			return fmt.Errorf("failed to dial UDP target: %w", err)
		}
		defer udpConn.Close()

		// Bidirectional forwarding between QUIC stream and UDP
		errChan := make(chan error, 2)

		// QUIC -> UDP
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := stream.Read(buf)
				if err != nil {
					errChan <- err
					return
				}
				if _, err := udpConn.Write(buf[:n]); err != nil {
					errChan <- err
					return
				}
			}
		}()

		// UDP -> QUIC
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := udpConn.Read(buf)
				if err != nil {
					errChan <- err
					return
				}
				if _, err := stream.Write(buf[:n]); err != nil {
					errChan <- err
					return
				}
			}
		}()

		return <-errChan
	})

	// Server accepts and handles streams
	acceptAndHandleStreams(serverConn, serverMux, 3)

	// Client opens UDP stream and sends test data
	testData := []string{
		"UDP packet 1",
		"UDP packet 2",
		"UDP packet 3",
	}

	testEchoMessages(t, clientMux, mux.ProtocolUDP, echoAddr, testData)

	t.Log("✅ UDP forwarding successful (3 datagrams echoed)")
}
