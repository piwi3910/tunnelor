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
	serverMux.RegisterHandler(mux.ProtocolRaw, func(ctx context.Context, stream *quicgo.Stream, header *mux.StreamHeader) error {
		// Echo back whatever is sent
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		_, err = stream.Write(buf[:n])
		return err
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
