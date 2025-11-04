//go:build integration
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
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/suite"

	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/quic"
)

// TunnelorIntegrationSuite is the test suite for Tunnelor integration tests
type TunnelorIntegrationSuite struct {
	suite.Suite
	ctx             context.Context
	tcpEchoListener net.Listener
	clientMux       *mux.Multiplexer
	serverMux       *mux.Multiplexer
	serverConn      *quic.Connection
	udpEchoConn     *net.UDPConn
	client          *quic.Client
	server          *quic.Server
	pskMap          map[string]string
	clientHandler   *control.ClientHandler
	serverHandler   *control.ServerHandler
	pskEncoded      string
	psk             string
	keyFile         string
	clientID        string
	certFile        string
}

// SetupSuite runs once before all tests
func (suite *TunnelorIntegrationSuite) SetupSuite() {
	// Setup quiet logging
	logger.Setup(logger.Config{
		Level:  logger.ErrorLevel,
		Pretty: false,
	})

	suite.ctx = context.Background()
	suite.clientID = "test-client"
	suite.psk = "test-secret-key-1234567890"
	suite.pskEncoded = base64.StdEncoding.EncodeToString([]byte(suite.psk))
	suite.pskMap = map[string]string{
		suite.clientID: suite.pskEncoded,
	}
}

// SetupTest runs before each test
func (suite *TunnelorIntegrationSuite) SetupTest() {
	// Generate test certificates
	suite.certFile, suite.keyFile = suite.generateTestCerts()

	// Create and start QUIC server
	suite.startQUICServer()

	// Create and connect QUIC client
	suite.connectQUICClient()

	// Wait for server to accept connection
	suite.acceptServerConnection()

	// Authenticate client
	suite.authenticateClient()

	// Create multiplexers
	suite.clientMux = mux.NewMultiplexer(suite.client.Connection())
	suite.serverMux = mux.NewMultiplexer(suite.serverConn)
}

// TearDownTest runs after each test
func (suite *TunnelorIntegrationSuite) TearDownTest() {
	// Close multiplexers
	if suite.clientMux != nil {
		_ = suite.clientMux.Close()
	}
	if suite.serverMux != nil {
		_ = suite.serverMux.Close()
	}

	// Close connections
	if suite.client != nil {
		_ = suite.client.Close()
	}
	if suite.server != nil {
		_ = suite.server.Close()
	}

	// Close echo servers
	if suite.tcpEchoListener != nil {
		_ = suite.tcpEchoListener.Close()
		suite.tcpEchoListener = nil
	}
	if suite.udpEchoConn != nil {
		_ = suite.udpEchoConn.Close()
		suite.udpEchoConn = nil
	}
}

// Helper methods

func (suite *TunnelorIntegrationSuite) generateTestCerts() (certFile, keyFile string) {
	tmpDir := suite.T().TempDir()
	certFile = filepath.Join(tmpDir, "server.crt")
	keyFile = filepath.Join(tmpDir, "server.key")

	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err, "Failed to generate private key")

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
	suite.Require().NoError(err, "Failed to create certificate")

	// Write certificate
	certOut, err := os.Create(certFile)
	suite.Require().NoError(err, "Failed to create cert file")
	defer certOut.Close()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	suite.Require().NoError(err, "Failed to encode certificate")

	// Write private key
	keyOut, err := os.Create(keyFile)
	suite.Require().NoError(err, "Failed to create key file")
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	suite.Require().NoError(err, "Failed to marshal private key")
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	suite.Require().NoError(err, "Failed to encode private key")

	return certFile, keyFile
}

func (suite *TunnelorIntegrationSuite) startQUICServer() {
	server, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: "127.0.0.1:0",
		TLSCert:    suite.certFile,
		TLSKey:     suite.keyFile,
	})
	suite.Require().NoError(err, "Failed to create QUIC server")
	suite.server = server

	// Start server in background
	serverStarted := make(chan error, 1)
	go func() {
		serverStarted <- server.Start("127.0.0.1:0")
	}()

	// Wait for server to start or fail
	select {
	case err := <-serverStarted:
		suite.Require().NoError(err, "Server failed to start")
	case <-time.After(500 * time.Millisecond):
		// Server started successfully (Start is blocking)
	}

	suite.T().Logf("QUIC server listening on %s", suite.server.Addr().String())
}

func (suite *TunnelorIntegrationSuite) connectQUICClient() {
	client, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         suite.server.Addr().String(),
		InsecureSkipVerify: true, // OK for tests
	})
	suite.Require().NoError(err, "Failed to create QUIC client")
	suite.client = client

	err = client.Connect()
	suite.Require().NoError(err, "Failed to connect QUIC client")
	suite.Require().NotNil(suite.client.Connection(), "Client connection should not be nil")
}

func (suite *TunnelorIntegrationSuite) acceptServerConnection() {
	connectionAccepted := make(chan *quic.Connection, 1)
	go func() {
		time.Sleep(100 * time.Millisecond) // Give server time to initialize
		conn, err := suite.server.Accept()
		if err != nil {
			suite.T().Logf("Accept error: %v", err)
			return
		}
		connectionAccepted <- conn
	}()

	// Wait for connection
	select {
	case conn := <-connectionAccepted:
		suite.serverConn = conn
	case <-time.After(2 * time.Second):
		suite.Fail("Timeout waiting for server to accept connection")
	}
}

func (suite *TunnelorIntegrationSuite) authenticateClient() {
	// Setup control handlers
	var err error
	suite.clientHandler, err = control.NewClientHandler(suite.clientID, suite.pskEncoded, suite.client.Connection())
	suite.Require().NoError(err, "Failed to create client handler")

	suite.serverHandler, err = control.NewServerHandler(suite.pskMap, suite.serverConn)
	suite.Require().NoError(err, "Failed to create server handler")

	// Server accepts control stream
	authResult := make(chan error, 1)
	go func() {
		stream, err := suite.serverConn.AcceptStream()
		if err != nil {
			authResult <- err
			return
		}
		authResult <- suite.serverHandler.HandleControlStream(stream)
	}()

	// Client authenticates
	err = suite.clientHandler.Authenticate()
	suite.Require().NoError(err, "Client authentication should succeed")

	// Wait for server authentication result
	select {
	case err := <-authResult:
		suite.Require().NoError(err, "Server authentication should succeed")
	case <-time.After(3 * time.Second):
		suite.Fail("Timeout waiting for authentication")
	}

	// Verify client got session ID
	suite.Assert().NotEmpty(suite.clientHandler.GetSessionID(), "Client should receive session ID")
	suite.T().Logf("Authentication successful (session: %s)", suite.clientHandler.GetSessionID())
}

func (suite *TunnelorIntegrationSuite) startTCPEchoServer() string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	suite.Require().NoError(err, "Failed to create TCP echo server")
	suite.tcpEchoListener = listener

	echoAddr := listener.Addr().String()
	suite.T().Logf("TCP echo server listening on %s", echoAddr)

	// Start echo server
	go func() {
		for {
			conn, err := listener.Accept()
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

	return echoAddr
}

func (suite *TunnelorIntegrationSuite) startUDPEchoServer() string {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	suite.Require().NoError(err, "Failed to create UDP echo server")
	suite.udpEchoConn = conn

	echoAddr := conn.LocalAddr().String()
	suite.T().Logf("UDP echo server listening on %s", echoAddr)

	// Start echo server
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()

	return echoAddr
}

// Helper methods for UDP bridge testing
func (suite *TunnelorIntegrationSuite) sendUDPDatagramOverQUIC(stream *quicgo.Stream, data []byte) error {
	// Write length prefix (2 bytes, big-endian)
	length := uint16(len(data))
	lengthBytes := []byte{byte(length >> 8), byte(length & 0xFF)}
	if _, err := stream.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}
	// Write data
	if _, err := stream.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	return nil
}

func (suite *TunnelorIntegrationSuite) receiveUDPDatagramFromQUIC(stream *quicgo.Stream) ([]byte, error) {
	// Read length prefix
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(stream, lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}
	length := uint16(lengthBytes[0])<<8 | uint16(lengthBytes[1])

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(stream, data); err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}
	return data, nil
}

func (suite *TunnelorIntegrationSuite) handleUDPToQUIC(stream *quicgo.Stream, targetAddr string) error {
	// This mirrors the QUICToUDP function from udpbridge
	// Create UDP connection to target
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer udpConn.Close()

	// Read datagram from QUIC, send to UDP, read response, send back to QUIC
	for {
		// Read from QUIC
		data, err := suite.receiveUDPDatagramFromQUIC(stream)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		// Forward to UDP
		if _, err := udpConn.Write(data); err != nil {
			return fmt.Errorf("failed to write to UDP: %w", err)
		}

		// Read UDP response
		buf := make([]byte, 65535)
		n, err := udpConn.Read(buf)
		if err != nil {
			return fmt.Errorf("failed to read from UDP: %w", err)
		}

		// Send response back over QUIC
		if err := suite.sendUDPDatagramOverQUIC(stream, buf[:n]); err != nil {
			return err
		}
	}
}

// TestRunner runs the test suite
func TestTunnelorIntegrationSuite(t *testing.T) {
	suite.Run(t, new(TunnelorIntegrationSuite))
}
