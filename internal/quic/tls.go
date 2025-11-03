package quic

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadServerTLSConfig loads TLS configuration for the QUIC server
func LoadServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	// Load certificate and private key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Create TLS config for server
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"tunnelor"},
		MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3
	}

	return tlsConfig, nil
}

// LoadClientTLSConfig loads TLS configuration for the QUIC client
func LoadClientTLSConfig(serverName string, insecureSkipVerify bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{"tunnelor"},
		MinVersion:         tls.VersionTLS13,   // QUIC requires TLS 1.3
		InsecureSkipVerify: insecureSkipVerify, // #nosec G402 -- Controlled by user configuration for dev/test environments
	}

	return tlsConfig, nil
}

// LoadClientTLSConfigWithCA loads TLS configuration with custom CA certificate
func LoadClientTLSConfigWithCA(serverName, caFile string) (*tls.Config, error) {
	// Load CA certificate
	caCert, err := os.ReadFile(caFile) // #nosec G304 -- CA file path is from user configuration
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Create certificate pool
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		ServerName: serverName,
		NextProtos: []string{"tunnelor"},
		MinVersion: tls.VersionTLS13,
		RootCAs:    caCertPool,
	}

	return tlsConfig, nil
}
