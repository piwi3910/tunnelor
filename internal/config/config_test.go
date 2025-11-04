package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateServerConfig(t *testing.T) {
	// Create temporary test files for TLS cert/key
	tmpDir := t.TempDir()
	testCert := filepath.Join(tmpDir, "test.crt")
	testKey := filepath.Join(tmpDir, "test.key")

	// Create dummy cert/key files
	if err := os.WriteFile(testCert, []byte("test cert"), 0o600); err != nil {
		t.Fatalf("Failed to create test cert: %v", err)
	}
	if err := os.WriteFile(testKey, []byte("test key"), 0o600); err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	tests := []struct {
		name    string
		errMsg  string
		config  ServerConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ServerConfig{
				Listen:      "0.0.0.0:4433",
				TLSCert:     testCert,
				TLSKey:      testKey,
				MetricsPort: 9090,
				Auth: ServerAuthConfig{
					PSKMap: map[string]string{
						"client1": "secret1",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing listen",
			config: ServerConfig{
				Listen:  "",
				TLSCert: testCert,
				TLSKey:  testKey,
				Auth: ServerAuthConfig{
					PSKMap: map[string]string{"client1": "secret1"},
				},
			},
			wantErr: true,
			errMsg:  "server.listen is required",
		},
		{
			name: "missing tls_cert",
			config: ServerConfig{
				Listen:  "0.0.0.0:4433",
				TLSCert: "",
				TLSKey:  testKey,
				Auth: ServerAuthConfig{
					PSKMap: map[string]string{"client1": "secret1"},
				},
			},
			wantErr: true,
			errMsg:  "server.tls_cert is required",
		},
		{
			name: "missing tls_key",
			config: ServerConfig{
				Listen:  "0.0.0.0:4433",
				TLSCert: testCert,
				TLSKey:  "",
				Auth: ServerAuthConfig{
					PSKMap: map[string]string{"client1": "secret1"},
				},
			},
			wantErr: true,
			errMsg:  "server.tls_key is required",
		},
		{
			name: "empty psk_map",
			config: ServerConfig{
				Listen:  "0.0.0.0:4433",
				TLSCert: testCert,
				TLSKey:  testKey,
				Auth: ServerAuthConfig{
					PSKMap: map[string]string{},
				},
			},
			wantErr: true,
			errMsg:  "auth.psk_map must contain at least one entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateServerConfig(&tt.config)
			if tt.wantErr {
				require.Error(t, err, "validateServerConfig() should return error")
				assert.Contains(t, err.Error(), tt.errMsg, "error message should match")
			} else {
				assert.NoError(t, err, "validateServerConfig() should not return error")
			}
		})
	}
}

func TestValidateClientConfig(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		config  ClientConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "test-client",
				PSK:      "secret123",
				Forwards: []ForwardConfig{
					{
						Local:  "127.0.0.1:8080",
						Remote: "10.0.0.5:9000",
						Proto:  "tcp",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing server",
			config: ClientConfig{
				Server:   "",
				ClientID: "test-client",
				PSK:      "secret123",
			},
			wantErr: true,
			errMsg:  "client.server is required",
		},
		{
			name: "missing client_id",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "",
				PSK:      "secret123",
			},
			wantErr: true,
			errMsg:  "client.client_id is required",
		},
		{
			name: "missing psk",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "test-client",
				PSK:      "",
			},
			wantErr: true,
			errMsg:  "client.psk is required",
		},
		{
			name: "forward missing local",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "test-client",
				PSK:      "secret123",
				Forwards: []ForwardConfig{
					{
						Local:  "",
						Remote: "10.0.0.5:9000",
						Proto:  "tcp",
					},
				},
			},
			wantErr: true,
			errMsg:  "forward[0].local is required",
		},
		{
			name: "forward missing remote",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "test-client",
				PSK:      "secret123",
				Forwards: []ForwardConfig{
					{
						Local:  "127.0.0.1:8080",
						Remote: "",
						Proto:  "tcp",
					},
				},
			},
			wantErr: true,
			errMsg:  "forward[0].remote is required",
		},
		{
			name: "forward invalid proto",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "test-client",
				PSK:      "secret123",
				Forwards: []ForwardConfig{
					{
						Local:  "127.0.0.1:8080",
						Remote: "10.0.0.5:9000",
						Proto:  "http",
					},
				},
			},
			wantErr: true,
			errMsg:  "forward[0].proto must be 'tcp' or 'udp', got 'http'",
		},
		{
			name: "multiple forwards with valid udp",
			config: ClientConfig{
				Server:   "quic://server.com:4433",
				ClientID: "test-client",
				PSK:      "secret123",
				Forwards: []ForwardConfig{
					{
						Local:  "127.0.0.1:8080",
						Remote: "10.0.0.5:9000",
						Proto:  "tcp",
					},
					{
						Local:  "127.0.0.1:5353",
						Remote: "10.0.0.5:53",
						Proto:  "udp",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClientConfig(&tt.config)
			if tt.wantErr {
				require.Error(t, err, "validateClientConfig() should return error")
				assert.Contains(t, err.Error(), tt.errMsg, "error message should match")
			} else {
				assert.NoError(t, err, "validateClientConfig() should not return error")
			}
		})
	}
}

func TestLoadServerConfig(t *testing.T) {
	// Create temporary directory for test configs
	tmpDir := t.TempDir()

	// Create temporary test files for TLS cert/key
	testCert := filepath.Join(tmpDir, "test.crt")
	testKey := filepath.Join(tmpDir, "test.key")

	// Create dummy cert/key files
	if err := os.WriteFile(testCert, []byte("test cert"), 0o600); err != nil {
		t.Fatalf("Failed to create test cert: %v", err)
	}
	if err := os.WriteFile(testKey, []byte("test key"), 0o600); err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	tests := []struct {
		name       string
		configYAML string
		wantErr    bool
	}{
		{
			name: "valid server config",
			configYAML: `server:
  listen: 0.0.0.0:4433
  tls_cert: ` + testCert + `
  tls_key: ` + testKey + `
  metrics_port: 9090

auth:
  psk_map:
    client1: secret1
    client2: secret2
`,
			wantErr: false,
		},
		{
			name: "invalid yaml",
			configYAML: `server:
  listen: 0.0.0.0:4433
  tls_cert: /etc/tunnelor/server.crt
  tls_key: /etc/tunnelor/server.key
auth
  psk_map:
    client1: secret1
`,
			wantErr: true,
		},
		{
			name: "missing required fields",
			configYAML: `server:
  listen: 0.0.0.0:4433

auth:
  psk_map:
    client1: secret1
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write config to temp file
			configPath := filepath.Join(tmpDir, tt.name+".yaml")
			err := os.WriteFile(configPath, []byte(tt.configYAML), 0o600)
			require.NoError(t, err, "Failed to write test config")

			// Load config
			cfg, err := LoadServerConfig(configPath)

			if tt.wantErr {
				assert.Error(t, err, "LoadServerConfig() should return error")
			} else {
				assert.NoError(t, err, "LoadServerConfig() should not return error")
				assert.NotNil(t, cfg, "LoadServerConfig() should return non-nil config")
			}
		})
	}
}

func TestLoadClientConfig(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		configYAML string
		wantErr    bool
	}{
		{
			name: "valid client config",
			configYAML: `client:
  server: quic://server.com:4433
  client_id: test-client
  psk: secret123
  forwards:
    - local: 127.0.0.1:8080
      remote: 10.0.0.5:9000
      proto: tcp
    - local: 127.0.0.1:5353
      remote: 10.0.0.5:53
      proto: udp
`,
			wantErr: false,
		},
		{
			name: "invalid yaml",
			configYAML: `client:
  server: quic://server.com:4433
  client_id: test-client
  psk: secret123
  forwards
    - local: 127.0.0.1:8080
`,
			wantErr: true,
		},
		{
			name: "missing required fields",
			configYAML: `client:
  server: quic://server.com:4433
  forwards:
    - local: 127.0.0.1:8080
      remote: 10.0.0.5:9000
      proto: tcp
`,
			wantErr: true,
		},
		{
			name: "invalid forward proto",
			configYAML: `client:
  server: quic://server.com:4433
  client_id: test-client
  psk: secret123
  forwards:
    - local: 127.0.0.1:8080
      remote: 10.0.0.5:9000
      proto: http
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(tmpDir, tt.name+".yaml")
			err := os.WriteFile(configPath, []byte(tt.configYAML), 0o600)
			require.NoError(t, err, "Failed to write test config")

			cfg, err := LoadClientConfig(configPath)

			if tt.wantErr {
				assert.Error(t, err, "LoadClientConfig() should return error")
			} else {
				assert.NoError(t, err, "LoadClientConfig() should not return error")
				assert.NotNil(t, cfg, "LoadClientConfig() should return non-nil config")
			}
		})
	}
}

func TestLoadServerConfigNonExistent(t *testing.T) {
	_, err := LoadServerConfig("/nonexistent/path/config.yaml")
	assert.Error(t, err, "LoadServerConfig() should return error for nonexistent file")
}

func TestLoadClientConfigNonExistent(t *testing.T) {
	_, err := LoadClientConfig("/nonexistent/path/config.yaml")
	assert.Error(t, err, "LoadClientConfig() should return error for nonexistent file")
}
