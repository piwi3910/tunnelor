package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateServerConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ServerConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: ServerConfig{
				Listen:      "0.0.0.0:4433",
				TLSCert:     "/etc/tunnelor/server.crt",
				TLSKey:      "/etc/tunnelor/server.key",
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
				TLSCert: "/etc/tunnelor/server.crt",
				TLSKey:  "/etc/tunnelor/server.key",
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
				TLSKey:  "/etc/tunnelor/server.key",
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
				TLSCert: "/etc/tunnelor/server.crt",
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
				TLSCert: "/etc/tunnelor/server.crt",
				TLSKey:  "/etc/tunnelor/server.key",
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
				if err == nil {
					t.Errorf("validateServerConfig() expected error, got nil")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("validateServerConfig() error = %v, want %v", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("validateServerConfig() unexpected error: %v", err)
			}
		})
	}
}

func TestValidateClientConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
		errMsg  string
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
				if err == nil {
					t.Errorf("validateClientConfig() expected error, got nil")
					return
				}
				if err.Error() != tt.errMsg {
					t.Errorf("validateClientConfig() error = %v, want %v", err, tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("validateClientConfig() unexpected error: %v", err)
			}
		})
	}
}

func TestLoadServerConfig(t *testing.T) {
	// Create temporary directory for test configs
	tmpDir := t.TempDir()

	tests := []struct {
		name       string
		configYAML string
		wantErr    bool
	}{
		{
			name: "valid server config",
			configYAML: `server:
  listen: 0.0.0.0:4433
  tls_cert: /etc/tunnelor/server.crt
  tls_key: /etc/tunnelor/server.key
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
			err := os.WriteFile(configPath, []byte(tt.configYAML), 0o644)
			if err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			// Load config
			cfg, err := LoadServerConfig(configPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadServerConfig() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("LoadServerConfig() unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("LoadServerConfig() returned nil config")
				}
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
			err := os.WriteFile(configPath, []byte(tt.configYAML), 0o644)
			if err != nil {
				t.Fatalf("Failed to write test config: %v", err)
			}

			cfg, err := LoadClientConfig(configPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("LoadClientConfig() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("LoadClientConfig() unexpected error: %v", err)
				}
				if cfg == nil {
					t.Error("LoadClientConfig() returned nil config")
				}
			}
		})
	}
}

func TestLoadServerConfigNonExistent(t *testing.T) {
	_, err := LoadServerConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("LoadServerConfig() expected error for nonexistent file, got nil")
	}
}

func TestLoadClientConfigNonExistent(t *testing.T) {
	_, err := LoadClientConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("LoadClientConfig() expected error for nonexistent file, got nil")
	}
}
