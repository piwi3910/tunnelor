package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Auth        ServerAuthConfig `mapstructure:"auth"`
	Listen      string           `mapstructure:"listen"`
	TLSCert     string           `mapstructure:"tls_cert"`
	TLSKey      string           `mapstructure:"tls_key"`
	MetricsPort int              `mapstructure:"metrics_port"`
}

// ServerAuthConfig holds server authentication configuration
type ServerAuthConfig struct {
	PSKMap map[string]string `mapstructure:"psk_map"`
}

// ClientConfig holds client-specific configuration
type ClientConfig struct {
	Server   string          `mapstructure:"server"`
	ClientID string          `mapstructure:"client_id"`
	PSK      string          `mapstructure:"psk"`
	Forwards []ForwardConfig `mapstructure:"forwards"`
}

// ForwardConfig defines a forwarding rule
type ForwardConfig struct {
	Local  string `mapstructure:"local"`
	Remote string `mapstructure:"remote"`
	Proto  string `mapstructure:"proto"`
}

// LoadServerConfig loads server configuration from the specified file
func LoadServerConfig(configPath string) (*ServerConfig, error) {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read server config: %w", err)
	}

	var cfg ServerConfig
	if err := v.UnmarshalKey("server", &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal server config: %w", err)
	}

	// Unmarshal auth separately since it's at root level in the example
	if err := v.UnmarshalKey("auth", &cfg.Auth); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth config: %w", err)
	}

	// Validate server config
	if err := validateServerConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadClientConfig loads client configuration from the specified file
func LoadClientConfig(configPath string) (*ClientConfig, error) {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read client config: %w", err)
	}

	var cfg ClientConfig
	if err := v.UnmarshalKey("client", &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client config: %w", err)
	}

	// Validate client config
	if err := validateClientConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateServerConfig validates the server configuration
func validateServerConfig(cfg *ServerConfig) error {
	if cfg.Listen == "" {
		return fmt.Errorf("server.listen is required")
	}
	if cfg.TLSCert == "" {
		return fmt.Errorf("server.tls_cert is required")
	}
	if cfg.TLSKey == "" {
		return fmt.Errorf("server.tls_key is required")
	}
	if len(cfg.Auth.PSKMap) == 0 {
		return fmt.Errorf("auth.psk_map must contain at least one entry")
	}
	return nil
}

// validateClientConfig validates the client configuration
func validateClientConfig(cfg *ClientConfig) error {
	if cfg.Server == "" {
		return fmt.Errorf("client.server is required")
	}
	if cfg.ClientID == "" {
		return fmt.Errorf("client.client_id is required")
	}
	if cfg.PSK == "" {
		return fmt.Errorf("client.psk is required")
	}

	// Validate forwards
	for i, fwd := range cfg.Forwards {
		if fwd.Local == "" {
			return fmt.Errorf("forward[%d].local is required", i)
		}
		if fwd.Remote == "" {
			return fmt.Errorf("forward[%d].remote is required", i)
		}
		if fwd.Proto != "tcp" && fwd.Proto != "udp" {
			return fmt.Errorf("forward[%d].proto must be 'tcp' or 'udp', got '%s'", i, fwd.Proto)
		}
	}

	return nil
}
