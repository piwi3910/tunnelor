// Package config provides configuration loading and parsing for Tunnelor server and client.
// It uses Viper for YAML-based configuration management with validation.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// ServerConfig holds server-specific configuration
type ServerConfig struct {
	Auth                    ServerAuthConfig `mapstructure:"auth"`
	Listen                  string           `mapstructure:"listen"`
	TLSCert                 string           `mapstructure:"tls_cert"`
	TLSKey                  string           `mapstructure:"tls_key"`
	MetricsPort             int              `mapstructure:"metrics_port"`
	MaxConnectionsPerClient int              `mapstructure:"max_connections_per_client"` // Max connections per client ID (0 = unlimited)
	MaxTotalConnections     int              `mapstructure:"max_total_connections"`      // Max total connections (0 = unlimited)
}

// ServerAuthConfig holds server authentication configuration
type ServerAuthConfig struct {
	PSKMap map[string]string `mapstructure:"psk_map"`
}

// ClientConfig holds client-specific configuration
type ClientConfig struct {
	Server             string          `mapstructure:"server"`
	ClientID           string          `mapstructure:"client_id"`
	PSK                string          `mapstructure:"psk"`
	CAFile             string          `mapstructure:"ca_file"`
	Forwards           []ForwardConfig `mapstructure:"forwards"`
	InsecureSkipVerify bool            `mapstructure:"insecure_skip_verify"`
}

// ForwardConfig defines a forwarding rule
type ForwardConfig struct {
	Local  string `mapstructure:"local"`
	Remote string `mapstructure:"remote"`
	Proto  string `mapstructure:"proto"`
}

// loadConfig is a generic config loader that handles the common Viper operations
func loadConfig(configPath, configType string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.SetConfigType(configType)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return v, nil
}

// LoadServerConfig loads server configuration from the specified file
func LoadServerConfig(configPath string) (*ServerConfig, error) {
	v, err := loadConfig(configPath, "yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load server config: %w", err)
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
	v, err := loadConfig(configPath, "yaml")
	if err != nil {
		return nil, fmt.Errorf("failed to load client config: %w", err)
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
	// Validate listen address
	if cfg.Listen == "" {
		return fmt.Errorf("server.listen is required")
	}
	if err := validateAddress(cfg.Listen); err != nil {
		return fmt.Errorf("server.listen invalid: %w", err)
	}

	// Validate TLS certificate files
	if cfg.TLSCert == "" {
		return fmt.Errorf("server.tls_cert is required")
	}
	if err := validateFileExists(cfg.TLSCert); err != nil {
		return fmt.Errorf("server.tls_cert: %w", err)
	}

	if cfg.TLSKey == "" {
		return fmt.Errorf("server.tls_key is required")
	}
	if err := validateFileExists(cfg.TLSKey); err != nil {
		return fmt.Errorf("server.tls_key: %w", err)
	}

	// Validate PSK map
	if len(cfg.Auth.PSKMap) == 0 {
		return fmt.Errorf("auth.psk_map must contain at least one entry")
	}
	for clientID, psk := range cfg.Auth.PSKMap {
		if clientID == "" {
			return fmt.Errorf("auth.psk_map contains empty client_id")
		}
		if psk == "" {
			return fmt.Errorf("auth.psk_map[%s] has empty PSK", clientID)
		}
	}

	// Validate metrics port
	if cfg.MetricsPort < 0 || cfg.MetricsPort > 65535 {
		return fmt.Errorf("server.metrics_port must be between 0 and 65535, got %d", cfg.MetricsPort)
	}

	// Validate connection limits
	if cfg.MaxConnectionsPerClient < 0 {
		return fmt.Errorf("server.max_connections_per_client must be >= 0, got %d", cfg.MaxConnectionsPerClient)
	}
	if cfg.MaxTotalConnections < 0 {
		return fmt.Errorf("server.max_total_connections must be >= 0, got %d", cfg.MaxTotalConnections)
	}

	return nil
}

// validateClientConfig validates the client configuration
func validateClientConfig(cfg *ClientConfig) error {
	// Validate server address
	if cfg.Server == "" {
		return fmt.Errorf("client.server is required")
	}
	if err := validateServerURL(cfg.Server); err != nil {
		return fmt.Errorf("client.server invalid: %w", err)
	}

	// Validate client ID
	if cfg.ClientID == "" {
		return fmt.Errorf("client.client_id is required")
	}

	// Validate PSK
	if cfg.PSK == "" {
		return fmt.Errorf("client.psk is required")
	}

	// Validate CA file if specified
	if cfg.CAFile != "" {
		if err := validateFileExists(cfg.CAFile); err != nil {
			return fmt.Errorf("client.ca_file: %w", err)
		}
	}

	// Warn about insecure mode
	if cfg.InsecureSkipVerify && cfg.CAFile != "" {
		return fmt.Errorf("client.insecure_skip_verify and client.ca_file are mutually exclusive")
	}

	// Validate forwards
	return validateForwards(cfg.Forwards)
}

// validateForwards validates all forward configurations
func validateForwards(forwards []ForwardConfig) error {
	for i, fwd := range forwards {
		if err := validateForward(i, fwd); err != nil {
			return err
		}
	}
	return nil
}

// validateForward validates a single forward configuration
func validateForward(index int, fwd ForwardConfig) error {
	if fwd.Local == "" {
		return fmt.Errorf("forward[%d].local is required", index)
	}
	if err := validateAddress(fwd.Local); err != nil {
		return fmt.Errorf("forward[%d].local invalid: %w", index, err)
	}

	if fwd.Remote == "" {
		return fmt.Errorf("forward[%d].remote is required", index)
	}
	if err := validateAddress(fwd.Remote); err != nil {
		return fmt.Errorf("forward[%d].remote invalid: %w", index, err)
	}

	if fwd.Proto != "tcp" && fwd.Proto != "udp" {
		return fmt.Errorf("forward[%d].proto must be 'tcp' or 'udp', got '%s'", index, fwd.Proto)
	}

	return nil
}

// validateAddress validates a host:port address format
func validateAddress(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format (expected host:port): %w", err)
	}

	// Validate host
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port number: %w", err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}

	return nil
}

// validateServerURL validates a server URL (quic://host:port or host:port)
func validateServerURL(serverURL string) error {
	// Remove protocol prefix if present
	addr := serverURL
	if strings.HasPrefix(serverURL, "quic://") {
		addr = strings.TrimPrefix(serverURL, "quic://")
	}

	return validateAddress(addr)
}

// validateFileExists checks if a file exists and is readable
func validateFileExists(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", path)
		}
		return fmt.Errorf("cannot access file: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}

	return nil
}
