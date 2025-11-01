package logger

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Level != InfoLevel {
		t.Errorf("Expected default level to be InfoLevel, got %s", cfg.Level)
	}

	if cfg.Pretty {
		t.Error("Expected default Pretty to be false")
	}

	if cfg.TimeFormat != time.RFC3339 {
		t.Errorf("Expected default TimeFormat to be RFC3339, got %s", cfg.TimeFormat)
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name     string
		level    Level
		expected zerolog.Level
	}{
		{
			name:     "debug level",
			level:    DebugLevel,
			expected: zerolog.DebugLevel,
		},
		{
			name:     "info level",
			level:    InfoLevel,
			expected: zerolog.InfoLevel,
		},
		{
			name:     "warn level",
			level:    WarnLevel,
			expected: zerolog.WarnLevel,
		},
		{
			name:     "error level",
			level:    ErrorLevel,
			expected: zerolog.ErrorLevel,
		},
		{
			name:     "unknown level defaults to info",
			level:    Level("unknown"),
			expected: zerolog.InfoLevel,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLevel(tt.level)
			if result != tt.expected {
				t.Errorf("parseLevel(%s) = %v, expected %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestSetup(t *testing.T) {
	tests := []struct {
		name   string
		config Config
	}{
		{
			name: "default config",
			config: Config{
				Level:      InfoLevel,
				Pretty:     false,
				TimeFormat: time.RFC3339,
			},
		},
		{
			name: "debug config",
			config: Config{
				Level:      DebugLevel,
				Pretty:     false,
				TimeFormat: time.RFC3339,
			},
		},
		{
			name: "pretty config",
			config: Config{
				Level:      InfoLevel,
				Pretty:     true,
				TimeFormat: time.RFC3339,
			},
		},
		{
			name: "custom time format",
			config: Config{
				Level:      InfoLevel,
				Pretty:     false,
				TimeFormat: "2006-01-02T15:04:05.000Z07:00",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup should not panic
			Setup(tt.config)

			// Verify global level was set
			if zerolog.GlobalLevel() != parseLevel(tt.config.Level) {
				t.Errorf("Global level not set correctly, expected %v, got %v",
					parseLevel(tt.config.Level), zerolog.GlobalLevel())
			}

			// Verify time format was set
			if zerolog.TimeFieldFormat != tt.config.TimeFormat {
				t.Errorf("TimeFieldFormat not set correctly, expected %s, got %s",
					tt.config.TimeFormat, zerolog.TimeFieldFormat)
			}
		})
	}
}

func TestWithContext(t *testing.T) {
	// Setup logger first
	Setup(DefaultConfig())

	fields := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": true,
	}

	logger := WithContext(fields)

	// Logger should not be nil
	if logger.GetLevel() == zerolog.Disabled {
		t.Error("Expected logger to be enabled")
	}
}

func TestWithClientID(t *testing.T) {
	Setup(DefaultConfig())

	clientID := "test-client-123"
	logger := WithClientID(clientID)

	if logger.GetLevel() == zerolog.Disabled {
		t.Error("Expected logger to be enabled")
	}
}

func TestWithStreamID(t *testing.T) {
	Setup(DefaultConfig())

	streamID := uint64(12345)
	logger := WithStreamID(streamID)

	if logger.GetLevel() == zerolog.Disabled {
		t.Error("Expected logger to be enabled")
	}
}

func TestWithProto(t *testing.T) {
	Setup(DefaultConfig())

	proto := "tcp"
	logger := WithProto(proto)

	if logger.GetLevel() == zerolog.Disabled {
		t.Error("Expected logger to be enabled")
	}
}

func TestWithAddresses(t *testing.T) {
	Setup(DefaultConfig())

	local := "127.0.0.1:8080"
	remote := "10.0.0.5:9000"
	logger := WithAddresses(local, remote)

	if logger.GetLevel() == zerolog.Disabled {
		t.Error("Expected logger to be enabled")
	}
}
