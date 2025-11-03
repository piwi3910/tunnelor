package logger

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, InfoLevel, cfg.Level, "Expected default level to be InfoLevel")
	assert.False(t, cfg.Pretty, "Expected default Pretty to be false")
	assert.Equal(t, time.RFC3339, cfg.TimeFormat, "Expected default TimeFormat to be RFC3339")
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
			assert.Equal(t, tt.expected, result, "parseLevel(%s) should return expected value", tt.level)
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
			assert.Equal(t, parseLevel(tt.config.Level), zerolog.GlobalLevel(),
				"Global level should be set correctly")

			// Verify time format was set
			assert.Equal(t, tt.config.TimeFormat, zerolog.TimeFieldFormat,
				"TimeFieldFormat should be set correctly")
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
	assert.NotEqual(t, zerolog.Disabled, logger.GetLevel(), "Expected logger to be enabled")
}

func TestWithClientID(t *testing.T) {
	Setup(DefaultConfig())

	clientID := "test-client-123"
	logger := WithClientID(clientID)

	assert.NotEqual(t, zerolog.Disabled, logger.GetLevel(), "Expected logger to be enabled")
}

func TestWithStreamID(t *testing.T) {
	Setup(DefaultConfig())

	streamID := uint64(12345)
	logger := WithStreamID(streamID)

	assert.NotEqual(t, zerolog.Disabled, logger.GetLevel(), "Expected logger to be enabled")
}

func TestWithProto(t *testing.T) {
	Setup(DefaultConfig())

	proto := "tcp"
	logger := WithProto(proto)

	assert.NotEqual(t, zerolog.Disabled, logger.GetLevel(), "Expected logger to be enabled")
}

func TestWithAddresses(t *testing.T) {
	Setup(DefaultConfig())

	local := "127.0.0.1:8080"
	remote := "10.0.0.5:9000"
	logger := WithAddresses(local, remote)

	assert.NotEqual(t, zerolog.Disabled, logger.GetLevel(), "Expected logger to be enabled")
}
