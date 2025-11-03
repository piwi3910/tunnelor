// Package logger provides structured logging capabilities using zerolog.
// It supports configurable log levels, pretty printing, and custom time formatting.
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Level represents the log level
type Level string

// Log level constants define the available logging levels
const (
	DebugLevel Level = "debug" // DebugLevel enables debug-level logging
	InfoLevel  Level = "info"  // InfoLevel enables info-level logging
	WarnLevel  Level = "warn"  // WarnLevel enables warning-level logging
	ErrorLevel Level = "error" // ErrorLevel enables error-level logging
)

// Config holds logger configuration
type Config struct {
	Level      Level
	TimeFormat string
	Pretty     bool
}

// DefaultConfig returns the default logger configuration
func DefaultConfig() Config {
	return Config{
		Level:      InfoLevel,
		Pretty:     false,
		TimeFormat: time.RFC3339,
	}
}

// ConfigFromFlags creates a logger config from common command-line flags
func ConfigFromFlags(verbose, pretty bool) Config {
	level := InfoLevel
	if verbose {
		level = DebugLevel
	}

	return Config{
		Level:      level,
		Pretty:     pretty,
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
	}
}

// SetupFromFlags is a convenience function to setup logging from command-line flags
func SetupFromFlags(verbose, pretty bool) {
	Setup(ConfigFromFlags(verbose, pretty))
}

// Setup initializes the global logger with the given configuration
func Setup(cfg Config) {
	// Set global log level
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Configure time format
	zerolog.TimeFieldFormat = cfg.TimeFormat

	// Configure output writer
	var output io.Writer = os.Stdout
	if cfg.Pretty {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
	}

	// Set the global logger
	log.Logger = zerolog.New(output).With().Timestamp().Logger()
}

// parseLevel converts a Level string to zerolog.Level
func parseLevel(level Level) zerolog.Level {
	switch level {
	case DebugLevel:
		return zerolog.DebugLevel
	case InfoLevel:
		return zerolog.InfoLevel
	case WarnLevel:
		return zerolog.WarnLevel
	case ErrorLevel:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// WithContext returns a logger with the given context fields
func WithContext(fields map[string]interface{}) zerolog.Logger {
	logger := log.With()
	for k, v := range fields {
		logger = logger.Interface(k, v)
	}
	return logger.Logger()
}

// WithClientID returns a logger with client_id field
func WithClientID(clientID string) zerolog.Logger {
	return log.With().Str("client_id", clientID).Logger()
}

// WithStreamID returns a logger with stream_id field
func WithStreamID(streamID uint64) zerolog.Logger {
	return log.With().Uint64("stream_id", streamID).Logger()
}

// WithProto returns a logger with proto field
func WithProto(proto string) zerolog.Logger {
	return log.With().Str("proto", proto).Logger()
}

// WithAddresses returns a logger with local_addr and remote_addr fields
func WithAddresses(local, remote string) zerolog.Logger {
	return log.With().
		Str("local_addr", local).
		Str("remote_addr", remote).
		Logger()
}
