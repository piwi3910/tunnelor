package main

import (
	"fmt"
	"os"

	"github.com/piwi3910/tunnelor/internal/config"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
	pretty  bool
)

var rootCmd = &cobra.Command{
	Use:   "tunnelord",
	Short: "Tunnelor server daemon - QUIC-based tunneling gateway",
	Long: `Tunnelord is the server component of Tunnelor, a secure QUIC-based
tunneling and multiplexing platform. It listens for QUIC client connections,
handles authentication, and provides secure forwarding of TCP/UDP traffic.`,
	Run: runServer,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file path (required)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose/debug logging")
	rootCmd.PersistentFlags().BoolVar(&pretty, "pretty", false, "enable pretty console logging")
	rootCmd.MarkPersistentFlagRequired("config")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(cmd *cobra.Command, args []string) {
	// Setup logging
	logLevel := logger.InfoLevel
	if verbose {
		logLevel = logger.DebugLevel
	}

	logger.Setup(logger.Config{
		Level:      logLevel,
		Pretty:     pretty,
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
	})

	log.Info().Msg("Starting Tunnelord server...")

	// Load configuration
	cfg, err := config.LoadServerConfig(cfgFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load server configuration")
	}

	log.Info().
		Str("listen", cfg.Listen).
		Int("metrics_port", cfg.MetricsPort).
		Int("authorized_clients", len(cfg.Auth.PSKMap)).
		Msg("Server configuration loaded")

	// TODO: Initialize QUIC server
	// TODO: Start metrics server
	// TODO: Start accepting connections

	log.Info().Msg("Tunnelord server started successfully")

	// Keep server running
	select {}
}
