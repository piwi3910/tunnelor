package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/piwi3910/tunnelor/internal/config"
	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/quic"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	verbose bool
	pretty  bool
)

var rootCmd = &cobra.Command{
	Use:   "tunnelorc",
	Short: "Tunnelor client agent - QUIC-based tunneling client",
	Long: `Tunnelorc is the client component of Tunnelor, a secure QUIC-based
tunneling and multiplexing platform. It establishes QUIC sessions with the
server, authenticates using PSK, and creates local/remote port forwards.`,
}

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to Tunnelor server and establish tunnels",
	Long:  `Connects to the Tunnelor server using configuration from the config file and establishes the configured port forwards.`,
	Run:   runConnect,
}

var forwardCmd = &cobra.Command{
	Use:   "forward",
	Short: "Add a new port forward dynamically",
	Long:  `Dynamically add a new port forward to an existing connection.`,
	Run:   runForward,
}

var (
	fwdLocal  string
	fwdRemote string
	fwdProto  string
)

func init() {
	// Root flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose/debug logging")
	rootCmd.PersistentFlags().BoolVar(&pretty, "pretty", false, "enable pretty console logging")

	// Connect command flags
	connectCmd.Flags().StringVar(&cfgFile, "config", "", "config file path (required)")
	connectCmd.MarkFlagRequired("config")

	// Forward command flags
	forwardCmd.Flags().StringVar(&fwdLocal, "local", "", "local address (e.g., 127.0.0.1:8080)")
	forwardCmd.Flags().StringVar(&fwdRemote, "remote", "", "remote address (e.g., 10.0.0.5:9000)")
	forwardCmd.Flags().StringVar(&fwdProto, "proto", "tcp", "protocol (tcp or udp)")
	forwardCmd.MarkFlagRequired("local")
	forwardCmd.MarkFlagRequired("remote")

	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(forwardCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runConnect(cmd *cobra.Command, args []string) {
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

	log.Info().Msg("Starting Tunnelorc client...")

	// Load configuration
	cfg, err := config.LoadClientConfig(cfgFile)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load client configuration")
	}

	log.Info().
		Str("server", cfg.Server).
		Str("client_id", cfg.ClientID).
		Int("forwards", len(cfg.Forwards)).
		Msg("Client configuration loaded")

	// Create QUIC client
	quicClient, err := quic.NewClient(quic.ClientConfig{
		ServerAddr:         cfg.Server,
		InsecureSkipVerify: true, // TODO: Add CA certificate support
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create QUIC client")
	}
	defer quicClient.Close()

	// Connect to QUIC server
	if err := quicClient.Connect(); err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to QUIC server")
	}

	log.Info().
		Str("server", cfg.Server).
		Str("local_addr", quicClient.Connection().LocalAddr()).
		Msg("Connected to server")

	// Create control handler
	controlHandler := control.NewClientHandler(cfg.ClientID, cfg.PSK, quicClient.Connection())

	// Authenticate with server
	if err := controlHandler.Authenticate(); err != nil {
		log.Fatal().Err(err).Msg("Failed to authenticate with server")
	}

	log.Info().
		Str("session_id", controlHandler.GetSessionID()).
		Msg("Authentication successful")

	// TODO: Establish port forwards

	log.Info().Msg("Tunnelorc client ready")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down Tunnelorc client...")
}

func runForward(cmd *cobra.Command, args []string) {
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

	log.Info().
		Str("local", fwdLocal).
		Str("remote", fwdRemote).
		Str("proto", fwdProto).
		Msg("Adding new forward...")

	// Validate protocol
	if fwdProto != "tcp" && fwdProto != "udp" {
		log.Fatal().Str("proto", fwdProto).Msg("Protocol must be 'tcp' or 'udp'")
	}

	// TODO: Add forward to running client
	log.Info().Msg("Forward added successfully")
}
