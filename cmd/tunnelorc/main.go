package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/piwi3910/tunnelor/internal/config"
	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/quic"
	"github.com/piwi3910/tunnelor/internal/tcpbridge"
	"github.com/piwi3910/tunnelor/internal/udpbridge"
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
	if err := connectCmd.MarkFlagRequired("config"); err != nil {
		panic(err) // This should never fail for a valid flag name
	}

	// Forward command flags
	forwardCmd.Flags().StringVar(&fwdLocal, "local", "", "local address (e.g., 127.0.0.1:8080)")
	forwardCmd.Flags().StringVar(&fwdRemote, "remote", "", "remote address (e.g., 10.0.0.5:9000)")
	forwardCmd.Flags().StringVar(&fwdProto, "proto", "tcp", "protocol (tcp or udp)")
	if err := forwardCmd.MarkFlagRequired("local"); err != nil {
		panic(err)
	}
	if err := forwardCmd.MarkFlagRequired("remote"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(connectCmd)
	rootCmd.AddCommand(forwardCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// setupLogging configures the logger based on verbosity flags
func setupLogging(verbose, pretty bool) {
	logLevel := logger.InfoLevel
	if verbose {
		logLevel = logger.DebugLevel
	}

	logger.Setup(logger.Config{
		Level:      logLevel,
		Pretty:     pretty,
		TimeFormat: "2006-01-02T15:04:05.000Z07:00",
	})
}

// setupTCPForward creates and starts a TCP forward listener
func setupTCPForward(fwd config.ForwardConfig, multiplexer *mux.Multiplexer) (*tcpbridge.TCPListener, error) {
	targetAddr := fwd.Remote
	streamOpener := func() (*quicgo.Stream, error) {
		// Encode TCP metadata
		metadata, err := mux.EncodeTCPMetadata(mux.TCPMetadata{
			SourceAddr: fwd.Local,
			TargetAddr: targetAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode TCP metadata: %w", err)
		}

		// Open multiplexed stream
		muxStream, err := multiplexer.OpenStream(mux.ProtocolTCP, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to open TCP stream: %w", err)
		}

		return muxStream.Stream, nil
	}

	// Create TCP listener
	listener := tcpbridge.NewTCPListener(fwd.Local, fwd.Remote, streamOpener)
	if err := listener.Start(); err != nil {
		return nil, fmt.Errorf("failed to start TCP listener: %w", err)
	}

	// Start serving in background
	go func(l *tcpbridge.TCPListener) {
		if err := l.Serve(); err != nil {
			log.Error().Err(err).Msg("TCP listener error")
		}
	}(listener)

	log.Info().
		Str("local", fwd.Local).
		Str("remote", fwd.Remote).
		Msg("TCP forward established")

	return listener, nil
}

// setupUDPForward creates and starts a UDP forward listener
func setupUDPForward(fwd config.ForwardConfig, multiplexer *mux.Multiplexer) (*udpbridge.UDPListener, error) {
	targetAddr := fwd.Remote
	streamOpener := func() (*quicgo.Stream, error) {
		// Encode UDP metadata
		metadata, err := mux.EncodeUDPMetadata(mux.UDPMetadata{
			SourceAddr: fwd.Local,
			TargetAddr: targetAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to encode UDP metadata: %w", err)
		}

		// Open multiplexed stream
		muxStream, err := multiplexer.OpenStream(mux.ProtocolUDP, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to open UDP stream: %w", err)
		}

		return muxStream.Stream, nil
	}

	// Create UDP listener
	listener := udpbridge.NewUDPListener(fwd.Local, fwd.Remote, streamOpener)
	if err := listener.Start(); err != nil {
		return nil, fmt.Errorf("failed to start UDP listener: %w", err)
	}

	// Start serving in background
	go func(l *udpbridge.UDPListener) {
		if err := l.Serve(); err != nil {
			log.Error().Err(err).Msg("UDP listener error")
		}
	}(listener)

	log.Info().
		Str("local", fwd.Local).
		Str("remote", fwd.Remote).
		Msg("UDP forward established")

	return listener, nil
}

func runConnect(_ *cobra.Command, _ []string) {
	// Setup logging
	setupLogging(verbose, pretty)

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

	// Connect to QUIC server
	if err := quicClient.Connect(); err != nil {
		quicClient.Close()
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
		quicClient.Close()
		log.Fatal().Err(err).Msg("Failed to authenticate with server")
	}
	defer quicClient.Close()

	log.Info().
		Str("session_id", controlHandler.GetSessionID()).
		Msg("Authentication successful")

	// Create multiplexer for opening streams
	multiplexer := mux.NewMultiplexer(quicClient.Connection())
	defer multiplexer.Close()

	// Register default handlers (for responses from server)
	mux.RegisterDefaultHandlers(multiplexer)

	// Start TCP and UDP forwards
	var tcpListeners []*tcpbridge.TCPListener
	var udpListeners []*udpbridge.UDPListener

	for _, fwd := range cfg.Forwards {
		if fwd.Proto == "tcp" {
			listener, err := setupTCPForward(fwd, multiplexer)
			if err != nil {
				multiplexer.Close()
				quicClient.Close()
				log.Fatal().Err(err).Str("local", fwd.Local).Msg("Failed to start TCP listener")
			}
			tcpListeners = append(tcpListeners, listener)
		} else if fwd.Proto == "udp" {
			listener, err := setupUDPForward(fwd, multiplexer)
			if err != nil {
				multiplexer.Close()
				quicClient.Close()
				log.Fatal().Err(err).Str("local", fwd.Local).Msg("Failed to start UDP listener")
			}
			udpListeners = append(udpListeners, listener)
		}
	}

	// Clean up listeners on exit
	defer func() {
		for _, l := range tcpListeners {
			l.Close()
		}
		for _, l := range udpListeners {
			l.Close()
		}
	}()

	log.Info().Msg("Tunnelorc client ready")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down Tunnelorc client...")
}

func runForward(_ *cobra.Command, _ []string) {
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
