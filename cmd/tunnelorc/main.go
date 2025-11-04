// Package main provides the Tunnelorc client binary for establishing QUIC-based tunnels.
// It connects to a Tunnelor server, authenticates using PSK, and creates local/remote port forwards.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	quicgo "github.com/quic-go/quic-go"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/piwi3910/tunnelor/internal/config"
	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/ipc"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/quic"
	"github.com/piwi3910/tunnelor/internal/tcpbridge"
	"github.com/piwi3910/tunnelor/internal/udpbridge"
)

const (
	protoTCP = "tcp"
	protoUDP = "udp"
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
	RunE:  runConnect,
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
	forwardCmd.Flags().StringVar(&fwdProto, "proto", protoTCP, "protocol (tcp or udp)")
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

// forwardListener is a common interface for TCP and UDP listeners
type forwardListener interface {
	Start() error
	Serve() error
	Close() error
}

// clientState holds the runtime state needed for dynamic forwarding
type clientState struct {
	multiplexer   *mux.Multiplexer
	tcpListeners  []*tcpbridge.TCPListener
	udpListeners  []*udpbridge.UDPListener
	forwardErrors chan error
	mu            sync.Mutex
}

// addForward dynamically adds a new forward to the running client
func (s *clientState) addForward(req ipc.ForwardRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate protocol
	if req.Proto != protoTCP && req.Proto != protoUDP {
		return fmt.Errorf("protocol must be 'tcp' or 'udp', got '%s'", req.Proto)
	}

	// Create forward config
	fwd := config.ForwardConfig{
		Local:  req.Local,
		Remote: req.Remote,
		Proto:  req.Proto,
	}

	log.Info().
		Str("local", fwd.Local).
		Str("remote", fwd.Remote).
		Str("proto", fwd.Proto).
		Msg("Adding dynamic forward")

	// Setup forward based on protocol
	if fwd.Proto == protoTCP {
		listener, errChan, err := setupTCPForward(fwd, s.multiplexer)
		if err != nil {
			return fmt.Errorf("failed to setup TCP forward: %w", err)
		}
		s.tcpListeners = append(s.tcpListeners, listener)

		// Monitor errors
		go func(ch <-chan error) {
			if err := <-ch; err != nil {
				s.forwardErrors <- err
			}
		}(errChan)
	} else if fwd.Proto == protoUDP {
		listener, errChan, err := setupUDPForward(fwd, s.multiplexer)
		if err != nil {
			return fmt.Errorf("failed to setup UDP forward: %w", err)
		}
		s.udpListeners = append(s.udpListeners, listener)

		// Monitor errors
		go func(ch <-chan error) {
			if err := <-ch; err != nil {
				s.forwardErrors <- err
			}
		}(errChan)
	}

	log.Info().
		Str("local", fwd.Local).
		Str("remote", fwd.Remote).
		Str("proto", fwd.Proto).
		Msg("Dynamic forward added successfully")

	return nil
}

// setupForwardListener creates and starts a forward listener
// Returns an error channel that will receive any serve errors
func setupForwardListener(listener forwardListener, protocol string, fwd config.ForwardConfig) (<-chan error, error) {
	if err := listener.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s listener: %w", protocol, err)
	}

	// Start serving in background with error channel
	errChan := make(chan error, 1)
	go func() {
		if err := listener.Serve(); err != nil {
			log.Error().Err(err).Msgf("%s listener error", protocol)
			errChan <- fmt.Errorf("%s listener failed: %w", protocol, err)
		}
	}()

	log.Info().
		Str("local", fwd.Local).
		Str("remote", fwd.Remote).
		Msgf("%s forward established", protocol)

	return errChan, nil
}

// createStreamOpener creates a stream opener function for the given protocol
func createStreamOpener(fwd config.ForwardConfig, multiplexer *mux.Multiplexer, protocol mux.ProtocolID) func() (*quicgo.Stream, error) {
	targetAddr := fwd.Remote
	return func() (*quicgo.Stream, error) {
		var metadata []byte
		var err error

		// Encode protocol-specific metadata
		switch protocol {
		case mux.ProtocolTCP:
			metadata, err = mux.EncodeTCPMetadata(mux.TCPMetadata{
				SourceAddr: fwd.Local,
				TargetAddr: targetAddr,
			})
		case mux.ProtocolUDP:
			metadata, err = mux.EncodeUDPMetadata(mux.UDPMetadata{
				SourceAddr: fwd.Local,
				TargetAddr: targetAddr,
			})
		}
		if err != nil {
			return nil, fmt.Errorf("failed to encode %s metadata: %w", protocol.String(), err)
		}

		// Open multiplexed stream
		muxStream, err := multiplexer.OpenStream(protocol, metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s stream: %w", protocol.String(), err)
		}

		return muxStream.Stream, nil
	}
}

// setupTCPForward creates and starts a TCP forward listener
func setupTCPForward(fwd config.ForwardConfig, multiplexer *mux.Multiplexer) (*tcpbridge.TCPListener, <-chan error, error) {
	streamOpener := createStreamOpener(fwd, multiplexer, mux.ProtocolTCP)
	listener := tcpbridge.NewTCPListener(fwd.Local, fwd.Remote, streamOpener)

	errChan, err := setupForwardListener(listener, "TCP", fwd)
	if err != nil {
		return nil, nil, err
	}

	return listener, errChan, nil
}

// setupUDPForward creates and starts a UDP forward listener
func setupUDPForward(fwd config.ForwardConfig, multiplexer *mux.Multiplexer) (*udpbridge.UDPListener, <-chan error, error) {
	streamOpener := createStreamOpener(fwd, multiplexer, mux.ProtocolUDP)
	listener := udpbridge.NewUDPListener(fwd.Local, fwd.Remote, streamOpener)

	errChan, err := setupForwardListener(listener, "UDP", fwd)
	if err != nil {
		return nil, nil, err
	}

	return listener, errChan, nil
}

func runConnect(_ *cobra.Command, _ []string) error {
	// Setup logging
	logger.SetupFromFlags(verbose, pretty)

	log.Info().Msg("Starting Tunnelorc client...")

	// Load configuration
	cfg, err := config.LoadClientConfig(cfgFile)
	if err != nil {
		log.Error().Err(err).Msg("Failed to load client configuration")
		return fmt.Errorf("failed to load client configuration: %w", err)
	}

	log.Info().
		Str("server", cfg.Server).
		Str("client_id", cfg.ClientID).
		Int("forwards", len(cfg.Forwards)).
		Msg("Client configuration loaded")

	// Create QUIC client with proper TLS configuration
	clientConfig := quic.ClientConfig{
		ServerAddr:         cfg.Server,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		CAFile:             cfg.CAFile,
	}

	// Warn if insecure mode is enabled
	if cfg.InsecureSkipVerify {
		log.Warn().Msg("TLS certificate verification is disabled - NOT RECOMMENDED for production!")
	}

	quicClient, err := quic.NewClient(clientConfig)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create QUIC client")
		return fmt.Errorf("failed to create QUIC client: %w", err)
	}

	// Connect to QUIC server
	if err := quicClient.Connect(); err != nil {
		if closeErr := quicClient.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close QUIC client after connection error")
		}
		log.Error().Err(err).Msg("Failed to connect to QUIC server")
		return fmt.Errorf("failed to connect to QUIC server: %w", err)
	}

	log.Info().
		Str("server", cfg.Server).
		Str("local_addr", quicClient.Connection().LocalAddr()).
		Msg("Connected to server")

	// Create control handler
	controlHandler, err := control.NewClientHandler(cfg.ClientID, cfg.PSK, quicClient.Connection())
	if err != nil {
		if closeErr := quicClient.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close QUIC client after handler creation error")
		}
		log.Error().Err(err).Msg("Failed to create control handler")
		return fmt.Errorf("failed to create control handler: %w", err)
	}

	// Authenticate with server
	if err := controlHandler.Authenticate(); err != nil {
		if closeErr := quicClient.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close QUIC client after authentication error")
		}
		log.Error().Err(err).Msg("Failed to authenticate with server")
		return fmt.Errorf("failed to authenticate with server: %w", err)
	}
	defer func() {
		if err := quicClient.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC client")
		}
	}()

	log.Info().
		Str("session_id", controlHandler.GetSessionID()).
		Msg("Authentication successful")

	// Create multiplexer for opening streams
	multiplexer := mux.NewMultiplexer(quicClient.Connection())
	defer func() {
		if err := multiplexer.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close multiplexer")
		}
	}()

	// Register default handlers (for responses from server)
	mux.RegisterDefaultHandlers(multiplexer)

	// Create client state for dynamic forwarding
	state := &clientState{
		multiplexer:   multiplexer,
		tcpListeners:  make([]*tcpbridge.TCPListener, 0),
		udpListeners:  make([]*udpbridge.UDPListener, 0),
		forwardErrors: make(chan error, 10),
	}

	// Setup initial forwards from config
	var forwardErrChans []<-chan error
	setupSuccess := true
	for _, fwd := range cfg.Forwards {
		if fwd.Proto == protoTCP {
			listener, errChan, err := setupTCPForward(fwd, multiplexer)
			if err != nil {
				log.Error().Err(err).Str("local", fwd.Local).Msg("Failed to start TCP forward")
				setupSuccess = false
				break
			}
			state.tcpListeners = append(state.tcpListeners, listener)
			forwardErrChans = append(forwardErrChans, errChan)
		} else if fwd.Proto == protoUDP {
			listener, errChan, err := setupUDPForward(fwd, multiplexer)
			if err != nil {
				log.Error().Err(err).Str("local", fwd.Local).Msg("Failed to start UDP forward")
				setupSuccess = false
				break
			}
			state.udpListeners = append(state.udpListeners, listener)
			forwardErrChans = append(forwardErrChans, errChan)
		}
	}

	if !setupSuccess {
		return fmt.Errorf("failed to setup forwards")
	}

	// Merge all error channels into state's error channel
	for _, errChan := range forwardErrChans {
		go func(ch <-chan error) {
			if err := <-ch; err != nil {
				state.forwardErrors <- err
			}
		}(errChan)
	}

	// Start IPC server for dynamic forwarding
	ipcServer, err := ipc.NewServer(state.addForward)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to start IPC server - dynamic forwarding will not be available")
	} else {
		defer func() {
			if err := ipcServer.Close(); err != nil {
				log.Warn().Err(err).Msg("Failed to close IPC server")
			}
		}()

		// Start IPC server in background
		go func() {
			if err := ipcServer.Serve(); err != nil {
				log.Error().Err(err).Msg("IPC server error")
			}
		}()
	}

	// Clean up listeners on exit
	defer func() {
		for _, l := range state.tcpListeners {
			if err := l.Close(); err != nil {
				log.Warn().Err(err).Msg("Failed to close TCP listener")
			}
		}
		for _, l := range state.udpListeners {
			if err := l.Close(); err != nil {
				log.Warn().Err(err).Msg("Failed to close UDP listener")
			}
		}
	}()

	log.Info().Msg("Tunnelorc client ready")

	// Wait for shutdown signal or critical error
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Info().Str("signal", sig.String()).Msg("Shutdown signal received")
	case err := <-state.forwardErrors:
		log.Error().Err(err).Msg("Critical forward error - shutting down")
		return fmt.Errorf("forward error: %w", err)
	}

	log.Info().Msg("Shutting down Tunnelorc client...")
	return nil
}

func runForward(_ *cobra.Command, _ []string) {
	// Setup logging
	logger.SetupFromFlags(verbose, pretty)

	log.Info().
		Str("local", fwdLocal).
		Str("remote", fwdRemote).
		Str("proto", fwdProto).
		Msg("Adding new forward...")

	// Validate protocol
	if fwdProto != protoTCP && fwdProto != protoUDP {
		log.Fatal().Str("proto", fwdProto).Msg("Protocol must be 'tcp' or 'udp'")
	}

	// Create forward request
	req := ipc.ForwardRequest{
		Local:  fwdLocal,
		Remote: fwdRemote,
		Proto:  fwdProto,
	}

	// Send request to running client via IPC
	resp, err := ipc.SendForwardRequest(req)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to send forward request")
	}

	// Check response
	if !resp.Success {
		log.Fatal().Str("error", resp.Error).Msg("Forward request failed")
	}

	log.Info().Str("message", resp.Message).Msg("Forward added successfully")
}
