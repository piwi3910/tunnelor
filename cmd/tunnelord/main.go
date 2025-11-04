// Package main provides the Tunnelord server binary for accepting QUIC-based tunnel connections.
// It listens for incoming QUIC connections, authenticates clients using PSK, and handles port forwarding.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/piwi3910/tunnelor/internal/config"
	"github.com/piwi3910/tunnelor/internal/control"
	"github.com/piwi3910/tunnelor/internal/logger"
	"github.com/piwi3910/tunnelor/internal/metrics"
	"github.com/piwi3910/tunnelor/internal/mux"
	"github.com/piwi3910/tunnelor/internal/quic"
	"github.com/piwi3910/tunnelor/internal/server"
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
	if err := rootCmd.MarkPersistentFlagRequired("config"); err != nil {
		panic(err) // This should never fail for a valid flag name
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServer(_ *cobra.Command, _ []string) {
	// Setup logging
	logger.SetupFromFlags(verbose, pretty)

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

	// Initialize QUIC server
	quicServer, err := quic.NewServer(quic.ServerConfig{
		ListenAddr: cfg.Listen,
		TLSCert:    cfg.TLSCert,
		TLSKey:     cfg.TLSKey,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create QUIC server")
	}

	// Start QUIC server
	if err := quicServer.Start(cfg.Listen); err != nil {
		log.Fatal().Err(err).Msg("Failed to start QUIC server")
	}
	defer func() {
		if err := quicServer.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close QUIC server")
		}
	}()

	// Start metrics server
	var metricsServer *metrics.Server
	if cfg.MetricsPort > 0 {
		var err error
		metricsServer, err = metrics.Start(cfg.MetricsPort)
		if err != nil {
			log.Error().Err(err).Msg("Failed to start metrics server")
		} else {
			defer func() {
				if err := metricsServer.Stop(); err != nil {
					log.Warn().Err(err).Msg("Failed to stop metrics server")
				}
			}()
			log.Info().
				Int("metrics_port", cfg.MetricsPort).
				Msg("Metrics server started")
		}
	}

	// Create connection manager with configured limits
	connMgr := server.NewConnectionManager(cfg.MaxConnectionsPerClient, cfg.MaxTotalConnections)

	if cfg.MaxConnectionsPerClient > 0 || cfg.MaxTotalConnections > 0 {
		log.Info().
			Int("max_per_client", cfg.MaxConnectionsPerClient).
			Int("max_total", cfg.MaxTotalConnections).
			Msg("Connection limits enabled")
	} else {
		log.Info().Msg("No connection limits configured (unlimited)")
	}

	// Create forward registry and load configured forwards
	forwardRegistry := server.NewForwardRegistry()
	if err := forwardRegistry.LoadFromConfig(cfg.Forwards); err != nil {
		log.Error().Err(err).Msg("Failed to load forward configuration")
		return
	}

	if forwardRegistry.Count() > 0 {
		log.Info().
			Int("forward_count", forwardRegistry.Count()).
			Msg("Reverse tunnel forwards loaded from configuration")
	}

	log.Info().Msg("Tunnelord server started successfully")

	// Start accepting connections in background
	go func() {
		for {
			conn, err := quicServer.Accept()
			if err != nil {
				log.Error().Err(err).Msg("Failed to accept connection")
				return
			}

			// Handle connection in goroutine
			go handleConnection(conn, cfg.Auth.PSKMap, connMgr, forwardRegistry)
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down Tunnelord server...")
}

func handleConnection(conn *quic.Connection, pskMap map[string]string, connMgr *server.ConnectionManager, forwardRegistry *server.ForwardRegistry) {
	startTime := time.Now()

	log.Info().
		Str("remote_addr", conn.RemoteAddr()).
		Str("local_addr", conn.LocalAddr()).
		Msg("New connection established")

	// Create control handler
	controlHandler, err := control.NewServerHandler(pskMap, conn)
	if err != nil {
		log.Error().
			Err(err).
			Str("remote_addr", conn.RemoteAddr()).
			Msg("Failed to create control handler")
		return
	}

	// Accept first stream (should be control stream)
	controlStream, err := conn.AcceptStream()
	if err != nil {
		log.Error().
			Err(err).
			Str("remote_addr", conn.RemoteAddr()).
			Msg("Failed to accept control stream")
		return
	}

	// Handle authentication
	if err := controlHandler.HandleControlStream(controlStream); err != nil {
		log.Error().
			Err(err).
			Str("remote_addr", conn.RemoteAddr()).
			Msg("Authentication failed")
		metrics.RecordAuthAttempt(false)
		if closeErr := conn.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close connection after authentication failure")
		}
		return
	}

	// Record successful authentication
	metrics.RecordAuthAttempt(true)

	// Get authenticated client ID
	clientID := controlHandler.GetClientID()

	// Check if connection can be accepted (after authentication to know client ID)
	if err := connMgr.CanAccept(clientID); err != nil {
		log.Warn().
			Err(err).
			Str("client_id", clientID).
			Str("remote_addr", conn.RemoteAddr()).
			Msg("Connection rejected due to resource limits")
		if closeErr := conn.Close(); closeErr != nil {
			log.Warn().Err(closeErr).Msg("Failed to close connection after limit check")
		}
		return
	}

	// Register connection
	connMgr.AddConnection(clientID)
	metrics.RecordConnectionStart(clientID)
	defer func() {
		connMgr.RemoveConnection(clientID)
		metrics.RecordConnectionEnd(time.Since(startTime))
	}()

	log.Info().
		Str("remote_addr", conn.RemoteAddr()).
		Int("sessions", controlHandler.SessionCount()).
		Msg("Connection authenticated, setting up multiplexer")

	// Create multiplexer for this connection
	multiplexer := mux.NewMultiplexer(conn)
	defer func() {
		if err := multiplexer.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close multiplexer")
		}
	}()

	// Register default handlers
	mux.RegisterDefaultHandlers(multiplexer)

	// Start public listeners for this client's configured forwards
	var publicListeners []*server.PublicListener
	clientForwards := forwardRegistry.GetForwardsByClient(clientID)
	if len(clientForwards) > 0 {
		log.Info().
			Str("client_id", clientID).
			Int("forward_count", len(clientForwards)).
			Msg("Starting public listeners for reverse tunnels")

		for _, fwd := range clientForwards {
			listener, err := server.NewPublicListener(fwd, multiplexer)
			if err != nil {
				log.Error().
					Err(err).
					Str("forward_id", fwd.ID).
					Str("local", fwd.Local).
					Msg("Failed to create public listener")
				continue
			}

			publicListeners = append(publicListeners, listener)

			// Start listener in background
			go func(pl *server.PublicListener) {
				if err := pl.Start(); err != nil {
					log.Error().
						Err(err).
						Str("forward_id", fwd.ID).
						Msg("Public listener error")
				}
			}(listener)

			log.Info().
				Str("forward_id", fwd.ID).
				Str("local", fwd.Local).
				Str("remote", fwd.Remote).
				Str("proto", fwd.Proto).
				Msg("Public listener started for reverse tunnel")
		}
	}

	// Close all public listeners when connection ends
	defer func() {
		for _, listener := range publicListeners {
			if err := listener.Close(); err != nil {
				log.Warn().Err(err).Msg("Failed to close public listener")
			}
		}
	}()

	log.Info().
		Str("remote_addr", conn.RemoteAddr()).
		Msg("Multiplexer ready, serving streams")

	// Serve streams (blocking)
	if err := multiplexer.ServeStreams(); err != nil {
		log.Error().
			Err(err).
			Str("remote_addr", conn.RemoteAddr()).
			Msg("Error serving streams")
	}
}
