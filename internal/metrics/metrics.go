// Package metrics provides Prometheus metrics collection for the Tunnelor system.
package metrics

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
)

var (
	registerOnce sync.Once
	registered   bool
)

var (
	// ActiveConnections tracks the number of active QUIC connections
	ActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tunnelor_active_connections",
		Help: "Number of active QUIC connections",
	})

	// TotalConnections tracks the total number of connections established
	TotalConnections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelor_total_connections",
		Help: "Total number of connections established",
	}, []string{"client_id"})

	// ActiveStreams tracks the number of active streams by protocol
	ActiveStreams = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "tunnelor_active_streams",
		Help: "Number of active streams by protocol",
	}, []string{"protocol"}) // protocol: tcp, udp, control

	// TotalStreams tracks the total number of streams opened by protocol
	TotalStreams = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelor_total_streams",
		Help: "Total number of streams opened by protocol",
	}, []string{"protocol"})

	// StreamErrors tracks stream errors by protocol
	StreamErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelor_stream_errors",
		Help: "Number of stream errors by protocol",
	}, []string{"protocol"})

	// BytesTransferred tracks bytes transferred by protocol and direction
	BytesTransferred = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelor_bytes_transferred",
		Help: "Bytes transferred by protocol and direction",
	}, []string{"protocol", "direction"}) // direction: sent, received

	// AuthenticationAttempts tracks authentication attempts by result
	AuthenticationAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelor_auth_attempts",
		Help: "Authentication attempts by result",
	}, []string{"result"}) // result: success, failure

	// StreamLatency tracks stream operation latency by protocol
	StreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tunnelor_stream_latency_seconds",
		Help:    "Stream operation latency in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"protocol", "operation"}) // operation: open, close, data_transfer

	// ConnectionDuration tracks connection duration
	ConnectionDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "tunnelor_connection_duration_seconds",
		Help:    "Duration of QUIC connections in seconds",
		Buckets: []float64{1, 5, 10, 30, 60, 300, 600, 1800, 3600, 7200},
	})

	// UDPSessionCount tracks the number of active UDP sessions
	UDPSessionCount = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tunnelor_udp_sessions",
		Help: "Number of active UDP sessions",
	})

	// StreamReconnects tracks stream reconnection attempts
	StreamReconnects = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnelor_stream_reconnects",
		Help: "Number of stream reconnection attempts",
	}, []string{"protocol"})
)

// Server represents a Prometheus metrics HTTP server
type Server struct {
	httpServer *http.Server
	port       int
}

// NewServer creates a new metrics server
func NewServer(port int) *Server {
	return &Server{
		port: port,
	}
}

// Start starts the metrics HTTP server
func Start(port int) (*Server, error) {
	server := NewServer(port)
	if err := server.Start(); err != nil {
		return nil, err
	}
	return server, nil
}

// Start starts the metrics server
func (s *Server) Start() error {
	// Register all metrics (only once)
	registerOnce.Do(func() {
		prometheus.MustRegister(
			ActiveConnections,
			TotalConnections,
			ActiveStreams,
			TotalStreams,
			StreamErrors,
			BytesTransferred,
			AuthenticationAttempts,
			StreamLatency,
			ConnectionDuration,
			UDPSessionCount,
			StreamReconnects,
		)
		registered = true
	})

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	s.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", s.port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Start server in background
	go func() {
		log.Info().
			Int("port", s.port).
			Msg("Starting metrics server")

		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Metrics server error")
		}
	}()

	return nil
}

// Stop gracefully stops the metrics server
func (s *Server) Stop() error {
	if s.httpServer == nil {
		return nil
	}

	log.Info().Msg("Stopping metrics server")
	return s.httpServer.Close()
}

// RecordConnectionStart records a new connection start
func RecordConnectionStart(clientID string) {
	ActiveConnections.Inc()
	TotalConnections.WithLabelValues(clientID).Inc()
}

// RecordConnectionEnd records a connection end
func RecordConnectionEnd(duration time.Duration) {
	ActiveConnections.Dec()
	ConnectionDuration.Observe(duration.Seconds())
}

// RecordStreamOpen records a stream opening
func RecordStreamOpen(protocol string) {
	ActiveStreams.WithLabelValues(protocol).Inc()
	TotalStreams.WithLabelValues(protocol).Inc()
}

// RecordStreamClose records a stream closing
func RecordStreamClose(protocol string) {
	ActiveStreams.WithLabelValues(protocol).Dec()
}

// RecordStreamError records a stream error
func RecordStreamError(protocol string) {
	StreamErrors.WithLabelValues(protocol).Inc()
}

// RecordBytesTransferred records bytes transferred
func RecordBytesTransferred(protocol, direction string, bytes int64) {
	BytesTransferred.WithLabelValues(protocol, direction).Add(float64(bytes))
}

// RecordAuthAttempt records an authentication attempt
func RecordAuthAttempt(success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	AuthenticationAttempts.WithLabelValues(result).Inc()
}

// RecordStreamLatency records stream operation latency
func RecordStreamLatency(protocol, operation string, duration time.Duration) {
	StreamLatency.WithLabelValues(protocol, operation).Observe(duration.Seconds())
}

// RecordStreamReconnect records a stream reconnection attempt
func RecordStreamReconnect(protocol string) {
	StreamReconnects.WithLabelValues(protocol).Inc()
}

// SetUDPSessionCount sets the current UDP session count
func SetUDPSessionCount(count int) {
	UDPSessionCount.Set(float64(count))
}
