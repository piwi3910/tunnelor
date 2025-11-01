# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tunnelor is a secure, high-performance QUIC-based tunneling and multiplexing platform written in Go. The system consists of two core binaries:

- **tunnelord** — Server daemon that listens for QUIC client connections and exposes local services
- **tunnelorc** — Client agent that establishes QUIC sessions, authenticates, and creates local/remote forwards

The platform enables secure tunneling of TCP/UDP traffic over QUIC with built-in TLS 1.3 encryption, stream multiplexing, and PSK-based authentication.

## Technology Stack

- **Go 1.23+** — Core language (performance, concurrency, easy deployment)
- **quic-go** — QUIC + TLS 1.3 transport layer
- **spf13/viper** and **spf13/cobra** — Configuration and CLI management
- **zerolog** — Structured logging
- **prometheus/client_golang** — Optional metrics endpoint

## Architecture Principles

### Core Components

1. **QUIC Layer** (`internal/quic`)
   - Each QUIC connection carries multiple bidirectional streams
   - QUIC streams map 1:1 to logical tunnels
   - TLS 1.3 encryption by default

2. **Control Plane** (`internal/control`)
   - Dedicated control stream per connection manages session lifecycle
   - JSON or binary framed control messages (AUTH, OPEN, CLOSE, PING, METRICS)
   - PSK-based authentication using HMAC-SHA256

3. **Multiplexing Layer** (`internal/mux`)
   - Maps QUIC streams to logical tunnels
   - Stream header format: `version(1B) | proto_id(1B) | flags(1B) | meta_len(1B) | meta(...)`
   - Protocol IDs: 0x01=TCP, 0x02=UDP, 0x03=Control, 0x04=Raw framed

4. **Forwarding Engine**
   - **TCP Bridge** (`internal/tcpbridge`) — Accepts local TCP connections, forwards over QUIC streams
   - **UDP Bridge** (`internal/udpbridge`) — Encapsulates UDP datagrams per stream

5. **Crypto** (`internal/crypto`)
   - Optional AES-GCM payload encryption for zero-trust separation
   - HMAC-SHA256 for PSK authentication

6. **Config** (`internal/config`)
   - YAML-based configuration parsing using Viper

## Development Commands

### Building
```bash
# Build server binary
go build -o bin/tunnelord ./cmd/tunnelord

# Build client binary
go build -o bin/tunnelorc ./cmd/tunnelorc

# Build both binaries
go build -o bin/ ./cmd/...
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests for specific package
go test ./internal/control

# Run integration tests
go test -tags=integration ./test/integration/...

# Verbose test output
go test -v ./...
```

### Code Quality
```bash
# Format code
go fmt ./...

# Run linter (requires golangci-lint)
golangci-lint run

# Vet code for common issues
go vet ./...

# Check for security issues (requires gosec)
gosec ./...
```

### Running
```bash
# Start server with config
./bin/tunnelord --config examples/server.yaml

# Start client with config
./bin/tunnelorc connect --config examples/client.yaml

# Add forward dynamically
./bin/tunnelorc forward --local 127.0.0.1:8080 --remote 10.0.0.5:9000 --proto tcp

# View metrics
curl http://localhost:9090/metrics
```

### Dependencies
```bash
# Download dependencies
go mod download

# Tidy dependencies
go mod tidy

# Verify dependencies
go mod verify

# Update specific dependency
go get -u github.com/quic-go/quic-go@latest
```

## Package Organization

```
tunnelor/
├── cmd/
│   ├── tunnelord/      # Server binary entry point
│   └── tunnelorc/      # Client binary entry point
├── internal/
│   ├── quic/           # QUIC connection and stream lifecycle
│   ├── control/        # Control plane messages and auth
│   ├── mux/            # Multiplexing and stream registry
│   ├── tcpbridge/      # TCP proxy adapter
│   ├── udpbridge/      # UDP proxy adapter
│   ├── crypto/         # Encryption and authentication utilities
│   └── config/         # Configuration parsing and validation
├── pkg/                # Public API (if needed for extensions)
├── test/
│   ├── integration/    # End-to-end integration tests
│   └── fixtures/       # Test data and configurations
└── examples/           # Example configurations
```

## Authentication Flow

1. Client connects to server over QUIC
2. Client opens control stream (proto_id=0x03)
3. Client sends AUTH message with `HMAC-SHA256(psk, client_id|nonce)`
4. Server verifies HMAC against PSK map in config
5. Server responds with AUTH_OK or AUTH_FAIL
6. On success, client can open data streams

## Stream Protocol

Each stream begins with a header:
- **version** (1 byte) — Protocol version
- **proto_id** (1 byte) — 0x01=TCP, 0x02=UDP, 0x03=Control, 0x04=Raw
- **flags** (1 byte) — Reserved for future use
- **meta_len** (1 byte) — Length of metadata section
- **meta** (variable) — Protocol-specific metadata

## Configuration Structure

### Server Config (server.yaml)
```yaml
server:
  listen: 0.0.0.0:4433
  tls_cert: /etc/tunnelor/server.crt
  tls_key: /etc/tunnelor/server.key
  metrics_port: 9090

auth:
  psk_map:
    "client-a": "base64secret=="
```

### Client Config (client.yaml)
```yaml
client:
  server: quic://myserver.com:4433
  client_id: pascal
  psk: base64secret==
  forwards:
    - local: 127.0.0.1:8080
      remote: 10.0.0.5:9000
      proto: tcp
```

## Testing Strategy

### Unit Tests
- Frame parsing and serialization
- Control message validation
- HMAC authentication logic
- Stream header encoding/decoding

### Integration Tests
- QUIC echo between client and server
- TCP tunnel end-to-end data correctness
- UDP datagram order and size preservation
- Connection reconnect and resume
- Authentication success/failure scenarios

### Load Tests
- Simulate 500+ concurrent streams
- Measure throughput and latency
- Verify memory footprint stays < 50 MB per daemon

## Performance Targets

- **Concurrent Streams:** 500+
- **Reconnect Time:** < 3 seconds
- **Latency Overhead:** < 10ms vs TCP baseline
- **Memory Footprint:** < 50 MB per daemon

## Security Considerations

- QUIC/TLS 1.3 provides transport encryption
- PSK never logged or transmitted in plaintext
- Rate-limit control plane messages to prevent DoS
- Validate all message sizes and fields to avoid buffer exhaustion
- Implement PSK rotation strategy for production use
- Use constant-time comparison for HMAC validation

## MVP Acceptance Criteria

1. Client authenticates successfully using PSK
2. Client opens TCP stream and performs round-trip echo test
3. Server logs connections, streams, and bytes transferred
4. QUIC reconnection supported after transient network loss
5. Metrics endpoint returns Prometheus-formatted data

## Common Pitfalls

### QUIC Stream Management
- Always close streams explicitly to prevent resource leaks
- Handle stream errors gracefully (connection loss, peer reset)
- Respect QUIC flow control to avoid blocking

### Control Plane
- Control messages must be framed to avoid partial reads
- Implement timeouts for authentication to prevent hanging connections
- Validate control message types before processing

### Forwarding
- TCP bridges must handle half-closed connections
- UDP requires proper session tracking for bidirectional flows
- Buffer sizes should be tunable for different network conditions

## Error Handling Patterns

```go
// Always wrap errors with context
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// Use zerolog for structured error logging
log.Error().Err(err).Str("client_id", clientID).Msg("authentication failed")

// Close resources with defer
stream, err := conn.OpenStream()
if err != nil {
    return err
}
defer stream.Close()
```

## Logging Standards

- Use zerolog for all logging
- Include contextual fields: `client_id`, `stream_id`, `proto`, `local_addr`, `remote_addr`
- Log levels:
  - **Debug:** Protocol-level details, stream lifecycle events
  - **Info:** Connection establishment, successful auth, forwards created
  - **Warn:** Retries, degraded performance, auth failures
  - **Error:** Critical failures, connection drops, unrecoverable errors
- Never log PSK values or sensitive authentication material

## Metrics to Track

- Active QUIC connections
- Total streams opened/closed
- Bytes transferred per stream type (TCP/UDP)
- Authentication success/failure rates
- Stream errors and reconnection attempts
- Latency histograms per protocol type
