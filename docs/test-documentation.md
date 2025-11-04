# Tunnelor Test Documentation

This document provides comprehensive documentation for all unit tests and integration tests in the Tunnelor project.

## Table of Contents

- [Overview](#overview)
- [Unit Tests](#unit-tests)
  - [Control Package Tests](#control-package-tests)
  - [Multiplexer Tests](#multiplexer-tests)
  - [TCP Bridge Tests](#tcp-bridge-tests)
  - [UDP Bridge Tests](#udp-bridge-tests)
  - [Configuration Tests](#configuration-tests)
  - [Logger Tests](#logger-tests)
  - [Metrics Tests](#metrics-tests)
  - [IPC Tests](#ipc-tests)
  - [Server Tests](#server-tests)
- [Integration Tests](#integration-tests)
  - [Basic Integration Tests](#basic-integration-tests)
  - [Suite-Based Integration Tests](#suite-based-integration-tests)
- [Test Execution](#test-execution)
- [Test Coverage](#test-coverage)

## Overview

Tunnelor uses a comprehensive testing strategy that includes:

- **Unit Tests**: Test individual components in isolation
- **Integration Tests**: Test end-to-end functionality of the complete system
- **Build Tag Tests**: Integration tests are separated using `+build integration` tags

All tests are written using:
- **Testing Framework**: [Testify](https://github.com/stretchr/testify) for assertions and test suites
- **Test Runner**: Go's built-in testing package
- **Coverage Tool**: `go test -cover`

---

## Unit Tests

### Control Package Tests

**Location**: `internal/control/control_test.go`

The control package handles authentication, session management, and control plane messaging.

#### Authentication Tests

##### `TestGenerateNonce`
- **Purpose**: Verify nonce generation produces unique random values
- **Validates**:
  - Nonce length is exactly 32 characters (16 bytes hex-encoded)
  - Successive calls produce different nonces
  - No errors during generation
- **Coverage**: Randomness and uniqueness of authentication nonces

##### `TestComputeHMAC`
- **Purpose**: Test HMAC-SHA256 computation with base64-encoded keys
- **Validates**:
  - HMAC computation succeeds with valid base64 PSK
  - Same message produces same HMAC (determinism)
  - Different messages produce different HMACs
- **Coverage**: Core HMAC calculation logic

##### `TestComputeHMACInvalidKey`
- **Purpose**: Verify error handling for invalid base64 keys
- **Validates**: Function returns error when PSK is not valid base64
- **Coverage**: Error handling for malformed input

##### `TestVerifyHMAC`
- **Purpose**: Test HMAC verification using constant-time comparison
- **Validates**:
  - Correct HMAC passes verification
  - Incorrect HMAC fails verification
  - Different message fails verification even with valid HMAC
- **Coverage**: HMAC verification logic and security

##### `TestCreateAuthPayload`
- **Purpose**: Test authentication payload format
- **Validates**: Payload format is `clientID|nonce`
- **Coverage**: Authentication message structure

##### `TestComputeAuthHMAC`
- **Purpose**: Test authentication-specific HMAC computation
- **Validates**: HMAC is computed correctly for auth payload
- **Coverage**: Authentication flow HMAC generation

##### `TestVerifyAuthHMAC`
- **Purpose**: Test complete auth HMAC verification flow
- **Validates**:
  - Valid authentication HMAC passes
  - Invalid HMAC fails
  - Wrong client ID fails verification
- **Coverage**: End-to-end authentication verification

#### Message Handling Tests

##### `TestNewMessage`
- **Purpose**: Test control message creation
- **Validates**:
  - Messages can be created without data (e.g., PING)
  - Messages can be created with struct data (e.g., AuthMessage)
  - Messages can be created with map data (e.g., metrics)
- **Coverage**: Message construction for all types

##### `TestMessageParseData`
- **Purpose**: Test parsing message data into typed structs
- **Validates**:
  - JSON data correctly unmarshals into struct
  - All fields are preserved
- **Coverage**: Message data deserialization

##### `TestMessageParseDataNoData`
- **Purpose**: Verify error handling when parsing empty messages
- **Validates**: Error is returned when no data exists
- **Coverage**: Error handling for invalid parse operations

##### `TestMessageMarshalUnmarshal`
- **Purpose**: Test complete message serialization round-trip
- **Validates**:
  - Message marshals to bytes
  - Bytes unmarshal back to identical message
  - All fields preserved
- **Coverage**: Full serialization/deserialization cycle

##### `TestUnmarshalMessageInvalid`
- **Purpose**: Test error handling for invalid JSON
- **Validates**: Invalid JSON returns error
- **Coverage**: Error handling for corrupted messages

##### `TestAllMessageTypes`
- **Purpose**: Verify all message types can be created
- **Validates**: Each MessageType constant creates valid message
- **Coverage**: Complete message type enumeration

#### Framing Tests

##### `TestWriteReadMessageBuffered`
- **Purpose**: Test length-prefixed message framing
- **Validates**:
  - Messages write with 4-byte length prefix
  - Messages read correctly from buffer
  - Data integrity maintained
- **Coverage**: Message framing protocol

##### `TestWriteMessageBufferedTooLarge`
- **Purpose**: Test maximum message size enforcement
- **Validates**: Messages exceeding `MaxMessageSize` return error
- **Coverage**: Message size limits

##### `TestReadMessageBufferedTooLarge`
- **Purpose**: Test rejection of oversized incoming messages
- **Validates**: Oversized length prefix triggers error
- **Coverage**: Protection against memory exhaustion attacks

##### `TestReadMessageBufferedEOF`
- **Purpose**: Test EOF handling
- **Validates**: EOF on empty stream returns error
- **Coverage**: Stream termination handling

##### `TestMultipleMessagesBuffered`
- **Purpose**: Test reading sequence of messages
- **Validates**:
  - Multiple messages can be written sequentially
  - Each message reads correctly in order
  - No message boundaries crossed
- **Coverage**: Message stream handling

#### Handler Tests

##### `TestNewClientHandler`
- **Purpose**: Test client handler construction
- **Validates**:
  - Handler is created successfully with valid PSK
  - PSK cache is initialized
  - Client ID is set correctly
  - Session ID starts empty
- **Coverage**: Client handler initialization

##### `TestClientHandlerGetSessionID`
- **Purpose**: Test session ID getter
- **Validates**:
  - Initially returns empty string
  - Returns session ID after authentication
- **Coverage**: Session ID management

##### `TestClientHandlerIsAuthenticated`
- **Purpose**: Test authentication status tracking
- **Validates**:
  - Returns false before authentication
  - Returns true after session ID is set
- **Coverage**: Authentication state management

##### `TestNewServerHandler`
- **Purpose**: Test server handler construction
- **Validates**:
  - Handler created successfully with PSK map
  - PSK cache map is pre-populated
  - Sessions map is initialized
  - Correct number of PSK caches created
- **Coverage**: Server handler initialization with PSK caching optimization

##### `TestServerHandlerSessionManagement`
- **Purpose**: Test session CRUD operations
- **Validates**:
  - Initially has zero sessions
  - Sessions can be added
  - Sessions can be retrieved
  - Sessions can be removed
  - Session count updates correctly
- **Coverage**: Session lifecycle management

##### `TestServerHandlerMultipleSessions`
- **Purpose**: Test managing multiple concurrent sessions
- **Validates**:
  - Multiple sessions can coexist
  - Each session is independently retrievable
  - Removing one session doesn't affect others
  - Session count is accurate
- **Coverage**: Concurrent session handling

---

### Multiplexer Tests

**Location**: `internal/mux/multiplexer_test.go`, `internal/mux/protocol_test.go`

#### Multiplexer Core Tests

##### `TestNewMultiplexer`
- **Purpose**: Test multiplexer construction
- **Validates**:
  - Multiplexer is created successfully
  - Internal maps are initialized
  - Connection reference is stored
- **Coverage**: Multiplexer initialization

##### `TestRegisterHandler`
- **Purpose**: Test handler registration
- **Validates**:
  - Handler can be registered for protocol
  - Registration is confirmed
- **Coverage**: Handler registration mechanism

##### `TestRegisterMultipleHandlers`
- **Purpose**: Test registering handlers for different protocols
- **Validates**:
  - Each protocol can have its own handler
  - All four protocol types supported (TCP, UDP, Control, Raw)
- **Coverage**: Multi-protocol handler setup

##### `TestGetStream`
- **Purpose**: Test stream tracking and retrieval
- **Validates**:
  - Streams are tracked by ID
  - Streams can be retrieved by ID
  - Non-existent streams return nil
- **Coverage**: Stream registry operations

##### `TestStreamCount`
- **Purpose**: Test stream counting
- **Validates**: Active stream count is accurate
- **Coverage**: Stream lifecycle tracking

##### `TestClose`
- **Purpose**: Test multiplexer shutdown
- **Validates**:
  - Close completes without error
  - Resources are cleaned up
- **Coverage**: Graceful shutdown

##### `TestCloseIdempotent`
- **Purpose**: Test multiple close calls
- **Validates**: Multiple close calls don't cause errors
- **Coverage**: Idempotent shutdown

##### `TestCloseWithActiveStreams`
- **Purpose**: Test closing with active streams
- **Validates**: Close succeeds even with active streams
- **Coverage**: Shutdown with in-flight operations

##### `TestHandlerNotFound`
- **Purpose**: Test handling unknown protocols
- **Validates**: Error returned for unregistered protocol
- **Coverage**: Error handling for missing handlers

##### `TestRegisterHandlerOverwrite`
- **Purpose**: Test handler replacement
- **Validates**: Newer handler replaces older one
- **Coverage**: Handler update mechanism

##### `TestStreamOperations`
- **Purpose**: Test stream lifecycle operations
- **Validates**:
  - Streams can be added
  - Streams can be removed
  - Count updates correctly
- **Coverage**: Complete stream lifecycle

##### `TestConcurrentHandlerRegistration`
- **Purpose**: Test thread-safe handler registration
- **Validates**: Concurrent registration doesn't cause races
- **Coverage**: Thread safety of registration

#### Protocol Tests

##### `TestProtocolID_String`
- **Purpose**: Test protocol ID string representation
- **Validates**:
  - Each protocol has correct string name
  - Unknown protocols show as "UNKNOWN"
- **Coverage**: Protocol enumeration

##### `TestNewStreamHeader`
- **Purpose**: Test stream header construction
- **Validates**:
  - Headers created with/without metadata
  - Metadata size limits enforced
  - Headers at max size succeed
  - Oversized metadata rejected
- **Coverage**: Stream header validation

##### `TestWriteReadHeader`
- **Purpose**: Test header serialization
- **Validates**:
  - Headers with metadata serialize correctly
  - Headers without metadata serialize correctly
  - Flags are preserved
  - Round-trip produces identical header
- **Coverage**: Header wire format

##### `TestReadHeaderInvalidVersion`
- **Purpose**: Test version validation
- **Validates**: Invalid protocol version returns error
- **Coverage**: Protocol version enforcement

##### `TestHeaderSize`
- **Purpose**: Test header size calculation
- **Validates**:
  - Base header is 4 bytes
  - Metadata adds to size correctly
- **Coverage**: Header size computation

##### `TestHeaderFlags`
- **Purpose**: Test flag handling
- **Validates**: Flags are correctly stored and retrieved
- **Coverage**: Flag bits in header

##### `TestEncodeTCPMetadata`/`TestDecodeTCPMetadata`
- **Purpose**: Test TCP metadata encoding/decoding
- **Validates**:
  - Source and target addresses encoded correctly
  - JSON format is correct
  - Round-trip preserves data
- **Coverage**: TCP metadata serialization

##### `TestDecodeUDPMetadata`/`TestEncodeUDPMetadata`
- **Purpose**: Test UDP metadata encoding/decoding
- **Validates**:
  - Source and target addresses encoded correctly
  - Round-trip preserves data
- **Coverage**: UDP metadata serialization

##### `TestMetadataRoundTrip`
- **Purpose**: Test complete metadata serialization cycle
- **Validates**: Encode→Decode produces identical data
- **Coverage**: Metadata integrity

##### `TestReadHeaderEOF`
- **Purpose**: Test EOF handling during header read
- **Validates**: EOF returns appropriate error
- **Coverage**: Stream termination

##### `TestReadHeaderIncomplete`
- **Purpose**: Test partial header read
- **Validates**: Incomplete header returns error
- **Coverage**: Framing error handling

##### `TestWriteHeaderError`
- **Purpose**: Test write error handling
- **Validates**: Write errors are propagated
- **Coverage**: I/O error handling

---

### TCP Bridge Tests

**Location**: `internal/tcpbridge/bridge_test.go`

##### `TestQUICToTCP`
- **Purpose**: Test complete QUIC-to-TCP bridging
- **Validates**:
  - QUIC stream connects to TCP endpoint
  - Data flows bidirectionally
  - Echo test succeeds
  - Connections close cleanly
- **Coverage**: End-to-end TCP bridging

##### `TestQUICToTCPConnectionRefused`
- **Purpose**: Test error handling for unreachable TCP targets
- **Validates**: Connection refused error is handled gracefully
- **Coverage**: Error handling for unavailable targets

##### `TestQUICToTCPBufferPooling`
- **Purpose**: Test buffer pool usage
- **Validates**:
  - Buffers are obtained from pool
  - Buffers are returned to pool after use
  - Pool New function creates correct size buffers
- **Coverage**: Buffer pooling optimization

##### `TestQUICToTCPConcurrent`
- **Purpose**: Test multiple concurrent TCP bridges
- **Validates**:
  - Multiple bridges can run simultaneously
  - Each bridge maintains independent data flow
  - No data corruption between bridges
- **Coverage**: Concurrent bridge operations

---

### UDP Bridge Tests

**Location**: `internal/udpbridge/bridge_test.go`

##### `TestQUICToUDP`
- **Purpose**: Test complete QUIC-to-UDP bridging
- **Validates**:
  - QUIC stream connects to UDP endpoint
  - Datagrams flow bidirectionally
  - Echo test succeeds
  - Connections close cleanly
- **Coverage**: End-to-end UDP bridging

##### `TestQUICToUDPInvalidAddress`
- **Purpose**: Test error handling for invalid UDP addresses
- **Validates**: Invalid address format returns error
- **Coverage**: Input validation

##### `TestQUICToUDPBufferPooling`
- **Purpose**: Test UDP buffer pool usage
- **Validates**:
  - Buffers obtained from pool
  - Buffers returned after use
  - Correct buffer size
- **Coverage**: UDP buffer pooling optimization

---

### Configuration Tests

**Location**: `internal/config/config_test.go`

Tests configuration loading, validation, and parsing for both server and client configurations including TLS settings, PSK maps, and forward definitions.

---

### Logger Tests

**Location**: `internal/logger/logger_test.go`

Tests structured logging setup with various log levels, formatting options (pretty vs JSON), and output configurations.

---

### Metrics Tests

**Location**: `internal/metrics/metrics_test.go`

Tests Prometheus metrics collection, registration, and HTTP endpoint serving for monitoring active connections, streams, and data transfer.

---

### IPC Tests

**Location**: `internal/ipc/ipc_test.go`

Tests inter-process communication mechanisms used for runtime control and status reporting.

---

### Server Tests

**Location**: `internal/server/connection_manager_test.go`

Tests connection lifecycle management, client tracking, and concurrent connection handling.

---

## Integration Tests

Integration tests verify the complete system working together, from QUIC connection establishment through authentication to data forwarding.

### Basic Integration Tests

**Location**: `test/integration/basic_test.go`

These tests run independently without test suites, creating fresh components for each test.

#### `TestBasicConnection`
- **Purpose**: Verify basic QUIC connection establishment
- **Setup**:
  - Generate self-signed TLS certificates
  - Start QUIC server on random port
  - Create QUIC client
- **Validates**:
  - Server starts successfully
  - Client connects to server
  - Connection object is valid
- **Coverage**: Basic QUIC connectivity
- **Duration**: ~260ms

#### `TestAuthentication`
- **Purpose**: Test PSK-based authentication flow
- **Setup**:
  - Create QUIC server and client
  - Configure PSK map on server
  - Configure PSK on client
- **Flow**:
  1. Client connects via QUIC
  2. Server accepts connection
  3. Client opens control stream
  4. Client sends AUTH message with HMAC
  5. Server verifies HMAC against PSK map
  6. Server responds with AUTH_OK and session ID
  7. Client stores session ID
- **Validates**:
  - Authentication succeeds with valid PSK
  - Session ID is assigned
  - Client is marked as authenticated
- **Coverage**: Complete authentication protocol
- **Duration**: ~170ms

#### `TestStreamMultiplexing`
- **Purpose**: Test opening and using multiple multiplexed streams
- **Setup**:
  - Establish authenticated QUIC connection
  - Create multiplexers on both sides
  - Register echo handler on server
- **Flow**:
  1. Client opens 3 separate streams
  2. Each stream sends unique message
  3. Server echoes data back
  4. Client verifies echoed data
- **Validates**:
  - Multiple streams can coexist
  - Each stream maintains independent data flow
  - Stream headers are parsed correctly
  - Data integrity maintained per stream
- **Coverage**: Stream multiplexing protocol
- **Duration**: ~220ms

#### `TestTCPForwarding`
- **Purpose**: Test end-to-end TCP forwarding through QUIC tunnel
- **Setup**:
  1. Create TCP echo server (simulates remote service)
  2. Create QUIC server (tunnel endpoint)
  3. Create QUIC client
  4. Authenticate
  5. Setup multiplexers with TCP handler
- **Flow**:
  1. Client opens TCP stream with target metadata
  2. Server receives stream and connects to TCP target
  3. Server sets up bidirectional copy (QUIC ↔ TCP)
  4. Client sends 3 test messages
  5. Data flows: Client → QUIC → Server → TCP → Echo → TCP → Server → QUIC → Client
  6. Client verifies echoed data
- **Validates**:
  - TCP metadata encoding/decoding
  - Bidirectional TCP forwarding
  - Data integrity through tunnel
  - Multiple messages on same stream
- **Coverage**: Complete TCP tunneling
- **Duration**: ~280ms

#### `TestUDPForwarding`
- **Purpose**: Test end-to-end UDP forwarding through QUIC tunnel
- **Setup**:
  1. Create UDP echo server
  2. Create QUIC tunnel endpoints
  3. Authenticate
  4. Setup multiplexers with UDP handler
- **Flow**:
  1. Client opens UDP stream with target metadata
  2. Server receives stream and creates UDP socket
  3. Server sets up bidirectional forwarding (QUIC ↔ UDP)
  4. Client sends 3 UDP datagrams
  5. Data flows: Client → QUIC → Server → UDP → Echo → UDP → Server → QUIC → Client
  6. Client verifies echoed datagrams
- **Validates**:
  - UDP metadata encoding/decoding
  - UDP datagram forwarding
  - Datagram ordering and integrity
  - QUIC stream used as reliable UDP carrier
- **Coverage**: Complete UDP tunneling
- **Duration**: ~220ms

---

### Suite-Based Integration Tests

**Location**: `test/integration/suite_test.go`, `test/integration/connection_test.go`

These tests use Testify's suite package for shared setup/teardown and reusable test infrastructure.

#### Suite Setup (`TunnelorIntegrationSuite`)

The suite provides:
- Automatic TLS certificate generation
- QUIC server/client lifecycle management
- Authentication helpers
- TCP/UDP echo server management
- Multiplexer setup

**Lifecycle Methods**:
- `SetupSuite()`: Runs once before all tests
- `SetupTest()`: Runs before each test
  - Generates TLS certificates
  - Starts QUIC server
  - Creates QUIC client
  - Performs authentication
- `TearDownTest()`: Runs after each test
  - Closes connections
  - Cleans up resources

#### Suite Tests

##### `TestAuthentication`
- **Purpose**: Verify authentication in suite context
- **Validates**: Same as basic auth test but using suite infrastructure
- **Coverage**: Authentication with reusable components

##### `TestBasicConnection`
- **Purpose**: Verify QUIC connection in suite context
- **Validates**: Connection establishment using suite
- **Coverage**: Basic connectivity

##### `TestStreamMultiplexing`
- **Purpose**: Test stream multiplexing in suite context
- **Validates**: Multiple streams with suite infrastructure
- **Coverage**: Stream multiplexing

##### `TestTCPBridge`
- **Purpose**: Test direct TCP bridge functionality
- **Flow**:
  1. Suite sets up TCP echo server
  2. Client uses tcpbridge.QUICToTCP directly
  3. Data sent and verified
- **Validates**: TCP bridge component in isolation
- **Coverage**: tcpbridge package integration

##### `TestTCPForwarding`
- **Purpose**: Test TCP forwarding with multiplexer
- **Validates**: Same as basic TCP forwarding but with suite
- **Coverage**: Complete TCP tunneling via multiplexer

##### `TestUDPBridge`
- **Purpose**: Test direct UDP bridge functionality
- **Flow**:
  1. Suite sets up UDP echo server
  2. Client uses udpbridge.QUICToUDP directly
  3. Datagrams sent and verified
- **Validates**: UDP bridge component in isolation
- **Coverage**: udpbridge package integration

---

## Test Execution

### Running All Tests

```bash
# Run all unit tests
go test ./...

# Run with verbose output
go test -v ./...

# Run with coverage
go test -cover ./...
```

### Running Integration Tests

Integration tests are tagged with `+build integration`:

```bash
# Run only integration tests
go test -tags=integration ./test/integration -v

# Run specific integration test
go test -tags=integration ./test/integration -run TestTCPForwarding -v
```

### Running Specific Package Tests

```bash
# Control package
go test ./internal/control -v

# Multiplexer package
go test ./internal/mux -v

# TCP bridge
go test ./internal/tcpbridge -v

# UDP bridge
go test ./internal/udpbridge -v
```

### Running Specific Tests

```bash
# Run single test by name
go test ./internal/control -run TestComputeHMAC -v

# Run tests matching pattern
go test ./internal/control -run "TestClient.*" -v
```

### Test Timeouts

Integration tests have longer timeouts for network operations:

```bash
# Run with custom timeout
go test -tags=integration ./test/integration -timeout 5m -v
```

---

## Test Coverage

### Generating Coverage Reports

```bash
# Generate coverage profile
go test -coverprofile=coverage.out ./...

# View coverage in terminal
go tool cover -func=coverage.out

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html
```

### Coverage Breakdown by Package

**High Coverage (>80%)**:
- `internal/control` - Authentication and messaging
- `internal/mux` - Multiplexing and protocol handling
- `internal/tcpbridge` - TCP forwarding
- `internal/udpbridge` - UDP forwarding

**Medium Coverage (50-80%)**:
- `internal/config` - Configuration parsing
- `internal/logger` - Logging setup
- `internal/metrics` - Metrics collection

**Integration Coverage**:
- Full end-to-end scenarios
- Multi-component interaction
- Real network I/O
- Authentication flows
- Data forwarding paths

---

## Test Best Practices

### Unit Test Guidelines

1. **Isolation**: Each unit test tests one component in isolation
2. **Mocking**: Use interfaces to mock dependencies (e.g., QUIC connections)
3. **Table-Driven**: Use table-driven tests for multiple scenarios
4. **Assertions**: Use testify/assert and testify/require for clear error messages
5. **Cleanup**: Always clean up resources with defer

### Integration Test Guidelines

1. **Real Components**: Use actual QUIC, TCP, UDP - no mocking
2. **Randomized Ports**: Use port 0 to avoid conflicts
3. **Self-Signed Certs**: Generate fresh certs per test
4. **Cleanup**: Ensure all connections and servers are closed
5. **Timeouts**: Use appropriate timeouts for network operations
6. **Concurrency**: Test concurrent scenarios to find race conditions

### Common Test Patterns

#### Error Testing
```go
err := SomeFunction()
assert.Error(t, err, "Expected error for invalid input")
```

#### Success Testing
```go
result, err := SomeFunction()
require.NoError(t, err, "Should not error")
assert.Equal(t, expected, result)
```

#### Table-Driven Tests
```go
tests := []struct {
    name    string
    input   string
    want    string
    wantErr bool
}{
    {"valid", "input1", "output1", false},
    {"invalid", "bad", "", true},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        got, err := Function(tt.input)
        if tt.wantErr {
            assert.Error(t, err)
        } else {
            assert.NoError(t, err)
            assert.Equal(t, tt.want, got)
        }
    })
}
```

---

## Troubleshooting Test Failures

### Common Issues

**Port Already in Use**:
- Integration tests use random ports (`:0`)
- If you see port conflicts, ensure old processes are killed

**TLS Certificate Issues**:
- Tests generate self-signed certs in temp directories
- Certs are automatically cleaned up after tests

**Timeout Failures**:
- Network operations may be slow on some systems
- Increase timeout if needed: `-timeout 10m`

**Race Conditions**:
- Run with race detector: `go test -race ./...`
- Fix any data races before committing

### Debugging Tests

```bash
# Enable verbose logging
go test -v ./internal/control

# Run specific failing test
go test -run TestFailingFunction -v

# Run with race detector
go test -race ./...

# Show detailed coverage
go test -cover -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

---

## Test Metrics

### Test Execution Time (Approximate)

**Unit Tests** (~6 seconds total):
- Control: ~1.5s
- Mux: ~0.5s
- TCP Bridge: ~2.7s
- UDP Bridge: ~2.2s
- Other: ~1s

**Integration Tests** (~2.7 seconds total):
- Basic tests: ~1.2s
- Suite tests: ~1.5s

**Total Test Suite**: ~9 seconds

### Test Counts

- **Unit Tests**: ~140 tests across 10 packages
- **Integration Tests**: 11 comprehensive end-to-end tests
- **Total**: 150+ tests

---

## Continuous Integration

For CI/CD pipelines, run:

```bash
# Full test suite with coverage
go test -v -race -coverprofile=coverage.out ./...

# Integration tests
go test -v -tags=integration ./test/integration

# Coverage report
go tool cover -func=coverage.out

# Fail if coverage below threshold
go tool cover -func=coverage.out | grep total | awk '{if ($3+0 < 75.0) exit 1}'
```

---

## Future Test Improvements

1. **Benchmark Tests**: Add performance benchmarks for critical paths
2. **Fuzz Testing**: Add fuzzing for protocol parsing
3. **Chaos Testing**: Test network failures and recovery
4. **Load Testing**: Test with thousands of concurrent streams
5. **Security Testing**: Add tests for attack scenarios
6. **Property-Based Testing**: Use rapid or gopter for property tests
