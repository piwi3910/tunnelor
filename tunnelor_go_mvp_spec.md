# Tunnelor: Go-based QUIC Tunneling and Multiplexing Platform (MVP)

## Overview
**Tunnelor** is a secure, high-performance client-server system for tunneling multiple protocols (TCP, UDP, and custom framed streams) over QUIC, leveraging Go's `quic-go` library. The goal of the MVP is to deliver a lightweight, encrypted, multiplexed tunnel that can efficiently forward diverse network traffic between endpoints, with a simple configuration and CLI.

The system comprises two core binaries:
- **tunnelord** — Server daemon listening for QUIC client connections and exposing local services.
- **tunnelorc** — Client agent establishing QUIC sessions, authenticating, and creating local or remote forwards.

The design enables low-latency, secure communication through QUIC’s TLS 1.3 encryption and multiplexed stream capabilities.

---

## Goals
- Provide a reliable **tunnel for TCP/UDP** over QUIC.
- Enable **stream multiplexing** (many logical channels per QUIC connection).
- Implement **secure authentication** using a pre-shared key (PSK) model.
- Support **bidirectional forwarding** between local and remote ports.
- Deliver a simple **CLI + YAML config** system.
- Keep footprint minimal and cross-platform friendly.

---

## Tech Stack
| Component | Technology | Purpose |
|------------|-------------|----------|
| Core language | Go 1.23+ | Performance, concurrency, easy deployment |
| QUIC transport | [`quic-go`](https://github.com/quic-go/quic-go) | QUIC + TLS 1.3 transport layer |
| Config | `spf13/viper`, `spf13/cobra` | Config + CLI management |
| Logging | `zerolog` | Structured logging |
| Metrics | `prometheus/client_golang` | Optional metrics endpoint |

---

## System Architecture

### High-Level Diagram
```
          +-----------------------+                 +-----------------------+
          |      tunnelorc        |                 |       tunnelord       |
          | (Client / Edge Node)  |                 |  (Server / Gateway)   |
          +-----------------------+                 +-----------------------+
          | Local TCP/UDP Listener|                 |  QUIC Listener :4433  |
          | QUIC Session Manager  | <====QUIC====>  |  Connection Manager   |
          | Stream Multiplexer    |                 |  Stream Dispatcher    |
          | Control Channel (AUTH)|                 |  Control Channel Auth |
          +-----------------------+                 +-----------------------+
```

---

## Core Components

### 1. QUIC Layer
- Uses `quic-go` for transport.
- Each QUIC connection carries multiple **bidirectional streams**.
- QUIC streams are mapped 1:1 to logical tunnels.
- TLS 1.3 encryption is provided by default.

### 2. Control Plane
- A **dedicated control stream** per connection manages session lifecycle.
- Control messages are JSON or binary framed:
  ```json
  {
    "type": "AUTH",
    "client_id": "pascal",
    "hmac": "abc123...",
    "nonce": "xyz..."
  }
  ```

#### Control Message Types
| Type | Direction | Description |
|------|------------|-------------|
| AUTH | Client → Server | Authenticate session using PSK |
| AUTH_OK / AUTH_FAIL | Server → Client | Acknowledge authentication |
| OPEN | Client → Server | Request new logical tunnel |
| CLOSE | Bidirectional | Close a specific stream |
| METRICS | Server → Client | Send session metrics |
| PING | Bidirectional | Keepalive |

### 3. Multiplexing Layer
- Manages mapping between QUIC streams and logical tunnels.
- Each stream starts with a small header:
  ```
  version(1B) | proto_id(1B) | flags(1B) | meta_len(1B) | meta(...)
  ```
- Supported `proto_id` values:
  - `0x01` — TCP stream
  - `0x02` — UDP datagram
  - `0x03` — Control
  - `0x04` — Raw framed data

### 4. Forwarding Engine
- **TCP Bridge:**
  - Accepts local connections and forwards over QUIC streams.
  - Remote endpoint connects to specified target and returns data.
- **UDP Bridge:**
  - Receives datagrams, encapsulates them per stream, reassembles at destination.

### 5. Authentication
- PSK-based authentication over control stream:
  - Client computes `HMAC-SHA256(psk, client_id|nonce)`.
  - Server verifies HMAC against known PSK map.

---

## Configuration

### Server config (server.yaml)
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

### Client config (client.yaml)
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

---

## CLI Examples

### Start server
```bash
tunnelord --config /etc/tunnelor/server.yaml
```

### Start client
```bash
tunnelorc connect --config ./client.yaml
```

### Add a new forward
```bash
tunnelorc forward --local 127.0.0.1:8080 --remote 10.0.0.5:9000 --proto tcp
```

### View metrics
```bash
curl http://localhost:9090/metrics
```

---

## Internal Package Responsibilities

| Package | Responsibility |
|----------|----------------|
| `internal/quic` | Connection and stream lifecycle (using quic-go) |
| `internal/control` | Control plane messages and auth handling |
| `internal/mux` | Multiplexing and stream registry |
| `internal/tcpbridge` | TCP proxy adapter |
| `internal/udpbridge` | UDP proxy adapter |
| `internal/crypto` | AES-GCM payload encryption (optional) |
| `internal/config` | Config parsing (YAML/Viper) |

---

## MVP Acceptance Criteria
1. Client authenticates successfully using PSK.
2. Client opens TCP stream and performs round-trip echo test.
3. Server logs connections, streams, and bytes transferred.
4. QUIC reconnection supported after transient network loss.
5. Metrics endpoint returns JSON/Prometheus data.

---

## Performance Targets
| Metric | Target |
|---------|---------|
| Concurrent Streams | 500+ |
| Reconnect time | < 3s |
| Latency overhead | < 10ms vs TCP baseline |
| Memory footprint | < 50 MB per daemon |

---

## Roadmap (Post-MVP)
1. **mTLS / OIDC Auth** for enterprise environments.
2. **TURN-like relay** for NAT traversal.
3. **Per-stream AES-GCM encryption** for zero-trust separation.
4. **GUI Dashboard** for configuration and monitoring.
5. **Windows/macOS agents** with system tray integration.
6. **WebSocket-over-QUIC gateway** for browser access.

---

## Security Considerations
- QUIC/TLS 1.3 ensures transport encryption.
- PSK never logged or transmitted in plaintext.
- Limit control-plane message rate to prevent DoS.
- Validate message sizes and fields to avoid buffer exhaustion.
- Rotate PSKs periodically for security hygiene.

---

## Testing Strategy
- **Unit Tests:** framing, control message parsing, HMAC validation.
- **Integration Tests:**
  - QUIC echo between client and server.
  - TCP tunnel correctness (end-to-end data).
  - UDP datagram order/size preservation.
  - Reconnect + resume test.
- **Load Tests:** simulate 1000 streams; measure throughput and latency.

---

## Example Workflow
1. Start server: `tunnelord --config server.yaml`
2. Start client: `tunnelorc connect --config client.yaml`
3. Local app connects to `127.0.0.1:8080` → forwarded via QUIC → remote target.
4. Control stream keeps session alive; metrics accumulate.
5. If connection drops, QUIC resumes automatically.

---

## Deliverables for MVP
- `tunnelord` (server binary)
- `tunnelorc` (client binary)
- Example configs
- Integration test suite
- Markdown protocol specification
- Dockerfile for easy deployment

---

## License
MIT License — compatible with Go ecosystem and permissive for commercial use.

