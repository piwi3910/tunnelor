# Tunnel Types: Forward vs Reverse

This document explains the difference between forward tunnels and reverse tunnels, clarifying what Tunnelor currently supports and what's planned.

## Current Implementation: Forward Tunnels ✅

**Status**: Fully implemented and tested

### What is a Forward Tunnel?

A forward tunnel allows you to access a remote service through a tunnel server. You connect to a local port on your machine, and traffic is forwarded through the tunnel to a remote target.

**Data Flow**:
```
You → Client (localhost) → Tunnel Server → Remote Target
```

### When to Use Forward Tunnels

- Access a database that's only reachable from the server
- Reach an internal service behind a firewall (from the server's perspective)
- Bypass network restrictions to access remote resources
- Similar to SSH local port forwarding: `ssh -L 8080:remote:80 server`

### How It Works

```mermaid
sequenceDiagram
    participant You as You/Application
    participant Client as tunnelorc<br/>(Your Machine)
    participant Server as tunnelord<br/>(Tunnel Server)
    participant Target as Remote Service<br/>(10.0.0.5:8080)

    Note over You,Target: Forward Tunnel Flow

    You->>Client: Connect to localhost:8080
    Client->>Server: Open QUIC stream
    Server->>Target: Connect to 10.0.0.5:8080

    You->>Client: Send HTTP request
    Client->>Server: Forward via QUIC tunnel
    Server->>Target: Forward to target

    Target->>Server: HTTP response
    Server->>Client: Forward via QUIC tunnel
    Client->>You: HTTP response
```

### Configuration Example

**Server** (`tunnelord`):
```yaml
server:
  listen: 0.0.0.0:4433  # QUIC listen port
  tls_cert: /path/to/cert.pem
  tls_key: /path/to/key.pem

auth:
  psk_map:
    "my-client": "base64encodedkey=="
```

**Client** (`tunnelorc`):
```yaml
client:
  server: tunnel-server.example.com:4433
  client_id: my-client
  psk: base64encodedkey==

  forwards:
    # YOU connect to localhost:8080
    # Traffic goes to 10.0.0.5:8080 (reachable from SERVER)
    - local: 127.0.0.1:8080
      remote: 10.0.0.5:8080
      proto: tcp

    # Access database through tunnel
    - local: 127.0.0.1:5432
      remote: private-rds.internal:5432
      proto: tcp
```

**Usage**:
```bash
# Start server
./tunnelord --config server.yaml

# Start client (connects to server and sets up forwards)
./tunnelorc connect --config client.yaml

# In another terminal: Access remote service
curl http://localhost:8080
# Traffic flows: localhost:8080 → tunnel → 10.0.0.5:8080
```

### Use Cases

#### Example 1: Access Private Database
```
Problem: You need to connect to a production database that's only accessible from your AWS server

Solution:
- Run tunnelord on your AWS EC2 instance
- Run tunnelorc on your laptop
- Configure forward: local:5432 → remote:rds.internal:5432
- Connect to localhost:5432 with your database client
```

#### Example 2: Bypass Corporate Firewall
```
Problem: Your office network blocks direct access to certain services, but you have a server outside

Solution:
- Run tunnelord on your external VPS
- Run tunnelorc on your office computer
- Configure forward: local:443 → remote:blocked-site.com:443
- Access blocked-site.com through localhost:443
```

---

## Future Implementation: Reverse Tunnels ⏳

**Status**: Planned - See [Issue #9](https://github.com/piwi3910/tunnelor/issues/9)

### What is a Reverse Tunnel?

A reverse tunnel allows you to expose a local service publicly through a tunnel server. External users connect to the server's public port, and traffic is forwarded through the tunnel to your local service.

**Data Flow**:
```
External User → Tunnel Server (public) → Client (private) → Local Service
```

### When to Use Reverse Tunnels

- Expose a local web application for testing (like ngrok)
- Share a localhost development server with a client
- Provide temporary access to a service behind NAT/firewall
- Similar to SSH remote port forwarding: `ssh -R 8080:localhost:80 server`

### How It Will Work

```mermaid
sequenceDiagram
    participant ExtUser as External User
    participant Server as tunnelord<br/>(Public Server)
    participant Client as tunnelorc<br/>(Your Machine - Private)
    participant LocalSvc as Local Service<br/>(localhost:3000)

    Note over ExtUser,LocalSvc: Reverse Tunnel Flow

    ExtUser->>Server: Connect to public-server.com:8080
    Server->>Client: Open QUIC stream
    Client->>LocalSvc: Connect to localhost:3000

    ExtUser->>Server: Send HTTP request
    Server->>Client: Forward via QUIC tunnel
    Client->>LocalSvc: Forward to local service

    LocalSvc->>Client: HTTP response
    Client->>Server: Forward via QUIC tunnel
    Server->>ExtUser: HTTP response
```

### Planned Configuration

**Server** (`tunnelord`):
```yaml
server:
  listen: 0.0.0.0:4433  # QUIC control plane

  forwards:
    # External users connect to public-server.com:8080
    # Traffic forwarded to client "dev-laptop"
    # Client forwards to localhost:3000
    - public: 0.0.0.0:8080
      client_id: "dev-laptop"
      target: "localhost:3000"
      proto: tcp

    - public: 0.0.0.0:5432
      client_id: "dev-laptop"
      target: "192.168.1.100:5432"
      proto: tcp
```

**Client** (`tunnelorc`):
```yaml
client:
  server: tunnel-server.example.com:4433
  client_id: dev-laptop
  psk: base64encodedkey==

  # No forward configuration needed
  # Server controls what gets exposed
```

**Usage**:
```bash
# Start server (listens on public ports)
./tunnelord --config server.yaml

# Start client (just maintains connection)
./tunnelorc connect --config client.yaml

# External users can now access your local service:
curl http://public-server.com:8080
# Traffic flows: public:8080 → tunnel → localhost:3000
```

### Planned Use Cases

#### Example 1: Share Development Server
```
Problem: You're building a web app on localhost:3000 and want to share it with a client

Solution:
- Run tunnelord on a public VPS
- Run tunnelorc on your laptop
- Server exposes your localhost:3000 as public-server.com:8080
- Share http://public-server.com:8080 with your client
```

#### Example 2: Expose Home Services
```
Problem: You have a home server behind NAT and want to access it from anywhere

Solution:
- Run tunnelord on a cheap cloud VPS
- Run tunnelorc on your home server
- Server exposes your services publicly
- Access from anywhere via the public server
```

---

## Comparison Table

| Feature | Forward Tunnel (✅ Current) | Reverse Tunnel (⏳ Planned) |
|---------|---------------------------|---------------------------|
| **Who listens locally?** | Client | Server |
| **Who connects to target?** | Server | Client |
| **Configuration location** | Client defines forwards | Server defines forwards |
| **Use case** | Access remote resources | Expose local services |
| **Similar to** | SSH `-L` / ProxyJump | SSH `-R` / ngrok |
| **Target reachable from** | Server | Client |
| **Client behind NAT/firewall?** | OK | OK |
| **Server behind NAT/firewall?** | Must be reachable | Must be reachable |

## Hybrid Mode (Future)

Eventually, Tunnelor will support **both** forward and reverse tunnels simultaneously:

```yaml
client:
  server: tunnel-server.example.com:4433

  # Forward tunnels (client → server → remote)
  forward_tunnels:
    - local: 127.0.0.1:5432
      remote: db.internal:5432
      proto: tcp

  # Reverse tunnels (handled by server config)
  # Server exposes client's local services
```

This would allow a single client to both:
- Access remote resources through the tunnel (forward)
- Expose local services publicly (reverse)

---

## Implementation Status

### ✅ Implemented (Forward Tunnels)

- [x] Client-side local port listeners
- [x] QUIC stream opening from client to server
- [x] Server-side target connection
- [x] Bidirectional data forwarding
- [x] TCP and UDP protocol support
- [x] PSK authentication
- [x] Configuration and CLI
- [x] Comprehensive testing

### ⏳ Planned (Reverse Tunnels)

Track progress in [Issue #9](https://github.com/piwi3910/tunnelor/issues/9)

**Phase 1: Core Reverse Tunnel**
- [ ] Server-side public port listeners ([#10](https://github.com/piwi3910/tunnelor/issues/10))
- [ ] QUIC stream opening from server to client
- [ ] Client-side stream handling ([#11](https://github.com/piwi3910/tunnelor/issues/11))
- [ ] Client-side target connection
- [ ] Control plane extensions ([#13](https://github.com/piwi3910/tunnelor/issues/13))
- [ ] Configuration updates
- [ ] Integration tests

**Phase 2: Hybrid Mode**
- [ ] Support both modes simultaneously
- [ ] Tunnel type configuration flag
- [ ] Updated documentation

**Phase 3: Advanced Features**
- [ ] Dynamic port allocation
- [ ] Runtime forward management
- [ ] HTTP(S) virtual hosting
- [ ] Custom domains

---

## FAQ

### Q: Which mode should I use?

**Use Forward Tunnels (current) when:**
- You want to access a service that's only reachable from your server
- The target is "over there" (on the server's network)
- Example: Access AWS RDS from your laptop

**Use Reverse Tunnels (future) when:**
- You want to expose a local service publicly
- The target is "over here" (on your local network)
- Example: Share your localhost web app with others

### Q: Can I use both at the same time?

Not yet. This is planned for Phase 2 (Hybrid Mode).

### Q: Is this similar to ngrok/localtunnel?

**Forward tunnels**: No, those tools only do reverse tunnels
**Reverse tunnels** (future): Yes, very similar functionality

### Q: Is this similar to SSH port forwarding?

**Forward tunnels**: Yes, like `ssh -L local:remote`
**Reverse tunnels** (future): Yes, like `ssh -R remote:local`

### Q: Why QUIC instead of traditional TCP tunnels?

QUIC provides:
- Built-in TLS 1.3 encryption
- Better performance over lossy networks
- Native stream multiplexing
- 0-RTT connection establishment
- Improved congestion control

---

## Contributing

Interested in helping implement reverse tunnels? Check out:
- [Issue #9](https://github.com/piwi3910/tunnelor/issues/9) - Main tracking issue
- [Issue #10](https://github.com/piwi3910/tunnelor/issues/10) - Server-side listeners
- [Issue #11](https://github.com/piwi3910/tunnelor/issues/11) - Client-side handling
- [Issue #13](https://github.com/piwi3910/tunnelor/issues/13) - Control plane

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development guidelines.
