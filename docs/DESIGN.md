# Product Design (controlplane + agent)

## Scope
This document covers the product components: controlplane and agent. Gateway depends on customer infrastructure and is covered in [OPERATION.md](./OPERATION.md).

---

## Concept

### observe / enforce Mode

Resources have two modes.

| Mode | Access Control | Purpose |
|------|---------------|---------|
| `observe` | Same as traditional VPN. All Clients can access | Early migration. Collect logs to understand usage |
| `enforce` | Only Clients with Pair can access | After migration. Achieve Zero Trust |

### Migration Flow
1. Register Resources as `observe`, allowing all Clients to access
2. Review logs to understand who accesses which Resource
3. Create Pairs for required Client-Resource combinations
4. Switch Resources to `enforce`, blocking Clients without Pairs
5. If issues occur, immediately switch back to `observe`

---

## For Administrators (controlplane UI)

### Initial Setup
1. Register Gateway (name, endpoint, tunnel subnet)
2. Register Resources (CIDR, mode, associated Gateway)
3. Register Clients (name, username, password, WG public key)
4. Create Pairs (Client-Resource bindings)

### Client Registration Flow
1. Have the end user run `agent keygen` on their device
2. Receive the displayed public key
3. Create Client in UI and enter the public key

### Viewing Logs
Traffic logs are available on the Gateway detail page. Can filter by Resource.

---

## For End Users (agent)

### Setup
```bash
# 1. Generate key pair and display public key
sudo agent keygen
# → Share the displayed public key with your administrator

# 2. After administrator registers the Client, connect
sudo agent up --cp-url <url> --username <user> --password <pass>
```

### Commands
| Command | Description |
|---------|-------------|
| `keygen` | Generate WG key pair and display public key |
| `up` | Start connection (syncs config in background) |
| `down` | Disconnect |
| `status` | Show connection status and accessible CIDRs |

### Behavior
- Config syncs automatically every 15 seconds after connection
- Resource additions/removals are reflected automatically
- Auto re-login on session expiry

---

## Technical Details

### Entities
```
Client <─ Pair ─> Resource ─> Gateway
```

| Entity | Fields |
|--------|--------|
| Client | ID, Name, Username, PasswordHash(bcrypt), WGPublicKey |
| Resource | ID, Name, CIDR, Mode, GatewayID |
| Pair | ID, ClientID, ResourceID |
| Gateway | ID, Name, APIKeyHash, WGPublicKey, Endpoint, TunnelSubnet |
| LogEntry | ID, GatewayID, ClientID/Name, Src/Dst, Protocol, Timestamp |

### Authentication
| Target | Method |
|--------|--------|
| UI | Basic Auth |
| Client API | JWT (24h validity) |
| Gateway API | API Key (issued at creation) |

### API
| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /api/client/login` | None | Login |
| `GET /api/client/config` | JWT | Get config |
| `PUT /api/gateway/public-key` | API Key | Update Gateway public key |
| `GET /api/gateway/config` | API Key | Get Gateway config |
| `POST /api/logs` | API Key | Send logs |

### Tunnel IP
Dynamically allocated from Gateway's TunnelSubnet. `.1` is Gateway, `.2` onwards are Clients.

### Constraints
- Tunnel IP is IPv4 only
- Tunnel IP is in-memory (reallocated on restart)

### Local Files (agent)
| File | Purpose |
|------|---------|
| `/var/lib/migration-to-zero-trust/{iface}.key` | WG private key |
| `/var/lib/migration-to-zero-trust/{iface}.state.json` | Connection state |

Connection state example:
```json
{
  "control_plane_url": "<control-plane-url>",
  "interface_name": "wg0",
  "config": {
    "client_id": "<uuid>",
    "wg_public_key": "<client-public-key>",
    "gateways": [
      {
        "gateway_id": "163acbe4-7a06-4d2e-a001-8011674e90e1",
        "tunnel_ip": "10.100.0.2/24",
        "gateway_public_key": "<gateway-public-key>",
        "gateway_endpoint": "<gateway-url>",
        "allowed_cidrs": [
          "10.0.0.2/32"
        ]
      }
    ]
  },
  "updated_at": "2025-01-01T00:00:00Z"
}
```
