# controlplane

Zero Trust control plane with UI and API.

## Run
```bash
CONTROLPLANE_BASIC_USER=<user> CONTROLPLANE_BASIC_PASS=<pass> ./controlplane
```

## Entities

```
Client <─ Pair ─> Resource ─> Enforcer
```

| Entity | Fields |
|--------|--------|
| Client | ID, Name, Username, PasswordHash, WGPublicKey |
| Resource | ID, Name, CIDR, Mode (observe/enforce), EnforcerID |
| Pair | ID, ClientID, ResourceID |
| Enforcer | ID, Name, APIKeyHash, WGPublicKey, Endpoint, TunnelSubnet |
| LogEntry | ID, EnforcerID, ClientID, ResourceID, Src, Dst, Protocol, Timestamp |

## Authentication

| Target | Method | Reason |
|--------|--------|--------|
| UI | Basic Auth | Admin-facing, simplicity |
| Agent → API | JWT (24h) | Auto re-auth, session management |
| Enforcer → API | API Key | Long-running, no re-auth needed |

## API Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `POST /api/client/login` | - | Login, issue JWT |
| `GET /api/client/config` | JWT | Get agent config |
| `PUT /api/enforcer/public-key` | API Key | Register enforcer public key |
| `GET /api/enforcer/config` | API Key | Get enforcer config |
| `POST /api/logs` | API Key | Send logs |

## Config Sync

Agent and Enforcer poll the controlplane every 15 seconds to apply config changes.
