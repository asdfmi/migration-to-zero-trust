# enforcer

Zero Trust enforcer that syncs config from controlplane.

## Deployment Patterns

- **Aggregated**: Single enforcer protects multiple resources. Similar to traditional VPN gateway.
- **Sidecar**: One enforcer per resource. More microservice-oriented Zero Trust.

## Run
```bash
sudo sysctl -w net.ipv4.ip_forward=1

sudo CONTROLPLANE_URL=<url> \
     API_KEY=<api-key> \
     ./enforcer
```

## Config Sync

Enforcer polls the controlplane every 15 seconds to apply policy changes.
