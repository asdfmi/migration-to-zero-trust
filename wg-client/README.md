# wg-client

WireGuard client that syncs config from control-plane.

## Run
```bash
sudo ./wg-client up \
  --cp-url <url> \
  --username <user> \
  --password <pass>
```

## Commands
- `up`: connect
- `down`: disconnect
- `status`: show status
- `resources`: list allowed CIDRs
