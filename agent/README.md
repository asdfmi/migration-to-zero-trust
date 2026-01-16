# agent

Zero Trust agent that syncs config from controlplane.

## Setup
```bash
# Generate key pair and display public key
sudo ./agent keygen

# Register the public key in controlplane UI, then connect
sudo ./agent up \
  --cp-url <url> \
  --username <user> \
  --password <pass>
```

## Commands
- `keygen`: generate WireGuard key pair and display public key
- `up`: connect
- `down`: disconnect
- `status`: show status and allowed CIDRs
