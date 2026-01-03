# wg-client (MVP)
Runs the WireGuard client runtime with a minimal setup.

## Configuration
- `wg-client/configs/config.example.yaml`

## Run
```bash
sudo ./wg-client --config ./wg-client/configs/config.example.yaml
```

## Notes
- Requires root privileges
- Adds routes based on AllowedIPs
