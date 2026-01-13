# wg-server (MVP)
Minimal implementation that configures kernel WireGuard via `wgctrl`.

## Deploy to a GCP VM (scp)
### Build (local)
```bash
GOOS=linux GOARCH=amd64 go build -o wg-server ./wg-server/cmd/wg-server
```

### Transfer (gcloud)
```bash
gcloud compute scp --zone <ZONE> ./wg-server ./wg-server/configs/config.example.yaml <INSTANCE_NAME>:~/
```

### Run
```bash
gcloud compute ssh --zone <ZONE> <INSTANCE_NAME>
sudo ~/wg-server --config ~/config.yaml
```

## Logging (optional)
Logging reads packets via NFLOG and writes JSONL locally (default: `/var/log/wg-server/events.jsonl`).
It auto-installs an nftables rule on the forward chain for the WG interface.

## Notes
- Requires root privileges
- Creates the WG interface, assigns IPs, and configures peers
- When logging is enabled, the process stays running to stream events
