# wg-server

WireGuard gateway that syncs config from control-plane.

## Run
```bash
sudo sysctl -w net.ipv4.ip_forward=1

sudo CONTROL_PLANE_URL=<url> \
     API_KEY=<api-key> \
     ./wg-server
```
