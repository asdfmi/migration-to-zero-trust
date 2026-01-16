# gateway

Zero Trust gateway that syncs config from controlplane.

## Run
```bash
sudo sysctl -w net.ipv4.ip_forward=1

sudo CONTROLPLANE_URL=<url> \
     API_KEY=<api-key> \
     ./gateway
```
