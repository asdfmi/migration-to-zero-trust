# Operation Guide (Migration Scenario)

## About This Document
While [DESIGN.md](./DESIGN.md) explains "What" the product can do, this document demonstrates "How" to use it with a concrete customer environment example.

> **Note**: This example uses a minimal configuration (2 VMs, single subnet). Actual migrations vary by customer infrastructure.

---

## Customer Environment (Example: GCP)

Target: VMs without external IPs in GCP, reachable only via Cloud VPN.

### Target Resources
| Resource | Details |
|----------|---------|
| VPC | zt-migration-vpc |
| Subnet | zt-migration-subnet (10.0.0.0/29, IPv4 only) |
| protected-vm-1 | 10.0.0.2, Debian 12, no external IP |
| protected-vm-2 | 10.0.0.3, Debian 12, no external IP |
| Cloud VPN Gateway | zt-migration-vpn-gw (classic, IKEv2), has external IP |

### Before Migration
```
                              +-----------------------------+
[Client] <--- Cloud VPN ----> | [VPN GW] -----> p-vm-1      |
                              |            |   (10.0.0.2)   |
                              |            |                |
                              |            +---> p-vm-2     |
                              |                (10.0.0.3)   |
                              +-----------------------------+
                                      VPC: 10.0.0.0/29
```

### During Migration (First Resource Migrated)
```
                              +-----------------------------+
[Client] <--- WireGuard ----> | [WG GW] ------> p-vm-1      |
   ^                          | (10.0.0.4)   /  (10.0.0.2)  |
   |                          |             /               |
   +------ Cloud VPN -------> | [VPN GW] --+                |
                              |             \               |
                              |              \-> p-vm-2     |
                              |                 (10.0.0.3)  |
                              +-----------------------------+
                                      VPC: 10.0.0.0/29
```

- p-vm-1: Reachable via both WireGuard (/32) and VPN (/29). /32 takes priority
- p-vm-2: Via VPN (not yet registered with WireGuard)

### After Migration
```
                              +-----------------------------+
[Client] <--- WireGuard ----> | [WG GW] ------> p-vm-1      |
                              | (10.0.0.4)  |  (10.0.0.2)   |
                              |             |               |
                              |             +-> p-vm-2      |
                              |                (10.0.0.3)   |
                              +-----------------------------+
                                      VPC: 10.0.0.0/29
```

---

## Gateway Implementation

Access control is performed per resource. In this case, we use a single aggregated Gateway, but it can be split into multiple gateways depending on resource classification or fault isolation requirements. Deploying a sidecar to each resource enables true Zero Trust by completely eliminating single points of failure. Configuration varies by customer.

### Implementation Details

- Accept WireGuard connections from Clients
- Perform packet filtering with nftables (environment-dependent, but likely compatible with eBPF)
- Fetch and apply policies from controlplane every 30 seconds
- Capture traffic logs with nflog and send to controlplane

---

## Migration Strategy

- Switch to WireGuard route on a per-server basis
- Route traffic to migrated servers through WireGuard
- Maintain existing VPN for non-migrated servers
- When both routes exist for the same destination, WireGuard wins by specificity (/32 over /29)
- Start with `observe` mode, prioritizing logging

---

## Phased Migration

### Phase 0: Current State
Operating with existing VPN only. WireGuard not yet deployed.

### Phase 1: Infrastructure Setup

#### 1-1. Create Gateway VM
```bash
gcloud compute instances create zt-gateway \
  --zone=asia-northeast1-b \
  --machine-type=e2-small \
  --network=zt-migration-vpc \
  --subnet=zt-migration-subnet \
  --tags=wg-gateway \
  --image-family=debian-12 \
  --image-project=debian-cloud
```

#### 1-2. Create Firewall Rules
```bash
# WireGuard UDP port
gcloud compute firewall-rules create allow-wg \
  --network=zt-migration-vpc \
  --allow=udp:51820 \
  --target-tags=wg-gateway

# Traffic from Gateway to protected VMs
gcloud compute firewall-rules create allow-gateway-to-protected \
  --network=zt-migration-vpc \
  --allow=tcp,udp,icmp \
  --source-tags=wg-gateway \
  --target-tags=https-server
```

#### 1-3. Setup Gateway VM
```bash
# SSH to Gateway VM
gcloud compute ssh zt-gateway --zone=asia-northeast1-b

# Install packages
sudo apt update && sudo apt install -y wireguard nftables

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-wg.conf
sudo sysctl -p /etc/sysctl.d/99-wg.conf
```

#### 1-4. Register Gateway in controlplane
1. In UI: Gateways → Create Gateway
2. Input:
   - Name: `zt-gateway`
   - Endpoint: `<GATEWAY_PUBLIC_IP>:51820`
   - Tunnel Subnet: `10.100.0.0/24`

> **Note**: Tunnel Subnet must not overlap with VPC subnet (10.0.0.0/29). Overlap causes routing conflicts and packets won't be forwarded correctly.
3. Save the displayed API Key

#### 1-5. Start Gateway
```bash
# Set environment variables
export CONTROLPLANE_URL="http://<CONTROLPLANE_IP>:8080"
export API_KEY="gw_xxxx_yyyy"

# Start Gateway
sudo -E ./gateway
```

### Phase 2: Client Registration

#### 2-1. Register Client
```bash
# Generate public key on client side
sudo ./agent keygen
# → Save the displayed public key
```

1. In UI: Clients → Create Client
2. Input:
   - Name: `developer-1`
   - Username: `dev1`
   - Password: `****`
   - WG Public Key: `<public key generated above>`

#### 2-2. Connect from Client
```bash
sudo ./agent up \
  --cp-url http://<CONTROLPLANE_IP>:8080 \
  --username dev1 \
  --password ****
```

### Phase 3: First Resource Migration

#### 3-1. Register Resource (observe)
1. In UI: Resources → Create Resource
2. Input:
   - Name: `protected-resource1`
   - CIDR: `10.0.0.2/32`
   - Gateway: `zt-gateway`
   - Mode: `observe`

#### 3-2. Create Pair
1. In UI: Pairs → Create Pair
2. Select Client: `developer-1`, Resource: `protected-resource1`

#### 3-3. Verify Connectivity
```bash
ping -c 3 10.0.0.2
```

#### 3-4. Verify Routing
```bash
sudo ./agent status
```

Example output:
```
Resources:
  10.0.0.2/32
    wg0 ✓ (preferred)
    tun0: 10.0.0.0/29 (overlap)
```

- `wg0 ✓ (preferred)`: Accessed via WireGuard
- `(overlap)`: VPN has an overlapping route, but WireGuard is more specific so it takes priority

> **Note**: By Zero Trust design, WireGuard CIDRs (/32 etc.) are more specific than existing VPN, so VPN taking priority is rare. If VPN is prioritized, consider adjusting route metrics.

> **Note**: At this point, access to protected-vm-2 (10.0.0.3) continues via existing VPN. Resources not registered with WireGuard use the traditional route.

#### 3-5. Monitor and Add Pairs
1. In UI: Gateways → zt-gateway → Access Logs
2. Check the Pair column
   - ✓: Pair exists (accessible after enforce)
   - ✗: No Pair (will be blocked after enforce)
3. If legitimate access shows no Pair (✗), create a Pair
4. Repeat until no ✗ remains

#### 3-6. Switch to enforce
1. In UI: Resources → Change protected-resource1 Mode to `enforce`

#### 3-7. Verify Operation
```bash
# Clients with Pair can access
ping -c 3 10.0.0.2  # → responds
```

#### 3-8. Rollback if Issues Occur
```bash
# In UI: Change Resource Mode back to observe
# → All Clients can access immediately
```

### Phase 4: Second Resource Migration

#### 4-1. Register Resource (observe)
1. In UI: Resources → Create Resource
2. Name: `protected-resource2`, CIDR: `10.0.0.3/32`, Mode: `observe`

#### 4-2. Create Pair
1. In UI: Pairs → Create Pair
2. Client: `developer-1`, Resource: `protected-resource2`

#### 4-3. Verify Connectivity
```bash
# Configuration syncs automatically (within 15 seconds)
ping -c 3 10.0.0.3
```

#### 4-4. Verify Routing
```bash
sudo ./agent status
```

Example output:
```
Resources:
  10.0.0.2/32
    wg0 ✓ (preferred)
  10.0.0.3/32
    wg0 ✓ (preferred)
    tun0: 10.0.0.0/29 (overlap)
```

#### 4-5. Monitor and Add Pairs
1. In UI: Check Access Logs
2. If access to protected-resource2 shows no Pair (✗), create a Pair
3. Repeat until no ✗ remains

#### 4-6. Switch to enforce
1. In UI: Resources → Change protected-resource2 Mode to `enforce`

#### 4-7. Verify Operation
```bash
ping -c 3 10.0.0.3  # → responds
```

### Phase 5: Migration Complete

- All target servers accessible via WireGuard
- Decommission existing VPN

---

## Rollback

### If Issues Occur in enforce Mode
1. In UI: Change target Resource Mode to `observe`
2. Gateway fetches configuration on next poll (within 30 seconds)
3. All authorized Clients can access immediately

### If Gateway Has Issues
1. Stop agent on Client: `sudo ./agent down`
2. WireGuard routes are removed, allowing access via existing VPN (if still available)
3. After restarting Gateway VM and running `sudo ./gateway`, reconnect from Client

