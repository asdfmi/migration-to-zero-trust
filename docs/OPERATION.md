# MVP WG Migration

## Migration Target
This guide targets a GCP setup with a private-only protected VM reachable only through a classic Cloud VPN tunnel.
The concrete target is:

- VPC name: zt-migration-vpc
- Subnet: IPv4 only, primary 10.0.0.0/29
- Protected VM: zt-migration-protected-vm
  - Boot image: debian-12-bookworm-v20251209 (x86_64)
  - Internal IP: 10.0.0.2 (no external IP)
  - Network tag: https-server
- VPN tunnel: zt-migration-vpn-tunnel (route-based, IKEv2)
  - Remote peer gateway IP: <REMOTE_PEER_PUBLIC_IP>
  - Cloud VPN gateway: zt-migration-vpn-gw
  - Gateway IP: <CLOUD_VPN_GATEWAY_PUBLIC_IP>
- Cloud VPN gateway: zt-migration-vpn-gw (classic, IPv4 single-stack)
  - External IP: <CLOUD_VPN_GATEWAY_PUBLIC_IP>

## Migration Policy (per server)
- Switch to WG routes per target server
- Reach target servers via WG
- Keep the existing VPN for non-target servers
- Do not create two paths (VPN and WG) for the same server
- Start without enforcement (enforce) and prioritize logging

## Phased Migration (Example)
### Phase 0: Status quo
- Operate with the existing VPN only
- WG not introduced

### Phase 1: Base setup
- Place WG server in the VPC
- Prepare the public endpoint
- Prepare with authz_mode=observe and logging_enabled=on
- Do not switch routing yet

### Phase 2: Pilot (observe)
- Select the smallest possible target server scope
- Configure AllowedIPs and policy in local files
- Keep authz_mode=observe and collect logs

### Phase 3: Expand observation
- Expand the target server scope
- Build and adjust policy based on logs
- Confirm no increase in drop rate or latency

### Phase 4: enforce
- Set authz_mode=enforce for target servers
- If failures occur, immediately switch authz_mode back to observe

### Phase 5: Migration complete
- Major servers are reached via WG
- Remove the existing VPN

---

## 移行対象
GCP で private-only の protected VM を持ち、classic Cloud VPN の tunnel 経由でのみ到達できる構成を移行対象とする。
具体構成は以下:

- VPC 名: zt-migration-vpc
- Subnet: IPv4 only, primary 10.0.0.0/29
- Protected VM: zt-migration-protected-vm
  - Boot image: debian-12-bookworm-v20251209 (x86_64)
  - Internal IP: 10.0.0.2 (external IP なし)
  - Network tag: https-server
- VPN tunnel: zt-migration-vpn-tunnel (route-based, IKEv2)
  - Remote peer gateway IP: <REMOTE_PEER_PUBLIC_IP>
  - Cloud VPN gateway: zt-migration-vpn-gw
  - Gateway IP: <CLOUD_VPN_GATEWAY_PUBLIC_IP>
- Cloud VPN gateway: zt-migration-vpn-gw (classic, IPv4 single-stack)
  - External IP: <CLOUD_VPN_GATEWAY_PUBLIC_IP>

## 移行方針（server 単位）
- 対象サーバ単位で WG 経路に切り替える
- 移行対象サーバへの通信は WG で到達させる
- 既存 VPN は非対象サーバのために維持する
- 同一サーバに VPN と WG の二経路を作らない
- 最初は制御（enforce）をせず、logging を優先する

## 段階移行（例）
### Phase 0: 現状維持
- 既存 VPN のみで運用
- WG は未導入

### Phase 1: 基盤導入
- WG server を VPC 内に配置
- 公開エンドポイントを用意
- authz_mode=observe、logging_enabled=on で準備
- ルーティングはまだ切り替えない

### Phase 2: パイロット（observe）
- 対象サーバを最小範囲で選定
- AllowedIPs と policy をローカル設定に反映
- authz_mode=observe を維持し、ログを収集

### Phase 3: 観測拡大
- 対象サーバ範囲を拡大
- ログから policy を作成・調整
- drop 率やレイテンシの悪化がないことを確認

### Phase 4: enforce
- 対象サーバに対して authz_mode=enforce
- 失敗時は authz_mode=observe へ即時切替

### Phase 5: 移行完了
- 主要サーバは WG 経由
- 既存 VPN を撤去
