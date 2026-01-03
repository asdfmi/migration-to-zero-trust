# Zero Trust Data Plane Operations Design (WG in VPC / Coexist with VPN -> Remove)

## 1. Purpose
- Apply the implementation based on `docs/DESIGN.md` to the real environment in stages
- Show phased migration in a common configuration, assuming the MVP spec
- Migrate to WG while keeping the existing VPN, then remove the VPN after completion
- Do not create double tunnels (WG inside VPN)

## 2. Assumptions
- An existing VPN is already configured within a single VPC, and current traffic goes through the VPN
- WG server is placed inside the VPC and has a public endpoint reachable from outside
  - Example: EC2 with EIP / public LB that supports UDP
- The source side installs a WG client, and destinations remain private IPs within the VPC
- Do not chain VPN and WG (no double tunneling for the same traffic)

## 3. Assumed Architecture
### WG server
- Receives inner packets decrypted by WG and forwards to the next hop
- Holds authz_mode and logging_enabled
- authz_mode and logging_enabled are managed locally on the WG server (not distributed by the Control Plane)

### Control Plane
- Responsible only for distributing keys, AllowedIPs, and policy

### Logging
- Datapath only enqueues
- Resident daemon dequeues/pushes asynchronously

### Network
- Source -> public endpoint -> WG server -> VPC server
- On the VPC side, route return traffic for the WG tunnel CIDR back to the WG server

## 4. Management Ledger (Minimum Info Held by Control Plane)
- WG server public endpoint (IP:Port) and public key
- Source public key
- Mapping between target servers (private IP/CIDR) and policy
- Distribution targets for AllowedIPs

## 5. Migration Policy (per server)
- Switch to WG routes per target server
- Reach target servers via WG
- Keep the existing VPN for non-target servers
- Do not create two paths (VPN and WG) for the same server
- Start without enforcement (enforce) and prioritize logging

## 6. Phased Migration (Example)
### Phase 0: Status quo
- Operate with the existing VPN only
- WG / Control Plane not introduced

### Phase 1: Base setup
- Place WG server and Control Plane in the VPC
- Prepare the public endpoint
- Prepare with authz_mode=observe and logging_enabled=on
- Do not switch routing yet

### Phase 2: Pilot (observe)
- Select the smallest possible target server scope
- Distribute AllowedIPs and policy
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

## 7. Monitoring and Operations
- Monitor logging queue usage and drop rate
- Update policy via push from the Control Plane
- Rotate keys by regenerating on the client side and reflecting the public key in the Control Plane

## 8. Rollback
- Set authz_mode back to observe
- Withdraw AllowedIPs for target servers
- Return to VPN routes as needed

---

# Zero Trust Data Plane 運用設計（VPC 内 WG / 既存 VPN 併存 → 撤去）

## 1. 目的
- `docs/DESIGN.md` の仕様に沿った実装を、実環境に段階的に適用する
- MVP 仕様を前提に、よくある構成での段階移行を示す
- 既存 VPN を維持しつつ WG に移行し、完了後に VPN を撤去する
- 二重トンネル（VPN 内に WG）を作らない

## 2. 前提
- 1 つの VPC 内に既存 VPN が構成済みで、現行通信は VPN 経由
- WG server は VPC 内に配置し、外部から到達できる公開エンドポイントを持つ
  - 例: EIP を付与した EC2 / UDP 対応の公開 LB
- 接続元は WG client を導入し、宛先は VPC 内の private IP のままにする
- VPN と WG をチェーンしない（同一通信での二重トンネル禁止）

## 3. 想定構成
### WG server
- WG で復号された inner packet を受け、次ホップへ forward
- authz_mode と logging_enabled を保持
- authz_mode と logging_enabled は WG server のローカル設定で管理する（Control Plane から配布しない）

### Control Plane
- 鍵・AllowedIPs・policy の配布のみを担当

### Logging
- datapath は enqueue のみ
- 常駐 daemon が非同期で dequeue/push

### ネットワーク
- 接続元 → 公開エンドポイント → WG server → VPC 内サーバ という経路
- VPC 側は WG トンネル CIDR の戻り経路を WG server へ向ける

## 4. 管理台帳（Control Plane が保持する最小情報）
- WG server の公開エンドポイント（IP:Port）と公開鍵
- 接続元の公開鍵
- 対象サーバ（private IP / CIDR）と policy の対応
- AllowedIPs の配布対象

## 5. 移行方針（server 単位）
- 対象サーバ単位で WG 経路に切り替える
- 移行対象サーバへの通信は WG で到達させる
- 既存 VPN は非対象サーバのために維持する
- 同一サーバに VPN と WG の二経路を作らない
- 最初は制御（enforce）をせず、logging を優先する

## 6. 段階移行（例）
### Phase 0: 現状維持
- 既存 VPN のみで運用
- WG / Control Plane は未導入

### Phase 1: 基盤導入
- WG server と Control Plane を VPC 内に配置
- 公開エンドポイントを用意
- authz_mode=observe、logging_enabled=on で準備
- ルーティングはまだ切り替えない

### Phase 2: パイロット（observe）
- 対象サーバを最小範囲で選定
- AllowedIPs と policy を配布
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

## 7. 監視と運用
- logging queue の使用率、drop 率を監視する
- policy の更新は Control Plane から push する
- 鍵ローテーションは client 側で再生成し、Control Plane に公開鍵を反映する

## 8. 切り戻し
- authz_mode を observe に戻す
- 対象サーバの AllowedIPs を取り下げる
- 必要に応じて VPN 側の経路に戻す
