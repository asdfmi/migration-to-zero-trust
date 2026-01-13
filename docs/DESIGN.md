# MVP Data Plane Design (WireGuard)

### Topology
This implementation consists of three binaries: wg-client on the source host, wg-server as a gateway inside the target network, and protected-resource as a minimal HTTP service. Both wg-client and wg-server are configured from local YAML files. wg-client brings up a WireGuard interface and installs routes for AllowedIPs. wg-server brings up its WireGuard interface, configures peers, and optionally enables logging and L3 allowlist enforcement via nftables/NFLOG. Logging emits JSONL locally. The protected-resource is only for connectivity validation.
 
### wg-server ([README](../wg-server/README.md))
- Creates or reuses a WireGuard interface, assigns address, listen port, and peers from config.
- authz_mode:
  - observe: always forward, optionally log.
  - enforce: apply L3 allowlist rules (default drop) via nftables.
- logging_enabled:
  - Adds an nftables NFLOG rule on the forward path.
  - Writes JSONL events locally (src/dst IP, ports, proto, client_id).
- Policy mapping:
  - client_id is the peer public key.
- Config file: `wg-server/configs/config.example.yaml`

### wg-client ([README](../wg-client/README.md))
- Creates or reuses a WireGuard interface, assigns address, configures the server peer.
- Adds OS routes for AllowedIPs.
- Supports optional listen port and persistent keepalive.
- Config file: `wg-client/configs/config.example.yaml`

### protected-resource ([README](../protected-resource/README.md))
- Minimal HTTP server used as a protected resource.
- Listens on 0.0.0.0:8080; /healthz returns 200.

---

### 全体構成
本実装は 3 つのバイナリで構成される。接続元の wg-client、ゲートウェイとして動く wg-server、疎通確認用の最小 HTTP サービス protected-resource。wg-client と wg-server はどちらもローカル YAML 設定から起動する。wg-client は WireGuard インターフェースを作成し AllowedIPs のルートを追加する。wg-server は WireGuard インターフェースと peer を設定し、必要に応じて nftables/NFLOG によるローカル JSONL ログと L3 allowlist の enforce を有効化する。protected-resource は到達性の確認用に限る。
 
### wg-server（[README](../wg-server/README.md)）
- WireGuard インターフェースを作成/再利用し、アドレス、待受ポート、peer を設定。
- authz_mode:
  - observe: 常に forward、必要ならログのみ。
  - enforce: L3 allowlist を nftables で適用（デフォルト drop）。
- logging_enabled:
  - forward 経路に nftables の NFLOG ルールを追加。
  - JSONL でローカル出力（src/dst IP, port, proto, client_id）。
- Policy:
  - client_id は peer の公開鍵。
- 設定ファイル: `wg-server/configs/config.example.yaml`

### wg-client（[README](../wg-client/README.md)）
- WireGuard インターフェースを作成/再利用し、アドレスと server peer を設定。
- AllowedIPs へのルートを追加。
- listen_port と persistent keepalive を任意で設定可。
- 設定ファイル: `wg-client/configs/config.example.yaml`

### protected-resource（[README](../protected-resource/README.md)）
- 保護対象として使う最小 HTTP サーバ。
- 0.0.0.0:8080 で待受、/healthz は 200。
