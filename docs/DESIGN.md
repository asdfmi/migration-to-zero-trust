# Zero Trust Data Plane Implementation Design (WireGuard-based)

## 1. Purpose and Scope
- Define the minimal data plane specification for a WireGuard-based MVP
- Configuration distribution (control plane) is out of scope; assume local configuration files
- This design focuses on the MVP minimal implementation of the data plane and does not cover the whole Zero Trust picture
- Existing architecture, migration strategy, and operational policy are out of scope

## 2. Runtimes to Implement
- WireGuard client (embedded in Client)
- WG server

## 3. Terminology
- client ID: Identifier derived from the WireGuard public key
- inner packet: The inner packet decrypted by WireGuard

## 4. Configuration (MVP)
- Configuration is loaded from local files at runtime
- For client
  - WG server endpoint (IP:Port)
  - WG server public key
  - AllowedIPs (logical CIDR)
- For WG server
  - client ID
  - client public key
  - AllowedIPs (logical CIDR)
  - (Optional) policy definition

## 5. Client / WireGuard
### Client
- Embeds a WireGuard client
- The WG private key for the client is generated and held on the client side; it is never stored or distributed
- Configured with:
  - WG server endpoint (IP:Port)
  - WG server public key
  - AllowedIPs (logical CIDR)
- OS routing sends traffic destined for AllowedIPs to the wg interface

### WireGuard
- Has only the following roles:
  - Cryptographic verification
  - Peer identification (public key)
  - Inner packet generation
- Has no concepts of authorization, policy, or logging

## 6. WG Server (Implementation Target)
### Inputs
- Inner packet after WG decryption
- Corresponding client ID (derived from the public key)

### Outputs
- Packet forwarding to the next hop

### Required Functions
- authz_mode flag
  - observe: do not perform authorization; always forward
  - enforce: allow/deny based on policy
- logging_enabled flag
  - on/off (independent of authz_mode)
- authz_mode and logging_enabled are managed as local WG server settings

### Behavior (observe)
1. Receive packet
2. Obtain client ID
3. Do not perform authorization
4. Forward to next hop
5. Generate event only if logging_enabled is true

## 7. Logging (Optional)
### Implementation Constraints
- Datapath only enqueues
- I/O and synchronous processing are prohibited
### Destination (MVP)
- Logging output is local only (e.g., file/stdout); no centralized collection

### Implementation
- Lock-free ring buffer
- Resident daemon dequeues asynchronously

### Flush Conditions
- Buffer usage OR elapsed time

### Push
- Asynchronous batch push
- Free memory on success ACK
- Drop on failure (metric only)

## 8. Invariants
- WireGuard cryptographic verification is always performed
- "Ignoring verification and passing through" means not using the verification result for authz
- This is a gateway responsibility, not a WireGuard responsibility

## 9. State Switching
- authz_mode: observe <-> enforce
- logging_enabled: off <-> on
- Both can be switched independently

## 10. One-line Definition for Implementers
"WG confirms the ID. The WG server can choose to use it or discard it. It attaches no other meaning."

---

# Zero Trust Data Plane 実装設計（WireGuard ベース）

## 1. 目的と範囲
- WireGuard ベースの MVP における data plane の最小仕様を定義する
- 設定配布（Control Plane）は対象外とし、ローカル設定ファイルを前提とする
- 本設計は MVP としての data plane 最小実装に絞り、Zero Trust 全体像は扱わない
- 既存アーキテクチャ、移行戦略、運用方針は扱わない

## 2. 実装する runtime
- WireGuard client（Client 内包）
- WG server

## 3. 用語
- client ID: WireGuard 公開鍵に由来する識別子
- inner packet: WireGuard で復号された内側のパケット

## 4. 設定（MVP）
- 設定はローカルのファイルから読み込む
- client 向け
  - WG server endpoint（IP:Port）
  - WG server 公開鍵
  - AllowedIPs（論理 CIDR）
- WG server 向け
  - client ID
  - client 公開鍵
  - AllowedIPs（論理 CIDR）
  - （任意）policy 定義

## 5. Client / WireGuard
### Client
- WireGuard client を内包する
- client 用 WG 秘密鍵は client 側で生成・保持し、外部へ配布しない
- 以下を設定する:
  - WG server endpoint（IP:Port）
  - WG server 公開鍵
  - AllowedIPs（論理 CIDR）
- OS routing により、AllowedIPs 宛の通信を wg interface に送出する

### WireGuard
- 役割は以下のみ:
  - 暗号検証
  - peer 識別（公開鍵）
  - inner packet 生成
- 認可・policy・logging の概念を持たない

## 6. WG server（実装対象）
### 入力
- WG 通過後の inner packet
- 対応する client ID（公開鍵由来）

### 出力
- 次ホップへの packet forward

### 必須機能
- authz_mode フラグ
  - observe: 認可判断を行わず必ず forward
  - enforce: policy に基づき allow/deny
- logging_enabled フラグ
  - on/off（authz_mode とは独立）
- authz_mode と logging_enabled は WG server のローカル設定で管理する

### 動作仕様（observe）
1. packet 受信
2. client ID を取得
3. 認可判断を行わない
4. 次ホップへ forward
5. logging_enabled の場合のみ event 生成

## 7. Logging（オプション機能）
### 実装制約
- datapath は enqueue のみ
- I/O・同期処理は禁止
### 出力先（MVP）
- ログ出力はローカルのみ（例: file/stdout）とし、集約は行わない

### 実装
- lock-free ring buffer
- 常駐 daemon が非同期で dequeue

### flush 条件
- バッファ使用率 OR 経過時間

### push
- 非同期 batch push
- 成功 ACK でメモリ解放
- 失敗時は drop（metric のみ）

## 8. 不変条件
- WireGuard の暗号検証は常に実行される
- 「検証を無視して通す」とは、検証結果を authz に使わないことを意味する
- これは gateway の責務であり WireGuard の責務ではない

## 9. 状態切替
- authz_mode: observe ↔ enforce
- logging_enabled: off ↔ on
- 両者は独立して切替可能

## 10. 実装者向け一文定義
「WG は ID を確定する。WG server はそれを使うか捨てるかを選べる。それ以外の意味づけはしない。」
