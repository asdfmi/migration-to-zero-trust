# Design Document

## Ubiquitous Language

### Entities
| Term | Meaning |
|------|---------|
| **Client** | A user registered in the system. Has a WireGuard public key and credentials |
| **Resource** | A protected network resource. Defined by CIDR |
| **Pair** | An explicit binding between Client and Resource. The unit of access permission |
| **Enforcer** | An access control point deployed in the customer network. Both an entity and a server |

### Components (Binaries)
| Term | Meaning |
|------|---------|
| **controlplane** | Central server for policy management and config distribution |
| **enforcer** | WireGuard + firewall. Can be deployed aggregated (traditional gateway-style) or as sidecar |
| **agent** | Runs on user devices. Handles WireGuard connection and config sync |

### States & Concepts
| Term | Meaning |
|------|---------|
| **observe** | A mode set on Resource. Collects logs only, no access control |
| **enforce** | A mode set on Resource. Allows/denies access based on Pairs |
| **hasPair** | A flag shown in the log screen indicating whether a Pair exists for that access |
| **preferred** | Shown in agent status, indicates routing via WireGuard |
| **Tunnel Subnet** | IP range for WireGuard tunnels managed by the Enforcer |

---

## Overview

Migrating from VPN to Zero Trust faces the problem of "not knowing who is accessing what." Switching to enforce all at once can halt operations due to unexpected access denial.

This application focuses on **phased migration**. First observe, then enforce when ready, and roll back immediately if issues arise.

---

## Features Supporting Phased Migration

### observe/enforce Mode

Each Resource has its own mode.

| Mode | Behavior | Purpose |
|------|----------|---------|
| `observe` | Like traditional VPN, any authenticated Client can access (logs are collected) | Pre-migration observation |
| `enforce` | Only Clients explicitly permitted via Pair can access | Post-migration control |

**Rationale**: We consider "operations halting due to unexpected access denial" a key risk in VPN to Zero Trust migration. Switching to enforce all at once may suddenly block access patterns you weren't aware of. To prevent this, a two-phase approach of "observe first, then control" is necessary. Having mode per Resource allows gradual migration starting from less critical resources.

### hasPair (Migration Readiness Check)

The log screen shows whether each access has a Pair (✓/✗). The decision to switch to enforce is based on the ratio of ✗ and observation period (criteria are customer-dependent).

**Rationale**: We felt that collecting logs in observe mode alone doesn't clearly answer "is it safe to switch to enforce?" We believe what matters is "are current access patterns covered by Pairs?" By visualizing the hasPair flag, administrators can quantitatively assess migration risk.

### status prefer (Migration Verification)

The agent's status command shows whether routes to each Resource go through WireGuard.

```
$ sudo ./agent status

Interface:      wg0
Status:         connected
Peers:          1

Enforcers:
  [1] enforcer.example.com:51820
      Tunnel IP: 10.100.0.2
      CIDRs:     10.0.0.2/32, 10.0.0.3/32

Resources:
  10.0.0.2/32
    wg0 ✓ (preferred)
    tun0: 10.0.0.0/29 (overlap)
  10.0.0.3/32
    wg0 ✓ (preferred)
    tun0: 10.0.0.0/29 (overlap)

Control Plane:  http://controlplane.example.com:8080
Last Updated:   2025-01-15 10:30:00 UTC
```

- `✓ (preferred)`: Routed via WireGuard correctly
- `⚠ (not preferred)`: Another route (VPN, etc.) is being prioritized
- `(overlap)`: Another route exists, but WireGuard's CIDR is more specific (/32 > /29) so it takes priority

**Rationale**: During phased migration, the existing VPN and this application's WireGuard routes run in parallel, with multiple routes to the same destination. It's useful for clients to check their routing table and immediately self-diagnose whether the intended route is being used.

### Rollback

Provides two levels of recovery.

| Level | Action | Effect |
|-------|--------|--------|
| Minor | Switch to observe in UI | Clients without Pairs can access again |
| Major | `agent down` | Stops WireGuard, falls back to legacy VPN route |

**Rationale**: The value of phased migration is "being able to roll back anytime." A migration you can't roll back carries the same risk as "switching all at once." By providing two levels—minor (mode switch) and major (route switch)—recovery matches the severity of the problem. The major rollback especially guarantees that operations can continue via legacy VPN even if the Enforcer fails.
