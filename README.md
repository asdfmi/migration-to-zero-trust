# Migration to Zero Trust

This repository organizes the rationale and migration path from VPN-centered boundary trust to Zero Trust,
and provides MVP implementations for the data plane (WG server/client) in a monorepo layout.

## Docs
- Background and migration narrative: `docs/MIGRATION-TO-ZERO-TRUST.md`
- Data plane design: `docs/DESIGN.md`
- Operations and phased rollout: `docs/OPERATION.md`

## Components
### wg-server (MVP)
WireGuard server runtime that configures the kernel interface, address, and peers via `wgctrl`.
See `wg-server/README.md`.

### wg-client (MVP)
WireGuard client runtime that configures the kernel interface and routes for AllowedIPs.
See `wg-client/README.md`.

### control-plane (MVP)
Placeholder for the control plane (CRUD + config distribution).
See `control-plane/README.md`.

### protected-resource
Minimal HTTP service that represents a protected resource for the Zero Trust MVP.
See `protected-resource/README.md`.
