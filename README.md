# Migration to Zero Trust

This repository organizes the rationale and migration path from VPN-centered boundary trust to Zero Trust,
and provides MVP implementations for the data plane (WG server/client) in a monorepo layout.

## Scope and Intent
- Explain the migration mindset and operational approach from VPN boundary trust to Zero Trust
- Provide concrete, minimal data-plane examples to make the concepts tangible
- Offer phased rollout guidance and references for further study

## Docs
- Background and migration narrative: [docs/MIGRATION-TO-ZERO-TRUST.md](docs/MIGRATION-TO-ZERO-TRUST.md)
- Data plane design: [docs/DESIGN.md](docs/DESIGN.md)
- Operations and phased rollout: [docs/OPERATION.md](docs/OPERATION.md)

## Components
### wg-server (MVP)
WireGuard server runtime that configures the kernel interface, address, and peers via `wgctrl`.
See [wg-server/README.md](wg-server/README.md).

### wg-client (MVP)
WireGuard client runtime that configures the kernel interface and routes for AllowedIPs.
See [wg-client/README.md](wg-client/README.md).

### protected-resource
Minimal HTTP service that represents a protected resource for the Zero Trust MVP.
See [protected-resource/README.md](protected-resource/README.md).

## References
- https://csrc.nist.gov/pubs/sp/800/207/final
- https://research.google/pubs/beyondcorp-and-the-long-tail-of-zero-trust/
