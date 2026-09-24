# tpt-portcullis

[![CI](https://github.com/TPT-Solutions/tpt-portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/TPT-Solutions/tpt-portcullis/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/rust-1.82-orange.svg)](https://blog.rust-lang.org/2024/10/17/Rust-1.82.0.html)

Rust-native OPNsense-equivalent firewall/router — the rule model and
product-level glue that wires dataplane, privileged execution, and (later)
HA/declarative config into one coherent thing a person can install and run.

**Spec:** [spec.txt](spec.txt) · **Checklist:** [todo.md](todo.md)

## What this is

Most of the hard technical dependencies are deliberately *not* built here:

| Dependency | Repo | Role | Status |
|---|---|---|---|
| Dataplane enactment | [`tpt-netctl`](../tpt-netctl) | applies filter/NAT/rate-limit state to nftables/eBPF | real code |
| Privileged execution | [`tpt-privd`](../tpt-privd) | the only process allowed to touch the kernel | real code |
| HA / failover | `tpt-quorum` | 2-node active/passive coordination | missing |
| Declarative config engine | `tpt-bastion` (+ network provider) | plan/apply/drift-detection | missing |
| VPN (WireGuard) | `boringtun` (external, BSD-3-Clause) | adopted, not built | external |
| DNS resolver | `hickory-dns` (external, MIT/Apache dual) | adopted, not built | external |
| Protocol/packet inspection | `tpt-fathom` | DPI, logging substrate | missing |
| Admin UI framework | [`tpt-appfront`](../tpt-appfront) | cross-platform Rust UI | real code |
| Secrets/certs | [`tpt-citadel`](../tpt-citadel) | VPN keys, cert storage | real code |
| Admin auth | `tpt-aegis` | IAM, 2FA | missing |

What's actually new *in this repo* is the rule model and the product-level
glue. Phases 1–2 of the build (this checklist) cover `portcullis-rules` plus
a minimal single-box `portcullis-daemon`. HA, declarative config, admin UI,
and WireGuard/DNS adoption are tracked as follow-ups in [todo.md](todo.md).

## Crates

| Crate | Description |
| --- | --- |
| [`portcullis-rules`](crates/portcullis-rules) | Backend-independent rule model + lint/verify pass |
| [`portcullis-daemon`](crates/portcullis-daemon) | Single-box daemon: config → verify → netctl apply, privd health-check |
| [`portcullis-cli`](crates/portcullis-cli) | Admin CLI (`validate` / `apply` / `reload` / `status`) |

### MSRV note

Workspace MSRV is **1.82** so `portcullis-rules` remains a valid path
dependency for `tpt-netctl` (also 1.82). `portcullis-daemon` and
`portcullis-cli` declare `rust-version = "1.85"` because they depend on
`tpt-privd` (edition 2024 / rust 1.85). CI tests 1.82 against
`-p portcullis-rules` only; stable runs the full workspace.

### Path dependencies

This repo expects sibling checkouts for local development:

```
Open Source/
├── tpt-portcullis/   # this repo
├── tpt-netctl/
└── tpt-privd/
```

CI checks out those repositories as siblings so path deps resolve.

## Quickstart (Phase 2+)

```bash
# Validate a config offline (parse + lint, no apply):
cargo run -p portcullis-cli -- validate path/to/rules.toml

# Run the daemon (loads config, applies via netctl, serves control socket):
cargo run -p portcullis-daemon -- --config path/to/rules.toml

# Ask the running daemon to (re)apply:
cargo run -p portcullis-cli -- apply path/to/rules.toml
cargo run -p portcullis-cli -- status
```

See each crate's rustdoc for details.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.
