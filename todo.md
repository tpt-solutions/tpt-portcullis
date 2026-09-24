# tpt-portcullis — Task Checklist

**Project:** TPT Solutions — Rust-native OPNsense-equivalent firewall/router
**License:** MIT OR Apache-2.0
**MSRV:** Rust 1.82, edition 2021 (`portcullis-rules`); daemon/cli `rust-version = "1.85"` (see MSRV note below)
**Spec:** [spec.txt](spec.txt) — see "Resolved decisions (2026-09-24)" for
the decisions this checklist assumes.

**Scope note:** This checklist covers Phases 1–2 of the spec's phased build
order only — `portcullis-rules` (the rule model) and a minimal single-box
`portcullis-daemon` (wires `tpt-netctl` + `tpt-privd` directly, plain-file
config, no HA/declarative config yet). Phases 3–6 (`tpt-quorum` HA,
`tpt-bastion` declarative config, admin UI via `tpt-appfront`, WireGuard/DNS
adoption, IDS/IPS) are **not** broken into tasks — see Follow-ups.

**Dependency note (updated 2026-09-24):** `tpt-netctl` and `tpt-privd` are
real repos **with real code** (the earlier "spec-only" note was stale as of
implementation start). `tpt-netctl` exposes `DataplaneBackend::{validate,apply}`
taking its own placeholder `RulesetDiff` types (marked `TODO(upstream):
replace with portcullis_rules::*`). `tpt-privd` exposes an open
`CommandKind(u32)` envelope (`CUSTOM_START = 0x8000_0000`) and a one-shot
CBOR client over **Unix sockets only** (Windows returns
`UnsupportedPlatform`). `tpt-citadel` and `tpt-appfront` have real code.
`tpt-quorum`, `tpt-bastion` (+ `bastion-ir`), `tpt-fathom`, `tpt-aegis`, and
`tpt-gatemesh` do not exist anywhere in the portfolio. `portcullis-rules`'
`Matcher` vocabulary and lint/verify pass are therefore built self-contained
(own types, own graph model) rather than reusing `tpt-fathom`/`tpt-gatemesh`
— see Follow-ups for reconciling later.

**MSRV note (decision):** Workspace default is 1.82 so `portcullis-rules`
stays a valid path dependency for `tpt-netctl` (also 1.82).
`portcullis-daemon` and `portcullis-cli` declare `rust-version = "1.85"`
because they path-depend on `tpt-privd` (edition 2024 / rust 1.85). CI's
1.82 job reduces the workspace to `portcullis-rules` only (full-workspace
manifests cannot parse on 1.82); stable runs the full workspace.

---

## Phase 0 — Workspace Bootstrap

- [x] `git init`
- [x] Root `Cargo.toml` as a workspace:
  - `members = ["crates/portcullis-rules", "crates/portcullis-cli", "crates/portcullis-daemon"]`
  - `[workspace.package]`: `authors = ["TPT Solutions"]`, `license = "MIT OR Apache-2.0"`, `edition = "2021"`, `rust-version = "1.82"`
- [x] `rust-toolchain.toml` pinning `stable` channel, `1.82` minimum
- [x] `.gitignore` for Rust projects (`/target`, etc.) — commit `Cargo.lock` (this workspace ships binaries)
- [x] `rustfmt.toml`
- [x] `clippy.toml` + CI configured to deny warnings
- [x] `deny.toml` (cargo-deny: license check restricted to MIT/Apache-2.0-compatible, duplicate-dependency check, advisory check)
- [x] `.github/workflows/ci.yml`
  - Linux runner (`ubuntu-latest`)
  - Matrix: Rust `stable` + Rust `1.82`
  - Steps: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `cargo doc --no-deps`
  - 1.82 job reduces workspace to `portcullis-rules` (see MSRV note)
  - Sibling `tpt-netctl` / `tpt-privd` checked out for path deps on stable/deny jobs
- [x] Root `README.md`: what this repo is, the dependency table from spec.txt (with real/missing status noted), crate overview, license badges, link to spec.txt
- [x] Initial commit (spec.txt, todo.md, LICENSE-MIT, LICENSE-APACHE) + workspace scaffold commit

---

## Phase 1 — `portcullis-rules`

- [x] Scaffold crate (`crates/portcullis-rules/Cargo.toml`, `src/lib.rs`)
- [x] Core types per spec's sketch:
  - [x] `struct Ruleset { chains: Vec<Chain>, version: u64 }`
  - [x] `struct Chain { name: String, rules: Vec<Rule>, default_policy: Policy }`
  - [x] `struct Rule { id: RuleId, priority: u32, matcher: Matcher, action: Action }`
  - [x] `enum Action { Accept, Drop, Reject, Nat(NatRule), RateLimit(ShapingPolicy) }`
  - [x] `enum Policy { Accept, Drop }`
  - [x] `RuleId` (newtype — **decision: `u64`**, matches `tpt-netctl`'s placeholder `type RuleId = u64`, no uuid dep, stable for counters/diffing)
- [x] `NatRule` type (source/dest translation shape — SNAT/DNAT/masquerade, per what `tpt-netctl` will need to apply)
- [x] `ShapingPolicy` type (rate-limit shape — bandwidth cap, burst, per-rule vs. per-chain; per-chain shaping deferred to Follow-ups)
- [x] **`Matcher` vocabulary** (self-contained, own types — not borrowed from `tpt-fathom`):
  - [x] Protocol enum (TCP/UDP/ICMP/Any, extensible via `Number(u8)`)
  - [x] Address matcher (single IP, CIDR, range, `Any`; v4 + v6)
  - [x] Port matcher (single, range, `Any`)
  - [x] Interface matcher (by name)
  - [x] Combinator semantics documented (implicit AND across fields — confirmed and documented on `Matcher` + module docs)
- [x] serde `Serialize`/`Deserialize` derives on all public types
- [x] Versioned schema: document the `version: u64` migration story (even if v1 is trivial) — note in a doc comment that this is provisional pending `bastion-ir`'s actual versioning scheme (open question, `tpt-bastion` doesn't exist yet to confirm against)
- [x] **Validation/lint pass** (`fn verify(&Ruleset) -> Result<(), Vec<LintIssue>>`):
  - [x] Model ruleset as a graph (chains/rules as nodes, priority/matcher-overlap as edges) per spec's borrowed pattern
  - [x] Detect unreachable rules (shadowed by a higher-priority rule with a superset matcher and terminal action)
  - [x] Detect priority collisions (two rules, same priority, overlapping matcher)
  - [x] Detect shadowed rules generally (distinct from unreachable — e.g. same matcher, different action, wrong order)
  - [x] `LintIssue` type with enough detail to point a user at the offending rule(s)
  - [x] `tpt-netctl`/`tpt-bastion`-style contract: refuse to hand a `Ruleset` to a consumer if verification fails (expose this as the crate's documented usage contract, not enforced by this crate itself since it doesn't own the "hand to netctl" step)
- [x] Unit tests: serde round-trip for every public type
- [x] Unit tests: lint pass — unreachable rule, priority collision, shadowed rule, and a clean ruleset (no false positives)
- [x] rustdoc for all public types/functions, including rationale for the self-contained `Matcher`/lint-pass decision (link to spec.txt's Resolved Decisions)

---

## Phase 2 — Minimal `portcullis-daemon` + `portcullis-cli`

- [x] Scaffold `crates/portcullis-daemon` (bin crate)
- [x] Scaffold `crates/portcullis-cli` (bin crate)
- [x] Plain-file config format (TOML) that deserializes into a `portcullis-rules::Ruleset` (`FileConfig { ruleset }` wrapper)
- [x] Config loader: read file → parse → run `portcullis-rules`' verify pass → reject with clear error on lint failure
- [x] `tpt-netctl` integration:
  - [x] Add as path dependency
  - [x] Confirm current shape of `tpt-netctl`'s `apply(&RulesetDiff)` — **real:** `DataplaneBackend::{validate,apply}` on `tpt_netctl_core`, diff type is `RulesetDiff { add, update, remove }` against placeholder rule types
  - [x] Wire `portcullis-rules::Ruleset` → `tpt_netctl_core::RulesetDiff` via `bridge` module (type mismatch documented in bridge rustdoc: our `priority`/`NatRule`/`ShapingPolicy` vs their inline `Snat`/`Dnat`/`RateLimit` + `Jump`/`Continue`/`description`; priority order baked into declaration order at bridge time)
- [x] `tpt-privd` integration:
  - [x] Add as path dependency
  - [x] Confirm current shape of `tpt-privd`'s command envelope — **real:** open `CommandId`/`CommandKind(u32)`/`Command`/`CommandResult` CBOR envelope; one-shot Unix-socket client (`tpt-privd-client::call`)
  - [x] Wire daemon's privileged ops through `tpt-privd`'s client (health-check `NOP` on start when `--privd-socket` set; `PortcullisCommandKind` allocated from `CUSTOM_START` for future apply/read-state kinds); Windows: client returns `UnsupportedPlatform` → health-check degrades to warn-and-continue (dataplane apply is in-process)
- [x] Daemon lifecycle: start, load config, apply ruleset, hold state, graceful reload on config change (**decision:** mtime polling, portable — no SIGHUP-only design)
- [x] `portcullis-cli`: `validate <config-file>` (parse + lint, no apply), `apply <config-file>` (talks to running daemon — **decision:** daemon owns apply; CLI is a client over localhost TCP control socket); also `reload` and `status`
- [x] Structured logging (**decision:** `tracing` + `tracing-subscriber`; follow-up to align with siblings once they adopt a logger)
- [x] Integration test: config file → parsed `Ruleset` → verify pass → (mock/in-memory) `tpt-netctl` apply call; lint-failure rejection; control-socket round-trip
- [x] README section: how to run the daemon + CLI against a single box

---

## Follow-ups (not yet broken into tasks)

- `tpt-quorum` integration for 2-node HA (Phase 3) — blocked, repo doesn't exist
- `tpt-bastion` network-provider integration + drift detection (Phase 4) — blocked, repo doesn't exist; also blocked on the `bastion-providers` interface question referenced in spec.txt
- Admin UI via `tpt-appfront` (Phase 5) — `tpt-appfront` itself is real and has code; UI work can start once the daemon has a stable API to build against
- WireGuard (`boringtun`) and DNS (`hickory-dns`) adoption (Phase 6)
- IDS/IPS (Suricata) and OpenVPN/IPsec compatibility — explicitly out of scope per spec.txt, deferred to a later, separately-scoped decision
- Reconcile `portcullis-rules`' `Matcher`/lint pass with `tpt-fathom`'s protocol types and `tpt-gatemesh`'s verification implementation once those repos exist and have code
- Reconcile `portcullis-rules` with `tpt-netctl`'s existing placeholder `Ruleset`/`Chain`/`Rule`/`Matcher`/`Action`/`Policy` types (defined in `tpt-netctl`'s workspace, marked `TODO(upstream)`) — swap `tpt-netctl` over to depend on `portcullis-rules` directly
- Full "privd is the only kernel-toucher" posture: today's Phase 2 applies via in-process `tpt-netctl` (needs `CAP_NET_ADMIN`); long-term needs a netctl `CommandExecutor` inside `tpt-privd` so the daemon stays unprivileged — not blocked on code, but a design follow-up
- Confirm `bastion-ir`'s versioning scheme once `tpt-bastion` exists; migrate `Ruleset.version` if it doesn't match
- DHCP scope decision (own component vs. adopted) — open question from spec.txt, no mature permissive Rust alternative identified yet
- Admin-auth story once `tpt-aegis` exists, or a decision to build a minimal self-contained auth layer in `portcullis-daemon` (same move `tpt-privd` made for its audit log when `tpt-citadel`'s wasn't ready)
- Re-check `tpt-citadel` for VPN key/cert storage once WireGuard adoption (Phase 6) starts — its audit crate was immature as of the check that informed this checklist, but that's a different sub-crate; re-verify the secrets/cert storage piece specifically before depending on it
- Align structured logging crate with `tpt-netctl`/`tpt-privd` once they adopt one (currently `tracing` here, no logger there yet)
