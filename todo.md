# tpt-portcullis — Task Checklist

**Project:** TPT Solutions — Rust-native OPNsense-equivalent firewall/router
**License:** MIT OR Apache-2.0
**MSRV:** Rust 1.82, edition 2021
**Spec:** [spec.txt](spec.txt) — see "Resolved decisions (2026-09-24)" for
the decisions this checklist assumes.

**Scope note:** This checklist covers Phases 1–2 of the spec's phased build
order only — `portcullis-rules` (the rule model) and a minimal single-box
`portcullis-daemon` (wires `tpt-netctl` + `tpt-privd` directly, plain-file
config, no HA/declarative config yet). Phases 3–6 (`tpt-quorum` HA,
`tpt-bastion` declarative config, admin UI via `tpt-appfront`, WireGuard/DNS
adoption, IDS/IPS) are **not** broken into tasks — see Follow-ups.

**Dependency note:** `tpt-netctl` and `tpt-privd` are real repos but are
spec.txt + todo.md only today — no code. `tpt-citadel` and `tpt-appfront`
have real code. `tpt-quorum`, `tpt-bastion` (+ `bastion-ir`), `tpt-fathom`,
`tpt-aegis`, and `tpt-gatemesh` do not exist anywhere in the portfolio.
`portcullis-rules`' `Matcher` vocabulary and lint/verify pass are therefore
built self-contained (own types, own graph model) rather than reusing
`tpt-fathom`/`tpt-gatemesh` as the spec originally suggested — see Follow-ups
for reconciling later.

---

## Phase 0 — Workspace Bootstrap

- [ ] `git init`
- [ ] Root `Cargo.toml` as a workspace:
  - `members = ["crates/portcullis-rules", "crates/portcullis-cli", "crates/portcullis-daemon"]`
  - `[workspace.package]`: `authors = ["TPT Solutions"]`, `license = "MIT OR Apache-2.0"`, `edition = "2021"`, `rust-version = "1.82"`
- [ ] `rust-toolchain.toml` pinning `stable` channel, `1.82` minimum
- [ ] `.gitignore` for Rust projects (`/target`, etc.) — commit `Cargo.lock` (this workspace ships binaries)
- [ ] `rustfmt.toml`
- [ ] `clippy.toml` + CI configured to deny warnings
- [ ] `deny.toml` (cargo-deny: license check restricted to MIT/Apache-2.0-compatible, duplicate-dependency check, advisory check)
- [ ] `.github/workflows/ci.yml`
  - Linux runner (`ubuntu-latest`)
  - Matrix: Rust `stable` + Rust `1.82`
  - Steps: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --check`, `cargo deny check`, `cargo doc --no-deps`
- [ ] Root `README.md`: what this repo is, the dependency table from spec.txt (with real/missing status noted), crate overview, license badges, link to spec.txt
- [ ] Initial commit (spec.txt, todo.md, LICENSE-MIT, LICENSE-APACHE, workspace scaffold)

---

## Phase 1 — `portcullis-rules`

- [ ] Scaffold crate (`crates/portcullis-rules/Cargo.toml`, `src/lib.rs`)
- [ ] Core types per spec's sketch:
  - [ ] `struct Ruleset { chains: Vec<Chain>, version: u64 }`
  - [ ] `struct Chain { name: String, rules: Vec<Rule>, default_policy: Policy }`
  - [ ] `struct Rule { id: RuleId, priority: u32, matcher: Matcher, action: Action }`
  - [ ] `enum Action { Accept, Drop, Reject, Nat(NatRule), RateLimit(ShapingPolicy) }`
  - [ ] `enum Policy { Accept, Drop }`
  - [ ] `RuleId` (newtype, e.g. `Uuid` or `u64` — decide and document why)
- [ ] `NatRule` type (source/dest translation shape — SNAT/DNAT/masquerade, per what `tpt-netctl` will need to apply)
- [ ] `ShapingPolicy` type (rate-limit shape — bandwidth cap, burst, per-rule vs. per-chain)
- [ ] **`Matcher` vocabulary** (self-contained, own types — not borrowed from `tpt-fathom`):
  - [ ] Protocol enum (TCP/UDP/ICMP/Any, extensible)
  - [ ] Address matcher (single IP, CIDR, range, `Any`; v4 + v6)
  - [ ] Port matcher (single, range, `Any`)
  - [ ] Interface matcher (by name)
  - [ ] Combinator semantics documented (implicit AND across fields — confirm and document explicitly)
- [ ] serde `Serialize`/`Deserialize` derives on all public types
- [ ] Versioned schema: document the `version: u64` migration story (even if v1 is trivial) — note in a doc comment that this is provisional pending `bastion-ir`'s actual versioning scheme (open question, `tpt-bastion` doesn't exist yet to confirm against)
- [ ] **Validation/lint pass** (`fn verify(&Ruleset) -> Result<(), Vec<LintIssue>>` or similar):
  - [ ] Model ruleset as a graph (chains/rules as nodes, priority/matcher-overlap as edges) per spec's borrowed pattern
  - [ ] Detect unreachable rules (shadowed by a higher-priority rule with a superset matcher and terminal action)
  - [ ] Detect priority collisions (two rules, same priority, overlapping matcher)
  - [ ] Detect shadowed rules generally (distinct from unreachable — e.g. same matcher, different action, wrong order)
  - [ ] `LintIssue` type with enough detail to point a user at the offending rule(s)
  - [ ] `tpt-netctl`/`tpt-bastion`-style contract: refuse to hand a `Ruleset` to a consumer if verification fails (expose this as the crate's documented usage contract, not enforced by this crate itself since it doesn't own the "hand to netctl" step)
- [ ] Unit tests: serde round-trip for every public type
- [ ] Unit tests: lint pass — unreachable rule, priority collision, shadowed rule, and a clean ruleset (no false positives)
- [ ] rustdoc for all public types/functions, including rationale for the self-contained `Matcher`/lint-pass decision (link to spec.txt's Resolved Decisions)

---

## Phase 2 — Minimal `portcullis-daemon` + `portcullis-cli`

- [ ] Scaffold `crates/portcullis-daemon` (bin crate)
- [ ] Scaffold `crates/portcullis-cli` (bin crate)
- [ ] Plain-file config format (TOML or similar) that deserializes into a `portcullis-rules::Ruleset`
- [ ] Config loader: read file → parse → run `portcullis-rules`' verify pass → reject with clear error on lint failure
- [ ] `tpt-netctl` integration:
  - [ ] Add as path dependency
  - [ ] Confirm current shape of `tpt-netctl`'s `apply(&RulesetDiff)` (or whatever it's actually named today — it's spec-only, re-check against its todo.md/spec.txt before wiring)
  - [ ] Wire `portcullis-rules::Ruleset` → whatever `tpt-netctl` currently accepts (likely its own placeholder types today, not `portcullis-rules` — note the mismatch and how the daemon bridges it, or block this sub-task until `tpt-netctl` has real code to integrate against)
- [ ] `tpt-privd` integration:
  - [ ] Add as path dependency
  - [ ] Confirm current shape of `tpt-privd`'s command envelope (spec-only today — re-check before wiring)
  - [ ] Wire daemon's privileged operations (if any needed beyond what netctl handles) through `tpt-privd`'s client, not directly
- [ ] Daemon lifecycle: start, load config, apply ruleset, hold state, graceful reload on config change (signal or file-watch — decide which)
- [ ] `portcullis-cli`: `validate <config-file>` (parse + lint, no apply), `apply <config-file>` (talks to running daemon or applies directly — decide the daemon/CLI split)
- [ ] Structured logging (what crate — match whatever `tpt-netctl`/`tpt-privd` use once they have code; otherwise pick one now and note it as a follow-up to align)
- [ ] Integration test: config file → parsed `Ruleset` → verify pass → (mock or real, depending on what's exercisable) `tpt-netctl` apply call
- [ ] README section: how to run the daemon + CLI against a single box (once this phase is functional)

---

## Follow-ups (not yet broken into tasks)

- `tpt-quorum` integration for 2-node HA (Phase 3) — blocked, repo doesn't exist
- `tpt-bastion` network-provider integration + drift detection (Phase 4) — blocked, repo doesn't exist; also blocked on the `bastion-providers` interface question referenced in spec.txt
- Admin UI via `tpt-appfront` (Phase 5) — `tpt-appfront` itself is real and has code; UI work can start once the daemon has a stable API to build against
- WireGuard (`boringtun`) and DNS (`hickory-dns`) adoption (Phase 6)
- IDS/IPS (Suricata) and OpenVPN/IPsec compatibility — explicitly out of scope per spec.txt, deferred to a later, separately-scoped decision
- Reconcile `portcullis-rules`' `Matcher`/lint pass with `tpt-fathom`'s protocol types and `tpt-gatemesh`'s verification implementation once those repos exist and have code
- Reconcile `portcullis-rules` with `tpt-netctl`'s existing placeholder `Ruleset`/`Chain`/`Rule`/`Matcher`/`Action`/`Policy` types (defined in `tpt-netctl`'s workspace, marked `TODO(upstream)`) — swap `tpt-netctl` over to depend on `portcullis-rules` directly
- Confirm `bastion-ir`'s versioning scheme once `tpt-bastion` exists; migrate `Ruleset.version` if it doesn't match
- DHCP scope decision (own component vs. adopted) — open question from spec.txt, no mature permissive Rust alternative identified yet
- Admin-auth story once `tpt-aegis` exists, or a decision to build a minimal self-contained auth layer in `portcullis-daemon` (same move `tpt-privd` made for its audit log when `tpt-citadel`'s wasn't ready)
- Re-check `tpt-citadel` for VPN key/cert storage once WireGuard adoption (Phase 6) starts — its audit crate was immature as of the check that informed this checklist, but that's a different sub-crate; re-verify the secrets/cert storage piece specifically before depending on it
