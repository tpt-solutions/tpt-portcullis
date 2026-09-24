//! # portcullis-rules
//!
//! Backend-independent, serializable rule model for the TPT Portcullis
//! firewall/router.
//!
//! This crate is the type `tpt-netctl`'s `apply(&RulesetDiff)` will consume
//! and what `tpt-bastion`'s network provider will produce from a person's
//! declarative config. It is deliberately self-contained (own address/port/
//! protocol types, own graph-based lint pass) rather than borrowing from
//! `tpt-fathom`/`tpt-gatemesh` — see `spec.txt` Resolved decisions
//! (2026-09-24) for the rationale.
//!
//! ## Usage contract
//!
//! Consumers **must not** hand a [`Ruleset`] to a dataplane backend if
//! [`verify`] returns errors. This crate exposes the check but cannot enforce
//! the hand-off step itself (it does not own `tpt-netctl`'s apply path).
//!
//! ## License
//!
//! MIT OR Apache-2.0

#![deny(missing_docs)]

mod action;
mod lint;
mod matcher;
mod nat;
mod rule;
mod ruleset;
mod shaping;

pub use action::{Action, Policy};
pub use lint::{verify, LintIssue, LintKind};
pub use matcher::{
    AddressMatcher, InterfaceMatcher, IpVersion, Matcher, PortMatcher, PortRange, Protocol,
};
pub use nat::{NatRule, NatType, TranslationTarget};
pub use rule::{Rule, RuleId};
pub use ruleset::{Chain, Ruleset, RulesetDiff, SCHEMA_VERSION};
pub use shaping::{RateUnit, ShapingPolicy};
