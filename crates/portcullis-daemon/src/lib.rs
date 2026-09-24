//! # portcullis-daemon
//!
//! Single-box Portcullis daemon: loads a plain-file (TOML) config into a
//! [`portcullis_rules::Ruleset`], runs the lint/verify pass, bridges to
//! `tpt-netctl`'s dataplane backend, and health-checks `tpt-privd`.
//!
//! Intentionally thin — hard logic lives in the dependency repos.
//!
//! ## License
//!
//! MIT OR Apache-2.0

#![deny(missing_docs)]

pub mod bridge;
pub mod config;
pub mod control;
pub mod privd;
pub mod state;

pub use config::{load_ruleset, ConfigError};
pub use state::{ApplyOutcome, DaemonState};
