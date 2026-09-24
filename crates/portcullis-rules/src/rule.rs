//! Rule identity and the per-rule record.

use serde::{Deserialize, Serialize};

use crate::action::Action;
use crate::matcher::Matcher;

/// Stable identifier for a rule within a [`Ruleset`](crate::Ruleset).
///
/// **Decision:** a `u64` newtype (not a UUID). Rationale:
/// - Matches `tpt-netctl`'s placeholder `type RuleId = u64`, so the eventual
///   upstream swap is type-for-type.
/// - No extra dependency (uuid) for a local, single-box ruleset.
/// - Stable across serde round-trips and usable as a map key for counters
///   and diffing without parsing.
///
/// Uniqueness is required across the whole [`Ruleset`](crate::Ruleset)
/// (enforced by [`verify`](crate::verify)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(pub u64);

impl std::fmt::Display for RuleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A single filtering/NAT/rate-limit rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable identifier used for counters and diffing. Must be unique in
    /// the ruleset.
    pub id: RuleId,
    /// Evaluation priority within the chain: **lower runs first**.
    /// Two rules with the same priority and overlapping matchers are a
    /// lint error (priority collision).
    pub priority: u32,
    /// Conditions that must all match for the rule to fire.
    pub matcher: Matcher,
    /// What to do when [`matcher`](Self::matcher) matches.
    pub action: Action,
    /// Optional human-readable description (operators/logs).
    pub description: Option<String>,
}
