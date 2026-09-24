//! The [`Ruleset`] / [`Chain`] containers and schema version.

use serde::{Deserialize, Serialize};

use crate::action::Policy;
use crate::rule::{Rule, RuleId};

/// Current schema version written by this crate on serialize.
///
/// # Versioning story (provisional)
///
/// `version` is a monotonically increasing `u64` identifying the *shape* of
/// the ruleset document. v1 is the initial schema defined by this crate;
/// migration is trivial only in the sense that there is nothing to migrate
/// *from* yet.
///
/// This is **provisional** pending `bastion-ir`'s actual versioning scheme
/// (`tpt-bastion` does not exist yet to confirm against — open question in
/// `spec.txt`). When `bastion-ir` lands, reconcile: if its scheme is not a
/// plain integer, adapt `Ruleset::version` before any external consumer
/// depends on the wire format. Consumers should treat unknown versions as
/// hard errors (no silent best-effort parse).
pub const SCHEMA_VERSION: u64 = 1;

/// A complete, versioned set of chains to install in the dataplane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ruleset {
    /// Schema version — see [`SCHEMA_VERSION`]. Must be `<=` the version
    /// this crate understands for [`verify`](crate::verify) to accept it.
    pub version: u64,
    /// Named chains, evaluated in declaration order by consumers that walk
    /// the list linearly; within each chain, rules run in `priority` order
    /// (see [`Rule::priority`](crate::Rule::priority)).
    pub chains: Vec<Chain>,
}

impl Default for Ruleset {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
            chains: Vec::new(),
        }
    }
}

impl Ruleset {
    /// Construct a ruleset at the current [`SCHEMA_VERSION`].
    #[must_use]
    pub fn new(chains: Vec<Chain>) -> Self {
        Self {
            version: SCHEMA_VERSION,
            chains,
        }
    }

    /// Iterate every rule in the ruleset (chain order, then priority order
    /// is *not* applied here — this is raw declaration order per chain).
    pub fn iter_rules(&self) -> impl Iterator<Item = (&Chain, &Rule)> {
        self.chains
            .iter()
            .flat_map(|c| c.rules.iter().map(move |r| (c, r)))
    }
}

/// A named, ordered list of [`Rule`]s evaluated as a unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    /// Chain name (e.g. `input`, `forward`, `output`, or a custom chain).
    /// Must be unique in the ruleset (enforced by [`verify`](crate::verify)).
    pub name: String,
    /// Rules in this chain. Evaluation order is by [`Rule::priority`]
    /// ascending (ties are a lint error).
    pub rules: Vec<Rule>,
    /// Policy applied when no rule matches (the chain's default action).
    pub default_policy: Policy,
}

impl Chain {
    /// Construct a chain with an explicit default policy.
    #[must_use]
    pub fn new(name: impl Into<String>, rules: Vec<Rule>, default_policy: Policy) -> Self {
        Self {
            name: name.into(),
            rules,
            default_policy,
        }
    }
}

/// A computed difference between a desired [`Ruleset`] and live dataplane
/// state.
///
/// Produced by a backend's diff logic; submitted to its `validate`/`apply`
/// (e.g. `tpt_netctl_core::DataplaneBackend`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RulesetDiff {
    /// Rules present in the desired state but not live (to add).
    pub add: Vec<Rule>,
    /// Rules present in both but with changed matcher/action/priority
    /// (to update).
    pub update: Vec<Rule>,
    /// [`RuleId`]s present live but not desired (to remove).
    pub remove: Vec<RuleId>,
}

impl RulesetDiff {
    /// Returns `true` when the diff would make no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.add.is_empty() && self.update.is_empty() && self.remove.is_empty()
    }

    /// Total number of rule-level changes represented by this diff.
    #[must_use]
    pub fn len(&self) -> usize {
        self.add.len() + self.update.len() + self.remove.len()
    }
}
