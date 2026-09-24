//! Action and default-policy enums for a [`Rule`](crate::Rule) /
//! [`Chain`](crate::Chain).

use serde::{Deserialize, Serialize};

use crate::nat::NatRule;
use crate::shaping::ShapingPolicy;

/// What to do when a [`Rule`](crate::Rule)'s matcher succeeds.
///
/// Serde representation is externally tagged (default), so unit variants
/// serialize as bare strings (`"accept"`) — friendly for TOML configs.
/// Complex variants appear as single-key maps (`{ nat = { ... } }`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Accept the packet (stop evaluation, let it through).
    Accept,
    /// Drop the packet silently.
    Drop,
    /// Reject with an ICMP/TCP reset (notify the sender).
    Reject,
    /// Address and/or port translation (SNAT/DNAT/masquerade).
    Nat(NatRule),
    /// Rate-limit matching traffic.
    RateLimit(ShapingPolicy),
    /// Jump to another named chain (nftables `jump`); control returns to
    /// this chain after the target's evaluation finishes.
    Jump(String),
    /// Continue to the next rule without terminating evaluation.
    Continue,
}

impl Action {
    /// Returns `true` if this action terminates packet evaluation for the
    /// chain (as opposed to a non-terminal transform like NAT/rate-limit,
    /// or a transfer of control like `Jump`/`Continue`).
    ///
    /// Terminal actions are the ones that make a later rule *unreachable*
    /// when their matcher is a superset of a lower-priority rule's matcher.
    ///
    /// `Jump` is deliberately **not** terminal here: the target chain may
    /// return control, so a later rule can still run — treating it as
    /// terminal would produce false-positive `Unreachable` lints.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Accept | Self::Drop | Self::Reject)
    }
}

/// Default action for a [`Chain`](crate::Chain) when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    /// Accept unmatched traffic.
    Accept,
    /// Drop unmatched traffic.
    Drop,
    /// Reject unmatched traffic (notify the sender).
    Reject,
}

impl Policy {
    /// The equivalent terminal [`Action`] for this policy.
    #[must_use]
    pub const fn to_action(self) -> Action {
        match self {
            Self::Accept => Action::Accept,
            Self::Drop => Action::Drop,
            Self::Reject => Action::Reject,
        }
    }
}
