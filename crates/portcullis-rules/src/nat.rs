//! NAT rule shapes for [`Action::Nat`](crate::Action::Nat).

use serde::{Deserialize, Serialize};

/// Kind of address translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// Rewrite the source address of matching packets.
    Snat,
    /// Rewrite the destination address of matching packets.
    Dnat,
    /// Rewrite the source address to the egress interface's address
    /// (nftables `masquerade`).
    Masquerade,
}

/// A translation target: optional address and optional port rewrite.
///
/// `None` on either field means "leave unchanged".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TranslationTarget {
    /// Replacement address (e.g. `192.0.2.1` or `2001:db8::1`).
    pub address: Option<String>,
    /// Replacement port (applies to TCP/UDP).
    pub port: Option<u16>,
}

/// A single NAT rule attached to an [`Action::Nat`](crate::Action::Nat).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatRule {
    /// Which translation to perform.
    pub nat_type: NatType,
    /// What to rewrite to (address and/or port).
    pub to: TranslationTarget,
    /// Optional remark carried alongside the rule for operators/logs.
    pub remark: Option<String>,
}

impl NatRule {
    /// Convenience: source NAT to a fixed address.
    #[must_use]
    pub fn snat(address: impl Into<String>) -> Self {
        Self {
            nat_type: NatType::Snat,
            to: TranslationTarget {
                address: Some(address.into()),
                port: None,
            },
            remark: None,
        }
    }

    /// Convenience: destination NAT to a fixed address.
    #[must_use]
    pub fn dnat(address: impl Into<String>) -> Self {
        Self {
            nat_type: NatType::Dnat,
            to: TranslationTarget {
                address: Some(address.into()),
                port: None,
            },
            remark: None,
        }
    }

    /// Convenience: masquerade out the egress interface.
    #[must_use]
    pub fn masquerade() -> Self {
        Self {
            nat_type: NatType::Masquerade,
            to: TranslationTarget::default(),
            remark: None,
        }
    }
}
