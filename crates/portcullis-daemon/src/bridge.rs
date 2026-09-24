//! Bridge: `portcullis_rules::Ruleset` → `tpt_netctl_core` types.
//!
//! # Temporary type mismatch
//!
//! `tpt-netctl` still owns placeholder `Ruleset`/`Chain`/`Rule`/`Matcher`/
//! `Action`/`Policy` types (marked `TODO(upstream): replace with
//! portcullis_rules::*`). Until that swap lands upstream, this module is the
//! explicit conversion point. Shapes differ:
//!
//! | portcullis-rules | tpt-netctl-core (placeholder) |
//! |---|---|
//! | `Rule.priority: u32` | no priority (declaration order) |
//! | `Action::Nat(NatRule)` | `Action::Snat` / `Action::Dnat` |
//! | `Action::RateLimit(ShapingPolicy)` | `Action::RateLimit { rate, burst }` |
//! | `Policy::{Accept,Drop}` | `Policy::{Accept,Drop,Reject}` |
//! | typed `Matcher` fields (`Protocol`, `AddressMatcher`, …) | `Option<String>` fields |
//!
//! Evaluation order after bridge: rules sorted by `priority` ascending
//! (stable within equal priorities — equal priorities with overlap are a
//! lint error and never reach apply).

use portcullis_rules as pr;
use tpt_netctl_core as nc;

use crate::state::BridgeError;

/// Convert a verified [`pr::Ruleset`] into netctl's [`nc::Ruleset`].
///
/// # Errors
///
/// [`BridgeError`] when a typed field cannot be represented in netctl's
/// stringly-typed placeholders (currently: none expected for well-formed
/// matchers — address/port render to their canonical string forms).
pub fn ruleset_to_netctl(rs: &pr::Ruleset) -> Result<nc::Ruleset, BridgeError> {
    let mut chains = Vec::with_capacity(rs.chains.len());
    for chain in &rs.chains {
        // netctl evaluates declaration order — bake priority ordering in.
        let mut typed: Vec<&pr::Rule> = chain.rules.iter().collect();
        typed.sort_by_key(|r| r.priority);
        let rules: Vec<nc::Rule> = typed.iter().map(|r| rule_to_netctl(r)).collect();

        chains.push(nc::Chain {
            name: chain.name.clone(),
            rules,
            policy: policy_to_netctl(chain.default_policy),
        });
    }
    Ok(nc::Ruleset { chains })
}

/// Build a full desired-state [`nc::Ruleset`] (already priority-sorted).
///
/// Convenience wrapper used by the daemon's apply path.
pub fn desired_netctl_ruleset(rs: &pr::Ruleset) -> nc::Ruleset {
    // Infallible in practice: rule_to_netctl is total.
    ruleset_to_netctl(rs).expect("bridge is total for verified rulesets")
}

fn rule_to_netctl(rule: &pr::Rule) -> nc::Rule {
    nc::Rule {
        id: rule.id.0,
        description: rule.description.clone(),
        matcher: matcher_to_netctl(&rule.matcher),
        action: action_to_netctl(&rule.action),
    }
}

fn matcher_to_netctl(m: &pr::Matcher) -> nc::Matcher {
    nc::Matcher {
        in_interface: iface_field(&m.in_interface),
        out_interface: iface_field(&m.out_interface),
        protocol: protocol_field(&m.protocol),
        src_addr: addr_field(&m.src_addr),
        dst_addr: addr_field(&m.dst_addr),
        src_port: port_field(&m.src_port),
        dst_port: port_field(&m.dst_port),
    }
}

fn iface_field(m: &pr::InterfaceMatcher) -> Option<String> {
    match m {
        pr::InterfaceMatcher::Any => None,
        pr::InterfaceMatcher::Name(n) => Some(n.clone()),
    }
}

fn protocol_field(p: &pr::Protocol) -> Option<String> {
    match p {
        pr::Protocol::Any => None,
        pr::Protocol::Tcp => Some("tcp".into()),
        pr::Protocol::Udp => Some("udp".into()),
        pr::Protocol::Icmp => Some("icmp".into()),
        pr::Protocol::Icmpv6 => Some("icmpv6".into()),
        pr::Protocol::Number(n) => Some(n.to_string()),
    }
}

fn addr_field(a: &pr::AddressMatcher) -> Option<String> {
    match a {
        pr::AddressMatcher::Any => None,
        pr::AddressMatcher::Single(ip) => Some(ip.to_string()),
        pr::AddressMatcher::Cidr { addr, prefix } => Some(format!("{addr}/{prefix}")),
        pr::AddressMatcher::Range { start, end } => Some(format!("{start}-{end}")),
    }
}

fn port_field(p: &pr::PortMatcher) -> Option<String> {
    match p {
        pr::PortMatcher::Any => None,
        pr::PortMatcher::Single(port) => Some(port.to_string()),
        pr::PortMatcher::Range(r) => Some(format!("{}-{}", r.start, r.end)),
    }
}

fn action_to_netctl(a: &pr::Action) -> nc::Action {
    match a {
        pr::Action::Accept => nc::Action::Accept,
        pr::Action::Drop => nc::Action::Drop,
        pr::Action::Reject => nc::Action::Reject,
        pr::Action::Nat(nat) => match nat.nat_type {
            pr::NatType::Snat => nc::Action::Snat {
                address: nat.to.address.clone(),
            },
            pr::NatType::Dnat => nc::Action::Dnat {
                // netctl's Dnat requires a concrete address; masquerade
                // has none — represented as Snat(None) above for SNAT.
                // For Dnat without address, fall back to empty (should not
                // occur for verified rules: dnat() constructor always sets one).
                address: nat.to.address.clone().unwrap_or_default(),
            },
            pr::NatType::Masquerade => nc::Action::Snat { address: None },
        },
        pr::Action::RateLimit(s) => nc::Action::RateLimit {
            rate: s.rate,
            burst: u32::try_from(s.burst).unwrap_or(u32::MAX),
        },
    }
}

fn policy_to_netctl(p: pr::Policy) -> nc::Policy {
    match p {
        pr::Policy::Accept => nc::Policy::Accept,
        pr::Policy::Drop => nc::Policy::Drop,
    }
}
