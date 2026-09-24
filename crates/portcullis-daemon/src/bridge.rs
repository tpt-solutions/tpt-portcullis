//! Bridge: priority-order a verified `portcullis_rules::Ruleset` for netctl.
//!
//! # Types are now unified
//!
//! `tpt-netctl-core` re-exports `portcullis_rules::*` for its rule model,
//! so there is **no type conversion** left to do — `pr::Ruleset` and
//! `nc::Ruleset` are the same type. This module only handles the one
//! semantic gap that remains: netctl backends evaluate rules in
//! **declaration order**, while portcullis rules carry an explicit
//! [`priority`](portcullis_rules::Rule::priority) (lower runs first).
//!
//! [`desired_netctl_ruleset`] returns a clone with each chain's rules
//! sorted by `priority` ascending (stable — equal priorities with
//! overlapping matchers are a lint error and never reach apply).

use portcullis_rules as pr;
use tpt_netctl_core as nc;

/// Sort each chain's rules by `priority` ascending (stable).
///
/// Returns a clone; the input ruleset is unchanged.
pub fn desired_netctl_ruleset(rs: &pr::Ruleset) -> nc::Ruleset {
    let mut out = rs.clone();
    for chain in &mut out.chains {
        chain.rules.sort_by_key(|r| r.priority);
    }
    out
}
