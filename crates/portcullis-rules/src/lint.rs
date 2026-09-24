//! Lint / verify pass — graph-style ruleset validation.
//!
//! Models the ruleset as a graph: rules are nodes; an edge exists between
//! two rules in the same chain when their matchers overlap and the
//! higher-priority (lower `priority` value) rule can shadow the other.
//! Properties are checked over that view:
//!
//! - **Unreachable** — a terminal rule whose matcher is a strict/eq
//!   superset of every packet space a later rule could match, so the later
//!   rule can never fire.
//! - **Priority collision** — two rules, same chain, same `priority`,
//!   overlapping matchers (evaluation order between them is undefined).
//! - **Shadowed** — a later rule with the same matcher (or a subset) as an
//!   earlier terminal rule with a *different* action — present but dead.
//!
//! Pattern borrowed from `tpt-gatemesh`'s loop-free routing verification
//! (domain differs: HTTP routing vs packet filtering) — see `spec.txt`.
//! The implementation is self-contained because `tpt-gatemesh` does not
//! exist in the portfolio yet (resolved decision 2026-09-24).

use std::collections::HashSet;
use std::fmt;

use crate::rule::{Rule, RuleId};
use crate::ruleset::{Chain, Ruleset, SCHEMA_VERSION};

/// Kind of lint problem detected by [`verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LintKind {
    /// Ruleset schema version is newer than this crate understands.
    UnsupportedVersion,
    /// Duplicate chain name in the ruleset.
    DuplicateChain,
    /// Duplicate [`RuleId`] anywhere in the ruleset.
    DuplicateRuleId,
    /// Two rules share a priority in the same chain and overlap.
    PriorityCollision,
    /// A terminal rule fully shadows a later rule's matcher space.
    Unreachable,
    /// A later rule is dead because an earlier terminal rule matches the
    /// same (or a superset) packet space with a different action.
    Shadowed,
}

impl fmt::Display for LintKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => write!(f, "unsupported schema version"),
            Self::DuplicateChain => write!(f, "duplicate chain name"),
            Self::DuplicateRuleId => write!(f, "duplicate rule id"),
            Self::PriorityCollision => write!(f, "priority collision"),
            Self::Unreachable => write!(f, "unreachable rule"),
            Self::Shadowed => write!(f, "shadowed rule"),
        }
    }
}

/// A single lint finding, detailed enough to point a user at the offending
/// rule(s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintIssue {
    /// What kind of problem this is.
    pub kind: LintKind,
    /// Chain the issue lives in (None for ruleset-level issues like
    /// version / duplicate ids spanning chains).
    pub chain: Option<String>,
    /// Primary offending rule, when applicable.
    pub rule: Option<RuleId>,
    /// Secondary rule (e.g. the shadower), when applicable.
    pub other_rule: Option<RuleId>,
    /// Human-readable explanation.
    pub message: String,
}

impl LintIssue {
    fn new(kind: LintKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            chain: None,
            rule: None,
            other_rule: None,
            message: message.into(),
        }
    }

    fn in_chain(mut self, chain: impl Into<String>) -> Self {
        self.chain = Some(chain.into());
        self
    }

    fn primary(mut self, id: RuleId) -> Self {
        self.rule = Some(id);
        self
    }

    fn secondary(mut self, id: RuleId) -> Self {
        self.other_rule = Some(id);
        self
    }
}

impl fmt::Display for LintIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] ", self.kind)?;
        if let Some(c) = &self.chain {
            write!(f, "chain `{c}` ")?;
        }
        match (self.rule, self.other_rule) {
            (Some(a), Some(b)) => write!(f, "rules {a} / {b}: ")?,
            (Some(a), None) => write!(f, "rule {a}: ")?,
            _ => {}
        }
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for LintIssue {}

/// Verify a [`Ruleset`].
///
/// Returns `Ok(())` when no issues are found. On failure, returns **all**
/// issues found (not just the first) so operators can fix a batch at once.
///
/// # Usage contract
///
/// Callers that hand rulesets to a dataplane (e.g. `tpt-netctl`'s
/// `apply`) **must refuse** to do so when this returns `Err`. This crate
/// documents that contract but cannot enforce the hand-off step itself.
///
/// # Example
///
/// ```
/// use portcullis_rules::{
///     verify, Action, Chain, Matcher, Policy, Protocol, Rule, RuleId, Ruleset,
/// };
///
/// let ruleset = Ruleset::new(vec![Chain::new(
///     "input",
///     vec![Rule {
///         id: RuleId(1),
///         priority: 10,
///         matcher: Matcher {
///             protocol: Protocol::Tcp,
///             ..Matcher::any()
///         },
///         action: Action::Accept,
///         description: None,
///     }],
///     Policy::Drop,
/// )]);
///
/// assert!(verify(&ruleset).is_ok());
/// ```
pub fn verify(ruleset: &Ruleset) -> Result<(), Vec<LintIssue>> {
    let mut issues = Vec::new();

    if ruleset.version > SCHEMA_VERSION {
        issues.push(LintIssue::new(
            LintKind::UnsupportedVersion,
            format!(
                "ruleset version {} is newer than supported version {}",
                ruleset.version, SCHEMA_VERSION
            ),
        ));
    }

    // Duplicate chain names.
    let mut chain_names = HashSet::new();
    for chain in &ruleset.chains {
        if !chain_names.insert(chain.name.as_str()) {
            issues.push(
                LintIssue::new(
                    LintKind::DuplicateChain,
                    format!("chain name `{}` appears more than once", chain.name),
                )
                .in_chain(chain.name.clone()),
            );
        }
    }

    // Duplicate rule ids (global across ruleset).
    let mut seen_ids = HashSet::new();
    for (_, rule) in ruleset.iter_rules() {
        if !seen_ids.insert(rule.id) {
            issues.push(
                LintIssue::new(
                    LintKind::DuplicateRuleId,
                    format!("rule id {} is used more than once", rule.id),
                )
                .primary(rule.id),
            );
        }
    }

    for chain in &ruleset.chains {
        lint_chain(chain, &mut issues);
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

/// Lint one chain: sort by priority, then check collisions / unreachable /
/// shadowed pairs.
fn lint_chain(chain: &Chain, issues: &mut Vec<LintIssue>) {
    // Evaluation order: priority ascending; stable so declaration order
    // breaks ties for the *walk*, but ties themselves are reported.
    let mut ordered: Vec<&Rule> = chain.rules.iter().collect();
    ordered.sort_by_key(|r| r.priority);

    // Priority collisions: same priority + overlapping matchers.
    let mut i = 0;
    while i < ordered.len() {
        let mut j = i + 1;
        while j < ordered.len() && ordered[j].priority == ordered[i].priority {
            if ordered[i].id != ordered[j].id && ordered[i].matcher.overlaps(&ordered[j].matcher) {
                issues.push(
                    LintIssue::new(
                        LintKind::PriorityCollision,
                        format!(
                            "rules share priority {} and overlapping matchers; \
                             evaluation order between them is undefined",
                            ordered[i].priority
                        ),
                    )
                    .in_chain(chain.name.clone())
                    .primary(ordered[i].id)
                    .secondary(ordered[j].id),
                );
            }
            j += 1;
        }
        i = j;
    }

    // Unreachable / shadowed: walk in evaluation order; once a terminal
    // rule has been seen, every later rule whose matcher is a subset of
    // that terminal rule's matcher is dead.
    //
    // We track the union of terminal rules seen so far conceptually by
    // checking each later rule against *every* earlier terminal rule.
    // (Exact union-of-packet-spaces is coarser; per-pair superset is the
    // conservative, low-false-positive choice documented in the spec.)
    for (idx, rule) in ordered.iter().enumerate() {
        for earlier in ordered.iter().take(idx) {
            if !earlier.action.is_terminal() {
                continue;
            }
            // `earlier` fully covers `rule`'s matcher space.
            if earlier.matcher.is_superset_of(&rule.matcher) {
                let same = earlier.matcher == rule.matcher;
                let kind = if same {
                    LintKind::Shadowed
                } else {
                    LintKind::Unreachable
                };
                let message = if same {
                    format!(
                        "same matcher as rule {} (priority {}), which is terminal \
                         ({}); this rule can never fire",
                        earlier.id,
                        earlier.priority,
                        action_label(earlier)
                    )
                } else {
                    format!(
                        "matcher is a subset of rule {} (priority {}, terminal {}); \
                         every packet this rule would match is already consumed",
                        earlier.id,
                        earlier.priority,
                        action_label(earlier)
                    )
                };
                issues.push(
                    LintIssue::new(kind, message)
                        .in_chain(chain.name.clone())
                        .primary(rule.id)
                        .secondary(earlier.id),
                );
                // One report per dead rule is enough.
                break;
            }
        }
    }
}

fn action_label(rule: &Rule) -> String {
    match &rule.action {
        crate::Action::Accept => "accept".into(),
        crate::Action::Drop => "drop".into(),
        crate::Action::Reject => "reject".into(),
        crate::Action::Nat(_) => "nat".into(),
        crate::Action::RateLimit(_) => "rate-limit".into(),
    }
}
