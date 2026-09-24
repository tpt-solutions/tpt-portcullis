//! Unit tests: lint pass — unreachable, priority collision, shadowed,
//! and a clean ruleset (no false positives).

use portcullis_rules::*;

fn rule(id: u64, priority: u32, matcher: Matcher, action: Action) -> Rule {
    Rule {
        id: RuleId(id),
        priority,
        matcher,
        action,
        description: None,
    }
}

fn tcp_dst(port: PortMatcher) -> Matcher {
    Matcher {
        protocol: Protocol::Tcp,
        dst_port: port,
        ..Matcher::any()
    }
}

fn clean_ruleset() -> Ruleset {
    Ruleset::new(vec![Chain::new(
        "input",
        vec![
            // Distinct, non-overlapping priorities and matchers.
            rule(
                1,
                10,
                Matcher {
                    dst_port: PortMatcher::Single(22),
                    protocol: Protocol::Tcp,
                    ..Matcher::any()
                },
                Action::Accept,
            ),
            rule(
                2,
                20,
                Matcher {
                    dst_port: PortMatcher::Single(80),
                    protocol: Protocol::Tcp,
                    ..Matcher::any()
                },
                Action::Accept,
            ),
            // Non-terminal, so later rules are fine even if it overlapped.
            rule(
                3,
                30,
                Matcher {
                    protocol: Protocol::Udp,
                    ..Matcher::any()
                },
                Action::RateLimit(ShapingPolicy::pps(100, 200)),
            ),
        ],
        Policy::Drop,
    )])
}

#[test]
fn clean_ruleset_has_no_issues() {
    assert_eq!(
        verify(&clean_ruleset()),
        Ok(()),
        "false positive on clean set"
    );
}

#[test]
fn empty_ruleset_is_ok() {
    assert_eq!(verify(&Ruleset::default()), Ok(()));
}

#[test]
fn detects_unreachable_rule() {
    // Rule 1: terminal Accept on tcp port-range 0-65535 (superset of 22).
    // Rule 2: tcp dport 22 — unreachable (strict subset).
    let rs = Ruleset::new(vec![Chain::new(
        "input",
        vec![
            rule(
                1,
                10,
                Matcher {
                    protocol: Protocol::Tcp,
                    dst_port: PortMatcher::Range(PortRange::new(0, 65535).unwrap()),
                    ..Matcher::any()
                },
                Action::Accept,
            ),
            rule(2, 20, tcp_dst(PortMatcher::Single(22)), Action::Drop),
        ],
        Policy::Drop,
    )]);

    let err = verify(&rs).expect_err("expected unreachable issue");
    assert!(
        err.iter().any(|i| i.kind == LintKind::Unreachable),
        "expected Unreachable, got: {err:?}"
    );
    let issue = err
        .iter()
        .find(|i| i.kind == LintKind::Unreachable)
        .unwrap();
    assert_eq!(issue.rule, Some(RuleId(2)));
    assert_eq!(issue.other_rule, Some(RuleId(1)));
    assert_eq!(issue.chain.as_deref(), Some("input"));
}

#[test]
fn detects_priority_collision() {
    // Two rules, same priority, overlapping matchers (both Any on dst).
    let rs = Ruleset::new(vec![Chain::new(
        "forward",
        vec![
            rule(1, 10, Matcher::any(), Action::Accept),
            rule(
                2,
                10,
                Matcher {
                    protocol: Protocol::Tcp,
                    ..Matcher::any()
                },
                Action::Drop,
            ),
        ],
        Policy::Drop,
    )]);

    let err = verify(&rs).expect_err("expected collision");
    assert!(
        err.iter().any(|i| i.kind == LintKind::PriorityCollision),
        "expected PriorityCollision, got: {err:?}"
    );
}

#[test]
fn detects_shadowed_same_matcher() {
    // Same matcher, different action, wrong order: second is dead.
    let m = tcp_dst(PortMatcher::Single(443));
    let rs = Ruleset::new(vec![Chain::new(
        "input",
        vec![
            rule(1, 10, m.clone(), Action::Accept),
            rule(2, 20, m, Action::Drop),
        ],
        Policy::Drop,
    )]);

    let err = verify(&rs).expect_err("expected shadowed");
    assert!(
        err.iter().any(|i| i.kind == LintKind::Shadowed),
        "expected Shadowed, got: {err:?}"
    );
    let issue = err.iter().find(|i| i.kind == LintKind::Shadowed).unwrap();
    assert_eq!(issue.rule, Some(RuleId(2)));
    assert_eq!(issue.other_rule, Some(RuleId(1)));
}

#[test]
fn no_collision_when_matchers_disjoint() {
    // Same priority, non-overlapping ports → fine.
    let rs = Ruleset::new(vec![Chain::new(
        "input",
        vec![
            rule(1, 10, tcp_dst(PortMatcher::Single(22)), Action::Accept),
            rule(2, 10, tcp_dst(PortMatcher::Single(80)), Action::Accept),
        ],
        Policy::Drop,
    )]);
    assert_eq!(verify(&rs), Ok(()));
}

#[test]
fn non_terminal_does_not_shadow() {
    // RateLimit is non-terminal: later rule with subset matcher is fine.
    let rs = Ruleset::new(vec![Chain::new(
        "input",
        vec![
            rule(
                1,
                10,
                Matcher {
                    protocol: Protocol::Tcp,
                    ..Matcher::any()
                },
                Action::RateLimit(ShapingPolicy::pps(10, 20)),
            ),
            rule(2, 20, tcp_dst(PortMatcher::Single(22)), Action::Accept),
        ],
        Policy::Drop,
    )]);
    assert_eq!(verify(&rs), Ok(()));
}

#[test]
fn detects_duplicate_rule_id() {
    let rs = Ruleset::new(vec![
        Chain::new(
            "input",
            vec![rule(
                1,
                10,
                tcp_dst(PortMatcher::Single(22)),
                Action::Accept,
            )],
            Policy::Drop,
        ),
        Chain::new(
            "output",
            vec![rule(
                1,
                10,
                tcp_dst(PortMatcher::Single(80)),
                Action::Accept,
            )],
            Policy::Drop,
        ),
    ]);
    let err = verify(&rs).expect_err("expected duplicate id");
    assert!(err.iter().any(|i| i.kind == LintKind::DuplicateRuleId));
}

#[test]
fn detects_duplicate_chain_name() {
    let rs = Ruleset::new(vec![
        Chain::new("input", vec![], Policy::Drop),
        Chain::new("input", vec![], Policy::Accept),
    ]);
    let err = verify(&rs).expect_err("expected duplicate chain");
    assert!(err.iter().any(|i| i.kind == LintKind::DuplicateChain));
}

#[test]
fn detects_unsupported_version() {
    let rs = Ruleset {
        version: SCHEMA_VERSION + 1,
        ..Default::default()
    };
    let err = verify(&rs).expect_err("expected version issue");
    assert!(err.iter().any(|i| i.kind == LintKind::UnsupportedVersion));
}

#[test]
fn multiple_issues_reported_together() {
    let m = tcp_dst(PortMatcher::Single(443));
    let rs = Ruleset::new(vec![
        Chain::new(
            "input",
            vec![
                rule(1, 10, m.clone(), Action::Accept),
                rule(1, 20, m, Action::Drop), // duplicate id + shadowed
            ],
            Policy::Drop,
        ),
        Chain::new("input", vec![], Policy::Drop), // duplicate chain
    ]);
    let err = verify(&rs).expect_err("expected multiple issues");
    assert!(err.len() >= 3, "expected >=3 issues, got {err:?}");
}

#[test]
fn lint_issue_display_is_useful() {
    let issue = LintIssue {
        kind: LintKind::Unreachable,
        chain: Some("input".into()),
        rule: Some(RuleId(2)),
        other_rule: Some(RuleId(1)),
        message: "matcher is a subset of rule 1".into(),
    };
    let s = issue.to_string();
    assert!(s.contains("unreachable rule"));
    assert!(s.contains("input"));
    assert!(s.contains('2'));
    assert!(s.contains('1'));
}
