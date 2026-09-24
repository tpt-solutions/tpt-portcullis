//! Unit tests: serde round-trips for every public type.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use portcullis_rules::*;
use serde_json::{from_str, to_string};

fn round_trip<T>(value: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let json = to_string(value).expect("serialize");
    from_str(&json).expect("deserialize")
}

#[test]
fn ruleset_round_trip() {
    let rs = sample();
    assert_eq!(rs, round_trip(&rs));
}

#[test]
fn chain_round_trip() {
    let c = Chain::new("input", vec![], Policy::Drop);
    assert_eq!(c, round_trip(&c));
}

#[test]
fn rule_round_trip() {
    let r = sample_rule(RuleId(1), 10, Action::Accept);
    assert_eq!(r, round_trip(&r));
}

#[test]
fn rule_id_round_trip() {
    assert_eq!(RuleId(42), round_trip(&RuleId(42)));
}

#[test]
fn action_variants_round_trip() {
    let actions = [
        Action::Accept,
        Action::Drop,
        Action::Reject,
        Action::Nat(NatRule::snat("192.0.2.1")),
        Action::Nat(NatRule::dnat("198.51.100.10")),
        Action::Nat(NatRule::masquerade()),
        Action::RateLimit(ShapingPolicy::pps(100, 200)),
        Action::Jump("log_chain".into()),
        Action::Continue,
    ];
    for a in actions {
        assert_eq!(a, round_trip(&a), "action round-trip failed");
    }
}

#[test]
fn policy_round_trip() {
    assert_eq!(Policy::Accept, round_trip(&Policy::Accept));
    assert_eq!(Policy::Drop, round_trip(&Policy::Drop));
    assert_eq!(Policy::Reject, round_trip(&Policy::Reject));
}

#[test]
fn ruleset_diff_round_trip() {
    let diff = RulesetDiff {
        add: vec![sample_rule(RuleId(10), 10, Action::Accept)],
        update: vec![],
        remove: vec![RuleId(3), RuleId(4)],
    };
    assert_eq!(diff, round_trip(&diff));
    assert!(!diff.is_empty());
    assert_eq!(diff.len(), 3);
    assert!(RulesetDiff::default().is_empty());
}

#[test]
fn nat_rule_round_trip() {
    let mut nat = NatRule::snat("203.0.113.1");
    nat.to.port = Some(8080);
    nat.remark = Some("egress".into());
    assert_eq!(nat, round_trip(&nat));
    assert_eq!(NatRule::masquerade(), round_trip(&NatRule::masquerade()));
}

#[test]
fn translation_target_round_trip() {
    let t = TranslationTarget {
        address: Some("10.0.0.1".into()),
        port: Some(443),
    };
    assert_eq!(t, round_trip(&t));
    assert_eq!(
        TranslationTarget::default(),
        round_trip(&TranslationTarget::default())
    );
}

#[test]
fn shaping_policy_round_trip() {
    let s = ShapingPolicy {
        rate: 1_000_000,
        burst: 2_000_000,
        unit: RateUnit::BitsPerSecond,
        remark: Some("wan".into()),
    };
    assert_eq!(s, round_trip(&s));
    assert_eq!(
        ShapingPolicy::pps(1, 2),
        round_trip(&ShapingPolicy::pps(1, 2))
    );
}

#[test]
fn rate_unit_round_trip() {
    for u in [
        RateUnit::PacketsPerSecond,
        RateUnit::BitsPerSecond,
        RateUnit::BytesPerSecond,
    ] {
        assert_eq!(u, round_trip(&u));
    }
}

#[test]
fn protocol_round_trip() {
    for p in [
        Protocol::Any,
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::Icmpv6,
        Protocol::Number(47),
    ] {
        assert_eq!(p, round_trip(&p));
    }
}

#[test]
fn address_matcher_round_trip() {
    let cases = [
        AddressMatcher::Any,
        AddressMatcher::Single(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        AddressMatcher::Single(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        AddressMatcher::Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix: 8,
        },
        AddressMatcher::Cidr {
            addr: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            prefix: 32,
        },
        AddressMatcher::Range {
            start: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            end: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255)),
        },
    ];
    for c in cases {
        assert_eq!(c, round_trip(&c), "address round-trip failed");
    }
}

#[test]
fn port_matcher_round_trip() {
    let cases = [
        PortMatcher::Any,
        PortMatcher::Single(443),
        PortMatcher::Range(PortRange::new(1024, 65535).unwrap()),
    ];
    for c in cases {
        assert_eq!(c, round_trip(&c));
    }
}

#[test]
fn interface_matcher_round_trip() {
    for c in [InterfaceMatcher::Any, InterfaceMatcher::Name("eth0".into())] {
        assert_eq!(c, round_trip(&c));
    }
}

#[test]
fn matcher_round_trip() {
    let m = Matcher {
        protocol: Protocol::Tcp,
        src_addr: AddressMatcher::Cidr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)),
            prefix: 16,
        },
        dst_addr: AddressMatcher::Any,
        src_port: PortMatcher::Any,
        dst_port: PortMatcher::Single(22),
        in_interface: InterfaceMatcher::Name("wan0".into()),
        out_interface: InterfaceMatcher::Any,
    };
    assert_eq!(m, round_trip(&m));
    assert_eq!(Matcher::any(), round_trip(&Matcher::any()));
}

#[test]
fn ip_version_round_trip() {
    assert_eq!(IpVersion::V4, round_trip(&IpVersion::V4));
    assert_eq!(IpVersion::V6, round_trip(&IpVersion::V6));
}

#[test]
fn schema_version_written_on_default() {
    let rs = Ruleset::default();
    assert_eq!(rs.version, SCHEMA_VERSION);
    let json = to_string(&rs).unwrap();
    assert!(json.contains(&format!("\"version\":{SCHEMA_VERSION}")));
}

fn sample_rule(id: RuleId, priority: u32, action: Action) -> Rule {
    Rule {
        id,
        priority,
        matcher: Matcher {
            protocol: Protocol::Tcp,
            dst_port: PortMatcher::Single(22),
            ..Matcher::any()
        },
        action,
        description: Some("allow ssh".into()),
    }
}

fn sample() -> Ruleset {
    Ruleset::new(vec![Chain::new(
        "input",
        vec![
            sample_rule(RuleId(1), 10, Action::Accept),
            sample_rule(RuleId(2), 20, Action::Drop),
        ],
        Policy::Drop,
    )])
}
