//! The [`Matcher`] vocabulary — protocol, address, port, interface.
//!
//! # Combinator semantics
//!
//! All present fields are **AND**-ed: a packet matches the rule only if
//! every field matches. A field set to its `Any`/`None` equivalent is a
//! wildcard and imposes no constraint. There is no implicit OR across
//! fields, and there is no per-rule OR combinator in v1 (multiple rules
//! with the same action are the way to express OR).
//!
//! This is documented explicitly here (and repeated on [`Matcher`]) because
//! the self-contained design was a deliberate resolved decision
//! (`spec.txt` Resolved decisions, 2026-09-24) — not an oversight of the
//! missing `tpt-fathom` types.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

/// IP protocol / next-header matcher.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Match any protocol (wildcard).
    #[default]
    Any,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP (v4).
    Icmp,
    /// ICMPv6.
    Icmpv6,
    /// Explicit next-header / IP protocol number (extensible catch-all).
    Number(u8),
}

/// Which IP address family an [`AddressMatcher`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersion {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}

/// Address matcher: single IP, CIDR, range, or any (v4 + v6).
///
/// Serde representation is externally tagged (default), e.g.
/// `{"Single": "192.0.2.1"}` / `{"Cidr": {"addr": "...", "prefix": 24}}` —
/// chosen because internally-tagged forms cannot carry newtype variants
/// holding scalars.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressMatcher {
    /// Match any address (wildcard).
    #[default]
    Any,
    /// A single IP address (v4 or v6 — family inferred from the value).
    Single(IpAddr),
    /// CIDR block: address + prefix length.
    Cidr {
        /// Network address.
        addr: IpAddr,
        /// Prefix length (0..=32 for v4, 0..=128 for v6).
        prefix: u8,
    },
    /// Inclusive address range (both endpoints must be the same family).
    Range {
        /// Start address (inclusive).
        start: IpAddr,
        /// End address (inclusive).
        end: IpAddr,
    },
}

impl AddressMatcher {
    /// Returns `true` if every address of `other` is also matched by `self`
    /// (i.e. `self` is a superset of `other`). Used by the lint pass for
    /// shadow/unreachable detection.
    ///
    /// Conservative: when the relationship cannot be decided exactly (mixed
    /// families, non-aligned CIDRs), returns `false` (not a superset) so
    /// the linter does not invent false positives.
    #[must_use]
    pub fn is_superset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Single(a), Self::Single(b)) => a == b,
            (Self::Single(a), Self::Range { start, end }) => in_range(*a, start, end),
            (Self::Single(a), Self::Cidr { addr, prefix }) => in_cidr(*a, addr, *prefix),
            (
                Self::Cidr {
                    addr: a1,
                    prefix: p1,
                },
                Self::Cidr {
                    addr: a2,
                    prefix: p2,
                },
            ) => p1 <= p2 && in_cidr(*a2, a1, *p1),
            (Self::Cidr { addr, prefix }, Self::Single(a)) => in_cidr(*a, addr, *prefix),
            (Self::Cidr { addr, prefix }, Self::Range { start, end }) => {
                in_cidr(*start, addr, *prefix) && in_cidr(*end, addr, *prefix)
            }
            (Self::Range { start: s1, end: e1 }, Self::Range { start: s2, end: e2 }) => {
                cmp_addr(s2, s1).is_ge() && cmp_addr(e2, e1).is_le()
            }
            (Self::Range { start, end }, Self::Single(a)) => in_range(*a, start, end),
            (Self::Range { start, end }, Self::Cidr { addr, prefix }) => {
                // Range ⊇ CIDR only if the CIDR's first and last address
                // both fall in the range. Conservative on partial overlap.
                match cidr_bounds(addr, *prefix) {
                    Some((lo, hi)) => in_range(lo, start, end) && in_range(hi, start, end),
                    None => false,
                }
            }
            (Self::Single(_), Self::Any)
            | (Self::Cidr { .. }, Self::Any)
            | (Self::Range { .. }, Self::Any) => false,
        }
    }

    /// Returns `true` if the two matchers can match at least one common
    /// address (used for priority-collision detection).
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Single(a), Self::Single(b)) => a == b,
            (Self::Single(a), Self::Range { start, end })
            | (Self::Range { start, end }, Self::Single(a)) => in_range(*a, start, end),
            (Self::Single(a), Self::Cidr { addr, prefix })
            | (Self::Cidr { addr, prefix }, Self::Single(a)) => in_cidr(*a, addr, *prefix),
            (Self::Cidr { .. }, Self::Cidr { .. }) => {
                self.is_superset_of(other) || other.is_superset_of(self)
            }
            (Self::Range { .. }, Self::Range { .. }) => {
                // Overlap iff each start <= other's end.
                let (s1, e1) = match self {
                    Self::Range { start, end } => (*start, *end),
                    _ => unreachable!(),
                };
                let (s2, e2) = match other {
                    Self::Range { start, end } => (*start, *end),
                    _ => unreachable!(),
                };
                cmp_addr(&s1, &e2).is_le() && cmp_addr(&s2, &e1).is_le()
            }
            (Self::Cidr { addr, prefix }, Self::Range { start, end })
            | (Self::Range { start, end }, Self::Cidr { addr, prefix }) => {
                match cidr_bounds(addr, *prefix) {
                    Some((lo, hi)) => cmp_addr(&lo, end).is_le() && cmp_addr(start, &hi).is_le(),
                    None => false,
                }
            }
        }
    }
}

fn in_range(a: IpAddr, start: &IpAddr, end: &IpAddr) -> bool {
    same_family(a, *start)
        && same_family(a, *end)
        && cmp_addr(&a, start).is_ge()
        && cmp_addr(&a, end).is_le()
}

fn in_cidr(a: IpAddr, net: &IpAddr, prefix: u8) -> bool {
    match (a, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(*n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix > 128 {
                return false;
            }
            let a = u128::from(a);
            let n = u128::from(*n);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (a & mask) == (n & mask)
        }
        _ => false,
    }
}

fn cidr_bounds(net: &IpAddr, prefix: u8) -> Option<(IpAddr, IpAddr)> {
    match net {
        IpAddr::V4(n) => {
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let base = u32::from(*n) & mask;
            let broadcast = base | !mask;
            Some((
                IpAddr::V4(Ipv4Addr::from(base)),
                IpAddr::V4(Ipv4Addr::from(broadcast)),
            ))
        }
        IpAddr::V6(n) => {
            if prefix > 128 {
                return None;
            }
            let n = u128::from(*n);
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            let base = n & mask;
            let broadcast = base | !mask;
            Some((
                IpAddr::V6(Ipv6Addr::from(base)),
                IpAddr::V6(Ipv6Addr::from(broadcast)),
            ))
        }
    }
}

fn same_family(a: IpAddr, b: IpAddr) -> bool {
    a.is_ipv4() == b.is_ipv4()
}

/// Order two addresses; different families compare by `is_ipv4` (v4 < v6)
/// so mixed-family comparisons are deterministic (never equal unless same).
fn cmp_addr(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x.cmp(y),
        (IpAddr::V6(x), IpAddr::V6(y)) => x.cmp(y),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

/// Inclusive port range, or a wildcard.
///
/// Externally tagged for serde (see [`AddressMatcher`] for rationale).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortMatcher {
    /// Match any port (wildcard).
    #[default]
    Any,
    /// A single port.
    Single(u16),
    /// Inclusive port range.
    Range(PortRange),
}

/// Inclusive `[start, end]` port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    /// First port (inclusive).
    pub start: u16,
    /// Last port (inclusive).
    pub end: u16,
}

impl PortRange {
    /// Construct a range; returns `None` if `start > end`.
    #[must_use]
    pub fn new(start: u16, end: u16) -> Option<Self> {
        if start <= end {
            Some(Self { start, end })
        } else {
            None
        }
    }
}

impl PortMatcher {
    /// Returns `true` if every port of `other` is also matched by `self`.
    #[must_use]
    pub fn is_superset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Single(a), Self::Single(b)) => a == b,
            (Self::Single(a), Self::Range(r)) => r.start <= *a && *a <= r.end,
            (Self::Range(r1), Self::Range(r2)) => r1.start <= r2.start && r2.end <= r1.end,
            (Self::Range(r), Self::Single(a)) => r.start <= *a && *a <= r.end,
            (Self::Single(_), Self::Any) | (Self::Range(_), Self::Any) => false,
        }
    }

    /// Returns `true` if the two matchers can match at least one common port.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Single(a), Self::Single(b)) => a == b,
            (Self::Single(a), Self::Range(r)) | (Self::Range(r), Self::Single(a)) => {
                r.start <= *a && *a <= r.end
            }
            (Self::Range(r1), Self::Range(r2)) => r1.start <= r2.end && r2.start <= r1.end,
        }
    }
}

/// Interface matcher: by name (ingress or egress — see [`Matcher`]).
///
/// Externally tagged for serde (see [`AddressMatcher`] for rationale).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceMatcher {
    /// Match any interface (wildcard).
    #[default]
    Any,
    /// Exact interface name (e.g. `eth0`, `wan0`).
    Name(String),
}

impl InterfaceMatcher {
    /// Returns `true` if every interface of `other` is also matched by `self`.
    #[must_use]
    pub fn is_superset_of(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Name(a), Self::Name(b)) => a == b,
            (Self::Name(_), Self::Any) => false,
        }
    }

    /// Returns `true` if the two matchers can match at least one common interface.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Name(a), Self::Name(b)) => a == b,
        }
    }
}

/// Conditions a packet must satisfy for a [`Rule`](crate::Rule) to fire.
///
/// **All present fields are AND-ed**; `Any` / absent fields are wildcards.
/// See the `matcher` module docs for the full combinator rationale.
/// Fields default to wildcards when omitted from a config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Matcher {
    /// IP protocol.
    pub protocol: Protocol,
    /// Source address.
    pub src_addr: AddressMatcher,
    /// Destination address.
    pub dst_addr: AddressMatcher,
    /// Source port.
    pub src_port: PortMatcher,
    /// Destination port.
    pub dst_port: PortMatcher,
    /// Ingress interface.
    pub in_interface: InterfaceMatcher,
    /// Egress interface.
    pub out_interface: InterfaceMatcher,
}

impl Matcher {
    /// A wildcard matcher (matches everything).
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Returns `true` if every packet matched by `other` is also matched by
    /// `self` (field-wise AND superset). Conservative on undecidable pairs.
    #[must_use]
    pub fn is_superset_of(&self, other: &Self) -> bool {
        self.protocol.allows_all(&other.protocol)
            && self.src_addr.is_superset_of(&other.src_addr)
            && self.dst_addr.is_superset_of(&other.dst_addr)
            && self.src_port.is_superset_of(&other.src_port)
            && self.dst_port.is_superset_of(&other.dst_port)
            && self.in_interface.is_superset_of(&other.in_interface)
            && self.out_interface.is_superset_of(&other.out_interface)
    }

    /// Returns `true` if both matchers can match at least one common packet
    /// (field-wise AND of per-field overlaps). Conservative: any undecided
    /// field is treated as overlapping.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.protocol.overlaps(&other.protocol)
            && self.src_addr.overlaps(&other.src_addr)
            && self.dst_addr.overlaps(&other.dst_addr)
            && self.src_port.overlaps(&other.src_port)
            && self.dst_port.overlaps(&other.dst_port)
            && self.in_interface.overlaps(&other.in_interface)
            && self.out_interface.overlaps(&other.out_interface)
    }
}

impl Protocol {
    /// Returns `true` if every protocol of `other` is also allowed by `self`.
    #[must_use]
    pub fn allows_all(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) => true,
            (Self::Number(_), Self::Any) => false,
            (a, b) => a == b,
        }
    }

    /// Returns `true` if the two protocol matchers can match a common value.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (a, b) => a == b,
        }
    }
}
