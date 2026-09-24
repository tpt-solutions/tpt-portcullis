//! Traffic-shaping policy for [`Action::RateLimit`](crate::Action::RateLimit).

use serde::{Deserialize, Serialize};

/// Unit for a rate-limit's numeric `rate` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateUnit {
    /// Packets per second.
    PacketsPerSecond,
    /// Bits per second.
    BitsPerSecond,
    /// Bytes per second.
    BytesPerSecond,
}

/// A rate-limit / shaping policy applied to matching traffic.
///
/// Phase 2 scope: a simple token-bucket style cap (rate + burst). Per-chain
/// shaping (aggregate caps across rules) is a follow-up — see `todo.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShapingPolicy {
    /// Maximum rate in [`unit`](Self::unit) terms.
    pub rate: u64,
    /// Burst size. For [`RateUnit::PacketsPerSecond`] this is in packets;
    /// for bit/byte units it is in the same unit as `rate` (bits/bytes).
    pub burst: u64,
    /// What `rate` is measured in.
    pub unit: RateUnit,
    /// Optional remark for operators/logs.
    pub remark: Option<String>,
}

impl ShapingPolicy {
    /// Packets-per-second cap.
    #[must_use]
    pub fn pps(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            unit: RateUnit::PacketsPerSecond,
            remark: None,
        }
    }
}
