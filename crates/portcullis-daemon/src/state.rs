//! Shared daemon state: loaded ruleset, apply bookkeeping, backend handle.

use std::path::PathBuf;
use std::sync::Mutex;

use portcullis_rules::Ruleset;
use thiserror::Error;
use tpt_netctl_core::DataplaneBackend;
use tpt_netctl_nftables::NftablesBackend;

use crate::bridge::desired_netctl_ruleset;

/// Errors from bridging / applying.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// netctl rejected the diff during validate.
    #[error("netctl validate failed: {0}")]
    Validate(String),
    /// netctl apply failed (dataplane unchanged on atomicity guarantee).
    #[error("netctl apply failed: {0}")]
    Apply(String),
    /// Could not connect to the dataplane backend.
    #[error("failed to connect dataplane backend: {0}")]
    Connect(String),
}

/// Result of a successful apply attempt (for status reporting).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApplyOutcome {
    /// Schema version of the ruleset that was applied.
    pub version: u64,
    /// Number of chains in the applied ruleset.
    pub chains: usize,
    /// Number of rules in the applied ruleset.
    pub rules: usize,
    /// How many adds netctl reported (from `ApplyReport` / diff length).
    pub planned_changes: usize,
}

/// Daemon-held state behind the control socket.
pub struct DaemonState {
    /// Config file path this daemon was started with (reload target).
    pub config_path: PathBuf,
    /// Last successfully loaded+verified ruleset.
    rules: Mutex<Option<Ruleset>>,
    /// Last successful apply, if any.
    last_apply: Mutex<Option<ApplyOutcome>>,
    /// Dataplane backend (in-process netctl).
    backend: NftablesBackend,
}

impl DaemonState {
    /// Connect the backend and initialize empty state.
    ///
    /// # Errors
    ///
    /// [`BridgeError::Connect`] if the dataplane cannot be reached.
    pub fn new(config_path: PathBuf) -> Result<Self, BridgeError> {
        let backend =
            NftablesBackend::connect().map_err(|e| BridgeError::Connect(e.to_string()))?;
        Ok(Self {
            config_path,
            rules: Mutex::new(None),
            last_apply: Mutex::new(None),
            backend,
        })
    }

    /// Validate + apply a ruleset through netctl, storing it on success.
    ///
    /// # Errors
    ///
    /// [`BridgeError`] from validate or apply.
    pub fn apply(&self, ruleset: &Ruleset) -> Result<ApplyOutcome, BridgeError> {
        let desired = desired_netctl_ruleset(ruleset);
        let diff = self
            .backend
            .compute_diff(&desired)
            .map_err(|e| BridgeError::Validate(e.to_string()))?;

        // Dry-run first (no mutation on failure).
        let _report = self
            .backend
            .validate(&diff)
            .map_err(|e| BridgeError::Validate(e.to_string()))?;

        let planned = diff.len();
        let _applied = self
            .backend
            .apply(&diff)
            .map_err(|e| BridgeError::Apply(e.to_string()))?;

        let outcome = ApplyOutcome {
            version: ruleset.version,
            chains: ruleset.chains.len(),
            rules: ruleset.iter_rules().count(),
            planned_changes: planned,
        };

        *self.rules.lock().expect("rules lock") = Some(ruleset.clone());
        *self.last_apply.lock().expect("last_apply lock") = Some(outcome.clone());
        Ok(outcome)
    }

    /// Currently loaded ruleset, if any.
    pub fn current_ruleset(&self) -> Option<Ruleset> {
        self.rules.lock().expect("rules lock").clone()
    }

    /// Last apply outcome, if any.
    pub fn last_apply(&self) -> Option<ApplyOutcome> {
        self.last_apply.lock().expect("last_apply lock").clone()
    }
}
