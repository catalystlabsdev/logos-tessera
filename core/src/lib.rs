//! # tessera_core
//!
//! Runtime-agnostic authorisation rules for the Tessera M-of-N multisig. Pure functions
//! over borsh-serialisable state; no LEZ dependency. Intended to run inside a RISC Zero
//! guest (`no_std` + `alloc`), and identically in clients so predictable refusals are
//! reported before proving.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod digest;
pub mod error;
pub mod rules;
pub mod types;

#[cfg(feature = "fixtures")]
pub mod fixtures;

pub use digest::{
    action_digest, action_digest_parts, activation_digest, config_commitment, signing_message,
    verify_approval, verify_bip340, Purpose,
};
pub use error::{ConfigFault, Error, Result};
pub use rules::{
    activate, apply_cancel, apply_config_change, check_action, current_approver_weight, execute,
    queue, queue_and_execute, tally_approvals, validate_config, validate_window, MAX_MEMBERS,
    MAX_WINDOW_MS,
};
pub use types::{
    roles, AccountRef, Action, AllowedCall, Approval, Call, Config, ConfigUpdate, Context, Effect,
    Executed, Member, Proposal, Queued, TxEnv, Window,
};
