//! Messages the Tessera program accepts and the state its configuration actor stores.
//!
//! The configuration actor lives at the program-derived account
//! `for_public_pda(tessera_program, multisig_id)`; the vault is
//! `for_public_pda(tessera_program, vault_seed)`. Only Tessera can attach `vault_seed`,
//! and it does so only after `tessera_core` has verified a quorum.
#![no_std]
extern crate alloc;
use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};
use tessera_core::{Approval, Config, Context, Proposal, Queued, TxEnv};

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct State {
    pub ctx: Context,
    pub config: Config,
    pub vault_seed: [u8; 32],
    /// The vault's address: `for_public_pda` in the public posture, `for_private_pda` (bound to
    /// the group's keys) in the private posture. Tessera lends authority only over this account.
    pub vault_id: [u8; 32],
    pub queued: Vec<Queued>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Msg {
    /// Write a new, not-yet-active configuration. The actor must be empty.
    Create { ctx: Context, config: Config, vault_seed: [u8; 32], vault_id: [u8; 32], private: bool },
    /// Members confirm the configuration they are bound by.
    Activate { approvals: Vec<Approval> },
    /// Verify a quorum and record the action; it becomes executable after the time lock.
    Queue { proposal: Proposal, signed_epoch: u64, proposer: Approval, approvals: Vec<Approval>, env: TxEnv },
    /// Re-check the queued quorum against the current configuration and perform the action.
    Execute { proposal: Proposal, executor: Approval, env: TxEnv },
    /// Zero-time-lock path: queue and execute in one transaction.
    QueueAndExecute {
        proposal: Proposal,
        signed_epoch: u64,
        proposer: Approval,
        approvals: Vec<Approval>,
        executor: Approval,
        env: TxEnv,
    },
}
