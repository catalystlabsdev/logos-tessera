//! Borsh-serialisable data model. Field order is part of the digest; do not reorder.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};

/// Role bits carried in [`Member::roles`].
pub mod roles {
    /// May open (sign) a proposal.
    pub const PROPOSE: u8 = 1;
    /// Approval weight counts toward the threshold.
    pub const APPROVE: u8 = 2;
    /// May submit `Execute` for an already-queued action.
    pub const EXECUTE: u8 = 4;
    /// All defined bits.
    pub const ALL: u8 = PROPOSE | APPROVE | EXECUTE;
}

/// A member: BIP-340 x-only approval key, role bits and weight.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Member {
    pub key: [u8; 32],
    pub roles: u8,
    pub weight: u32,
}

impl Member {
    pub fn has(&self, role: u8) -> bool {
        self.roles & role == role
    }
}

/// A permitted call target. `discriminator: None` allows any instruction to the program;
/// `Some(d)` requires the call data to start with those 8 bytes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AllowedCall {
    pub program_id: [u8; 32],
    pub discriminator: Option<[u8; 8]>,
}

/// The multisig configuration account.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Config {
    pub multisig_id: [u8; 32],
    pub members: Vec<Member>,
    /// Minimum total weight of APPROVE members' approvals.
    pub threshold: u64,
    pub timelock_ms: u64,
    /// Empty means any call is allowed.
    pub action_set: Vec<AllowedCall>,
    pub epoch: u64,
    pub initialised: bool,
}

impl Config {
    pub fn member(&self, key: &[u8; 32]) -> Option<&Member> {
        self.members.iter().find(|m| &m.key == key)
    }
}

/// An account touched by a chained call, with the privileges the call asks for.
/// `authorised = true` asks that the account be passed as authorised; the guest may only
/// grant that through Tessera's own PDA seeds (e.g. the vault), never by inheriting
/// a root-authorised account, which [`crate::queue`]/[`crate::execute`] refuse outright.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountRef {
    pub id: [u8; 32],
    pub writable: bool,
    pub authorised: bool,
}

/// One chained call, pinned to a program id and its ImageID.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Call {
    pub program_id: [u8; 32],
    pub image_id: [u8; 32],
    pub accounts: Vec<AccountRef>,
    pub data: Vec<u8>,
}

/// Full replacement of the mutable configuration fields.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ConfigUpdate {
    pub members: Vec<Member>,
    pub threshold: u64,
    pub action_set: Vec<AllowedCall>,
    pub timelock_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Action {
    Calls(Vec<Call>),
    ChangeConfig(ConfigUpdate),
    Cancel { digest: [u8; 32] },
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    pub proposal_id: u64,
    pub expires_at_ms: u64,
    pub action: Action,
}

/// Fixed per deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Context {
    pub network_id: [u8; 32],
    pub program_id: [u8; 32],
}

/// A BIP-340 signature by `key` (x-only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Approval {
    pub key: [u8; 32],
    pub sig: [u8; 64],
}

/// The queued-action account.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Queued {
    pub digest: [u8; 32],
    /// Epoch the approvals were verified under.
    pub epoch: u64,
    /// Commitment of the configuration the approvals were verified under (needed to
    /// recompute the digest at `Execute` after the configuration has moved on).
    pub config_commitment: [u8; 32],
    /// Keys whose approvals counted at `Queue`.
    pub approvers: Vec<[u8; 32]>,
    pub queued_window_end_ms: u64,
    /// Time-lock snapshot taken at `Queue`.
    pub timelock_ms: u64,
    pub expires_at_ms: u64,
    pub executed: bool,
    pub cancelled: bool,
}

/// Sequencer-enforced validity window `[start_ms, end_ms)`: the transaction lands at some
/// unknown time `t` with `start_ms <= t < end_ms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct Window {
    pub start_ms: u64,
    pub end_ms: u64,
}

/// Per-transaction environment the guest observes.
#[derive(Clone, Debug, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct TxEnv {
    pub window: Window,
    /// Accounts that are authorised at the transaction root (e.g. the relayer signer).
    /// No call in an action may name one of them.
    pub root_authorised: Vec<[u8; 32]>,
}

impl TxEnv {
    pub fn new(window: Window) -> Self {
        TxEnv {
            window,
            root_authorised: Vec::new(),
        }
    }
}

/// What an `Execute` does once authorised; the guest performs it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    /// Emit these chained calls with the vault seed.
    Calls(Vec<Call>),
    /// Write this configuration (epoch already incremented).
    NewConfig(Config),
    /// Mark the queued action with this digest cancelled (see [`crate::apply_cancel`]).
    Cancel { digest: [u8; 32] },
}

/// Result of a successful `Execute`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Executed {
    /// The queued action, now `executed = true`.
    pub queued: Queued,
    pub effect: Effect,
}
