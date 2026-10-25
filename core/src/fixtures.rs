//! Deterministic keys and ready-made inputs for tests and guest benchmarks.
//!
//! Not for production: keys are derived from a public seed. Functions here may panic on
//! nonsensical arguments (e.g. `m > n`); they are never on a verification path.

use alloc::vec;
use alloc::vec::Vec;
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

use crate::digest::{action_digest, signing_message, Purpose};
use crate::types::{
    roles, AccountRef, Action, Approval, Call, Config, Context, Member, Proposal, TxEnv, Window,
};

/// Deterministic BIP-340 signing key number `index` for `seed`.
pub fn signing_key(seed: &[u8; 32], index: u32) -> SigningKey {
    let mut ctr: u32 = 0;
    loop {
        let mut h = Sha256::new();
        h.update(b"tessera/fixture/key");
        h.update(seed);
        h.update(index.to_le_bytes());
        h.update(ctr.to_le_bytes());
        if let Ok(sk) = SigningKey::from_bytes(&h.finalize()) {
            return sk;
        }
        ctr += 1;
    }
}

/// x-only public key of `sk`.
pub fn key_of(sk: &SigningKey) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&sk.verifying_key().to_bytes());
    k
}

/// Sign `digest` for `purpose` with deterministic aux randomness.
pub fn sign(sk: &SigningKey, purpose: Purpose, digest: &[u8; 32]) -> Approval {
    let msg = signing_message(purpose, digest);
    let aux: [u8; 32] = Sha256::new()
        .chain_update(b"tessera/fixture/aux")
        .chain_update(msg)
        .finalize()
        .into();
    let sig = sk.sign_raw(&msg, &aux).expect("BIP-340 signing failed");
    Approval {
        key: key_of(sk),
        sig: sig.to_bytes(),
    }
}

fn tag(label: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"tessera/fixture/")
        .chain_update(label)
        .finalize()
        .into()
}

/// A fixed deployment context.
pub fn context() -> Context {
    Context {
        network_id: tag(b"network"),
        program_id: tag(b"tessera-program"),
    }
}

/// Program id of the fixture's native-transfer-shaped target.
pub fn transfer_program_id() -> [u8; 32] {
    tag(b"native-transfer-program")
}

/// A native-transfer-shaped call: debit `vault` (writable, authorised via Tessera's PDA
/// seed), credit `recipient` (writable). Data = `b"transfer"` discriminator ‖ amount (u128 LE).
pub fn transfer_call(vault: [u8; 32], recipient: [u8; 32], amount: u128) -> Call {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(b"transfer");
    data.extend_from_slice(&amount.to_le_bytes());
    Call {
        program_id: transfer_program_id(),
        image_id: tag(b"native-transfer-image"),
        accounts: vec![
            AccountRef {
                id: vault,
                writable: true,
                authorised: true,
            },
            AccountRef {
                id: recipient,
                writable: true,
                authorised: false,
            },
        ],
        data,
    }
}

/// Everything needed to exercise `queue`/`execute`.
pub struct Fixture {
    pub ctx: Context,
    pub config: Config,
    pub proposal: Proposal,
    pub proposer: Approval,
    pub approvals: Vec<Approval>,
    pub executor: Approval,
    pub env: TxEnv,
    pub keys: Vec<SigningKey>,
}

impl core::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fixture")
            .field("ctx", &self.ctx)
            .field("config", &self.config)
            .field("proposal", &self.proposal)
            .field("approvals", &self.approvals.len())
            .field("env", &self.env)
            .finish_non_exhaustive()
    }
}

impl Fixture {
    /// Sign `digest` for `purpose` as member `i`.
    pub fn sign_as(&self, i: usize, purpose: Purpose, digest: &[u8; 32]) -> Approval {
        sign(&self.keys[i], purpose, digest)
    }

    /// Digest of `proposal` under the fixture's current config.
    pub fn digest_of(&self, proposal: &Proposal) -> [u8; 32] {
        action_digest(&self.ctx, &self.config, proposal).expect("digest")
    }

    /// Re-sign proposer, approvals (members `0..m`) and executor for a new proposal.
    pub fn resign(&mut self, proposal: Proposal, m: usize) {
        let d = self.digest_of(&proposal);
        self.proposer = self.sign_as(0, Purpose::Propose, &d);
        self.approvals = (0..m)
            .map(|i| self.sign_as(i, Purpose::Approve, &d))
            .collect();
        self.executor = self.sign_as(0, Purpose::Execute, &d);
        self.proposal = proposal;
    }
}

/// N members (all roles, weight 1), threshold M, time lock 0, activated; a `Calls` action
/// with one native-transfer-shaped call; proposer and executor = member 0; approvals from
/// members `0..M`; window `[1_000, 61_000)`.
pub fn fixture(n: usize, m: usize, seed: [u8; 32]) -> Fixture {
    assert!(
        n >= 1 && m >= 1 && m <= n && n <= crate::MAX_MEMBERS,
        "bad fixture shape"
    );
    let ctx = context();
    let keys: Vec<SigningKey> = (0..n as u32).map(|i| signing_key(&seed, i)).collect();
    let multisig_id: [u8; 32] = Sha256::new()
        .chain_update(b"tessera/fixture/multisig")
        .chain_update(seed)
        .finalize()
        .into();
    let config = Config {
        multisig_id,
        members: keys
            .iter()
            .map(|k| Member {
                key: key_of(k),
                roles: roles::ALL,
                weight: 1,
            })
            .collect(),
        threshold: m as u64,
        timelock_ms: 0,
        action_set: Vec::new(),
        epoch: 0,
        initialised: true,
    };
    let vault: [u8; 32] = Sha256::new()
        .chain_update(b"tessera/fixture/vault")
        .chain_update(multisig_id)
        .finalize()
        .into();
    let proposal = Proposal {
        proposal_id: 1,
        expires_at_ms: 1_000_000_000,
        action: Action::Calls(vec![transfer_call(vault, tag(b"recipient"), 1_000)]),
    };
    let mut f = Fixture {
        ctx,
        config,
        proposal: proposal.clone(),
        proposer: Approval {
            key: [0; 32],
            sig: [0; 64],
        },
        approvals: Vec::new(),
        executor: Approval {
            key: [0; 32],
            sig: [0; 64],
        },
        env: TxEnv::new(Window {
            start_ms: 1_000,
            end_ms: 61_000,
        }),
        keys,
    };
    f.resign(proposal, m);
    f
}

/// The benchmark tuple: `(ctx, config, proposal, proposer, approvals, window)`.
pub fn multisig_fixture(
    n: usize,
    m: usize,
    seed: [u8; 32],
) -> (Context, Config, Proposal, Approval, Vec<Approval>, Window) {
    let f = fixture(n, m, seed);
    (
        f.ctx,
        f.config,
        f.proposal,
        f.proposer,
        f.approvals,
        f.env.window,
    )
}
