//! Digests, domain separation and BIP-340 verification.

use crate::error::{Error, Result};
use crate::types::{Approval, Config, Context, Proposal};
use borsh::BorshSerialize;
use k256::schnorr::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Version tag prefixed to every action digest.
pub const ACTION_TAG: &[u8] = b"tessera/v1/action";
/// Version tag prefixed to every activation digest.
pub const ACTIVATION_TAG: &[u8] = b"tessera/v1/activation";

/// What a signature is for. Each purpose has its own domain tag, so a signature for one
/// purpose never verifies for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Propose,
    Approve,
    Reject,
    Activate,
    Execute,
}

impl Purpose {
    pub const fn tag(&self) -> &'static [u8] {
        match self {
            Purpose::Propose => b"tessera/v1/propose",
            Purpose::Approve => b"tessera/v1/approve",
            Purpose::Reject => b"tessera/v1/reject",
            Purpose::Activate => b"tessera/v1/activate",
            Purpose::Execute => b"tessera/v1/execute",
        }
    }
}

/// Streams borsh output straight into a hasher (no intermediate allocation).
struct HashWriter<'a>(&'a mut Sha256);

impl borsh::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> borsh::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> borsh::io::Result<()> {
        Ok(())
    }
}

fn hash_borsh<T: BorshSerialize>(h: &mut Sha256, value: &T) -> Result<()> {
    value
        .serialize(&mut HashWriter(h))
        .map_err(|_| Error::Encoding)
}

/// `sha256(borsh(config))`.
pub fn config_commitment(config: &Config) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    hash_borsh(&mut h, config)?;
    Ok(h.finalize().into())
}

/// Action digest from its explicit parts. Used at `Execute`, where the epoch and
/// commitment are the ones recorded at `Queue`.
pub fn action_digest_parts(
    ctx: &Context,
    multisig_id: &[u8; 32],
    epoch: u64,
    commitment: &[u8; 32],
    proposal: &Proposal,
) -> Result<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(ACTION_TAG);
    h.update(ctx.network_id);
    h.update(ctx.program_id);
    h.update(multisig_id);
    h.update(epoch.to_le_bytes());
    h.update(commitment);
    h.update(proposal.proposal_id.to_le_bytes());
    h.update(proposal.expires_at_ms.to_le_bytes());
    hash_borsh(&mut h, &proposal.action)?;
    Ok(h.finalize().into())
}

/// `sha256("tessera/v1/action" ‖ network_id ‖ program_id ‖ multisig_id ‖ epoch_le ‖
/// config_commitment ‖ proposal_id_le ‖ expires_at_ms_le ‖ borsh(action))`.
pub fn action_digest(ctx: &Context, config: &Config, proposal: &Proposal) -> Result<[u8; 32]> {
    let commitment = config_commitment(config)?;
    action_digest_parts(
        ctx,
        &config.multisig_id,
        config.epoch,
        &commitment,
        proposal,
    )
}

/// `sha256("tessera/v1/activation" ‖ network_id ‖ program_id ‖ config_commitment ‖ epoch_le)`,
/// where the commitment is over the not-yet-activated configuration.
pub fn activation_digest(ctx: &Context, config: &Config) -> Result<[u8; 32]> {
    let commitment = config_commitment(config)?;
    let mut h = Sha256::new();
    h.update(ACTIVATION_TAG);
    h.update(ctx.network_id);
    h.update(ctx.program_id);
    h.update(commitment);
    h.update(config.epoch.to_le_bytes());
    Ok(h.finalize().into())
}

/// The 32-byte message actually signed: `sha256(purpose_tag ‖ digest)`.
pub fn signing_message(purpose: Purpose, digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(purpose.tag());
    h.update(digest);
    h.finalize().into()
}

/// BIP-340 verification of `sig` by x-only `key` over a 32-byte message.
pub fn verify_bip340(key: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(key).map_err(|_| Error::BadSignature)?;
    let sig = Signature::try_from(&sig[..]).map_err(|_| Error::BadSignature)?;
    vk.verify_raw(msg, &sig).map_err(|_| Error::BadSignature)
}

/// Verify an approval for `purpose` over `digest`.
pub fn verify_approval(purpose: Purpose, digest: &[u8; 32], approval: &Approval) -> Result<()> {
    verify_bip340(
        &approval.key,
        &signing_message(purpose, digest),
        &approval.sig,
    )
}

/// True iff `key` parses as a BIP-340 x-only public key.
pub fn is_valid_key(key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(key).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{roles, AccountRef, Action, Call, Member};
    use alloc::vec;
    use alloc::vec::Vec;

    fn sample() -> (Context, Config, Proposal) {
        let ctx = Context {
            network_id: [1; 32],
            program_id: [2; 32],
        };
        let config = Config {
            multisig_id: [3; 32],
            members: vec![Member {
                key: [4; 32],
                roles: roles::ALL,
                weight: 1,
            }],
            threshold: 1,
            timelock_ms: 0,
            action_set: vec![],
            epoch: 7,
            initialised: true,
        };
        let proposal = Proposal {
            proposal_id: 9,
            expires_at_ms: 1_000,
            action: Action::Calls(vec![Call {
                program_id: [5; 32],
                image_id: [6; 32],
                accounts: vec![AccountRef {
                    id: [7; 32],
                    writable: true,
                    authorised: false,
                }],
                data: vec![0xaa, 0xbb],
            }]),
        };
        (ctx, config, proposal)
    }

    fn sha(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = Sha256::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    #[test]
    fn action_digest_matches_documented_layout() {
        let (ctx, config, proposal) = sample();
        let commitment = sha(&[&borsh::to_vec(&config).unwrap()]);
        assert_eq!(config_commitment(&config).unwrap(), commitment);
        let action = borsh::to_vec(&proposal.action).unwrap();
        let expected = sha(&[
            b"tessera/v1/action",
            &ctx.network_id,
            &ctx.program_id,
            &config.multisig_id,
            &7u64.to_le_bytes(),
            &commitment,
            &9u64.to_le_bytes(),
            &1_000u64.to_le_bytes(),
            &action,
        ]);
        assert_eq!(action_digest(&ctx, &config, &proposal).unwrap(), expected);
        assert_eq!(
            signing_message(Purpose::Approve, &expected),
            sha(&[b"tessera/v1/approve", &expected])
        );
    }

    #[test]
    fn activation_digest_matches_documented_layout() {
        let (ctx, mut config, _) = sample();
        config.initialised = false;
        let commitment = config_commitment(&config).unwrap();
        let expected = sha(&[
            b"tessera/v1/activation",
            &ctx.network_id,
            &ctx.program_id,
            &commitment,
            &7u64.to_le_bytes(),
        ]);
        assert_eq!(activation_digest(&ctx, &config).unwrap(), expected);
    }

    /// Frozen known-answer value: changing it is a wire-format break for every client.
    #[test]
    fn action_digest_known_answer() {
        let (ctx, config, proposal) = sample();
        let d = action_digest(&ctx, &config, &proposal).unwrap();
        let hex: Vec<u8> = d
            .iter()
            .flat_map(|b| {
                let h = b"0123456789abcdef";
                [h[(b >> 4) as usize], h[(b & 15) as usize]]
            })
            .collect();
        assert_eq!(core::str::from_utf8(&hex).unwrap(), KNOWN_ANSWER);
    }

    const KNOWN_ANSWER: &str = "3571121cc7073825a34bb0cdb8177809ca6085ceb8de0227250dd9eb11677175";

    #[test]
    fn malformed_keys_and_signatures_are_errors_not_panics() {
        let msg = [0u8; 32];
        assert_eq!(
            verify_bip340(&[0xff; 32], &msg, &[0; 64]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            verify_bip340(&[0; 32], &msg, &[0xff; 64]),
            Err(Error::BadSignature)
        );
    }
}
