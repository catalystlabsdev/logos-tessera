//! The authorisation rules as pure functions.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::digest::{
    action_digest_parts, activation_digest, config_commitment, is_valid_key, verify_approval,
    Purpose,
};
use crate::error::{ConfigFault, Error, Result};
use crate::types::{
    roles, Action, Approval, Call, Config, ConfigUpdate, Context, Effect, Executed, Proposal,
    Queued, TxEnv, Window,
};

/// Upper bound on roster size (bounds in-guest work and account size).
pub const MAX_MEMBERS: usize = 256;
/// Upper bound on a transaction validity window. Wider windows are never unsafe (time is
/// evaluated pessimistically) but are refused as almost certainly a client bug.
pub const MAX_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// Rule 1: structural validity of a configuration.
pub fn validate_config(config: &Config) -> Result<()> {
    let fault = |f| Err(Error::InvalidConfig(f));
    if config.members.is_empty() {
        return fault(ConfigFault::NoMembers);
    }
    if config.members.len() > MAX_MEMBERS {
        return fault(ConfigFault::TooManyMembers);
    }
    if config.threshold == 0 {
        return fault(ConfigFault::ZeroThreshold);
    }
    let mut seen = BTreeSet::new();
    let mut approve_weight: u64 = 0;
    let (mut any_proposer, mut any_executor) = (false, false);
    for m in &config.members {
        if m.weight == 0 {
            return fault(ConfigFault::ZeroWeight);
        }
        if m.roles == 0 || m.roles & !roles::ALL != 0 {
            return fault(ConfigFault::InvalidRoles);
        }
        if !seen.insert(m.key) {
            return fault(ConfigFault::DuplicateMember);
        }
        if !is_valid_key(&m.key) {
            return fault(ConfigFault::InvalidMemberKey);
        }
        if m.has(roles::APPROVE) {
            // At most 256 * u32::MAX: cannot overflow u64, but stay checked.
            approve_weight = approve_weight
                .checked_add(u64::from(m.weight))
                .ok_or(Error::InvalidConfig(ConfigFault::TooManyMembers))?;
        }
        any_proposer |= m.has(roles::PROPOSE);
        any_executor |= m.has(roles::EXECUTE);
    }
    if config.threshold > approve_weight {
        return fault(ConfigFault::ThresholdUnreachable);
    }
    if !any_proposer {
        return fault(ConfigFault::NoProposer);
    }
    if !any_executor {
        return fault(ConfigFault::NoExecutor);
    }
    Ok(())
}

/// A transaction window must be non-empty and at most [`MAX_WINDOW_MS`] wide.
pub fn validate_window(w: &Window) -> Result<()> {
    if w.start_ms >= w.end_ms {
        return Err(Error::WindowInvalid);
    }
    if w.end_ms - w.start_ms > MAX_WINDOW_MS {
        return Err(Error::WindowTooWide);
    }
    Ok(())
}

/// Sum the weight of valid, distinct, APPROVE-holding approvals over `digest` for `purpose`.
/// Returns the weight and the keys that counted, in submission order.
pub fn tally_approvals(
    config: &Config,
    purpose: Purpose,
    digest: &[u8; 32],
    approvals: &[Approval],
) -> Result<(u64, Vec<[u8; 32]>)> {
    let mut seen = BTreeSet::new();
    let mut keys = Vec::with_capacity(approvals.len());
    let mut weight: u64 = 0;
    for a in approvals {
        if !seen.insert(a.key) {
            return Err(Error::DuplicateApprover);
        }
        let member = config.member(&a.key).ok_or(Error::UnknownKey)?;
        if !member.has(roles::APPROVE) {
            return Err(Error::NotApprover);
        }
        verify_approval(purpose, digest, a)?;
        weight = weight
            .checked_add(u64::from(member.weight))
            .ok_or(Error::Encoding)?;
        keys.push(a.key);
    }
    Ok((weight, keys))
}

/// Verify a single signer holding `role` (PROPOSE or EXECUTE) for `purpose`.
fn check_signer(
    config: &Config,
    role: u8,
    missing: Error,
    purpose: Purpose,
    digest: &[u8; 32],
    signer: &Approval,
) -> Result<()> {
    let member = config.member(&signer.key).ok_or(Error::UnknownKey)?;
    if !member.has(role) {
        return Err(missing);
    }
    verify_approval(purpose, digest, signer)
}

/// Rule 2: `Activate`. Threshold-weight approvals over the activation digest of the
/// not-yet-activated configuration; returns it with `initialised = true`.
pub fn activate(ctx: &Context, config: &Config, approvals: &[Approval]) -> Result<Config> {
    if config.initialised {
        return Err(Error::AlreadyInitialised);
    }
    validate_config(config)?;
    let digest = activation_digest(ctx, config)?;
    let (weight, _) = tally_approvals(config, Purpose::Activate, &digest, approvals)?;
    if weight < config.threshold {
        return Err(Error::BelowThreshold);
    }
    let mut out = config.clone();
    out.initialised = true;
    Ok(out)
}

fn call_is_allowed(config: &Config, call: &Call) -> bool {
    config.action_set.is_empty()
        || config.action_set.iter().any(|a| {
            a.program_id == call.program_id
                && match a.discriminator {
                    None => true,
                    Some(d) => call.data.len() >= 8 && call.data[..8] == d,
                }
        })
}

/// The configuration `update` would produce from `config` (epoch + 1), validated.
fn updated_config(config: &Config, update: &ConfigUpdate) -> Result<Config> {
    let next = Config {
        multisig_id: config.multisig_id,
        members: update.members.clone(),
        threshold: update.threshold,
        timelock_ms: update.timelock_ms,
        action_set: update.action_set.clone(),
        epoch: config
            .epoch
            .checked_add(1)
            .ok_or(Error::InvalidConfig(ConfigFault::EpochOverflow))?,
        initialised: config.initialised,
    };
    validate_config(&next)?;
    Ok(next)
}

/// Static checks on an action against a configuration and the transaction's root
/// authorisations: forbidden accounts, the action set, and validity of a proposed config.
pub fn check_action(
    ctx: &Context,
    config: &Config,
    action: &Action,
    root_authorised: &[[u8; 32]],
) -> Result<()> {
    match action {
        Action::Calls(calls) => {
            for call in calls {
                if call.program_id == ctx.program_id {
                    return Err(Error::ForbiddenAccount);
                }
                for acc in &call.accounts {
                    if acc.id == ctx.program_id
                        || acc.id == config.multisig_id
                        || root_authorised.contains(&acc.id)
                    {
                        return Err(Error::ForbiddenAccount);
                    }
                }
                if !call_is_allowed(config, call) {
                    return Err(Error::CallNotAllowed);
                }
            }
            Ok(())
        }
        Action::ChangeConfig(update) => updated_config(config, update).map(|_| ()),
        Action::Cancel { .. } => Ok(()),
    }
}

/// Rule 3: `Queue`.
///
/// `signed_epoch` is the epoch the client says the signers used; a mismatch is reported
/// as [`Error::StaleEpoch`] before any signature work (a signature made under another
/// epoch would in any case fail verification, since the epoch is inside the digest).
pub fn queue(
    ctx: &Context,
    config: &Config,
    proposal: &Proposal,
    signed_epoch: u64,
    proposer: &Approval,
    approvals: &[Approval],
    env: &TxEnv,
) -> Result<Queued> {
    if !config.initialised {
        return Err(Error::NotInitialised);
    }
    if signed_epoch != config.epoch {
        return Err(Error::StaleEpoch);
    }
    let w = env.window;
    validate_window(&w)?;
    if w.end_ms >= proposal.expires_at_ms {
        return Err(Error::Expired);
    }
    let is_cancel = matches!(proposal.action, Action::Cancel { .. });
    if !is_cancel && config.timelock_ms > 0 {
        // Refuse early if the time lock could never elapse before expiry.
        match w.end_ms.checked_add(config.timelock_ms) {
            Some(earliest) if earliest < proposal.expires_at_ms => {}
            _ => return Err(Error::Expired),
        }
    }
    check_action(ctx, config, &proposal.action, &env.root_authorised)?;

    let commitment = config_commitment(config)?;
    let digest = action_digest_parts(
        ctx,
        &config.multisig_id,
        config.epoch,
        &commitment,
        proposal,
    )?;
    check_signer(
        config,
        roles::PROPOSE,
        Error::NotProposer,
        Purpose::Propose,
        &digest,
        proposer,
    )?;
    let (weight, approvers) = tally_approvals(config, Purpose::Approve, &digest, approvals)?;
    if weight < config.threshold {
        return Err(Error::BelowThreshold);
    }
    Ok(Queued {
        digest,
        epoch: config.epoch,
        config_commitment: commitment,
        approvers,
        queued_window_end_ms: w.end_ms,
        timelock_ms: config.timelock_ms,
        expires_at_ms: proposal.expires_at_ms,
        executed: false,
        cancelled: false,
    })
}

/// Current weight of the stored approvers that are still members holding APPROVE (R.2).
pub fn current_approver_weight(config_now: &Config, approvers: &[[u8; 32]]) -> u64 {
    let mut seen = BTreeSet::new();
    approvers
        .iter()
        .filter(|k| seen.insert(**k))
        .filter_map(|k| config_now.member(k))
        .filter(|m| m.has(roles::APPROVE))
        .fold(0u64, |acc, m| acc.saturating_add(u64::from(m.weight)))
}

/// Rule 4: `Execute`. Returns the queued action marked executed and the effect to perform.
pub fn execute(
    ctx: &Context,
    config_now: &Config,
    queued: &Queued,
    proposal: &Proposal,
    executor: &Approval,
    env: &TxEnv,
) -> Result<Executed> {
    if !config_now.initialised {
        return Err(Error::NotInitialised);
    }
    if queued.executed {
        return Err(Error::AlreadyExecuted);
    }
    if queued.cancelled {
        return Err(Error::Cancelled);
    }
    let digest = action_digest_parts(
        ctx,
        &config_now.multisig_id,
        queued.epoch,
        &queued.config_commitment,
        proposal,
    )?;
    if digest != queued.digest {
        return Err(Error::DigestMismatch);
    }
    let w = env.window;
    validate_window(&w)?;
    if w.end_ms >= queued.expires_at_ms {
        return Err(Error::Expired);
    }
    let is_cancel = matches!(proposal.action, Action::Cancel { .. });
    if !is_cancel && queued.timelock_ms > 0 {
        // Pessimistic: Queue may have landed as late as its window end, and Execute may
        // land as early as this window's start.
        match queued.queued_window_end_ms.checked_add(queued.timelock_ms) {
            Some(unlock) if w.start_ms >= unlock => {}
            _ => return Err(Error::TimelockActive),
        }
    }
    if matches!(proposal.action, Action::ChangeConfig(_)) && queued.epoch != config_now.epoch {
        return Err(Error::StaleConfigChange);
    }
    check_action(ctx, config_now, &proposal.action, &env.root_authorised)?;
    check_signer(
        config_now,
        roles::EXECUTE,
        Error::NotExecutor,
        Purpose::Execute,
        &digest,
        executor,
    )?;
    if current_approver_weight(config_now, &queued.approvers) < config_now.threshold {
        return Err(Error::QuorumNoLongerHeld);
    }
    let effect = match &proposal.action {
        Action::Calls(calls) => Effect::Calls(calls.clone()),
        Action::ChangeConfig(update) => Effect::NewConfig(updated_config(config_now, update)?),
        Action::Cancel { digest } => Effect::Cancel { digest: *digest },
    };
    let mut done = queued.clone();
    done.executed = true;
    Ok(Executed {
        queued: done,
        effect,
    })
}

/// `Queue` and `Execute` in one transaction (F.7). Succeeds only when the time lock is zero
/// or the action is a cancellation.
#[allow(clippy::too_many_arguments)]
pub fn queue_and_execute(
    ctx: &Context,
    config: &Config,
    proposal: &Proposal,
    signed_epoch: u64,
    proposer: &Approval,
    approvals: &[Approval],
    executor: &Approval,
    env: &TxEnv,
) -> Result<Executed> {
    let queued = queue(
        ctx,
        config,
        proposal,
        signed_epoch,
        proposer,
        approvals,
        env,
    )?;
    execute(ctx, config, &queued, proposal, executor, env)
}

/// Rule 5: apply a configuration replacement. Validates the result and increments the epoch.
pub fn apply_config_change(config: &Config, update: &ConfigUpdate) -> Result<Config> {
    updated_config(config, update)
}

/// Rule 6: apply an executed `Cancel { digest }` to its target queued action.
pub fn apply_cancel(target: &Queued, digest: &[u8; 32]) -> Result<Queued> {
    if &target.digest != digest {
        return Err(Error::NotQueued);
    }
    if target.executed {
        return Err(Error::AlreadyExecuted);
    }
    if target.cancelled {
        return Err(Error::Cancelled);
    }
    let mut out = target.clone();
    out.cancelled = true;
    Ok(out)
}
