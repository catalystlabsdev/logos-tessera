//! One named test per authorisation rule.

use tessera_core::fixtures::{self, Fixture};
use tessera_core::*;

const SEED: [u8; 32] = [42u8; 32];

fn fx(n: usize, m: usize) -> Fixture {
    fixtures::fixture(n, m, SEED)
}

fn approvals_from(f: &Fixture, digest: &[u8; 32], who: &[usize]) -> Vec<Approval> {
    who.iter()
        .map(|&i| f.sign_as(i, Purpose::Approve, digest))
        .collect()
}

fn run_queue(f: &Fixture) -> Result<Queued> {
    queue(
        &f.ctx,
        &f.config,
        &f.proposal,
        f.config.epoch,
        &f.proposer,
        &f.approvals,
        &f.env,
    )
}

fn win(start_ms: u64, end_ms: u64) -> TxEnv {
    TxEnv::new(Window { start_ms, end_ms })
}

fn update_from(c: &Config) -> ConfigUpdate {
    ConfigUpdate {
        members: c.members.clone(),
        threshold: c.threshold,
        action_set: c.action_set.clone(),
        timelock_ms: c.timelock_ms,
    }
}

/// Fixture with a time lock, signatures refreshed.
fn fx_timelocked(n: usize, m: usize, timelock_ms: u64) -> Fixture {
    let mut f = fx(n, m);
    f.config.timelock_ms = timelock_ms;
    let p = f.proposal.clone();
    f.resign(p, m);
    f
}

/// Executor signature for an already-queued action.
fn executor_for(f: &Fixture, q: &Queued) -> Approval {
    f.sign_as(0, Purpose::Execute, &q.digest)
}

// ---------------------------------------------------------------- happy path

#[test]
fn fixture_queues_and_executes() {
    let f = fx(5, 3);
    let out = queue_and_execute(
        &f.ctx,
        &f.config,
        &f.proposal,
        0,
        &f.proposer,
        &f.approvals,
        &f.executor,
        &f.env,
    )
    .unwrap();
    assert!(out.queued.executed);
    assert_eq!(out.queued.approvers.len(), 3);
    match (&out.effect, &f.proposal.action) {
        (Effect::Calls(a), Action::Calls(b)) => assert_eq!(a, b),
        _ => panic!("wrong effect"),
    }
    let (ctx, config, proposal, proposer, approvals, window) =
        fixtures::multisig_fixture(5, 3, SEED);
    assert!(queue(
        &ctx,
        &config,
        &proposal,
        0,
        &proposer,
        &approvals,
        &TxEnv::new(window)
    )
    .is_ok());
}

// ---------------------------------------------------------------- threshold

#[test]
fn an_action_cannot_execute_below_threshold() {
    let mut f = fx(5, 3);
    f.approvals.truncate(2);
    assert_eq!(run_queue(&f), Err(Error::BelowThreshold));
    assert_eq!(
        queue_and_execute(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &f.approvals,
            &f.executor,
            &f.env
        ),
        Err(Error::BelowThreshold)
    );
    f.approvals.clear();
    assert_eq!(run_queue(&f), Err(Error::BelowThreshold));
    // Approvals from keys without APPROVE never add weight.
    let mut f = fx(5, 3);
    f.config.members[2].roles = roles::PROPOSE | roles::EXECUTE;
    let p = f.proposal.clone();
    f.resign(p, 3);
    assert_eq!(run_queue(&f), Err(Error::NotApprover));
}

#[test]
fn exhaustive_subsets_of_seven_with_threshold_five() {
    let f = fx(7, 5);
    let d = f.digest_of(&f.proposal);
    let all = approvals_from(&f, &d, &[0, 1, 2, 3, 4, 5, 6]);
    for mask in 0u32..128 {
        let subset: Vec<Approval> = (0..7)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| all[i])
            .collect();
        let r = queue(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &subset,
            &f.env,
        );
        if mask.count_ones() >= 5 {
            assert_eq!(
                r.unwrap().approvers.len(),
                mask.count_ones() as usize,
                "mask {mask:07b}"
            );
        } else {
            assert_eq!(r, Err(Error::BelowThreshold), "mask {mask:07b}");
        }
    }
}

#[test]
fn exhaustive_weighted_subsets_of_seven() {
    let weights = [1u32, 1, 1, 2, 2, 3, 5];
    let threshold = 8u64;
    let mut f = fx(7, 5);
    for (m, w) in f.config.members.iter_mut().zip(weights) {
        m.weight = w;
    }
    f.config.threshold = threshold;
    validate_config(&f.config).unwrap();
    let p = f.proposal.clone();
    f.resign(p, 1);
    let d = f.digest_of(&f.proposal);
    let all = approvals_from(&f, &d, &[0, 1, 2, 3, 4, 5, 6]);
    let mut passing = 0;
    for mask in 0u32..128 {
        let idx: Vec<usize> = (0..7).filter(|i| mask & (1 << i) != 0).collect();
        let weight: u64 = idx.iter().map(|&i| u64::from(weights[i])).sum();
        let subset: Vec<Approval> = idx.iter().map(|&i| all[i]).collect();
        let r = queue(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &subset,
            &f.env,
        );
        if weight >= threshold {
            passing += 1;
            assert!(r.is_ok(), "mask {mask:07b} weight {weight}");
        } else {
            assert_eq!(
                r,
                Err(Error::BelowThreshold),
                "mask {mask:07b} weight {weight}"
            );
        }
    }
    assert!(passing > 0 && passing < 128);
}

#[test]
fn duplicate_approver_counts_once() {
    let mut f = fx(5, 3);
    let dup = f.approvals[1];
    f.approvals.truncate(2);
    f.approvals.push(dup);
    assert_eq!(run_queue(&f), Err(Error::DuplicateApprover));
    // Without the duplicate the honest weight is 2 < 3.
    f.approvals.pop();
    assert_eq!(run_queue(&f), Err(Error::BelowThreshold));
}

// ---------------------------------------------------------------- roles

#[test]
fn roles_are_enforced() {
    // A propose-only key cannot approve; an execute-only key cannot propose.
    let mut f = fx(5, 3);
    f.config.members[0].roles = roles::EXECUTE;
    f.config.members[1].roles = roles::PROPOSE | roles::APPROVE;
    let p = f.proposal.clone();
    f.resign(p, 3);
    assert_eq!(run_queue(&f), Err(Error::NotProposer));
    let d = f.digest_of(&f.proposal);
    f.proposer = f.sign_as(1, Purpose::Propose, &d);
    f.approvals = approvals_from(&f, &d, &[1, 2, 3]);
    let q = run_queue(&f).unwrap();
    // Member 1 lacks EXECUTE.
    let bad_exec = f.sign_as(1, Purpose::Execute, &d);
    assert_eq!(
        execute(&f.ctx, &f.config, &q, &f.proposal, &bad_exec, &f.env),
        Err(Error::NotExecutor)
    );
    // Member 0 is execute-only and can submit what others approved.
    let exec = f.sign_as(0, Purpose::Execute, &d);
    assert!(execute(&f.ctx, &f.config, &q, &f.proposal, &exec, &f.env).is_ok());
}

#[test]
fn unknown_and_forged_signers_are_refused() {
    let mut f = fx(5, 3);
    let outsider = fixtures::signing_key(&[9u8; 32], 0);
    let d = f.digest_of(&f.proposal);
    f.approvals[2] = fixtures::sign(&outsider, Purpose::Approve, &d);
    assert_eq!(run_queue(&f), Err(Error::UnknownKey));
    let mut f = fx(5, 3);
    f.approvals[2].sig[10] ^= 1;
    assert_eq!(run_queue(&f), Err(Error::BadSignature));
    let mut f = fx(5, 3);
    f.proposer = Approval {
        key: fixtures::key_of(&outsider),
        sig: f.proposer.sig,
    };
    assert_eq!(run_queue(&f), Err(Error::UnknownKey));
}

// ---------------------------------------------------------------- binding

#[test]
fn approval_signed_for_one_proposal_does_not_count_for_another() {
    let f = fx(5, 3);
    let mut other = f.proposal.clone();
    other.proposal_id = 2;
    let d2 = f.digest_of(&other);
    let proposer2 = f.sign_as(0, Purpose::Propose, &d2);
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &other,
            0,
            &proposer2,
            &f.approvals,
            &f.env
        ),
        Err(Error::BadSignature)
    );
    // Same id, different body.
    let mut other = f.proposal.clone();
    if let Action::Calls(calls) = &mut other.action {
        calls[0].data[8] ^= 0xff;
    }
    let d3 = f.digest_of(&other);
    let proposer3 = f.sign_as(0, Purpose::Propose, &d3);
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &other,
            0,
            &proposer3,
            &f.approvals,
            &f.env
        ),
        Err(Error::BadSignature)
    );
    // Different expiry.
    let mut other = f.proposal.clone();
    other.expires_at_ms += 1;
    let d4 = f.digest_of(&other);
    let proposer4 = f.sign_as(0, Purpose::Propose, &d4);
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &other,
            0,
            &proposer4,
            &f.approvals,
            &f.env
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn approval_from_another_multisig_does_not_count() {
    let a = fx(5, 3);
    // Same members and keys, different multisig id.
    let mut b = fx(5, 3);
    b.config.multisig_id[0] ^= 1;
    let db = b.digest_of(&b.proposal);
    let proposer_b = b.sign_as(0, Purpose::Propose, &db);
    assert_eq!(
        queue(
            &b.ctx,
            &b.config,
            &b.proposal,
            0,
            &proposer_b,
            &a.approvals,
            &b.env
        ),
        Err(Error::BadSignature)
    );
    // Same multisig on another network / program deployment.
    let mut ctx = a.ctx;
    ctx.network_id[0] ^= 1;
    let dc = action_digest(&ctx, &a.config, &a.proposal).unwrap();
    let proposer_c = a.sign_as(0, Purpose::Propose, &dc);
    assert_eq!(
        queue(
            &ctx,
            &a.config,
            &a.proposal,
            0,
            &proposer_c,
            &a.approvals,
            &a.env
        ),
        Err(Error::BadSignature)
    );
}

#[test]
fn domains_are_not_interchangeable() {
    let f = fx(5, 3);
    let d = f.digest_of(&f.proposal);
    let approve0 = f.approvals[0];
    // Approve signature as proposer.
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &approve0,
            &f.approvals,
            &f.env
        ),
        Err(Error::BadSignature)
    );
    // Propose signature as an approval.
    let mut approvals = f.approvals.clone();
    approvals[0] = f.proposer;
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &approvals,
            &f.env
        ),
        Err(Error::BadSignature)
    );
    // Approve signature as executor.
    let q = run_queue(&f).unwrap();
    assert_eq!(
        execute(&f.ctx, &f.config, &q, &f.proposal, &approve0, &f.env),
        Err(Error::BadSignature)
    );
    // Reject and activate signatures over the same digest do not approve.
    for p in [Purpose::Reject, Purpose::Activate, Purpose::Execute] {
        let mut approvals = f.approvals.clone();
        approvals[1] = f.sign_as(1, p, &d);
        assert_eq!(
            queue(
                &f.ctx,
                &f.config,
                &f.proposal,
                0,
                &f.proposer,
                &approvals,
                &f.env
            ),
            Err(Error::BadSignature),
            "{p:?}"
        );
    }
    // All five tags are distinct.
    let tags = [
        Purpose::Propose,
        Purpose::Approve,
        Purpose::Reject,
        Purpose::Activate,
        Purpose::Execute,
    ]
    .map(|p| signing_message(p, &d));
    for i in 0..5 {
        for j in i + 1..5 {
            assert_ne!(tags[i], tags[j]);
        }
    }
}

// ---------------------------------------------------------------- initialisation

#[test]
fn a_vault_cannot_be_drained_before_initialisation() {
    let mut f = fx(5, 3);
    f.config.initialised = false;
    let p = f.proposal.clone();
    f.resign(p, 5);
    assert_eq!(run_queue(&f), Err(Error::NotInitialised));
    assert_eq!(
        queue_and_execute(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &f.approvals,
            &f.executor,
            &f.env
        ),
        Err(Error::NotInitialised)
    );
    // Even a forged queued record cannot be executed.
    let forged = Queued {
        digest: f.digest_of(&f.proposal),
        epoch: 0,
        config_commitment: config_commitment(&f.config).unwrap(),
        approvers: f.config.members.iter().map(|m| m.key).collect(),
        queued_window_end_ms: 0,
        timelock_ms: 0,
        expires_at_ms: f.proposal.expires_at_ms,
        executed: false,
        cancelled: false,
    };
    assert_eq!(
        execute(&f.ctx, &f.config, &forged, &f.proposal, &f.executor, &f.env),
        Err(Error::NotInitialised)
    );
}

#[test]
fn activation_needs_threshold_of_named_members() {
    let mut f = fx(5, 3);
    f.config.initialised = false;
    let d = activation_digest(&f.ctx, &f.config).unwrap();
    let sigs: Vec<Approval> = (0..3)
        .map(|i| f.sign_as(i, Purpose::Activate, &d))
        .collect();
    assert_eq!(
        activate(&f.ctx, &f.config, &sigs[..2]),
        Err(Error::BelowThreshold)
    );
    // Approve-domain signatures over the activation digest do not activate.
    let wrong: Vec<Approval> = (0..3).map(|i| f.sign_as(i, Purpose::Approve, &d)).collect();
    assert_eq!(
        activate(&f.ctx, &f.config, &wrong),
        Err(Error::BadSignature)
    );
    let active = activate(&f.ctx, &f.config, &sigs).unwrap();
    assert!(active.initialised);
    assert_eq!(
        activate(&f.ctx, &active, &sigs),
        Err(Error::AlreadyInitialised)
    );
    // Activation of a different configuration is a different digest.
    let mut other = f.config.clone();
    other.threshold = 2;
    assert_eq!(activate(&f.ctx, &other, &sigs), Err(Error::BadSignature));
}

// ---------------------------------------------------------------- epochs and R.2

#[test]
fn a_configuration_change_invalidates_unqueued_approvals() {
    let f = fx(5, 3);
    // Approvals were collected under epoch 0; then a configuration change applies.
    let mut upd = update_from(&f.config);
    upd.timelock_ms = 5;
    let next = apply_config_change(&f.config, &upd).unwrap();
    assert_eq!(next.epoch, 1);
    assert_eq!(
        queue(
            &f.ctx,
            &next,
            &f.proposal,
            0,
            &f.proposer,
            &f.approvals,
            &f.env
        ),
        Err(Error::StaleEpoch)
    );
    // Claiming the new epoch does not help: the signatures name the old one.
    assert_eq!(
        queue(
            &f.ctx,
            &next,
            &f.proposal,
            1,
            &f.proposer,
            &f.approvals,
            &f.env
        ),
        Err(Error::BadSignature)
    );
}

fn without_member(c: &Config, i: usize) -> Config {
    let mut upd = update_from(c);
    upd.members.remove(i);
    apply_config_change(c, &upd).unwrap()
}

#[test]
fn a_removed_approver_is_discounted_at_execute() {
    let f = fx_timelocked(5, 3, 1_000);
    let later = win(62_000, 70_000);

    // Load-bearing: approvers {0,1,2}, member 2 removed during the lock.
    let q = run_queue(&f).unwrap();
    let now = without_member(&f.config, 2);
    assert_eq!(
        execute(&f.ctx, &now, &q, &f.proposal, &executor_for(&f, &q), &later),
        Err(Error::QuorumNoLongerHeld)
    );

    // Not load-bearing: approvers {0,1,2,3}, member 3 removed.
    let mut f4 = fx_timelocked(5, 3, 1_000);
    let p = f4.proposal.clone();
    f4.resign(p, 4);
    let q4 = run_queue(&f4).unwrap();
    let now = without_member(&f4.config, 3);
    let out = execute(
        &f4.ctx,
        &now,
        &q4,
        &f4.proposal,
        &executor_for(&f4, &q4),
        &later,
    )
    .unwrap();
    assert!(out.queued.executed);

    // Stripped of APPROVE counts as removed.
    let mut upd = update_from(&f.config);
    upd.members[2].roles = roles::PROPOSE | roles::EXECUTE;
    let now = apply_config_change(&f.config, &upd).unwrap();
    assert_eq!(
        execute(&f.ctx, &now, &q, &f.proposal, &executor_for(&f, &q), &later),
        Err(Error::QuorumNoLongerHeld)
    );

    // Threshold raised above the stored approvers' weight.
    let mut upd = update_from(&f.config);
    upd.threshold = 4;
    let now = apply_config_change(&f.config, &upd).unwrap();
    assert_eq!(
        execute(&f.ctx, &now, &q, &f.proposal, &executor_for(&f, &q), &later),
        Err(Error::QuorumNoLongerHeld)
    );

    // Re-weighting counts current weights: member 0 now weighs 2, so {0,1} still reach 3
    // even after member 2 leaves.
    let mut upd = update_from(&f.config);
    upd.members[0].weight = 2;
    upd.members.remove(2);
    let now = apply_config_change(&f.config, &upd).unwrap();
    assert!(execute(&f.ctx, &now, &q, &f.proposal, &executor_for(&f, &q), &later).is_ok());

    // Member added / threshold lowered / delay changed leave it executable.
    let mut upd = update_from(&f.config);
    upd.members.push(Member {
        key: fixtures::key_of(&fixtures::signing_key(&[1; 32], 0)),
        roles: roles::ALL,
        weight: 1,
    });
    upd.threshold = 2;
    upd.timelock_ms = 0;
    let now = apply_config_change(&f.config, &upd).unwrap();
    assert!(execute(&f.ctx, &now, &q, &f.proposal, &executor_for(&f, &q), &later).is_ok());
}

#[test]
fn queued_config_changes_are_serialised() {
    let f = fx(5, 3);
    let mk = |id: u64, threshold: u64| {
        let mut upd = update_from(&f.config);
        upd.threshold = threshold;
        Proposal {
            proposal_id: id,
            expires_at_ms: f.proposal.expires_at_ms,
            action: Action::ChangeConfig(upd),
        }
    };
    let (pa, pb) = (mk(10, 2), mk(11, 4));
    let sign_all = |p: &Proposal| {
        let d = f.digest_of(p);
        (
            f.sign_as(0, Purpose::Propose, &d),
            approvals_from(&f, &d, &[0, 1, 2]),
        )
    };
    let (prop_a, apps_a) = sign_all(&pa);
    let (prop_b, apps_b) = sign_all(&pb);
    let qa = queue(&f.ctx, &f.config, &pa, 0, &prop_a, &apps_a, &f.env).unwrap();
    let qb = queue(&f.ctx, &f.config, &pb, 0, &prop_b, &apps_b, &f.env).unwrap();

    let out = execute(&f.ctx, &f.config, &qa, &pa, &executor_for(&f, &qa), &f.env).unwrap();
    let Effect::NewConfig(next) = out.effect else {
        panic!("expected NewConfig")
    };
    assert_eq!((next.epoch, next.threshold), (1, 2));
    assert_eq!(
        execute(&f.ctx, &next, &qb, &pb, &executor_for(&f, &qb), &f.env),
        Err(Error::StaleConfigChange)
    );
    // Executing a change twice is refused too.
    assert_eq!(
        execute(
            &f.ctx,
            &next,
            &out.queued,
            &pa,
            &executor_for(&f, &qa),
            &f.env
        ),
        Err(Error::AlreadyExecuted)
    );
}

#[test]
fn invalid_config_change_is_refused_at_queue() {
    let f = fx(5, 3);
    let mut upd = update_from(&f.config);
    upd.threshold = 6;
    let p = Proposal {
        proposal_id: 3,
        expires_at_ms: f.proposal.expires_at_ms,
        action: Action::ChangeConfig(upd),
    };
    let d = f.digest_of(&p);
    let proposer = f.sign_as(0, Purpose::Propose, &d);
    let apps = approvals_from(&f, &d, &[0, 1, 2]);
    assert_eq!(
        queue(&f.ctx, &f.config, &p, 0, &proposer, &apps, &f.env),
        Err(Error::InvalidConfig(ConfigFault::ThresholdUnreachable))
    );
}

// ---------------------------------------------------------------- time

#[test]
fn timelock_is_enforced_pessimistically() {
    let f = fx_timelocked(5, 3, 1_000);
    let q = run_queue(&f).unwrap(); // queue window [1_000, 61_000)
    assert_eq!((q.queued_window_end_ms, q.timelock_ms), (61_000, 1_000));
    let ex = executor_for(&f, &q);
    // Would be past the lock had Queue landed at its window start, but it may have landed
    // at 60_999; refused.
    assert_eq!(
        execute(
            &f.ctx,
            &f.config,
            &q,
            &f.proposal,
            &ex,
            &win(61_500, 70_000)
        ),
        Err(Error::TimelockActive)
    );
    // Ends far after the unlock but could land before it; refused.
    assert_eq!(
        execute(
            &f.ctx,
            &f.config,
            &q,
            &f.proposal,
            &ex,
            &win(61_999, 90_000)
        ),
        Err(Error::TimelockActive)
    );
    assert!(execute(
        &f.ctx,
        &f.config,
        &q,
        &f.proposal,
        &ex,
        &win(62_000, 70_000)
    )
    .is_ok());
    // Lowering the time lock later does not shorten the snapshot.
    let mut upd = update_from(&f.config);
    upd.timelock_ms = 0;
    let now = apply_config_change(&f.config, &upd).unwrap();
    assert_eq!(
        execute(&f.ctx, &now, &q, &f.proposal, &ex, &win(61_500, 70_000)),
        Err(Error::TimelockActive)
    );
}

#[test]
fn zero_timelock_executes_in_one_window() {
    let f = fx(5, 3);
    assert_eq!(f.config.timelock_ms, 0);
    assert!(queue_and_execute(
        &f.ctx,
        &f.config,
        &f.proposal,
        0,
        &f.proposer,
        &f.approvals,
        &f.executor,
        &f.env
    )
    .is_ok());
    let f = fx_timelocked(5, 3, 1);
    assert_eq!(
        queue_and_execute(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &f.approvals,
            &f.executor,
            &f.env
        ),
        Err(Error::TimelockActive)
    );
}

#[test]
fn expired_proposal_is_refused() {
    let f = fx(5, 3);
    let exp = f.proposal.expires_at_ms;
    // A window that could reach the expiry is refused at Queue.
    let env = win(exp - 10, exp);
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &f.approvals,
            &env
        ),
        Err(Error::Expired)
    );
    assert!(queue(
        &f.ctx,
        &f.config,
        &f.proposal,
        0,
        &f.proposer,
        &f.approvals,
        &win(exp - 10, exp - 1)
    )
    .is_ok());
    // ...and at Execute.
    let q = run_queue(&f).unwrap();
    assert_eq!(
        execute(
            &f.ctx,
            &f.config,
            &q,
            &f.proposal,
            &f.executor,
            &win(exp - 5, exp + 5)
        ),
        Err(Error::Expired)
    );
    // A time lock that could never elapse before expiry is refused at Queue.
    let mut f = fx_timelocked(5, 3, 1_000);
    let mut p = f.proposal.clone();
    p.expires_at_ms = 61_500;
    f.resign(p, 3);
    assert_eq!(run_queue(&f), Err(Error::Expired));
}

#[test]
fn windows_are_validated() {
    let f = fx(5, 3);
    for (env, e) in [
        (win(10, 10), Error::WindowInvalid),
        (win(20, 10), Error::WindowInvalid),
        (win(0, MAX_WINDOW_MS + 1), Error::WindowTooWide),
    ] {
        assert_eq!(
            queue(
                &f.ctx,
                &f.config,
                &f.proposal,
                0,
                &f.proposer,
                &f.approvals,
                &env
            ),
            Err(e)
        );
    }
}

// ---------------------------------------------------------------- cancel

#[test]
fn cancel_ignores_timelock() {
    let f = fx_timelocked(5, 3, 100_000);
    let target = run_queue(&f).unwrap();
    let cancel = Proposal {
        proposal_id: 99,
        expires_at_ms: f.proposal.expires_at_ms,
        action: Action::Cancel {
            digest: target.digest,
        },
    };
    let d = f.digest_of(&cancel);
    let proposer = f.sign_as(0, Purpose::Propose, &d);
    let apps = approvals_from(&f, &d, &[1, 2, 3]);
    let exec = f.sign_as(0, Purpose::Execute, &d);
    // Below threshold is refused even for cancel.
    assert_eq!(
        queue_and_execute(
            &f.ctx,
            &f.config,
            &cancel,
            0,
            &proposer,
            &apps[..2],
            &exec,
            &f.env
        ),
        Err(Error::BelowThreshold)
    );
    // Same window as the target's queue, well inside its time lock.
    let out = queue_and_execute(
        &f.ctx, &f.config, &cancel, 0, &proposer, &apps, &exec, &f.env,
    )
    .unwrap();
    let Effect::Cancel { digest } = out.effect else {
        panic!("expected Cancel")
    };
    let cancelled = apply_cancel(&target, &digest).unwrap();
    assert!(cancelled.cancelled);
    assert_eq!(apply_cancel(&cancelled, &digest), Err(Error::Cancelled));
    assert_eq!(apply_cancel(&target, &[0u8; 32]), Err(Error::NotQueued));
    // The cancelled action can never execute.
    assert_eq!(
        execute(
            &f.ctx,
            &f.config,
            &cancelled,
            &f.proposal,
            &executor_for(&f, &target),
            &win(200_000, 210_000)
        ),
        Err(Error::Cancelled)
    );
    // Executed actions cannot be cancelled.
    let mut done = target.clone();
    done.executed = true;
    assert_eq!(apply_cancel(&done, &digest), Err(Error::AlreadyExecuted));
}

// ---------------------------------------------------------------- calls

fn with_calls(f: &mut Fixture, calls: Vec<Call>) {
    let p = Proposal {
        proposal_id: 7,
        expires_at_ms: f.proposal.expires_at_ms,
        action: Action::Calls(calls),
    };
    f.resign(p, 3);
}

#[test]
fn forbidden_account_is_refused() {
    let base = fx(5, 3);
    let vault = [5u8; 32];
    let relayer = [6u8; 32];
    let ctx = base.ctx;
    let cases: Vec<Call> = vec![
        // Names Tessera's program id as an account.
        fixtures::transfer_call(vault, ctx.program_id, 1),
        // Names the multisig's configuration header.
        fixtures::transfer_call(vault, base.config.multisig_id, 1),
        // Calls Tessera itself.
        Call {
            program_id: ctx.program_id,
            ..fixtures::transfer_call(vault, [7u8; 32], 1)
        },
    ];
    for call in cases {
        let mut f = fx(5, 3);
        with_calls(&mut f, vec![call]);
        assert_eq!(run_queue(&f), Err(Error::ForbiddenAccount));
    }
    // A root-authorised account (the relayer) named by a call: refused at Queue...
    let mut f = fx(5, 3);
    with_calls(&mut f, vec![fixtures::transfer_call(vault, relayer, 1)]);
    let mut env = f.env.clone();
    env.root_authorised.push(relayer);
    assert_eq!(
        queue(
            &f.ctx,
            &f.config,
            &f.proposal,
            0,
            &f.proposer,
            &f.approvals,
            &env
        ),
        Err(Error::ForbiddenAccount)
    );
    // ...and at Execute when that account signs the Execute transaction.
    let q = run_queue(&f).unwrap();
    assert_eq!(
        execute(&f.ctx, &f.config, &q, &f.proposal, &f.executor, &env),
        Err(Error::ForbiddenAccount)
    );
    assert!(execute(&f.ctx, &f.config, &q, &f.proposal, &f.executor, &f.env).is_ok());
}

#[test]
fn call_outside_action_set_is_refused() {
    let vault = [5u8; 32];
    let restrict = |f: &mut Fixture| {
        f.config.action_set = vec![AllowedCall {
            program_id: fixtures::transfer_program_id(),
            discriminator: Some(*b"transfer"),
        }];
    };
    let mut f = fx(5, 3);
    restrict(&mut f);
    with_calls(&mut f, vec![fixtures::transfer_call(vault, [8u8; 32], 1)]);
    assert!(run_queue(&f).is_ok());

    let other_program = Call {
        program_id: [9u8; 32],
        ..fixtures::transfer_call(vault, [8u8; 32], 1)
    };
    let mut wrong_disc = fixtures::transfer_call(vault, [8u8; 32], 1);
    wrong_disc.data[0] ^= 1;
    let mut short = fixtures::transfer_call(vault, [8u8; 32], 1);
    short.data.truncate(4);
    for bad in [other_program, wrong_disc, short] {
        let mut f = fx(5, 3);
        restrict(&mut f);
        with_calls(
            &mut f,
            vec![fixtures::transfer_call(vault, [8u8; 32], 1), bad],
        );
        assert_eq!(run_queue(&f), Err(Error::CallNotAllowed));
    }
    // A program-wide entry allows any instruction to that program.
    let mut f = fx(5, 3);
    f.config.action_set = vec![AllowedCall {
        program_id: fixtures::transfer_program_id(),
        discriminator: None,
    }];
    let mut any = fixtures::transfer_call(vault, [8u8; 32], 1);
    any.data = vec![1];
    with_calls(&mut f, vec![any]);
    assert!(run_queue(&f).is_ok());
}

// ---------------------------------------------------------------- execute integrity

#[test]
fn execute_requires_the_exact_queued_proposal() {
    let f = fx(5, 3);
    let q = run_queue(&f).unwrap();
    let mut other = f.proposal.clone();
    other.proposal_id += 1;
    assert_eq!(
        execute(&f.ctx, &f.config, &q, &other, &f.executor, &f.env),
        Err(Error::DigestMismatch)
    );
    let done = execute(&f.ctx, &f.config, &q, &f.proposal, &f.executor, &f.env).unwrap();
    assert_eq!(
        execute(
            &f.ctx,
            &f.config,
            &done.queued,
            &f.proposal,
            &f.executor,
            &f.env
        ),
        Err(Error::AlreadyExecuted)
    );
}

// ---------------------------------------------------------------- config validation

#[test]
fn invalid_configs_are_refused() {
    let base = fx(3, 2).config;
    validate_config(&base).unwrap();
    let check = |mutate: &dyn Fn(&mut Config), fault: ConfigFault| {
        let mut c = base.clone();
        mutate(&mut c);
        assert_eq!(
            validate_config(&c),
            Err(Error::InvalidConfig(fault)),
            "{fault:?}"
        );
    };
    check(&|c| c.members.clear(), ConfigFault::NoMembers);
    check(&|c| c.threshold = 0, ConfigFault::ZeroThreshold);
    check(&|c| c.threshold = 4, ConfigFault::ThresholdUnreachable);
    check(
        &|c| {
            c.members[1].roles = roles::PROPOSE;
            c.members[2].roles = roles::EXECUTE;
        },
        ConfigFault::ThresholdUnreachable,
    );
    check(&|c| c.members[0].weight = 0, ConfigFault::ZeroWeight);
    check(
        &|c| c.members[1].key = c.members[0].key,
        ConfigFault::DuplicateMember,
    );
    check(
        &|c| c.members[0].key = [0xff; 32],
        ConfigFault::InvalidMemberKey,
    );
    check(&|c| c.members[0].roles = 0, ConfigFault::InvalidRoles);
    check(
        &|c| c.members[0].roles = 8 | roles::APPROVE,
        ConfigFault::InvalidRoles,
    );
    check(
        &|c| {
            c.members
                .iter_mut()
                .for_each(|m| m.roles = roles::APPROVE | roles::EXECUTE)
        },
        ConfigFault::NoProposer,
    );
    check(
        &|c| {
            c.members
                .iter_mut()
                .for_each(|m| m.roles = roles::APPROVE | roles::PROPOSE)
        },
        ConfigFault::NoExecutor,
    );
    check(
        &|c| {
            let m = c.members[0].clone();
            c.members = (0..=MAX_MEMBERS).map(|_| m.clone()).collect();
        },
        ConfigFault::TooManyMembers,
    );
    let mut c = base.clone();
    c.epoch = u64::MAX;
    assert_eq!(
        apply_config_change(&c, &update_from(&c)),
        Err(Error::InvalidConfig(ConfigFault::EpochOverflow))
    );
}

// ---------------------------------------------------------------- errors

#[test]
fn every_error_code_is_unique_and_stable() {
    let expected: &[(&str, u32)] = &[
        ("NotInitialised", 1),
        ("AlreadyInitialised", 2),
        ("StaleEpoch", 3),
        ("NotProposer", 4),
        ("NotApprover", 5),
        ("NotExecutor", 6),
        ("DuplicateApprover", 7),
        ("UnknownKey", 8),
        ("BadSignature", 9),
        ("BelowThreshold", 10),
        ("QuorumNoLongerHeld", 11),
        ("Expired", 12),
        ("TimelockActive", 13),
        ("WindowInvalid", 14),
        ("WindowTooWide", 15),
        ("NotQueued", 16),
        ("AlreadyExecuted", 17),
        ("Cancelled", 18),
        ("CallNotAllowed", 19),
        ("ForbiddenAccount", 20),
        ("InvalidConfig", 21),
        ("DigestMismatch", 22),
        ("StaleConfigChange", 23),
        ("Encoding", 24),
    ];
    assert_eq!(Error::ALL.len(), expected.len());
    for (e, (name, code)) in Error::ALL.iter().zip(expected) {
        assert_eq!((e.name(), e.code()), (*name, *code));
        assert!(!e.message().is_empty());
    }
    let mut codes: Vec<u32> = Error::ALL.iter().map(Error::code).collect();
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), Error::ALL.len());

    let faults = [
        ConfigFault::NoMembers,
        ConfigFault::TooManyMembers,
        ConfigFault::ZeroThreshold,
        ConfigFault::ThresholdUnreachable,
        ConfigFault::ZeroWeight,
        ConfigFault::DuplicateMember,
        ConfigFault::InvalidMemberKey,
        ConfigFault::InvalidRoles,
        ConfigFault::NoProposer,
        ConfigFault::NoExecutor,
        ConfigFault::EpochOverflow,
    ];
    for (i, f) in faults.iter().enumerate() {
        assert_eq!(f.code(), i as u32 + 1);
        assert_eq!(Error::InvalidConfig(*f).code(), 21);
        assert!(!f.message().is_empty());
    }
}
