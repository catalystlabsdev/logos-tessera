//! Tessera: an M-of-N multisig program on LEZ's actor model.
//!
//! Every authorisation rule lives in `tessera_core`; this file only maps the core's
//! decisions onto LEZ effects. A refusal panics, which rolls back the whole transaction.
use std::collections::BTreeSet;

use lee_core::{
    account::{AccountId, Actor},
    program::{PdaSeed, ReceiveInput, Response, SyncMessage},
};
use tessera_api::{Msg, State};
use tessera_core::{self as core, Effect, Executed, TxEnv};

lee_core::actor_entrypoint!(handle_message);

fn fail(e: core::Error) -> ! {
    panic!("tessera error {}: {}", e.code(), e.message())
}

fn load(input: &ReceiveInput) -> State {
    borsh::from_slice(&input.pre_state).unwrap_or_else(|_| panic!("tessera: no multisig at this account"))
}

fn store(state: &State) -> Vec<u8> {
    borsh::to_vec(state).expect("borsh encoding is infallible")
}

fn windowed(resp: Response, env: &TxEnv) -> Response {
    resp.try_timestamp_window(env.window.start_ms..env.window.end_ms)
        .unwrap_or_else(|_| fail(core::Error::WindowInvalid))
}

fn perform(mut state: State, executed: Executed, env: &TxEnv) -> Response {
    let Executed { queued, effect } = executed;
    match state.queued.iter_mut().find(|q| q.digest == queued.digest) {
        Some(slot) => *slot = queued,
        None => state.queued.push(queued),
    }
    let mut resp_msgs = Vec::new();
    match effect {
        Effect::Calls(calls) => {
            let vault_seed = PdaSeed::new(state.vault_seed);
            let vault = AccountId::new(state.vault_id);
            for call in calls {
                let target = call.accounts.first().unwrap_or_else(|| fail(core::Error::CallNotAllowed));
                // Tessera can only lend authority over its own vault.
                for acc in &call.accounts {
                    if acc.authorised && AccountId::new(acc.id) != vault {
                        fail(core::Error::ForbiddenAccount);
                    }
                }
                let to = Actor::new(AccountId::new(target.id), AccountId::new(call.program_id));
                resp_msgs.push(SyncMessage {
                    to,
                    message: call.data,
                    pda_seeds: BTreeSet::from([vault_seed]),
                });
            }
        }
        Effect::NewConfig(config) => state.config = config,
        Effect::Cancel { digest } => {
            let target = state
                .queued
                .iter_mut()
                .find(|q| q.digest == digest)
                .unwrap_or_else(|| fail(core::Error::NotQueued));
            *target = core::apply_cancel(target, &digest).unwrap_or_else(|e| fail(e));
        }
    }
    let mut resp = Response::set_state(store(&state));
    for m in resp_msgs {
        resp = resp.send(m);
    }
    windowed(resp, env)
}

fn handle_message(input: &ReceiveInput, msg: Msg) -> Response {
    let program = input.receiver.program_account_id;
    match msg {
        Msg::Create { ctx, config, vault_seed, vault_id, private } => {
            assert!(input.pre_state.is_empty(), "tessera: multisig already exists");
            // Public posture: the configuration lives at the public PDA. Private posture: the
            // privacy circuit has already bound the private PDA to (program, multisig_id).
            if !private {
                let expected = AccountId::for_public_pda(&program, &PdaSeed::new(config.multisig_id));
                assert!(input.receiver.account_id == expected, "tessera: wrong configuration account");
            }
            assert!(ctx.program_id == *program.value(), "tessera: context names another program");
            core::validate_config(&config).unwrap_or_else(|e| fail(e));
            let config = core::Config { initialised: false, ..config };
            Response::set_state(store(&State { ctx, config, vault_seed, vault_id, queued: Vec::new() }))
        }
        Msg::Activate { approvals } => {
            let mut state = load(input);
            state.config = core::activate(&state.ctx, &state.config, &approvals).unwrap_or_else(|e| fail(e));
            Response::set_state(store(&state))
        }
        Msg::Queue { proposal, signed_epoch, proposer, approvals, env } => {
            let mut state = load(input);
            let queued = core::queue(&state.ctx, &state.config, &proposal, signed_epoch, &proposer, &approvals, &env)
                .unwrap_or_else(|e| fail(e));
            assert!(
                !state.queued.iter().any(|q| q.digest == queued.digest),
                "tessera: already queued"
            );
            state.queued.push(queued);
            windowed(Response::set_state(store(&state)), &env)
        }
        Msg::Execute { proposal, executor, env } => {
            let state = load(input);
            let queued = state
                .queued
                .iter()
                .find(|q| {
                    core::action_digest_parts(&state.ctx, &state.config.multisig_id, q.epoch, &q.config_commitment, &proposal)
                        .is_ok_and(|d| d == q.digest)
                })
                .cloned()
                .unwrap_or_else(|| fail(core::Error::NotQueued));
            let executed = core::execute(&state.ctx, &state.config, &queued, &proposal, &executor, &env)
                .unwrap_or_else(|e| fail(e));
            perform(state, executed, &env)
        }
        Msg::QueueAndExecute { proposal, signed_epoch, proposer, approvals, executor, env } => {
            let state = load(input);
            let executed = core::queue_and_execute(
                &state.ctx,
                &state.config,
                &proposal,
                signed_epoch,
                &proposer,
                &approvals,
                &executor,
                &env,
            )
            .unwrap_or_else(|e| fail(e));
            assert!(
                !state.queued.iter().any(|q| q.digest == executed.queued.digest),
                "tessera: already executed"
            );
            perform(state, executed, &env)
        }
    }
}
