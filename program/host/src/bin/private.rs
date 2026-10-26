//! Private posture: one zero-time-lock `QueueAndExecute` proved inside LEZ's privacy-preserving
//! circuit. The configuration and the vault are private PDAs of Tessera, bound to the group's
//! keys; the payout goes to a public recipient. Prints proving time and proof size.
//!
//! `--padded` adds the wallet's 7-slot and 512-byte note padding.
//! RISC0_DEV_MODE=1 checks the composition quickly; RISC0_DEV_MODE=0 with `--features cuda`
//! (or `prove`) is the real measurement.
use std::{
    collections::{BTreeSet, HashSet},
    time::Instant,
};

use anyhow::{Result, anyhow};
use lee::{
    ProvingInput, PublicExecutionContext, SenderPresentation, Simulation, error::LeeError,
    execute_and_prove, privacy_preserving_transaction::circuit::ProgramCatalog,
};
use lee_core::{
    AuthorizationSecretKey, DUMMY_COMMITMENT_HASH, DummyInput, DummyOutput, EncryptedNote,
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness, RecipientEncryption,
    RootCall, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, Actor, ActorState},
    encryption::{Ciphertext, MlKem768EncapsulationKey, ViewingPublicKey},
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, PdaSeed},
};
use tessera_api::{Msg, State};
use tessera_core::{AccountRef, Action, Call, Context, Proposal, fixtures};
use tessera_host::{AMOUNT, VAULT_FUNDS, hex, program};

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, LeeError> {
    Err(LeeError::InvalidInput(format!("no seal for async message to {:?}", body.to)))
}

/// A wallet pads every private transaction to 7 private actions and 512-byte notes, so that
/// observers cannot count real accounts. Mirrors LEZ's own `cycle_bench` dummies.
const PADDED_ACTIONS: usize = 7;
const CIPHERTEXT_PAD: u32 = 512;

fn dummy_inputs(count: usize, seed: u8) -> Vec<DummyInput> {
    (0..count)
        .map(|i| {
            let tag = |k: u8| sha(&[b"tessera/dummy", &[seed, i as u8, k]]);
            let ek = MlKem768EncapsulationKey::from_seed(&tag(1), &tag(2));
            let (_, epk) = SharedSecretKey::encapsulate(&ek);
            let mut ciphertext = vec![0u8; CIPHERTEXT_PAD as usize];
            for (j, b) in ciphertext.iter_mut().enumerate() {
                *b = tag(3)[j % 32] ^ (j as u8);
            }
            DummyInput {
                nullifier_seed: tag(4),
                commitment_root: DUMMY_COMMITMENT_HASH,
                output: DummyOutput {
                    commitment_seed: tag(5),
                    note: EncryptedNote { ciphertext: Ciphertext::from_inner(ciphertext), epk },
                },
            }
        })
        .collect()
}

fn main() -> Result<()> {
    let m: usize = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(5);
    let padded = std::env::args().any(|a| a == "--padded");
    let n = m.max(7);
    let program = program()?;
    let program_acct = AccountId::from_builtin_program(program.id());
    println!("tessera image id: {}", hex(&program.id()));

    // The group's keys (the GMS-derived keys every member holds).
    let nsk = NullifierSecretKey::from(&AuthorizationSecretKey([11; 32]));
    let npk = NullifierPublicKey::from(&nsk);
    let vpk = ViewingPublicKey::from_seed(&[12; 32], &[13; 32]);

    let mut f = fixtures::fixture(n, m, [n as u8; 32]);
    f.ctx = Context { network_id: f.ctx.network_id, program_id: *program_acct.value() };
    let multisig_id = f.config.multisig_id;
    let config_seed = PdaSeed::new(multisig_id);
    let vault_seed = PdaSeed::new(sha(&[b"tessera/vault", &multisig_id]));
    let config_id = AccountId::for_private_pda(&program_acct, &config_seed, &npk, &vpk);
    let vault_id = AccountId::for_private_pda(&program_acct, &vault_seed, &npk, &vpk);
    let recipient = AccountId::new([7; 32]);

    let call = Call {
        program_id: *NATIVE_TOKEN_PROGRAM_ID.value(),
        image_id: [0; 32],
        accounts: vec![
            AccountRef { id: *vault_id.value(), writable: true, authorised: true },
            AccountRef { id: *recipient.value(), writable: true, authorised: false },
        ],
        data: borsh::to_vec(&native_token::Message::Transfer { to: recipient, amount: AMOUNT })?,
    };
    let proposal = Proposal { proposal_id: 1, expires_at_ms: 1_000_000_000, action: Action::Calls(vec![call]) };
    f.resign(proposal, m);

    let stored = State {
        ctx: f.ctx.clone(),
        config: f.config.clone(),
        vault_seed: *vault_seed.as_bytes(),
        vault_id: *vault_id.value(),
        queued: Vec::new(),
    };
    let config_account =
        Account::default().with_actor_state(program_acct, ActorState::from(borsh::to_vec(&stored)?));
    let vault_account =
        Account::default().with_actor_state(NATIVE_TOKEN_PROGRAM_ID, native_token::encode_balance(VAULT_FUNDS));

    let witness = |account: Account, seed: PdaSeed| PrivateWitness {
        vpk: vpk.clone(),
        random_seed: sha(&[b"seed", seed.as_bytes()]),
        kind: WitnessKind::Pda { nsk: nsk.clone(), binding: (program_acct, seed) },
        nullifier: NullifierWitness::Update { account, membership_proof: (0, Vec::new()) },
        address_openings: BTreeSet::new(),
    };

    let msg = Msg::QueueAndExecute {
        proposal: f.proposal.clone(),
        signed_epoch: f.config.epoch,
        proposer: f.proposer.clone(),
        approvals: f.approvals.clone(),
        executor: f.executor.clone(),
        env: f.env.clone(),
    };
    let input = ProvingInput {
        root: TransactionEntry::Sync(RootCall {
            to: Actor::new(config_id, program_acct),
            message: borsh::to_vec(&msg)?,
        }),
        public_context: PublicExecutionContext::new(vec![Actor::native_balance(recipient)], HashSet::new()),
        private_witnesses: vec![witness(config_account, config_seed), witness(vault_account, vault_seed)],
        dummy_inputs: if padded { dummy_inputs(PADDED_ACTIONS - 2, n as u8) } else { Vec::new() },
        ciphertext_padding: if padded { Some(CIPHERTEXT_PAD) } else { None },
        recoveries: Vec::new(),
        private_promotions: BTreeSet::new(),
    };
    let catalog = ProgramCatalog::from([(program_acct, program.clone())]);

    // Custody check: a holder of the group's keys tries to debit the private vault directly,
    // without Tessera's seed grant. The native token must refuse it.
    if std::env::args().any(|a| a == "--steal") {
        let steal = ProvingInput {
            root: TransactionEntry::Sync(RootCall {
                to: Actor::native_balance(vault_id),
                message: borsh::to_vec(&native_token::Message::Transfer { to: recipient, amount: AMOUNT })?,
            }),
            public_context: PublicExecutionContext::new(vec![Actor::native_balance(recipient)], HashSet::new()),
            private_witnesses: vec![witness(
                Account::default().with_actor_state(NATIVE_TOKEN_PROGRAM_ID, native_token::encode_balance(VAULT_FUNDS)),
                vault_seed,
            )],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        };
        let r = execute_and_prove(steal, &Simulation::default(), &catalog, |_| SenderPresentation::Canonical, |_, _| false, no_seal);
        match r {
            Ok(_) => anyhow::bail!("group-key holder debited the private vault without Tessera: custody boundary FAILED"),
            Err(e) => {
                let first: String = format!("{e:?}").chars().take(160).collect();
                println!("ok  group_key_holder_cannot_debit_private_vault: refused ({first})");
                return Ok(());
            }
        }
    }

    let dev = std::env::var("RISC0_DEV_MODE").unwrap_or_default();
    println!(
        "M = {m}, N = {n}, signatures checked = {}, padded = {padded}, RISC0_DEV_MODE={dev:?}",
        m + 2
    );
    let started = Instant::now();
    let (output, proof) = execute_and_prove(
        input,
        &Simulation::default(),
        &catalog,
        |_| SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .map_err(|e| anyhow!("{e:?}"))?;
    let secs = started.elapsed().as_secs_f64();
    let proof_bytes = proof.into_inner().len();
    println!(
        "RESULT private QueueAndExecute M={m} padded={padded} prove_wall_s={secs:.1} proof_bytes={proof_bytes} private_actions={}",
        output.execution.private_actions.len()
    );
    Ok(())
}
