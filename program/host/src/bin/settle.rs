//! The private posture, settled end to end on LEZ's state machine.
//!
//! Every step is a privacy-preserving transaction proved in LEZ's circuit against the live
//! commitment tree and applied by `V03State`:
//!
//! 1. `Create`: the configuration is born as a private PDA of Tessera (Init witness).
//! 2. `Activate`: the members confirm it (threshold signatures; Update witness).
//! 3. fund: a public account shields `VAULT_FUNDS` into the private vault PDA.
//! 4. custody: a group-key holder's direct debit of the live vault, without Tessera's seed, is
//!    refused by LEZ's native token inside the circuit (no proof can exist).
//! 5. `QueueAndExecute`, `--chain` times: M approvals verified, vault debited, an existing
//!    public recipient credited; with `--private-recipient`, a fresh regular private account
//!    is created and credited in the same transaction instead (a third private action).
//!
//! For each execute the harness also shows: refused outside its proven validity window
//! (`OutOfValidityWindow`), settled inside it with the exact post-state commitments recorded and
//! the pre-states' nullifiers marked spent, an identical resubmission refused (LEZ's
//! commitment-freshness check fires first), and, with `--double-spend`, a fresh execute proved
//! against the already-spent pre-state refused with `Nullifier already seen`. Each step's output
//! names its receipt kind (succinct STARK, or fake for a dev-mode stub).
//!
//! Flags: `--padded` (wallet padding: 7 private actions, 512-byte notes), `--chain N`,
//! `--private-recipient` (each payout goes to a new private account, see `PrivateRecipient`),
//! `--double-spend`, `--real-from K` (steps before K use dev-mode stubs: executed on the real
//! inputs and settled with every check except receipt verification, so a CPU run only pays for
//! the execute; every RESULT line says whether its step was real).
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Instant,
};

use anyhow::{Result, anyhow, bail, ensure};
use lee::{
    PrivacyPreservingTransaction, PrivateKey, ProvingInput, PublicExecutionContext, PublicKey, SenderPresentation,
    Simulation, V03State,
    error::LeeError,
    execute_and_prove,
    privacy_preserving_transaction::{Message, WitnessSet, circuit::ProgramCatalog},
};
use lee_core::{
    AuthorizationSecretKey, Commitment, Nullifier, NullifierPublicKey, NullifierSecretKey, NullifierWitness,
    PrivateWitness, RegularKey, RootCall, WitnessKind,
    account::{Account, AccountId, Actor, ActorState, Nonce},
    encryption::ViewingPublicKey,
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::PdaSeed,
};
use risc0_zkvm::InnerReceipt;
use tessera_api::{Msg, State};
use tessera_core::{AccountRef, Action, Call, Config, Context, Proposal, Purpose, fixtures};
use tessera_host::{AMOUNT, CIPHERTEXT_PAD, PADDED_ACTIONS, VAULT_FUNDS, dummy_inputs, hex, no_seal, program, sha};

const BLOCK: u64 = 1;
const INSIDE_MS: u64 = 2_000; // the fixture's execute window is [1_000, 61_000)
const OUTSIDE_MS: u64 = 100_000;

fn set_dev_mode(on: bool) {
    // SAFETY: `set_var` is unsound only if another thread reads or writes the environment at
    // the same time. RISC Zero's rayon workers stay alive after the first proof, but they only
    // run while a proof is in progress, and none is in progress here; this harness has no other
    // threads of its own. The flip takes effect because `lee::execute_and_prove` calls
    // `risc0_zkvm::default_prover()` afresh on every call and `is_dev_mode()` re-reads the
    // variable each time; neither caches a prover.
    unsafe { std::env::set_var("RISC0_DEV_MODE", if on { "1" } else { "0" }) }
}

/// What a refused settlement must say; anything else is a failure, not a pass.
enum Refusal {
    OutsideWindow,
    DuplicateCommitments,
    NullifierSpent,
}

impl Refusal {
    fn matches(&self, e: &LeeError) -> bool {
        match (self, e) {
            (Refusal::OutsideWindow, LeeError::OutOfValidityWindow) => true,
            (Refusal::DuplicateCommitments, LeeError::InvalidInput(m)) => m == "Commitment already seen",
            (Refusal::NullifierSpent, LeeError::InvalidInput(m)) => m == "Nullifier already seen",
            _ => false,
        }
    }
}

struct Proved {
    tx: PrivacyPreservingTransaction,
    secs: f64,
    real: bool,
    proof_bytes: usize,
    actions: usize,
    kind: &'static str,
}

/// A fresh regular private account that receives one payout. The payee gives the payer its
/// nullifier key and its viewing public key, so the account can be created by the payout
/// transaction itself with an Init witness holding `RegularKey::Nullifying` (the LEZ wallet's
/// automatic credit to a private recipient it holds keys for). The payer cannot spend the funds.
/// A recipient known only by its public keys is paid by a sealed async message and a separate
/// claim transaction instead; that shape is not measured here.
struct PrivateRecipient {
    nsk: NullifierSecretKey,
    vpk: ViewingPublicKey,
    id: AccountId,
}

impl PrivateRecipient {
    fn new(tag: u64) -> Self {
        let t = tag.to_le_bytes();
        let nsk = NullifierSecretKey::from(&AuthorizationSecretKey(sha(&[b"tessera/recipient/ask", &t])));
        let vpk = ViewingPublicKey::from_seed(&sha(&[b"tessera/recipient/d", &t]), &sha(&[b"tessera/recipient/z", &t]));
        let id = AccountId::for_regular_private_account(&NullifierPublicKey::from(&nsk), &vpk);
        PrivateRecipient { nsk, vpk, id }
    }

    /// The account after it is created holding `amount` of the native token.
    fn credited(&self, amount: u128) -> Account {
        bump(&Account::default(), &self.nsk, NATIVE_TOKEN_PROGRAM_ID, native_token::encode_balance(amount))
    }
}

struct Run {
    state: V03State,
    catalog: ProgramCatalog,
    program_acct: AccountId,
    nsk: NullifierSecretKey,
    vpk: ViewingPublicKey,
    padded: bool,
    step_no: usize,
    real_from: usize,
    real_prove_s: f64,
}

impl Run {
    /// Opens the next step; witnesses built after this carry the step's number in their seeds.
    fn next_step(&mut self) -> usize {
        self.step_no += 1;
        self.step_no
    }

    fn is_real(&self) -> bool {
        self.step_no >= self.real_from
    }

    fn pda_witness(&self, seed: PdaSeed, nullifier: NullifierWitness) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk.clone(),
            random_seed: sha(&[b"seed", seed.as_bytes(), &[self.step_no as u8]]),
            kind: WitnessKind::Pda { nsk: self.nsk, binding: (self.program_acct, seed) },
            nullifier,
            address_openings: BTreeSet::new(),
        }
    }

    /// An Update witness with a membership proof taken from the live tree.
    fn update(&self, seed: PdaSeed, id: AccountId, account: &Account) -> Result<PrivateWitness> {
        let proof = self
            .state
            .get_proof_for_commitment(&Commitment::new(&id, account))
            .ok_or_else(|| anyhow!("step {}: commitment of {id} not in the tree", self.step_no))?;
        Ok(self.pda_witness(seed, NullifierWitness::Update { account: account.clone(), membership_proof: proof }))
    }

    fn init(&self, seed: PdaSeed) -> PrivateWitness {
        self.pda_witness(seed, NullifierWitness::Init { commitment_root: self.state.commitment_root() })
    }

    /// Init witness creating `r`'s account at the live root, holding only its nullifier key.
    fn recipient_init(&self, r: &PrivateRecipient) -> PrivateWitness {
        PrivateWitness {
            vpk: r.vpk.clone(),
            random_seed: sha(&[b"seed/recipient", r.id.value(), &[self.step_no as u8]]),
            kind: WitnessKind::Regular(RegularKey::Nullifying(r.nsk)),
            nullifier: NullifierWitness::Init { commitment_root: self.state.commitment_root() },
            address_openings: BTreeSet::new(),
        }
    }

    fn prove(&mut self, label: &str, step: Step) -> Result<Proved> {
        let real = self.is_real();
        set_dev_mode(!real);
        let signer_ids: HashSet<AccountId> =
            step.signers.iter().map(|k| AccountId::from(&PublicKey::new_from_private_key(k))).collect();
        let nonces: BTreeMap<AccountId, Nonce> =
            signer_ids.iter().map(|id| (*id, self.state.get_account_by_id(*id).nonce)).collect();
        let n_private = step.witnesses.len();
        let input = ProvingInput {
            root: TransactionEntry::Sync(step.root),
            public_context: PublicExecutionContext::new(step.public_actors, signer_ids),
            private_witnesses: step.witnesses,
            dummy_inputs: if self.padded {
                dummy_inputs(PADDED_ACTIONS - n_private, self.state.commitment_root())
            } else {
                Vec::new()
            },
            ciphertext_padding: if self.padded { Some(CIPHERTEXT_PAD) } else { None },
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        };
        let simulation =
            Simulation { public_actor_states: step.public_states.into_iter().collect(), admitted_accounts: None };
        let promote_to = step.promote_to;
        let started = Instant::now();
        let (output, proof) = execute_and_prove(
            input,
            &simulation,
            &self.catalog,
            |_| SenderPresentation::Canonical,
            |_, body| promote_to.is_some_and(|id| body.to.account_id == id),
            no_seal,
        )
        .map_err(|e| anyhow!("step {} ({label}): proving failed: {e:?}", self.step_no))?;
        let secs = started.elapsed().as_secs_f64();
        if real {
            self.real_prove_s += secs;
        }
        let actions = output.execution.private_actions.len();
        // The proof is the borsh encoding of a RISC Zero `InnerReceipt`; its kind is the record of
        // whether this step carried a real STARK (succinct) or a dev-mode stub (fake).
        let raw: Vec<u8> = borsh::from_slice(&borsh::to_vec(&proof)?)?;
        let proof_bytes = raw.len();
        let kind = match borsh::from_slice::<InnerReceipt>(&raw) {
            Ok(InnerReceipt::Succinct(_)) => "succinct",
            Ok(InnerReceipt::Composite(_)) => "composite",
            Ok(InnerReceipt::Fake(_)) => "fake(dev-mode)",
            Ok(_) => "other",
            Err(_) => "undecodable",
        };
        ensure!(
            real == (kind == "succinct" || kind == "composite"),
            "step {}: receipt kind {kind} does not match real={real}",
            self.step_no
        );
        let message = Message::from_circuit_output(nonces, output);
        let witness_set = WitnessSet::for_message(&message, proof, step.signers);
        println!(
            "    step {} ({label}): {} in {secs:.1} s, {actions} private actions, receipt {kind}, {proof_bytes} B",
            self.step_no,
            if real { "proved" } else { "dev-mode stub (no proof)" }
        );
        Ok(Proved {
            tx: PrivacyPreservingTransaction::new(message, witness_set),
            secs,
            real,
            proof_bytes,
            actions,
            kind,
        })
    }

    fn settle(&mut self, label: &str, tx: &PrivacyPreservingTransaction, at_ms: u64) -> Result<f64> {
        let t = Instant::now();
        self.state
            .transition_from_privacy_preserving_transaction(tx, BLOCK, at_ms)
            .map_err(|e| anyhow!("step {} ({label}): settlement refused: {e:?}", self.step_no))?;
        Ok(t.elapsed().as_secs_f64() * 1000.0)
    }

    /// Settles `tx` on a copy of the state and requires exactly `expected` as the refusal.
    fn expect_refused(
        &self,
        label: &str,
        tx: &PrivacyPreservingTransaction,
        at_ms: u64,
        expected: Refusal,
    ) -> Result<()> {
        let mut copy = self.state.clone();
        match copy.transition_from_privacy_preserving_transaction(tx, BLOCK, at_ms) {
            Ok(()) => bail!("step {} ({label}): was accepted, expected a refusal", self.step_no),
            Err(e) if expected.matches(&e) => {
                println!("ok  step {} ({label}): refused ({e:?})", self.step_no);
                Ok(())
            }
            Err(e) => bail!("step {} ({label}): refused for the wrong reason: {e:?}", self.step_no),
        }
    }

    /// Runs the circuit on `step` and requires it to refuse before any proof exists.
    fn expect_unprovable(&mut self, label: &str, step: Step, needle: &str) -> Result<()> {
        let signer_ids: HashSet<AccountId> =
            step.signers.iter().map(|k| AccountId::from(&PublicKey::new_from_private_key(k))).collect();
        let input = ProvingInput {
            root: TransactionEntry::Sync(step.root),
            public_context: PublicExecutionContext::new(step.public_actors, signer_ids),
            private_witnesses: step.witnesses,
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        };
        let simulation =
            Simulation { public_actor_states: step.public_states.into_iter().collect(), admitted_accounts: None };
        match execute_and_prove(
            input,
            &simulation,
            &self.catalog,
            |_| SenderPresentation::Canonical,
            |_, _| false,
            no_seal,
        ) {
            Ok(_) => bail!("step {} ({label}): a proof was produced, expected a refusal", self.step_no),
            Err(e) => {
                let text = format!("{e:?}");
                ensure!(text.contains(needle), "step {} ({label}): refused for the wrong reason: {text}", self.step_no);
                println!(
                    "ok  step {} ({label}): no proof possible ({})",
                    self.step_no,
                    text.chars().take(110).collect::<String>()
                );
                Ok(())
            }
        }
    }

    fn assert_spent(&self, label: &str, id: AccountId, pre: &Account) -> Result<()> {
        let n = Nullifier::for_account_update(&Commitment::new(&id, pre), &self.nsk);
        ensure!(self.state.is_spent(&n), "{label}: nullifier of the spent {id} pre-state not recorded");
        Ok(())
    }

    fn balance(&self, id: AccountId) -> Result<u128> {
        self.state.get_account_by_id(id).data.native_balance().map_err(|e| anyhow!("{e:?}"))
    }
}

struct Step<'a> {
    root: RootCall,
    public_actors: Vec<Actor>,
    signers: &'a [&'a PrivateKey],
    public_states: Vec<(Actor, ActorState)>,
    witnesses: Vec<PrivateWitness>,
    promote_to: Option<AccountId>,
}

impl<'a> Step<'a> {
    fn private(root: RootCall, witnesses: Vec<PrivateWitness>) -> Self {
        Step { root, public_actors: Vec::new(), signers: &[], public_states: Vec::new(), witnesses, promote_to: None }
    }
}

fn bump(account: &Account, nsk: &NullifierSecretKey, program: AccountId, data: ActorState) -> Account {
    Account {
        nonce: account.nonce.private_account_nonce_increment(nsk),
        ..Account::default().with_actor_state(program, data)
    }
}

fn payout_proposal(id: u64, vault_id: AccountId, recipient: AccountId, amount: u128) -> Result<Proposal> {
    Ok(Proposal {
        proposal_id: id,
        expires_at_ms: 1_000_000_000,
        action: Action::Calls(vec![Call {
            program_id: *NATIVE_TOKEN_PROGRAM_ID.value(),
            image_id: [0; 32],
            accounts: vec![
                AccountRef { id: *vault_id.value(), writable: true, authorised: true },
                AccountRef { id: *recipient.value(), writable: true, authorised: false },
            ],
            data: borsh::to_vec(&native_token::Message::Transfer { to: recipient, amount })?,
        }]),
    })
}

fn execute_msg(f: &fixtures::Fixture) -> Msg {
    Msg::QueueAndExecute {
        proposal: f.proposal.clone(),
        signed_epoch: f.config.epoch,
        proposer: f.proposer,
        approvals: f.approvals.clone(),
        executor: f.executor,
        env: f.env.clone(),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let m: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(5);
    let flag = |name: &str| {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse::<usize>().ok())
    };
    let padded = args.iter().any(|a| a == "--padded");
    let double_spend = args.iter().any(|a| a == "--double-spend");
    let private_recipient = args.iter().any(|a| a == "--private-recipient");
    let recipient_kind = if private_recipient { "private" } else { "public" };
    let chain = flag("--chain").unwrap_or(1);
    let dev_env = std::env::var("RISC0_DEV_MODE").unwrap_or_default() == "1";
    let real_from = if dev_env { usize::MAX } else { flag("--real-from").unwrap_or(1) };
    let n = m.max(7);

    let program = program()?;
    let program_acct = AccountId::from_builtin_program(program.id());
    println!("tessera image id: {}", hex(&program.id()));
    println!(
        "M = {m}, N = {n}, signatures per execute = {}, padded = {padded}, recipient = {recipient_kind}, chain = {chain}, double_spend = {double_spend}, real proving from step {}",
        m + 2,
        if dev_env { "never (RISC0_DEV_MODE=1)".to_owned() } else { real_from.to_string() }
    );

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
    let funder_key = PrivateKey::try_new([1; 32]).map_err(|e| anyhow!("{e:?}"))?;
    let funder = AccountId::from(&PublicKey::new_from_private_key(&funder_key));

    let mut run = Run {
        state: V03State::new()
            .with_public_account_balances([(funder, VAULT_FUNDS), (recipient, 0)])
            .with_programs([program.clone()]),
        catalog: ProgramCatalog::from([(program_acct, program.clone())]),
        program_acct,
        nsk,
        vpk,
        padded,
        step_no: 0,
        real_from,
        real_prove_s: 0.0,
    };
    let config_actor = Actor::new(config_id, program_acct);

    // 1. Create: the configuration PDA is born private and inactive.
    let inactive = Config { initialised: false, ..f.config.clone() };
    run.next_step();
    let msg = Msg::Create {
        ctx: f.ctx,
        config: f.config.clone(),
        vault_seed: *vault_seed.as_bytes(),
        vault_id: *vault_id.value(),
        private: true,
    };
    let w = run.init(config_seed);
    let p =
        run.prove("create", Step::private(RootCall { to: config_actor, message: borsh::to_vec(&msg)? }, vec![w]))?;
    run.settle("create", &p.tx, INSIDE_MS)?;
    let mut tessera_state = State {
        ctx: f.ctx,
        config: inactive.clone(),
        vault_seed: *vault_seed.as_bytes(),
        vault_id: *vault_id.value(),
        queued: Vec::new(),
    };
    let mut config_account = Account {
        nonce: Nonce::default().private_account_nonce_increment(&nsk),
        ..Account::default().with_actor_state(program_acct, ActorState::from(borsh::to_vec(&tessera_state)?))
    };
    ensure!(
        run.state.get_proof_for_commitment(&Commitment::new(&config_id, &config_account)).is_some(),
        "create: configuration commitment not recorded"
    );
    println!("ok  step 1 (create): settled; inactive configuration committed");

    // 2. Activate: threshold approvals over the inactive configuration.
    run.next_step();
    let act_digest = tessera_core::activation_digest(&f.ctx, &inactive).map_err(|e| anyhow!("{}", e.message()))?;
    let approvals: Vec<_> = (0..m).map(|i| f.sign_as(i, Purpose::Activate, &act_digest)).collect();
    let msg = Msg::Activate { approvals };
    let w = run.update(config_seed, config_id, &config_account)?;
    let p =
        run.prove("activate", Step::private(RootCall { to: config_actor, message: borsh::to_vec(&msg)? }, vec![w]))?;
    run.settle("activate", &p.tx, INSIDE_MS)?;
    tessera_state.config = f.config.clone();
    config_account = bump(&config_account, &nsk, program_acct, ActorState::from(borsh::to_vec(&tessera_state)?));
    ensure!(
        run.state.get_proof_for_commitment(&Commitment::new(&config_id, &config_account)).is_some(),
        "activate: active configuration commitment not recorded"
    );
    println!("ok  step 2 (activate): settled; active configuration committed");

    // 3. Fund: a public account shields VAULT_FUNDS into the private vault PDA.
    run.next_step();
    let funder_actor = Actor::native_balance(funder);
    let msg = native_token::Message::Transfer { to: vault_id, amount: VAULT_FUNDS };
    let w = run.init(vault_seed);
    let p = run.prove(
        "fund",
        Step {
            root: RootCall { to: funder_actor, message: borsh::to_vec(&msg)? },
            public_actors: vec![funder_actor],
            signers: &[&funder_key],
            public_states: vec![(funder_actor, native_token::encode_balance(VAULT_FUNDS))],
            witnesses: vec![w],
            promote_to: Some(vault_id),
        },
    )?;
    run.settle("fund", &p.tx, INSIDE_MS)?;
    let mut vault_account = Account {
        nonce: Nonce::default().private_account_nonce_increment(&nsk),
        ..Account::default().with_actor_state(NATIVE_TOKEN_PROGRAM_ID, native_token::encode_balance(VAULT_FUNDS))
    };
    ensure!(run.balance(funder)? == 0, "funder not debited");
    ensure!(
        run.state.get_proof_for_commitment(&Commitment::new(&vault_id, &vault_account)).is_some(),
        "fund: vault commitment not recorded"
    );
    println!("ok  step 3 (fund): settled; funder debited to 0, private vault committed with {VAULT_FUNDS}");

    // 4. Custody: a holder of the group's keys tries to debit the live private vault directly,
    //    without Tessera's seed grant. LEZ's native token refuses inside the circuit, so no
    //    proof can exist, let alone settle.
    run.next_step();
    let recipient_actor = Actor::native_balance(recipient);
    let w = run.update(vault_seed, vault_id, &vault_account)?;
    run.expect_unprovable(
        "group-key holder debits the live vault without Tessera's seed",
        Step {
            root: RootCall {
                to: Actor::native_balance(vault_id),
                message: borsh::to_vec(&native_token::Message::Transfer { to: recipient, amount: AMOUNT })?,
            },
            public_actors: vec![recipient_actor],
            signers: &[],
            public_states: vec![(recipient_actor, native_token::encode_balance(0))],
            witnesses: vec![w],
            promote_to: None,
        },
        "UnauthorizedSender",
    )?;

    // 5.. Execute, `chain` times.
    for k in 1..=chain {
        let step = run.next_step();
        let payee = private_recipient.then(|| PrivateRecipient::new(k as u64));
        let payee_id = payee.as_ref().map_or(recipient, |r| r.id);
        f.resign(payout_proposal(k as u64, vault_id, payee_id, AMOUNT)?, m);
        let msg = execute_msg(&f);
        let pre = run.balance(recipient)?;
        let stale_config = config_account.clone();
        let stale_vault = vault_account.clone();
        let mut witnesses = vec![
            run.update(config_seed, config_id, &config_account)?,
            run.update(vault_seed, vault_id, &vault_account)?,
        ];
        if let Some(r) = &payee {
            // The account must not exist yet, so the execute below is what creates it.
            ensure!(
                !run.state.is_spent(&Nullifier::for_account_initialization(&r.id, &r.nsk)),
                "execute {k}: the private recipient already exists before the payout"
            );
            witnesses.push(run.recipient_init(r));
        }
        let p = run.prove(
            "execute",
            Step {
                root: RootCall { to: config_actor, message: borsh::to_vec(&msg)? },
                public_actors: if private_recipient { Vec::new() } else { vec![recipient_actor] },
                signers: &[],
                public_states: if private_recipient {
                    Vec::new()
                } else {
                    vec![(recipient_actor, native_token::encode_balance(pre))]
                },
                witnesses,
                promote_to: payee.as_ref().map(|r| r.id),
            },
        )?;
        let tx_bytes = borsh::to_vec(&p.tx)?.len();
        run.expect_refused("execute outside the validity window", &p.tx, OUTSIDE_MS, Refusal::OutsideWindow)?;
        let settle_ms = run.settle("execute", &p.tx, INSIDE_MS)?;
        let paid = run.balance(recipient)?;
        if let Some(r) = &payee {
            ensure!(paid == pre, "a private payout changed the public recipient's balance");
            ensure!(
                run.state.get_proof_for_commitment(&Commitment::new(&r.id, &r.credited(AMOUNT))).is_some(),
                "execute {k}: the private recipient's account holding {AMOUNT} is not in the tree"
            );
            // Negative control: the same account with any other balance is not in the tree, so the
            // check above pins the amount rather than passing for any commitment.
            ensure!(
                run.state.get_proof_for_commitment(&Commitment::new(&r.id, &r.credited(AMOUNT + 1))).is_none(),
                "execute {k}: commitment lookup does not distinguish balances"
            );
            ensure!(
                run.state.is_spent(&Nullifier::for_account_initialization(&r.id, &r.nsk)),
                "execute {k}: the private recipient's init nullifier is not recorded"
            );
            println!(
                "ok  step {step} (execute {k}): settled inside the window; new private recipient {} created holding {AMOUNT} (commitment in the tree, init nullifier spent)",
                r.id
            );
        } else {
            ensure!(paid == AMOUNT * k as u128, "recipient holds {paid}, expected {}", AMOUNT * k as u128);
            println!("ok  step {step} (execute {k}): settled inside the window; recipient credited {paid}");
        }

        let executed = tessera_core::queue_and_execute(
            &f.ctx,
            &f.config,
            &f.proposal,
            f.config.epoch,
            &f.proposer,
            &f.approvals,
            &f.executor,
            &f.env,
        )
        .map_err(|e| anyhow!("core refused: {}", e.message()))?;
        tessera_state.queued.push(executed.queued);
        config_account = bump(&config_account, &nsk, program_acct, ActorState::from(borsh::to_vec(&tessera_state)?));
        vault_account = bump(
            &vault_account,
            &nsk,
            NATIVE_TOKEN_PROGRAM_ID,
            native_token::encode_balance(VAULT_FUNDS - AMOUNT * k as u128),
        );
        for (name, id, acc) in [("configuration", config_id, &config_account), ("vault", vault_id, &vault_account)] {
            ensure!(
                run.state.get_proof_for_commitment(&Commitment::new(&id, acc)).is_some(),
                "execute {k}: post-state commitment of the {name} not recorded"
            );
        }
        println!(
            "ok  step {step} (execute {k}): post-state commitments recorded (vault now {})",
            VAULT_FUNDS - AMOUNT * k as u128
        );
        run.assert_spent("execute", config_id, &stale_config)?;
        run.assert_spent("execute", vault_id, &stale_vault)?;
        println!("ok  step {step} (execute {k}): nullifiers of the spent configuration and vault pre-states recorded");
        run.expect_refused("execute resubmitted unchanged", &p.tx, INSIDE_MS + 500, Refusal::DuplicateCommitments)?;
        println!(
            "RESULT settled private execute k={k} M={m} padded={padded} recipient={recipient_kind} real={} receipt={} prove_wall_s={:.1} proof_bytes={} tx_bytes={tx_bytes} settle_ms={settle_ms:.0} private_actions={}",
            p.real, p.kind, p.secs, p.proof_bytes, p.actions
        );

        if double_spend {
            // A different payout (other proposal id and amount, so no output commitment can
            // coincide with execute k's) proved against the pre-state execute k already spent.
            let ds = run.next_step();
            let mut g = f.clone();
            let thief = private_recipient.then(|| PrivateRecipient::new(100 + k as u64));
            g.resign(
                payout_proposal(100 + k as u64, vault_id, thief.as_ref().map_or(recipient, |r| r.id), AMOUNT * 2)?,
                m,
            );
            let msg = execute_msg(&g);
            let mut witnesses = vec![
                run.update(config_seed, config_id, &stale_config)?,
                run.update(vault_seed, vault_id, &stale_vault)?,
            ];
            if let Some(r) = &thief {
                witnesses.push(run.recipient_init(r));
            }
            let p2 = run.prove(
                "double-spend attempt",
                Step {
                    root: RootCall { to: config_actor, message: borsh::to_vec(&msg)? },
                    public_actors: if private_recipient { Vec::new() } else { vec![recipient_actor] },
                    signers: &[],
                    public_states: if private_recipient {
                        Vec::new()
                    } else {
                        vec![(recipient_actor, native_token::encode_balance(paid))]
                    },
                    witnesses,
                    promote_to: thief.as_ref().map(|r| r.id),
                },
            )?;
            run.expect_refused(
                "double spend of the executed pre-state",
                &p2.tx,
                INSIDE_MS + 900,
                Refusal::NullifierSpent,
            )?;
            // Sanity only: a refused transaction is applied to a scratch copy, never to `run.state`.
            ensure!(run.balance(recipient)? == paid, "double spend changed the recipient's balance");
            println!(
                "RESULT double-spend k={k} M={m} real={} receipt={} refused=NullifierSpent step={ds}",
                p2.real, p2.kind
            );
        }
    }
    println!(
        "RESULT lifecycle M={m} padded={padded} recipient={recipient_kind} steps={} real_from={} dev_steps={} real_prove_s={:.1}",
        run.step_no,
        if dev_env { "never".to_owned() } else { real_from.to_string() },
        if dev_env { run.step_no } else { real_from.saturating_sub(1).min(run.step_no) },
        run.real_prove_s
    );
    println!("all settlement checks passed");
    Ok(())
}
