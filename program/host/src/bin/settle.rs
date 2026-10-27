//! The private posture, settled end to end on LEZ's state machine.
//!
//! Every step is a privacy-preserving transaction proved in LEZ's circuit against the live
//! commitment tree and applied by `V03State`:
//!   1. `Create`   — the configuration is born as a private PDA of Tessera (Init witness).
//!   2. `Activate` — the members confirm it (threshold signatures; Update witness).
//!   3. fund       — a public account shields `VAULT_FUNDS` into the private vault PDA.
//!   4. `QueueAndExecute` (×`--chain`) — M approvals verified, vault debited, recipient credited.
//! For each execute the harness also shows: refused outside its validity window, settled inside
//! it, exact post-state commitments recorded, and a replay refused (nullifiers spent).
//!
//! Flags: `--padded` (wallet padding: 7 private actions, 512-byte notes), `--chain N`,
//! `--real-from K` (steps before K prove in dev mode, so a CPU run only pays for the execute).
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Instant,
};

use anyhow::{Result, anyhow, bail, ensure};
use lee::{
    PrivacyPreservingTransaction, PrivateKey, ProvingInput, PublicExecutionContext, PublicKey,
    SenderPresentation, Simulation, V03State, error::LeeError, execute_and_prove,
    privacy_preserving_transaction::{Message, WitnessSet, circuit::ProgramCatalog},
};
use lee_core::{
    AuthorizationSecretKey, Commitment, DUMMY_COMMITMENT_HASH, DummyInput, DummyOutput,
    EncryptedNote, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness,
    RecipientEncryption, RootCall, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, Actor, ActorState, Nonce},
    encryption::{Ciphertext, MlKem768EncapsulationKey, ViewingPublicKey},
    execution_state::TransactionEntry,
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{MessageBody, PdaSeed},
};
use tessera_api::{Msg, State};
use tessera_core::{AccountRef, Action, Call, Config, Context, Proposal, Purpose, fixtures};
use tessera_host::{AMOUNT, VAULT_FUNDS, hex, program};

const PADDED_ACTIONS: usize = 7;
const CIPHERTEXT_PAD: u32 = 512;
const BLOCK: u64 = 1;
const INSIDE_MS: u64 = 2_000; // the fixture's execute window is [1_000, 61_000)
const OUTSIDE_MS: u64 = 100_000;

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

fn err_head(e: &LeeError) -> String {
    format!("{e:?}").chars().take(110).collect()
}

fn set_dev_mode(on: bool) {
    // RISC Zero reads RISC0_DEV_MODE when a prover is built, so flipping it between steps works.
    // SAFETY: single-threaded at this point; no other thread reads the environment.
    unsafe { std::env::set_var("RISC0_DEV_MODE", if on { "1" } else { "0" }) }
}

struct Run {
    state: V03State,
    catalog: ProgramCatalog,
    program_acct: AccountId,
    nsk: NullifierSecretKey,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    padded: bool,
    step_no: usize,
    real_from: usize,
}

impl Run {
    fn pda_witness(&self, seed: PdaSeed, nullifier: NullifierWitness) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk.clone(),
            random_seed: sha(&[b"seed", seed.as_bytes(), &[self.step_no as u8]]),
            kind: WitnessKind::Pda { nsk: self.nsk.clone(), binding: (self.program_acct, seed) },
            nullifier,
            address_openings: BTreeSet::new(),
        }
    }

    fn update(&self, seed: PdaSeed, id: AccountId, account: &Account) -> Result<PrivateWitness> {
        let proof = self
            .state
            .get_proof_for_commitment(&Commitment::new(&id, account))
            .ok_or_else(|| anyhow!("step {}: commitment of {id} not in the tree", self.step_no))?;
        Ok(self.pda_witness(seed, NullifierWitness::Update { account: account.clone(), membership_proof: proof }))
    }

    fn init(&self, seed: PdaSeed) -> PrivateWitness {
        self.pda_witness(seed, NullifierWitness::Init { commitment_root: DUMMY_COMMITMENT_HASH })
    }

    #[allow(clippy::too_many_arguments)]
    fn prove(
        &mut self,
        label: &str,
        root: RootCall,
        public_actors: Vec<Actor>,
        signers: &[&PrivateKey],
        public_states: Vec<(Actor, ActorState)>,
        witnesses: Vec<PrivateWitness>,
        promote_to: Option<AccountId>,
    ) -> Result<(PrivacyPreservingTransaction, f64, usize)> {
        self.step_no += 1;
        set_dev_mode(self.step_no < self.real_from);
        let signer_ids: HashSet<AccountId> =
            signers.iter().map(|k| AccountId::from(&PublicKey::new_from_private_key(k))).collect();
        let nonces: BTreeMap<AccountId, Nonce> = signer_ids
            .iter()
            .map(|id| (*id, self.state.get_account_by_id(*id).nonce))
            .collect();
        let n_private = witnesses.len();
        let input = ProvingInput {
            root: TransactionEntry::Sync(root),
            public_context: PublicExecutionContext::new(public_actors, signer_ids),
            private_witnesses: witnesses,
            dummy_inputs: if self.padded { dummy_inputs(PADDED_ACTIONS - n_private, self.step_no as u8) } else { Vec::new() },
            ciphertext_padding: if self.padded { Some(CIPHERTEXT_PAD) } else { None },
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
        };
        let simulation = Simulation { public_actor_states: public_states.into_iter().collect(), admitted_accounts: None };
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
        let actions = output.execution.private_actions.len();
        let message = Message::from_circuit_output(nonces, output);
        let witness_set = WitnessSet::for_message(&message, proof, signers);
        println!(
            "    step {} ({label}): proved in {secs:.1} s, {actions} private actions, dev_mode={}",
            self.step_no,
            self.step_no < self.real_from
        );
        Ok((PrivacyPreservingTransaction::new(message, witness_set), secs, actions))
    }

    fn settle(&mut self, label: &str, tx: &PrivacyPreservingTransaction, at_ms: u64) -> Result<f64> {
        let t = Instant::now();
        self.state
            .transition_from_privacy_preserving_transaction(tx, BLOCK, at_ms)
            .map_err(|e| anyhow!("step {} ({label}): settlement refused: {e:?}", self.step_no))?;
        Ok(t.elapsed().as_secs_f64() * 1000.0)
    }

    fn expect_refused(&self, label: &str, tx: &PrivacyPreservingTransaction, at_ms: u64) -> Result<()> {
        let mut copy = self.state.clone();
        match copy.transition_from_privacy_preserving_transaction(tx, BLOCK, at_ms) {
            Ok(()) => bail!("step {} ({label}): was accepted, expected a refusal", self.step_no),
            Err(e) => {
                println!("ok  step {} ({label}): refused ({})", self.step_no, err_head(&e));
                Ok(())
            }
        }
    }

    fn balance(&self, id: AccountId) -> Result<u128> {
        self.state.get_account_by_id(id).data.native_balance().map_err(|e| anyhow!("{e:?}"))
    }
}

fn bump(account: &Account, nsk: &NullifierSecretKey, program: AccountId, data: ActorState) -> Account {
    Account { nonce: account.nonce.private_account_nonce_increment(nsk), ..Account::default().with_actor_state(program, data) }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let m: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(5);
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse::<usize>().ok());
    let padded = args.iter().any(|a| a == "--padded");
    let chain = flag("--chain").unwrap_or(1);
    let real_from = flag("--real-from").unwrap_or(1);
    let n = m.max(7);
    let dev_env = std::env::var("RISC0_DEV_MODE").unwrap_or_default();
    if dev_env == "1" {
        // Honour a global dev-mode request: everything stays in dev mode.
    }
    let real_from = if dev_env == "1" { usize::MAX } else { real_from };

    let program = program()?;
    let program_acct = AccountId::from_builtin_program(program.id());
    println!("tessera image id: {}", hex(&program.id()));
    println!(
        "M = {m}, N = {n}, signatures per execute = {}, padded = {padded}, chain = {chain}, real proving from step {}",
        m + 2,
        if real_from == usize::MAX { "never (RISC0_DEV_MODE=1)".to_owned() } else { real_from.to_string() }
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
        nsk: nsk.clone(),
        npk,
        vpk,
        padded,
        step_no: 0,
        real_from,
    };
    let config_actor = Actor::new(config_id, program_acct);
    let mut total_prove = 0.0;

    // 1. Create: the configuration PDA is born private, inactive.
    let inactive = Config { initialised: false, ..f.config.clone() };
    let msg = Msg::Create { ctx: f.ctx.clone(), config: f.config.clone(), vault_seed: *vault_seed.as_bytes(), vault_id: *vault_id.value(), private: true };
    let init_witness = run.init(config_seed);
    let (tx, s, _) = run.prove("create", RootCall { to: config_actor, message: borsh::to_vec(&msg)? }, vec![], &[], vec![], vec![init_witness], None)?;
    total_prove += s;
    run.settle("create", &tx, INSIDE_MS)?;
    let mut tessera_state = State { ctx: f.ctx.clone(), config: inactive.clone(), vault_seed: *vault_seed.as_bytes(), vault_id: *vault_id.value(), queued: Vec::new() };
    let mut config_account = Account {
        nonce: Nonce::default().private_account_nonce_increment(&nsk),
        ..Account::default().with_actor_state(program_acct, ActorState::from(borsh::to_vec(&tessera_state)?))
    };
    ensure!(run.state.get_proof_for_commitment(&Commitment::new(&config_id, &config_account)).is_some(), "create: configuration commitment not recorded");
    println!("ok  step 1 (create): settled; inactive configuration committed");

    // 2. Activate: threshold approvals over the inactive configuration.
    let act_digest = tessera_core::activation_digest(&f.ctx, &inactive).map_err(|e| anyhow!("{}", e.message()))?;
    let approvals: Vec<_> = (0..m).map(|i| f.sign_as(i, Purpose::Activate, &act_digest)).collect();
    let msg = Msg::Activate { approvals };
    let w = run.update(config_seed, config_id, &config_account)?;
    let (tx, s, _) = run.prove("activate", RootCall { to: config_actor, message: borsh::to_vec(&msg)? }, vec![], &[], vec![], vec![w], None)?;
    total_prove += s;
    run.settle("activate", &tx, INSIDE_MS)?;
    tessera_state.config = f.config.clone();
    config_account = bump(&config_account, &nsk, program_acct, ActorState::from(borsh::to_vec(&tessera_state)?));
    ensure!(run.state.get_proof_for_commitment(&Commitment::new(&config_id, &config_account)).is_some(), "activate: active configuration commitment not recorded");
    println!("ok  step 2 (activate): settled; active configuration committed");

    // 3. Fund: a public account shields VAULT_FUNDS into the private vault PDA.
    let funder_actor = Actor::native_balance(funder);
    let msg = native_token::Message::Transfer { to: vault_id, amount: VAULT_FUNDS };
    let w = run.init(vault_seed);
    let (tx, s, _) = run.prove(
        "fund",
        RootCall { to: funder_actor, message: borsh::to_vec(&msg)? },
        vec![funder_actor],
        &[&funder_key],
        vec![(funder_actor, native_token::encode_balance(VAULT_FUNDS))],
        vec![w],
        Some(vault_id),
    )?;
    total_prove += s;
    run.settle("fund", &tx, INSIDE_MS)?;
    let mut vault_account = Account {
        nonce: Nonce::default().private_account_nonce_increment(&nsk),
        ..Account::default().with_actor_state(NATIVE_TOKEN_PROGRAM_ID, native_token::encode_balance(VAULT_FUNDS))
    };
    ensure!(run.balance(funder)? == 0, "funder not debited");
    ensure!(run.state.get_proof_for_commitment(&Commitment::new(&vault_id, &vault_account)).is_some(), "fund: vault commitment not recorded");
    println!("ok  step 3 (fund): settled; funder debited, private vault committed with {VAULT_FUNDS}");

    // 4.. Execute, `chain` times.
    for k in 1..=chain {
        let proposal = Proposal {
            proposal_id: k as u64,
            expires_at_ms: 1_000_000_000,
            action: Action::Calls(vec![Call {
                program_id: *NATIVE_TOKEN_PROGRAM_ID.value(),
                image_id: [0; 32],
                accounts: vec![
                    AccountRef { id: *vault_id.value(), writable: true, authorised: true },
                    AccountRef { id: *recipient.value(), writable: true, authorised: false },
                ],
                data: borsh::to_vec(&native_token::Message::Transfer { to: recipient, amount: AMOUNT })?,
            }]),
        };
        f.resign(proposal, m);
        let msg = Msg::QueueAndExecute {
            proposal: f.proposal.clone(),
            signed_epoch: f.config.epoch,
            proposer: f.proposer.clone(),
            approvals: f.approvals.clone(),
            executor: f.executor.clone(),
            env: f.env.clone(),
        };
        let recipient_actor = Actor::native_balance(recipient);
        let pre = run.balance(recipient)?;
        let wc = run.update(config_seed, config_id, &config_account)?;
        let wv = run.update(vault_seed, vault_id, &vault_account)?;
        let (tx, s, actions) = run.prove(
            "execute",
            RootCall { to: config_actor, message: borsh::to_vec(&msg)? },
            vec![recipient_actor],
            &[],
            vec![(recipient_actor, native_token::encode_balance(pre))],
            vec![wc, wv],
            None,
        )?;
        total_prove += s;
        let tx_bytes = borsh::to_vec(&tx)?.len();
        run.expect_refused("execute outside the validity window", &tx, OUTSIDE_MS)?;
        let settle_ms = run.settle("execute", &tx, INSIDE_MS)?;
        let paid = run.balance(recipient)?;
        ensure!(paid == AMOUNT * k as u128, "recipient holds {paid}, expected {}", AMOUNT * k as u128);
        println!("ok  step {} (execute {k}): settled inside the window; recipient credited {paid}", run.step_no);

        let executed = tessera_core::queue_and_execute(&f.ctx, &f.config, &f.proposal, f.config.epoch, &f.proposer, &f.approvals, &f.executor, &f.env)
            .map_err(|e| anyhow!("core refused: {}", e.message()))?;
        tessera_state.queued.push(executed.queued);
        config_account = bump(&config_account, &nsk, program_acct, ActorState::from(borsh::to_vec(&tessera_state)?));
        vault_account = bump(&vault_account, &nsk, NATIVE_TOKEN_PROGRAM_ID, native_token::encode_balance(VAULT_FUNDS - AMOUNT * k as u128));
        for (name, id, acc) in [("configuration", config_id, &config_account), ("vault", vault_id, &vault_account)] {
            ensure!(run.state.get_proof_for_commitment(&Commitment::new(&id, acc)).is_some(), "execute {k}: post-state commitment of the {name} not recorded");
        }
        println!("ok  step {} (execute {k}): post-state commitments recorded (vault now {})", run.step_no, VAULT_FUNDS - AMOUNT * k as u128);
        run.expect_refused("execute replay", &tx, INSIDE_MS + 500)?;
        println!(
            "RESULT settled private execute k={k} M={m} padded={padded} prove_wall_s={s:.1} settle_ms={settle_ms:.0} tx_bytes={tx_bytes} private_actions={actions}"
        );
    }
    println!("RESULT lifecycle M={m} padded={padded} steps={} total_prove_s={total_prove:.1}", run.step_no);
    println!("all settlement checks passed");
    Ok(())
}
