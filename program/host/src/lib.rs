//! Test harness: seed a LEZ state with one Tessera multisig and a funded vault, and build
//! the public transactions that drive it.
use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use lee::{
    Account, ExecutionCharge, PublicTransaction, V03State, ValidatedStateDiff,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::PdaSeed,
};
use tessera_api::{Msg, State};
use tessera_core::{AccountRef, Action, Call, Context, Proposal, fixtures::{self, Fixture}};

pub const MAX_GAS_EXEC: u64 = 10_000_000;
pub const AMOUNT: u128 = 1_000;
pub const VAULT_FUNDS: u128 = 1_000_000;

pub fn program() -> Result<Program> {
    Program::new(tessera_methods::TESSERA_ELF.into()).map_err(|e| anyhow!("{e:?}"))
}

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub struct World {
    pub state: V03State,
    pub fixture: Fixture,
    pub program_acct: AccountId,
    pub config_acct: AccountId,
    pub vault: AccountId,
    pub recipient: AccountId,
}

impl World {
    /// An active N-member multisig with threshold M, a funded vault, and a signed proposal
    /// paying `AMOUNT` from the vault to `recipient`.
    pub fn new(program: &Program, n: usize, m: usize) -> Result<Self> {
        let program_acct = AccountId::from_builtin_program(program.id());
        let mut f = fixtures::fixture(n, m, [n as u8; 32]);
        f.ctx = Context { network_id: f.ctx.network_id, program_id: *program_acct.value() };
        let multisig_id = f.config.multisig_id;
        let vault_seed = sha(&[b"tessera/vault", &multisig_id]);
        let vault = AccountId::for_public_pda(&program_acct, &PdaSeed::new(vault_seed));
        let config_acct = AccountId::for_public_pda(&program_acct, &PdaSeed::new(multisig_id));
        let recipient = AccountId::new([7; 32]);
        let call = Call {
            program_id: *NATIVE_TOKEN_PROGRAM_ID.value(),
            image_id: [0; 32],
            accounts: vec![
                AccountRef { id: *vault.value(), writable: true, authorised: true },
                AccountRef { id: *recipient.value(), writable: true, authorised: false },
            ],
            data: borsh::to_vec(&native_token::Message::Transfer { to: recipient, amount: AMOUNT })?,
        };
        let proposal = Proposal { proposal_id: 1, expires_at_ms: 1_000_000_000, action: Action::Calls(vec![call]) };
        f.resign(proposal, m);
        let stored = State { ctx: f.ctx.clone(), config: f.config.clone(), vault_seed, vault_id: *vault.value(), queued: Vec::new() };
        let config_account =
            Account::default().with_actor_state(program_acct, ActorState::from(borsh::to_vec(&stored)?));
        let state = V03State::new()
            .with_public_account_balances([(vault, VAULT_FUNDS), (recipient, 0)])
            .with_public_accounts([(config_acct, config_account)])
            .with_programs([program.clone()]);
        Ok(Self { state, fixture: f, program_acct, config_acct, vault, recipient })
    }

    pub fn config_actor(&self) -> Actor {
        Actor::new(self.config_acct, self.program_acct)
    }

    pub fn queue_and_execute_msg(&self) -> Msg {
        let f = &self.fixture;
        Msg::QueueAndExecute {
            proposal: f.proposal.clone(),
            signed_epoch: f.config.epoch,
            proposer: f.proposer.clone(),
            approvals: f.approvals.clone(),
            executor: f.executor.clone(),
            env: f.env.clone(),
        }
    }

    pub fn tx(&self, to: Actor, msg: &impl borsh::BorshSerialize) -> Result<PublicTransaction> {
        let actors = [self.config_actor(), Actor::native_balance(self.vault), Actor::native_balance(self.recipient)];
        let message = Message::try_new(to, actors, BTreeMap::new(), msg).map_err(|e| anyhow!("{e:?}"))?;
        let witness = WitnessSet::for_message(&message, &[]);
        Ok(PublicTransaction::new(message, witness))
    }

    /// Execute under the 10M cap inside the fixture's validity window; apply on success.
    pub fn submit(&mut self, tx: &PublicTransaction) -> Result<ExecutionCharge> {
        let now = self.fixture.env.window.start_ms + 1;
        let (diff, charge) =
            ValidatedStateDiff::from_public_transaction_with_cycle_budget(tx, &self.state, 1, now, MAX_GAS_EXEC)
                .map_err(|e| anyhow!("{e:?}"))?;
        self.state.apply_state_diff(diff).map_err(|e| anyhow!("{e:?}"))?;
        Ok(charge)
    }

    pub fn balance(&self, id: AccountId) -> Result<u128> {
        self.state.get_account_by_id(id).data.native_balance().map_err(|e| anyhow!("{e:?}"))
    }
}

pub fn hex(id: &[u32; 8]) -> String {
    id.iter().flat_map(|w| w.to_le_bytes()).map(|b| format!("{b:02x}")).collect()
}
