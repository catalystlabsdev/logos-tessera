//! Refusals the RFP names, driven through LEZ's state machine with the committed guest.
use anyhow::{Result, bail, ensure};
use lee_core::{account::Actor, native_token};
use tessera_api::Msg;
use tessera_host::{AMOUNT, VAULT_FUNDS, World, program};

fn expect_refused(name: &str, r: Result<impl Sized>) -> Result<()> {
    match r {
        Ok(_) => bail!("{name}: accepted, expected a refusal"),
        Err(e) => {
            let first = e.to_string().lines().next().unwrap_or_default().chars().take(140).collect::<String>();
            println!("ok  {name}: refused ({first})");
            Ok(())
        }
    }
}

fn main() -> Result<()> {
    let program = program()?;

    // 1. Below threshold: 5-of-7 with only 4 approvals.
    let mut w = World::new(&program, 7, 5)?;
    if let Msg::QueueAndExecute { proposal, signed_epoch, proposer, mut approvals, executor, env } =
        w.queue_and_execute_msg()
    {
        approvals.truncate(4);
        let msg = Msg::QueueAndExecute { proposal, signed_epoch, proposer, approvals, executor, env };
        let tx = w.tx(w.config_actor(), &msg)?;
        expect_refused("an_action_cannot_execute_below_threshold", w.submit(&tx))?;
    }
    ensure!(w.balance(w.vault)? == VAULT_FUNDS, "vault moved");

    // 2. The vault cannot be debited without Tessera attaching its seed.
    let mut w = World::new(&program, 7, 5)?;
    let steal = native_token::Message::Transfer { to: w.recipient, amount: AMOUNT };
    let tx = w.tx(Actor::native_balance(w.vault), &steal)?;
    expect_refused("vault_cannot_be_debited_directly", w.submit(&tx))?;
    ensure!(w.balance(w.vault)? == VAULT_FUNDS, "vault moved");

    // 3. An executed proposal cannot run twice.
    let mut w = World::new(&program, 7, 5)?;
    let tx = w.tx(w.config_actor(), &w.queue_and_execute_msg())?;
    w.submit(&tx)?;
    expect_refused("executed_proposal_cannot_replay", w.submit(&tx))?;
    ensure!(w.balance(w.recipient)? == AMOUNT, "paid twice");

    println!("all checks passed");
    Ok(())
}
