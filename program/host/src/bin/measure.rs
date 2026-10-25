//! Billed gas of a whole zero-time-lock `QueueAndExecute` (quorum verification, the executed
//! record and a real vault payout through LEZ's native token) under the 10M cap.
use anyhow::{Result, ensure};
use tessera_host::{AMOUNT, MAX_GAS_EXEC, VAULT_FUNDS, World, hex, program};

fn main() -> Result<()> {
    let program = program()?;
    println!("tessera image id: {}", hex(&program.id()));
    println!("| M | N | signatures checked | billed gas | share of 10M cap | tx bytes |");
    println!("|---:|---:|---:|---:|---:|---:|");
    let ms: Vec<usize> = std::env::args().skip(1).filter_map(|a| a.parse().ok()).collect();
    let ms = if ms.is_empty() { vec![1, 3, 5, 7, 10, 16, 32] } else { ms };
    for m in ms {
        let n = m.max(7);
        let mut w = World::new(&program, n, m)?;
        let tx = w.tx(w.config_actor(), &w.queue_and_execute_msg())?;
        let bytes = borsh::to_vec(&tx)?.len();
        let charge = w.submit(&tx)?;
        ensure!(w.balance(w.recipient)? == AMOUNT && w.balance(w.vault)? == VAULT_FUNDS - AMOUNT, "payout not applied");
        println!(
            "| {m} | {n} | {} | {} | {:.1}% | {bytes} |",
            m + 2,
            charge.cycles,
            charge.cycles as f64 / MAX_GAS_EXEC as f64 * 100.0
        );
    }
    Ok(())
}
