//! Builds the benchmark fixture and runs queue + execute once.
//! `cargo run --example fixture --features fixtures,std`
use tessera_core::{fixtures, queue_and_execute, TxEnv};

fn main() {
    let (ctx, config, proposal, proposer, approvals, window) =
        fixtures::multisig_fixture(7, 5, [7u8; 32]);
    let f = fixtures::fixture(7, 5, [7u8; 32]);
    let out = queue_and_execute(
        &ctx,
        &config,
        &proposal,
        config.epoch,
        &proposer,
        &approvals,
        &f.executor,
        &TxEnv::new(window),
    )
    .expect("fixture must execute");
    let encoded = borsh::to_vec(&(ctx, config, proposal, proposer, approvals, window)).unwrap();
    println!(
        "executed: {} ; digest {:02x?}",
        out.queued.executed,
        &out.queued.digest[..8]
    );
    println!("borsh-encoded fixture: {} bytes", encoded.len());
}
