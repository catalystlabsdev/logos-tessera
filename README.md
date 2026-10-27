# Tessera

[![ci](https://github.com/catalystlabsdev/logos-tessera/actions/workflows/ci.yml/badge.svg)](https://github.com/catalystlabsdev/logos-tessera/actions/workflows/ci.yml)

A private-by-default M-of-N multisig for the Logos Execution Zone (LEZ), built for
[Logos RFP-005](https://github.com/logos-co/rfp/blob/master/RFPs/RFP-005-multisig-and-coordination.md)
by Catalyst Labs. This repository is the prototype that accompanies our proposal: the
authorisation rules, a guest program on LEZ 0.4's actor model, and a harness that drives the
committed guest through LEZ's own state machine.

Status: prototype, 25 October 2026 (public and private posture measured). Not audited. Do not hold real funds with it.

## What runs today

| Piece | Where | State |
|---|---|---|
| Authorisation rules (digests, BIP-340 approvals, roles, weights, epochs, time lock, cancel, R.2 re-check at execution) | [`core/`](core/) | 33 tests, `no_std` |
| LEZ program on the actor model (`actor_entrypoint!`), paying from a program-derived vault | [`program/methods/guest/`](program/methods/guest/src/bin/tessera.rs) | builds against LEZ `7e3f7f76` |
| Messages and stored state | [`program/api/`](program/api/src/lib.rs) | |
| Gas measurement and on-chain refusal checks through `lee::V03State` | [`program/host/`](program/host/src/) | |

## Measured: a whole execute on LEZ 0.4, under the 10M cap

One zero-time-lock `QueueAndExecute` transaction: the program verifies the proposer, M approvals
and the executor (M + 2 BIP-340 signatures, RISC Zero's accelerated `k256`), writes the executed
record, and pays out of the vault through LEZ's native token. The harness checks the recipient
was paid and the vault debited. Gas is the cycle count LEZ's state machine bills
(`ValidatedStateDiff::from_public_transaction_with_cycle_budget`, budget `MAX_GAS_EXEC` = 10M).

| M | N | signatures checked | billed gas | share of 10M cap | tx bytes |
|---:|---:|---:|---:|---:|---:|
| 1 | 7 | 3 | 866,298 | 8.7% | 816 |
| 3 | 7 | 5 | 1,408,144 | 14.1% | 1,008 |
| 5 | 7 | 7 | 1,964,547 | 19.6% | 1,200 |
| 7 | 7 | 9 | 2,512,233 | 25.1% | 1,392 |
| 10 | 10 | 12 | 3,338,461 | 33.4% | 1,680 |
| 16 | 16 | 18 | 4,992,249 | 49.9% | 2,256 |
| 32 | 32 | 34 | 9,426,581 | 94.3% | 3,792 |

About 280k gas per signature, linear. M = 5 uses a fifth of one transaction's budget; M = 32
still fits in one transaction, and `tessera_core` caps a configuration at 32 members
(`MAX_MEMBERS`) so no quorum can be formed that one transaction cannot verify.

## Measured: the private lifecycle, proved and settled

`settle` runs Tessera's whole private lifecycle as privacy-preserving transactions and settles
each one, in process, through LEZ's own state machine (`lee::V03State` at `dev` commit
`7e3f7f76`, v0.3.0+135, the actor-model branch pending the testnet 0.4 tag). LEZ verifies each
RISC Zero receipt against the privacy circuit's image ID and the settled message before it
applies any diff; the steps:

1. `Create`: the configuration is committed as a **private PDA of Tessera** bound to the
   group's keys (`WitnessKind::Pda`).
2. `Activate`: the active configuration replaces it (nullifier spent, new commitment).
3. fund: a public account shields 1,000,000 units into the private vault PDA.
4. custody (not a proved step): a holder of the group's keys tries to debit the live vault
   directly, without Tessera's seed grant; LEZ's native token refuses at execution, so no
   proof can exist for that transaction.
5. `QueueAndExecute`, chained: M approvals verified in the guest, vault debited, an existing
   public recipient credited; repeated from the new state.

For every execute the harness also shows: refused outside its validity window
(`OutOfValidityWindow`, a check LEZ makes before it verifies the receipt); settled inside it with the exact post-state commitments recorded and
the pre-states' nullifiers marked spent; an unchanged resubmission refused (LEZ's commitment
freshness check); and, with `--double-spend`, a different payout proved against the already
spent pre-state, carrying its own verified receipt, refused with `Nullifier already seen`. Each
step prints the receipt kind decoded
from the proof bytes in the transaction (`succinct` STARK, or `fake` for a dev-mode stub), so a
log cannot pass a dev-mode step off as a proved one.

Real proving (`RISC0_DEV_MODE=0`, every proved step real), GCP `g2-standard-16` with one
NVIDIA L4 (driver 580), RISC Zero 3.0.5 CUDA prover, 27 October 2026, harness commit `5491369`,
guest image ID `ea578ba9b8d70127f0acfb45a0a1d3edf67b53c4379789740262660fa6de5e64`:

| run | M | N | padded | steps proved | execute proof (wall) | proof size | lifecycle proving | peak GPU memory |
|---|---:|---:|:-:|---:|---:|---:|---:|---:|
| chain 2 + double-spend | 5 | 7 | yes | 8 | 19.7 s, 19.8 s | 235,740 B | 109.8 s | 11.4 GB |
| double-spend | 5 | 7 | no | 6 | 19.2 s | 226,845 B | 68.5 s | 11.2 GB |
| single execute | 1 | 7 | yes | 5 | 14.6 s | 235,612 B | 41.5 s | 11.3 GB |
| single execute | 10 | 10 | yes | 5 | 25.6 s | 236,011 B | 62.8 s | 11.3 GB |
| single execute | 32 | 32 | yes | 5 | 52.9 s | 237,529 B | 121.3 s | 11.4 GB |

"Padded" is the wallet's padding: 7 private actions per transaction and 512-byte notes, with
the dummy inputs anchored at the live commitment root like a wallet would; on the L4 it costs
about 3% more proving time (22% on the laptop's CPU). About 1.2 s of GPU proving per extra
signature up to the 32-member cap; settlement of a proved transaction, receipt verification
included, takes about 25 ms. Every run ends in `all settlement checks passed`; the logs, the per-run GPU
samples and the queue log are in [`results/gpu-l4-settled/`](results/gpu-l4-settled/).

The same execute on a **16-thread CPU, no GPU** (GCP `c3d-standard-16`, AMD EPYC 9B14, Zen 4,
16 threads, 62 GB; RISC Zero CPU prover), settled the same way; steps 1 to 4 used dev-mode
stubs so the machine pays only for the execute (`--real-from 5`, `dev_steps=4` in the log):

| M | N | padded | execute proof (wall) | peak RSS | proof size | settle |
|---:|---:|:-:|---:|---:|---:|---:|
| 5 | 7 | no | 626.5 s | 9.6 GB | 226,845 B | 17 ms |
| 5 | 7 | yes | 654.7 s | 9.6 GB | 235,740 B | 17 ms |

The 32× gap between the two machines is the GPU, not the circuit (identical proof bytes).
Logs: [`results/cpu16-zen4-settled/`](results/cpu16-zen4-settled/).

The proof-only numbers from 25 October (same circuit, placeholder membership proofs, not
settled) are kept in [`results/gpu-l4/`](results/gpu-l4/) and
[`results/laptop-m4/`](results/laptop-m4/): on an Apple M4 laptop, CPU only, the M = 5
execute proof took 720.6 s unpadded and 881.1 s padded.

Caveats, stated plainly:

- The state machine is in process (`lee::V03State`), not the public testnet; the same
  lifecycle on a running sequencer is below, in dev mode. Privacy-preserving transactions are
  fee-exempt in this LEZ commit, so no fee path is exercised for them.
- The guest image ID differs between build hosts (macOS vs Linux) because it is not yet built in
  RISC Zero's reproducible Docker image.
- Keys are synthetic fixtures; the recipient is an existing public account.

## Settled on a running LEZ sequencer (dev mode)

`settle_rpc` runs the same lifecycle against a **running standalone LEZ sequencer** (commit
`7e3f7f76`, Bedrock mocked, started by `scripts/sequencer.sh`) over its JSON-RPC, with nothing
applied in process: Tessera's guest ELF is deployed on chain through `program_loader` (four
`WriteSegment` transactions and a `CreateHeader`; the node recomputes the image ID), every
step is proved locally and submitted with `sendTransaction`, and inclusion, balances and the
membership proofs for the next step's witnesses are read back from the node (`getTransaction`,
`getAccountBalance`, `getProofsAndRoot`). An execute submitted with a validity window in the
past and a byte-identical resubmission of a settled execute are both accepted into the mempool,
dropped by the block builder (`Execution outside of the validity window`, `Commitment already
seen`) and never appear in a block.

```text
ok  step 5 (execute 1): settled on the node inside the window; recipient holds 1000 (getAccountBalance)
ok  step 5 (execute replay): accepted into the mempool as 2a5b0adc…, then dropped by the block builder
      node: ERROR sequencer_core] Transaction with hash 2a5b0adc… failed settlement: ... Commitment already seen
RESULT settled private execute k=2 M=5 padded=false prove_wall_s=0.2 inclusion_ms=1793 tx_bytes=8107 private_actions=2 block=20
```

This run is **dev mode only**: the node runs with `RISC0_DEV_MODE=1` and accepts fake receipts,
so it verified no STARK; keys are synthetic; it is one local node, not the public testnet.
What it adds to the in-process evidence is the sequencer's own admission, block building,
fee handling for the public deploy, and wall-clock validity windows. Commands, RPC findings
and the full transcript: [`docs/SEQUENCER.md`](docs/SEQUENCER.md).

## Refusals, checked through the state machine

```text
ok  an_action_cannot_execute_below_threshold: refused (tessera error 10: approval weight below threshold)
ok  vault_cannot_be_debited_directly: refused (NativeTransferFailed(UnauthorizedSender))
ok  executed_proposal_cannot_replay: refused (tessera: already executed)
```

The second check is the custody boundary: a transaction that tries to move the vault's balance
without Tessera attaching the vault's seed is refused by LEZ's native token, not by Tessera.

## Run it

CI runs the core tests, the `no_std` build, rustfmt and clippy, the guest build, the refusal
checks, the dev-mode settled lifecycle and the gas table on every push (`.github/workflows/ci.yml`); the gas table is attached to each run.

```bash
curl -L https://risczero.com/install | bash && rzup install cargo-risczero 3.0.5 && rzup install r0vm 3.0.5 && rzup install rust
(cd core && cargo test --features std)
cd program && cargo build --release -p tessera_host
RISC0_DEV_MODE=0 ./target/release/measure
RISC0_DEV_MODE=0 ./target/release/checks
RISC0_DEV_MODE=1 ./target/release/settle 5 --padded --chain 2 --double-spend   # lifecycle, dev-mode receipts (fast)
# real private proving and settlement: on an NVIDIA machine
cargo build --release -p tessera_host --features cuda
RISC0_DEV_MODE=0 ./target/release/settle 5 --padded --chain 2 --double-spend
# CPU only (slow): prove just the execute, dev-mode stubs for the steps before it
cargo build --release -p tessera_host --features prove
RISC0_DEV_MODE=0 ./target/release/settle 5 --real-from 5
```

LEZ is pulled by git at commit `7e3f7f76` (the actor-model `dev` branch, pending the testnet 0.4
tag). The toolchain is pinned in `program/rust-toolchain.toml`.

## Not yet done

- Private queued records (today a queued proposal is executed in the same transaction by
  `QueueAndExecute`).
- The coordination room on the Logos chat module, the registry, the module, CLI and mini-app.
- Public transactions here carry no fee payer; the sequencer's fee path is not exercised.
- The program does not yet check a target's image ID against the signed call.

Related: the in-guest BIP-340 cost benchmark,
[catalystlabsdev/bip340-risc0-bench](https://github.com/catalystlabsdev/bip340-risc0-bench).

## Licence

MIT OR Apache-2.0, at your option.
