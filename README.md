# Tessera

A private-by-default M-of-N multisig for the Logos Execution Zone (LEZ), built for
[Logos RFP-005](https://github.com/logos-co/rfp/blob/master/RFPs/RFP-005-multisig-and-coordination.md)
by Catalyst Labs. This repository is the prototype that accompanies our proposal: the
authorisation rules, a guest program on LEZ 0.4's actor model, and a harness that drives the
committed guest through LEZ's own state machine.

Status: prototype, 25 October 2026 (public and private posture measured). Not audited. Do not hold real funds with it.

## What runs today

| Piece | Where | State |
|---|---|---|
| Authorisation rules (digests, BIP-340 approvals, roles, weights, epochs, time lock, cancel, R.2 re-check at execution) | [`core/`](core/) | 32 tests, `no_std` |
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
still fits in one transaction.

## Measured: the private posture, proved on a GPU

The same `QueueAndExecute`, proved inside LEZ's privacy-preserving circuit with
`execute_and_prove`. The configuration and the vault are **private PDAs of Tessera** bound to the
group's keys (`WitnessKind::Pda`); the payout goes to a public recipient. Real proving
(`RISC0_DEV_MODE=0`), GCP `g2-standard-16` with one NVIDIA L4 (driver 580), RISC Zero CUDA
prover, 25 October 2026:

| M | N | signatures checked | private proof (wall) | proof size | peak GPU memory |
|---:|---:|---:|---:|---:|---:|
| 1 | 7 | 3 | 14.5 s | 226,717 B | 11.3 GB |
| 5 | 7 | 7 | 19.8 s | 226,845 B | 8.1 GB |
| 10 | 10 | 12 | 25.8 s | 227,116 B | 11.1 GB |

About 1.3 s of GPU proving per extra signature; the proof grows by roughly 44 bytes per
signature. Logs: [`results/gpu-l4/`](results/gpu-l4/).

Custody, checked on the same proving path:

```text
ok  group_key_holder_cannot_debit_private_vault: refused (NativeTransferFailed(UnauthorizedSender))
```

A holder of the group's keys can spend the vault's note but cannot debit its balance without
Tessera's seed grant, which Tessera attaches only after verifying a quorum.

Caveats, stated plainly:

- Like LEZ's own circuit benchmark, the private accounts' membership proofs are placeholders,
  which proving does not check against a commitment tree; the proof is not settled on a chain.
  Proving time and proof size are representative; settlement is M0 work.
- No dummy inputs or ciphertext padding are added; a wallet pads to 7 private actions, which costs
  more proving time.
- The guest image ID differs between build hosts (macOS vs Linux) because it is not yet built in
  RISC Zero's reproducible Docker image.

## Refusals, checked through the state machine

```text
ok  an_action_cannot_execute_below_threshold: refused (tessera error 10: approval weight below threshold)
ok  vault_cannot_be_debited_directly: refused (NativeTransferFailed(UnauthorizedSender))
ok  executed_proposal_cannot_replay: refused (tessera: already executed)
```

The second check is the custody boundary: a transaction that tries to move the vault's balance
without Tessera attaching the vault's seed is refused by LEZ's native token, not by Tessera.

## Run it

```bash
curl -L https://risczero.com/install | bash && rzup install cargo-risczero 3.0.5 && rzup install r0vm 3.0.5 && rzup install rust
(cd core && cargo test --features std)
cd program && cargo build --release -p tessera_host
RISC0_DEV_MODE=0 ./target/release/measure
RISC0_DEV_MODE=0 ./target/release/checks
RISC0_DEV_MODE=1 ./target/release/private 5 --steal     # private custody check (fast)
# real private proving: on an NVIDIA machine
cargo build --release -p tessera_host --features cuda
RISC0_DEV_MODE=0 ./target/release/private 5
```

LEZ is pulled by git at commit `7e3f7f76` (the actor-model `dev` branch, pending the testnet 0.4
tag). The toolchain is pinned in `program/rust-toolchain.toml`.

## Not yet done

- Private posture beyond the execute: private queued records, settlement of the private
  transaction on a sequencer, wallet padding.
- The coordination room on the Logos chat module, the registry, the module, CLI and mini-app.
- Public transactions here carry no fee payer; the sequencer's fee path is not exercised.
- The program does not yet check a target's image ID against the signed call.

Related: the in-guest BIP-340 cost benchmark,
[catalystlabsdev/bip340-risc0-bench](https://github.com/catalystlabsdev/bip340-risc0-bench).

## Licence

MIT OR Apache-2.0, at your option.
