# Tessera

A private-by-default M-of-N multisig for the Logos Execution Zone (LEZ), built for
[Logos RFP-005](https://github.com/logos-co/rfp/blob/master/RFPs/RFP-005-multisig-and-coordination.md)
by Catalyst Labs. This repository is the prototype that accompanies our proposal: the
authorisation rules, a guest program on LEZ 0.4's actor model, and a harness that drives the
committed guest through LEZ's own state machine.

Status: prototype, 25 October 2026. Not audited. Do not hold real funds with it.

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
| 1 | 7 | 3 | 861,636 | 8.6% | 816 |
| 3 | 7 | 5 | 1,411,604 | 14.1% | 1,008 |
| 5 | 7 | 7 | 1,950,221 | 19.5% | 1,200 |
| 7 | 7 | 9 | 2,508,605 | 25.1% | 1,392 |
| 10 | 10 | 12 | 3,341,063 | 33.4% | 1,680 |
| 16 | 16 | 18 | 5,009,482 | 50.1% | 2,256 |
| 32 | 32 | 34 | 9,431,974 | 94.3% | 3,792 |

About 280k gas per signature, linear. M = 5 uses a fifth of one transaction's budget; M = 32
still fits in one transaction.

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
```

LEZ is pulled by git at commit `7e3f7f76` (the actor-model `dev` branch, pending the testnet 0.4
tag). The toolchain is pinned in `program/rust-toolchain.toml`.

## Not yet done

- Private posture: the same execute inside LEZ's privacy-preserving circuit, with real proving.
- The coordination room on the Logos chat module, the registry, the module, CLI and mini-app.
- Public transactions here carry no fee payer; the sequencer's fee path is not exercised.
- The program does not yet check a target's image ID against the signed call.

Related: the in-guest BIP-340 cost benchmark,
[catalystlabsdev/bip340-risc0-bench](https://github.com/catalystlabsdev/bip340-risc0-bench).

## Licence

MIT OR Apache-2.0, at your option.
