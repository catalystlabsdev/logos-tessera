# Tessera's private lifecycle on a running LEZ sequencer

`settle.rs` settles the private lifecycle against an in-process `lee::V03State`. This note is the
same lifecycle against a **running standalone LEZ sequencer** (commit `7e3f7f76`, the actor-model
`dev` branch) over its JSON-RPC, in RISC Zero dev mode on a laptop.

Pieces:

- `scripts/sequencer.sh` — builds the node (`sequencer_service --features standalone`, Bedrock
  mocked), writes a genesis that funds the harness's funder account, starts it with
  `RISC0_DEV_MODE=1`, waits for `checkHealth`, deploys Tessera through `program_loader`, prints
  the RPC URL. Node home and log: `.sequencer/` (gitignored).
- `program/host/src/bin/settle_rpc.rs` — proves each step locally, submits it with
  `sendTransaction`, polls `getTransaction` until a block holds it, reads balances back with
  `getAccountBalance`, and takes every membership proof from the chain with `getProofsAndRoot`.
  Flags: `--rpc URL`, `--log PATH` (the node's log, to quote what it says about dropped
  transactions), `--chain N`, `--padded`, `--deploy-only`, `--print-funder-key`, positional `M`.

## Commands

```sh
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
# LEZ checkout at 7e3f7f76; default /Users/xenowits/catalystlabs/src/logos-execution-zone
export LEZ_DIR=/Users/xenowits/catalystlabs/src/logos-execution-zone

scripts/sequencer.sh start --fresh          # build node + settle_rpc, genesis, start, deploy Tessera
RISC0_DEV_MODE=1 program/target/release/settle_rpc 5 --rpc http://127.0.0.1:3040 --log .sequencer/sequencer.log
scripts/sequencer.sh stop
```

`CARGO_TARGET_DIR` is honoured for the Tessera host build (the run below reused the cache at
`../logos-tessera/program/target` to keep the laptop build incremental).

## What the node does with each transaction

RPC surface used (`lez/sequencer/service/rpc/src/lib.rs`): `checkHealth`, `getChannelId`,
`getLastBlockId`, `getAccountsNonces`, `getAccountBalance`, `getAccountView`,
`getProofsAndRoot`, `sendTransaction`, `getTransaction`.

Admission (`rpc_server` → `executor` actor): `sendTransaction` runs only the stateless check
(signature/nonce shape) and the fee screen, then pushes to the mempool and returns the hash.
State validation — validity window, nullifier freshness, proof verification, program image
claims — happens when the block builder settles the transaction on a scratch state
(`sequencer_core::apply_mempool_transaction`). A transaction that fails there is **dropped from
the mempool and logged** (`Transaction with hash … failed settlement: …, skipping it`); it never
appears in a block, and `getTransaction` keeps returning `null`. So "rejected by the sequencer"
for the out-of-window and replay cases means: accepted into the mempool, then dropped by the
block builder, which `settle_rpc` shows by (a) three new blocks without the hash, (b) the
recipient's balance unchanged, and (c) the node's own log line.

Fees: privacy-preserving transactions are fee-exempt under the interim policy
(`chain_state::classify`), so the private steps carry no fee. The `program_loader` deploy
transactions are public and charged: `settle_rpc` attaches the wallet's default
`FeeDeclaration` (gas 2,000,000, max_fee 134,400,000) paid by the funder, who co-signs.

## Genesis and program availability

- Genesis actions at this commit are `supply_account`, `supply_private_account`,
  `supply_bridge_lock_holding`, `stake_sequencer` (`sequencer_core::config::GenesisAction`).
  **There is no genesis program action.** The only programs in genesis are the protocol's own
  (`lez/programs`, via `testnet_initial_state`). The funder (`PrivateKey::try_new([1; 32])`,
  public key printed by `settle_rpc --print-funder-key`) is funded with 10^13 by
  `supply_account`.
- Tessera is therefore **deployed through `program_loader`** after start: the guest ELF built
  by `program/methods` (`tessera_methods::TESSERA_ELF`) is split into 96 KiB `WriteSegment`
  transactions written tail-to-head into deterministic key accounts (`[0x10 + i; 32]`), then a
  `CreateHeader { immutable: true }` at the header account of key `[2; 32]`. The node recomputes
  the image id from the chain and `settle_rpc` checks it equals `TESSERA_ELF`'s. The program's
  on-chain account is that header account, so `ctx.program_id` and both private PDAs derive from
  it (not from `AccountId::from_builtin_program` as in `settle.rs`). The step is idempotent.
- Alternative not taken: LEZ also supports *shadow programs* (`ProgramCatalog::with_shadow`,
  `AccountId::for_shadow_program`), which never touch public state; the deployed, disclosed
  program is the posture real users would audit, so that is what runs here.

## Differences from `settle.rs`

- Validity windows are wall-clock: the node stamps blocks with `Utc::now()` ms, so the fixture's
  `[1_000, 61_000)` window becomes `[now − 60 s, now + 10 min)` for the settled execute and
  `[now − 20 min, now − 10 min)` for the out-of-window copy (a window entirely in the past, so
  the mempool can never settle it later).
- The recipient is a key-derived account (`[7; 32]`) and the execute carries
  `PublicAccountEvidence::Key` for it, because a public account that does not exist yet must be
  proved public at settlement (`PublicBackend::admits`). `settle.rs` pre-created it in the state.
- The funder's balance is read from the node before the fund step (it is 10^13 minus deploy
  fees, not exactly `VAULT_FUNDS`), and the check is `before − VAULT_FUNDS == after`.
- Membership proofs: `getProofsAndRoot([commitment])` instead of `V03State::get_proof_for_commitment`.

## Caveats

- **Dev mode only.** The node runs with `RISC0_DEV_MODE=1` and accepts fake receipts; the
  harness refuses to run without it. Nothing here proves anything cryptographically; a real
  sequencer rejects these transactions. Real proving is to be run elsewhere.
- **Standalone mode.** Bedrock is a mock (`--features standalone`); the channel is created
  locally with the debug channel params, `block_create_timeout` 2 s, no gossip, metrics on
  `127.0.0.1:9010`. The Bedrock funding key passed to `setup` is the Justfile's placeholder.
- **Synthetic keys.** Funder `[1; 32]`, header `[2; 32]`, recipient `[7; 32]`, segments
  `[0x10 + i; 32]`, nullifier key `[11; 32]`, viewing key seeds `[12; 32]`/`[13; 32]` — the same
  deterministic material as `settle.rs`. The multisig members are `tessera_core::fixtures`.
- **No wallet.** The harness talks to the node with `sequencer_service_rpc`'s client (the type
  the wallet uses) but does not go through `WalletCore`; the private-account bookkeeping
  (expected post-state accounts, nonces) is recomputed locally the way `settle.rs` does.
- The sequencer is built from the LEZ checkout's own toolchain (`1.98.1`), release profile.
- Restarting the node keeps `.sequencer/` state (deploy is skipped as already present); the
  lifecycle itself is not re-runnable on the same chain without new fixture seeds, because the
  configuration PDA's Init commitment would collide. Use `start --fresh` between runs.

## Run output (2026-10-27, Apple M-series laptop, dev mode)

`scripts/sequencer.sh start --fresh` (both binaries already built; the node answered
`checkHealth` within a second of starting and makes a block every 2 s):

```text
== building sequencer_service (standalone) in /Users/xenowits/catalystlabs/src/logos-execution-zone
== building settle_rpc in /Users/xenowits/catalystlabs/logos-tessera-rpc/program (target /Users/xenowits/catalystlabs/logos-tessera/program/target)
== funder public key (PrivateKey [1; 32]): 1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f
== setting up /Users/xenowits/catalystlabs/logos-tessera-rpc/.sequencer (genesis funds 1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f with 10000000000000)
/Users/xenowits/catalystlabs/logos-tessera-rpc/.sequencer is set up
  channel signing public key  1d319158c34be4ec31f1b5365ed08809336909deedf6f850722a7c015ef2522f
`start` creates the channel if it does not exist yet.
Creating the channel stakes that key at genesis.
== starting sequencer (RISC0_DEV_MODE=1), log: /Users/xenowits/catalystlabs/logos-tessera-rpc/.sequencer/sequencer.log
== waiting for checkHealth at http://127.0.0.1:3040
== deploying Tessera through program_loader (idempotent)
sequencer http://127.0.0.1:3040: healthy, channel ChannelId([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), head block 1
funder B1UN3hPgxacgHKBRoThcAmsPajGcUf6YXUhgB36x4DAd holds 10000000000000; recipient 65fTAPEquXmXNvJieTPdsR5FEw4fo2wLZQdS3RCpyX9a holds 0
tessera image id: 125ac96f235f2d7f5f4e48a584600587f1e59de116258b7346c09646d2057577
    step 0 (deploy): 383696 bytes of user ELF in 4 segments, header 34Kqgek6R7N1zU5FSJz8ziXwSPEPCuWGcn1T7GCVrfib
    step 0 (deploy): segment 3 (88784 bytes) at 8Ao5LWQjuLiwpV2nYBf8SVL7CbrbPwyYWBc2e884ntpK included in block 2 as a851174d40958004ac452df6a433519b2cfafd7f973a35b2b15085c6721c44b0 (2019 ms)
    step 0 (deploy): segment 2 (98304 bytes) at 9dMuLgA2yPF5oTn4QphXQj2QFeCjfkSVNh4zEfxKt7BL included in block 3 as 06c7b6836f8ae8ea23a5ac53e74394ecdf7fde737642071f709c2aca551dea76 (1823 ms)
    step 0 (deploy): segment 1 (98304 bytes) at 78Skt7EQTvVwfWVYnA1XMjghv3aUR1V5wgQAfVLKJZG5 included in block 4 as 4dbfb470ecba07500c74d1801b3b104477fd675e9dee2797ea53f7202c6a06c1 (2015 ms)
    step 0 (deploy): segment 0 (98304 bytes) at 8GQd91bxT9vsEgCqAp2eWWaAJCUJzxCZ9MH6WZszEYcg included in block 5 as d30e989fe1154d8b1c91b9d2851d5160fbb1a730ecc7d36e98c0a4308ab07a82 (2019 ms)
ok  step 0 (deploy): header included in block 6 as a4af586cf9154792a7dddfa3830aa107d98d49dc66f7ef543f1dbfc8f759a84e (2017 ms); node holds image 125ac96f235f2d7f5f4e48a584600587f1e59de116258b7346c09646d2057577
tessera program account (loader header): 34Kqgek6R7N1zU5FSJz8ziXwSPEPCuWGcn1T7GCVrfib

RPC_URL=http://127.0.0.1:3040
LOG=/Users/xenowits/catalystlabs/logos-tessera-rpc/.sequencer/sequencer.log
run:  RISC0_DEV_MODE=1 /Users/xenowits/catalystlabs/logos-tessera/program/target/release/settle_rpc 5 --rpc http://127.0.0.1:3040 --log /Users/xenowits/catalystlabs/logos-tessera-rpc/.sequencer/sequencer.log
stop: scripts/sequencer.sh stop
```

`RISC0_DEV_MODE=1 settle_rpc 5 --chain 2 --rpc http://127.0.0.1:3040 --log .sequencer/sequencer.log`
(RISC Zero's "proving in dev mode" warnings elided):

```text
sequencer http://127.0.0.1:3040: healthy, channel ChannelId([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), head block 6
funder B1UN3hPgxacgHKBRoThcAmsPajGcUf6YXUhgB36x4DAd holds 9999996906240; recipient 65fTAPEquXmXNvJieTPdsR5FEw4fo2wLZQdS3RCpyX9a holds 0
tessera image id: 125ac96f235f2d7f5f4e48a584600587f1e59de116258b7346c09646d2057577
ok  step 0 (deploy): Tessera already deployed at 34Kqgek6R7N1zU5FSJz8ziXwSPEPCuWGcn1T7GCVrfib (image 125ac96f235f2d7f5f4e48a584600587f1e59de116258b7346c09646d2057577)
tessera program account (loader header): 34Kqgek6R7N1zU5FSJz8ziXwSPEPCuWGcn1T7GCVrfib
M = 5, N = 7, signatures per execute = 7, padded = false, chain = 2, proving: RISC0_DEV_MODE
private configuration PDA Y26i7WRadQRRJwwamD7R9NwrydA7EqaKzoVLzJVpb5c, private vault PDA dz94h2zzwrY4mRPpavJHBFu8YS7Zq7GJyxFdTh8WLbo
    step 1 (create): proved in 0.1 s, 1 private actions, dev_mode=true
    step 1 (create): d15b73cb8af4055c93f78416c9b9cd28bcb40c2c42b4d332ffba22d4253cd4ff included in block 7 after 1707 ms
ok  step 1 (create): settled on the node; inactive configuration commitment in the tree
    step 2 (activate): proved in 0.2 s, 1 private actions, dev_mode=true
    step 2 (activate): 664f2a317822e977b31a87ada651a6c921cc853565e312daa7785dd23018c26a included in block 8 after 2018 ms
ok  step 2 (activate): settled on the node; active configuration commitment in the tree
    step 3 (fund): proved in 0.1 s, 1 private actions, dev_mode=true
    step 3 (fund): 0ceaab0d28a27d1b28d113ba6b7f30dc21486ff3044ae3aeee7c01fed14b0210 included in block 9 after 1725 ms
ok  step 3 (fund): settled on the node; funder 9999996906240 -> 9999995906240 (getAccountBalance), private vault committed with 1000000
    step 4 (execute, window in the past): proved in 0.2 s, 2 private actions, dev_mode=true
ok  step 4 (execute outside the validity window): accepted into the mempool as 53ee2e8bfa152b7ac0dd72c4191da40adf7a2826d6798623686d5517d74b8a81, then dropped by the block builder (not in any new block after 3 blocks)
      node: [2026-10-27T05:17:48Z ERROR sequencer_core] Transaction with hash 53ee2e8bfa152b7ac0dd72c4191da40adf7a2826d6798623686d5517d74b8a81 failed settlement: State transition failed at transaction 0: Execution outside of the validity window, skipping it
    step 5 (execute): proved in 0.2 s, 2 private actions, dev_mode=true
    step 5 (execute): 2a5b0adcf977593a4d1d5b85948345f370cdf79ad5d9cfc2041116338d4046be included in block 13 after 1724 ms
ok  step 5 (execute 1): settled on the node inside the window; recipient holds 1000 (getAccountBalance)
ok  step 5 (execute 1): post-state commitments in the node's tree (vault now 999000)
ok  step 5 (execute replay): accepted into the mempool as 2a5b0adcf977593a4d1d5b85948345f370cdf79ad5d9cfc2041116338d4046be, then dropped by the block builder (not in any new block after 3 blocks)
      node: [2026-10-27T05:17:56Z ERROR sequencer_core] Transaction with hash 2a5b0adcf977593a4d1d5b85948345f370cdf79ad5d9cfc2041116338d4046be failed settlement: State transition failed at transaction 0: Invalid input: Commitment already seen, skipping it
RESULT settled private execute k=1 M=5 padded=false prove_wall_s=0.2 inclusion_ms=1724 tx_bytes=7583 private_actions=2 block=13
    step 6 (execute, window in the past): proved in 0.2 s, 2 private actions, dev_mode=true
ok  step 6 (execute outside the validity window): accepted into the mempool as 7bfd65c3e2854969dfe3984eda08942234998a4ba59191323bc49cef7c837c8f, then dropped by the block builder (not in any new block after 3 blocks)
      node: [2026-10-27T05:18:02Z ERROR sequencer_core] Transaction with hash 7bfd65c3e2854969dfe3984eda08942234998a4ba59191323bc49cef7c837c8f failed settlement: State transition failed at transaction 0: Execution outside of the validity window, skipping it
    step 7 (execute): proved in 0.2 s, 2 private actions, dev_mode=true
    step 7 (execute): 7305d91deec0a17ffd2675325fd69494814d1da89f17dc28a2651e4f38d16613 included in block 20 after 1793 ms
ok  step 7 (execute 2): settled on the node inside the window; recipient holds 2000 (getAccountBalance)
ok  step 7 (execute 2): post-state commitments in the node's tree (vault now 998000)
ok  step 7 (execute replay): accepted into the mempool as 7305d91deec0a17ffd2675325fd69494814d1da89f17dc28a2651e4f38d16613, then dropped by the block builder (not in any new block after 3 blocks)
      node: [2026-10-27T05:18:10Z ERROR sequencer_core] Transaction with hash 7305d91deec0a17ffd2675325fd69494814d1da89f17dc28a2651e4f38d16613 failed settlement: State transition failed at transaction 0: Invalid input: Commitment already seen, skipping it
RESULT settled private execute k=2 M=5 padded=false prove_wall_s=0.2 inclusion_ms=1793 tx_bytes=8107 private_actions=2 block=20
RESULT lifecycle M=5 padded=false steps=7 total_prove_s=0.8 rpc=http://127.0.0.1:3040
all settlement checks passed on the sequencer
```

What the node returned, step by step:

| step | RPC | node's answer |
|---|---|---|
| deploy, 4 × `WriteSegment` + `CreateHeader` (public, charged) | `sendTransaction` → `getTransaction` | each in the next block; header's loader actor state holds image `125ac96f…7577`, equal to `TESSERA_ELF`'s; 5 txs cost the funder 3,093,760 in fees |
| 1 `Create` (private, Init witness) | `sendTransaction` → `getTransaction` | block 7; `getProofsAndRoot` then returns a proof for the inactive configuration's commitment |
| 2 `Activate` (Update witness, proof from `getProofsAndRoot`) | same | block 8; active configuration committed |
| 3 fund (funder signs, vault PDA promoted private) | same, `getAccountBalance` | block 9; funder 9999996906240 → 9999995906240 |
| 4 execute, window `[now−20 min, now−10 min)` | `sendTransaction` accepted (hash returned) | never in a block; log: `failed settlement: … Execution outside of the validity window, skipping it`; recipient still 0 |
| 5 execute, window `[now−60 s, now+10 min)` | `sendTransaction` → `getTransaction`, `getAccountBalance` | block 13; recipient 1000; both post-state commitments present |
| 5 replay of the identical bytes | `sendTransaction` accepted again (same hash) | never in a new block; log: `failed settlement: … Commitment already seen, skipping it`; recipient still 1000 |
| 6/7 second execute | same pattern | dropped / block 20, recipient 2000 / dropped |

Notes on those answers:

- `sendTransaction` never refuses either bad transaction: at this commit the RPC door only
  runs the stateless check and the fee screen, so "rejected by the sequencer" is the block
  builder's drop (it pops the transaction from the mempool, logs `error!`, and moves on). A
  client can only observe it as absence plus the log; there is no RPC that reports a dropped
  transaction's reason.
- The replay is refused by commitment freshness (`check_commitments_are_new`, step 5 of
  `ValidatedStateDiff::from_privacy_preserving_transaction`), which runs before the nullifier
  check (step 6). `settle.rs` saw the same ordering; the message differs from the in-process
  one only in the sequencer's wrapping.
- Inclusion latency is the 2 s block cadence (`block_create_timeout`), not execution.
- Dev-mode proving is ~0.2 s per step; `tx_bytes` 7583/8107 for the two executes, unpadded.
