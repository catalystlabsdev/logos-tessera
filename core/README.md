# tessera_core

Runtime-agnostic authorisation rules for **Tessera**, an M-of-N multisig for the Logos
Execution Zone (LEZ). Pure Rust, `no_std` + `alloc`, no LEZ dependency: the same code runs
inside the RISC Zero guest (as the only authority on validity) and in clients (to predict
refusals before minutes of proving). Implements §3–§4 of the RFP-005 proposal.

What it decides, as pure functions over borsh-serialisable state:

| Function | Rule |
|---|---|
| `validate_config` | roster/threshold sanity (non-empty, ≤32 members, weights ≥1, distinct valid BIP-340 keys, role bits ⊆ PROPOSE\|APPROVE\|EXECUTE, 1 ≤ threshold ≤ total APPROVE weight, ≥1 proposer, ≥1 executor) |
| `activate` | threshold-weight `activate`-domain approvals over the activation digest; sets `initialised` |
| `queue` | activated; `signed_epoch == epoch`; window valid and closes before expiry; calls inside action set; no forbidden account; PROPOSE signer; distinct APPROVE signers reach threshold → `Queued` |
| `execute` | exact queued proposal (digest recomputed); not executed/cancelled; EXECUTE signer; time lock elapsed pessimistically; window closes before expiry; serialised config changes; **R.2: stored approvers re-counted against the current roster and threshold** → `Executed { queued, effect }` |
| `queue_and_execute` | both in one transaction (time lock 0, or a cancellation) |
| `apply_config_change` | full replacement of mutable fields, validated, `epoch += 1` |
| `apply_cancel` | applies an executed `Cancel { digest }` to its target |

The guest performs the returned `Effect` (emit chained calls with the vault seed, write the
new config, or mark a queued record cancelled) and persists the returned `Queued`/`Config`.

## Digests and signing

```
config_commitment = sha256(borsh(Config))

action_digest     = sha256("tessera/v1/action" ‖ network_id ‖ program_id ‖ multisig_id
                           ‖ epoch:u64le ‖ config_commitment ‖ proposal_id:u64le
                           ‖ expires_at_ms:u64le ‖ borsh(Action))

activation_digest = sha256("tessera/v1/activation" ‖ network_id ‖ program_id
                           ‖ config_commitment(initialised = false) ‖ epoch:u64le)

signed message    = sha256(purpose_tag ‖ digest)      (32 bytes, BIP-340 signed as-is)
purpose_tag       ∈ "tessera/v1/propose" | "tessera/v1/approve" | "tessera/v1/reject"
                  | "tessera/v1/activate" | "tessera/v1/execute"
```

Verification is `k256::schnorr::VerifyingKey::from_bytes(key)?.verify_raw(msg, sig)` (BIP-340
over the 32-byte message). `k256` is pinned to `=0.13.4` so the guest can patch in RISC
Zero's accelerated fork. A frozen known-answer digest is in `src/digest.rs` tests.

## Time

The guest has no clock; every transaction carries a sequencer-enforced window
`[start_ms, end_ms)` and lands at an unknown `t` in it. Checks are pessimistic:

- expiry: refused unless `window.end_ms < expires_at_ms` (Queue and Execute);
- time lock: `Execute.window.start_ms ≥ Queue.window.end_ms + timelock_snapshot`
  (skipped when the snapshot is 0, and for `Cancel`);
- `Queue` with a non-zero lock is refused early if `window.end_ms + timelock ≥ expiry`;
- windows must be non-empty and ≤ `MAX_WINDOW_MS` (24 h).

## Error codes (stable; append only)

| Code | Name | Operator action |
|---:|---|---|
| 1 | NotInitialised | collect threshold activation approvals and submit Activate |
| 2 | AlreadyInitialised | nothing to do |
| 3 | StaleEpoch | re-sign the proposal under the current epoch |
| 4 | NotProposer | have a member with propose sign the proposal |
| 5 | NotApprover | drop the approval from a key without approve |
| 6 | NotExecutor | submit with a member holding execute |
| 7 | DuplicateApprover | drop the duplicate approval |
| 8 | UnknownKey | drop the signature from a non-member key |
| 9 | BadSignature | re-collect the signature for this action and purpose |
| 10 | BelowThreshold | collect more approvals |
| 11 | QuorumNoLongerHeld | re-propose and re-approve |
| 12 | Expired | re-propose with a later expiry |
| 13 | TimelockActive | resubmit with a later window |
| 14 | WindowInvalid | rebuild with start before end |
| 15 | WindowTooWide | rebuild with a narrower window |
| 16 | NotQueued | queue the action first or check the digest |
| 17 | AlreadyExecuted | nothing to do |
| 18 | Cancelled | re-propose if still wanted |
| 19 | CallNotAllowed | change the action or the action set |
| 20 | ForbiddenAccount | remove Tessera / the config header / root-authorised accounts from the action |
| 21 | InvalidConfig(fault) | fix the configuration (sub-code from `ConfigFault::code`, 1–11) |
| 22 | DigestMismatch | submit the exact queued proposal |
| 23 | StaleConfigChange | re-propose this change under the current epoch |
| 24 | Encoding | report as a bug |

`Error::code()`, `Error::name()` and `Error::message()` expose these; `Error::ALL` lists them.

## Features

- `std` — std for dependencies (tests).
- `fixtures` — deterministic keys (`fixtures::signing_key(seed, i)`), `fixtures::sign`, and
  `fixtures::fixture(n, m, seed)` / `fixtures::multisig_fixture(n, m, seed)` returning a
  ready-made N-member, M-approval `Calls` action with one native-transfer-shaped call, for
  the guest benchmark. Test-only keys; never use in production.

## Running

```
cargo test --features std                                   # unit + integration tests
cargo build --no-default-features                           # no_std check
cargo build --no-default-features --target wasm32v1-none    # no_std on a bare target
cargo clippy --all-targets --features std -- -D warnings
cargo run --example fixture --features fixtures,std
```

Tests include the BIP-340 official vectors (32-byte-message rows 0–14) and an exhaustive
check over all 128 subsets of a 7-member roster (unit weights, threshold 5, and a weighted
variant).

Licence: MIT OR Apache-2.0.
