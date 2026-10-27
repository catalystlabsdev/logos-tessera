#!/usr/bin/env bash
# Builds and runs a standalone LEZ sequencer (no Bedrock: mocked, `--features standalone`) in
# RISC Zero dev mode, with a genesis that funds settle_rpc's funder account, then deploys the
# Tessera program through `program_loader` and prints the RPC URL.
#
#   scripts/sequencer.sh start [--fresh]   build, start, wait for health, deploy Tessera
#   scripts/sequencer.sh stop              stop the node started here
#   scripts/sequencer.sh status            health + head block
#   scripts/sequencer.sh log               tail the node's log
#
# Environment:
#   LEZ_DIR            LEZ checkout at 7e3f7f76 (default /Users/xenowits/catalystlabs/src/logos-execution-zone)
#   SEQ_HOME           node home (default <repo>/.sequencer, gitignored); holds config, keys, rocksdb, sequencer.log
#   RPC_ADDR           bind address (default 127.0.0.1:3040)
#   CARGO_TARGET_DIR   where the Tessera host crate builds (default <repo>/program/target)
#
# Dev mode is mandatory here: the node runs with RISC0_DEV_MODE=1 so it accepts the fake
# receipts settle_rpc produces. Real proofs are a job for another machine.
set -euo pipefail

export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LEZ_DIR="${LEZ_DIR:-/Users/xenowits/catalystlabs/src/logos-execution-zone}"
LEZ_REV="7e3f7f76"
SEQ_HOME="${SEQ_HOME:-$REPO/.sequencer}"
RPC_ADDR="${RPC_ADDR:-127.0.0.1:3040}"
RPC_URL="http://$RPC_ADDR"
LOG="$SEQ_HOME/sequencer.log"
PIDFILE="$SEQ_HOME/sequencer.pid"
# Any valid ed25519 key: standalone mode mocks Bedrock, so nothing is ever paid from it.
# (The Justfile's `BEDROCK_FUNDING_PUBLIC_KEY`.)
BEDROCK_FUNDING_PUBLIC_KEY="2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26"
HOST_TARGET="${CARGO_TARGET_DIR:-$REPO/program/target}"
SETTLE_RPC="$HOST_TARGET/release/settle_rpc"

rpc() { # method [params-json]
    curl -sS -X POST "$RPC_URL" -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}"
}

build() {
    local have
    have="$(git -C "$LEZ_DIR" rev-parse --short=8 HEAD)"
    if [ "$have" != "$LEZ_REV" ]; then
        echo "warning: $LEZ_DIR is at $have, expected $LEZ_REV" >&2
    fi
    echo "== building sequencer_service (standalone) in $LEZ_DIR"
    (cd "$LEZ_DIR" && cargo build --release -q -p sequencer_service --features standalone)
    echo "== building settle_rpc in $REPO/program (target $HOST_TARGET)"
    (cd "$REPO/program" && CARGO_TARGET_DIR="$HOST_TARGET" cargo build --release -q -p tessera_host --bin settle_rpc)
}

write_config() { # funder-public-key-hex
    cat >"$SEQ_HOME.config.json" <<EOF
{
    "home": ".",
    "max_num_tx_in_block": 20,
    "mempool_max_size": 1000,
    "block_create_timeout": "2s",
    "retry_pending_blocks_timeout": "5s",
    "metrics_address": "127.0.0.1:9010",
    "bedrock_config": {
        "channel_id": "0101010101010101010101010101010101010101010101010101010101010101",
        "node_url": "http://localhost:18080"
    },
    "genesis": {
        "channel_params": {
            "minimum_sequencer_stake": 149,
            "posting_timeframe": 300,
            "posting_timeout": 25,
            "exit_delay": 100,
            "max_block_size": 1048576
        },
        "actions": [
            {
                "supply_account": {
                    "recipient": { "identified": { "key": "$1" } },
                    "balance": 10000000000000
                }
            }
        ]
    },
    "gossip": null
}
EOF
}

start() {
    local fresh=0
    [ "${1:-}" = "--fresh" ] && fresh=1
    build
    local funder
    funder="$("$SETTLE_RPC" --print-funder-key)"
    echo "== funder public key (PrivateKey [1; 32]): $funder"
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "== sequencer already running (pid $(cat "$PIDFILE"))"
    else
        if rpc checkHealth 2>/dev/null | grep -q '"result"'; then
            echo "something already answers on $RPC_URL and it is not ours (no $PIDFILE); stop it first" >&2
            exit 1
        fi
        if [ "$fresh" = 1 ]; then
            rm -rf "$SEQ_HOME"
        fi
        if [ ! -f "$SEQ_HOME/sequencer_config.json" ]; then
            write_config "$funder"
            echo "== setting up $SEQ_HOME (genesis funds $funder with 10000000000000)"
            (cd "$LEZ_DIR" && ./target/release/sequencer_service setup "$SEQ_HOME" \
                --config "$SEQ_HOME.config.json" \
                --funding-public-key "$BEDROCK_FUNDING_PUBLIC_KEY" --create-channel)
        fi
        echo "== starting sequencer (RISC0_DEV_MODE=1), log: $LOG"
        printf '\n=== %s  start ===\n' "$(date +%Y-%m-%dT%H:%M:%S%z)" >>"$LOG"
        # No `&&` before the `&`: an and-list is backgrounded as a subshell and $! would be the
        # subshell's pid, not the node's.
        (
            cd "$LEZ_DIR" || exit 1
            RISC0_DEV_MODE=1 RUST_LOG="${RUST_LOG:-info,kameo=warn}" \
                nohup ./target/release/sequencer_service start "$SEQ_HOME" --rpc-listen-address "$RPC_ADDR" \
                >>"$LOG" 2>&1 </dev/null &
            echo $! >"$PIDFILE"
        )
    fi
    echo "== waiting for checkHealth at $RPC_URL"
    for _ in $(seq 1 120); do
        if rpc checkHealth 2>/dev/null | grep -q '"result"'; then break; fi
        if ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "sequencer exited; last log lines:" >&2; tail -20 "$LOG" >&2; exit 1
        fi
        sleep 1
    done
    rpc checkHealth | grep -q '"result"' || { echo "sequencer not healthy; see $LOG" >&2; exit 1; }
    echo "== deploying Tessera through program_loader (idempotent)"
    RISC0_DEV_MODE=1 "$SETTLE_RPC" --rpc "$RPC_URL" --log "$LOG" --deploy-only
    echo
    echo "RPC_URL=$RPC_URL"
    echo "LOG=$LOG"
    echo "run:  RISC0_DEV_MODE=1 $SETTLE_RPC 5 --rpc $RPC_URL --log $LOG"
    echo "stop: $0 stop"
}

stop() {
    if [ ! -f "$PIDFILE" ]; then
        echo "not running"
        return
    fi
    local pid
    pid="$(cat "$PIDFILE")"
    kill "$pid" 2>/dev/null || true
    # Graceful shutdown closes the store; wait for it, then insist.
    for _ in $(seq 1 30); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "stopped"
}

case "${1:-start}" in
    start) start "${2:-}" ;;
    stop) stop ;;
    status) rpc checkHealth; echo; rpc getLastBlockId; echo ;;
    log) tail -n "${2:-50}" -f "$LOG" ;;
    write-config) write_config "${2:?funder public key hex}"; echo "$SEQ_HOME.config.json" ;;
    *) echo "usage: $0 {start [--fresh]|stop|status|log}" >&2; exit 2 ;;
esac
