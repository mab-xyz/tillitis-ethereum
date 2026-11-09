#!/usr/bin/env bash
# Hardware check of BIP-32 mode on a freshly plugged TKey (HD app not yet loaded or already loaded).
# Silent and exit 0 on success; prints the failing check and exits 1 otherwise.
# Usage: scripts/hw_check_hd.sh [PORT]   (run from the repo root, after `go build -o .bin/tkey-eth ./cmd/tkey-eth`)
set -u
PORT=${1:-/dev/ttyACM0}
BIN=.bin/tkey-eth
fail() { echo "FAIL: $*"; exit 1; }
addr() { "$BIN" address --port "$PORT" --path "$1" | sed -n 's/^address=//p'; }

out=$("$BIN" verify-hd --port "$PORT" --count 3 2>&1) || fail "verify-hd: $out"
[ -z "$out" ] || fail "verify-hd not silent: $out"

a0=$(addr "m/44'/60'/0'/0/0") || fail "address /0/0"
a1=$(addr "m/44'/60'/0'/0/1") || fail "address /0/1"
a0b=$(addr "m/44'/60'/0'/0/0") || fail "address /0/0 (again)"
[[ $a0 =~ ^0x[0-9a-fA-F]{40}$ ]] || fail "bad address: $a0"
[ "$a0" = "$a0b" ] || fail "/0/0 not stable: $a0 vs $a0b"
[ "$a0" != "$a1" ] || fail "/0/0 and /0/1 collide: $a0"

sig=$("$BIN" sign-personal --port "$PORT" --path "m/44'/60'/0'/0/1" --message "hw-check") || fail "sign-personal"
echo "$sig" | grep -q "\"address\": *\"$a1\"" || fail "sign-personal /0/1 signed as other address: $sig"
exit 0
