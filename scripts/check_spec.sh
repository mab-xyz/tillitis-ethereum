#!/usr/bin/env bash
# Check the CLI against hw-wallet-cli-spec: flags in --help and the golden JSON of the Go tests.
# Silent and exit 0 when it conforms; prints the gaps and exits 1 otherwise.
# Needs hw-wallet-cli-check on PATH (https://github.com/mab-xyz/hw-wallet-cli-spec); run from the repo root.
set -eu
BIN=$(mktemp -d)/tkey-eth
trap 'rm -rf "$(dirname "$BIN")"' EXIT
go build -o "$BIN" ./cmd/tkey-eth/
go test -count=1 ./cmd/tkey-eth/ >/dev/null   # the golden files match what the code prints
hw-wallet-cli-check "$BIN" --golden cmd/tkey-eth/testdata/golden
