#!/usr/bin/env python3

import argparse
import os
import shlex
import subprocess
import sys
from typing import Iterable


DEFAULT_BIN = os.path.join(".bin", "tkey-eth")
DEFAULT_BUNDLE = os.path.join("artifacts", "two-key-bind.json")
DEFAULT_APP = os.path.join("device", "ethsign", "app.bin")


class CeremonyError(RuntimeError):
    pass


def shell_join(parts: Iterable[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def prompt(message: str, dry_run: bool) -> None:
    if dry_run:
        print(f"\n{message}")
        return
    try:
        input(f"\n{message}\nPress Enter to continue...")
    except EOFError as exc:
        raise CeremonyError("stdin closed while waiting for operator confirmation") from exc


def run_step(name: str, cmd: list[str], dry_run: bool) -> None:
    print(f"\n== {name} ==")
    print(shell_join(cmd))
    if dry_run:
        return
    completed = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0:
        raise CeremonyError(f"{name} failed with exit code {completed.returncode}")


def run_retryable_step(
    name: str,
    cmd: list[str],
    retry_prompt: str,
    dry_run: bool,
    retry_on: tuple[str, ...] = (),
) -> None:
    print(f"\n== {name} ==")
    print(shell_join(cmd))
    if dry_run:
        return

    while True:
        completed = subprocess.run(cmd, check=False, text=True, capture_output=True)
        combined = f"{completed.stdout}{completed.stderr}"
        if completed.stdout:
            print(completed.stdout, end="")
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        if completed.returncode == 0:
            return
        if retry_on and not any(marker in combined for marker in retry_on):
            raise CeremonyError(f"{name} failed with exit code {completed.returncode}")
        prompt(retry_prompt, dry_run=False)


def wait_for_device(port: str, dry_run: bool) -> None:
    message = (
        f"Waiting for TKey serial device at {port}. "
        "Plug in or replug the TKey, then press Enter once it is connected."
    )
    if dry_run:
        print(f"\n{message}")
        return

    while not os.path.exists(port):
        try:
            input(f"\n{message}\n")
        except EOFError as exc:
            raise CeremonyError("stdin closed while waiting for TKey to appear") from exc
        if not os.path.exists(port):
            print(f"{port} is still not present.")

    print(f"\nFound TKey device at {port}.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Guide and execute the Tillitis two-key binding ceremony."
    )
    parser.add_argument("--bin", default=DEFAULT_BIN, help="Path to tkey-eth binary")
    parser.add_argument("--device", default="/dev/ttyACM0", help="Serial device path")
    parser.add_argument("--bundle", default=DEFAULT_BUNDLE, help="Output bundle JSON")
    parser.add_argument("--app", default=DEFAULT_APP, help="Wallet app binary")
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Do not run the final offline verify-two-key step",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands and prompts without executing them",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    print("Tillitis two-key ceremony")
    print(f"Binary: {args.bin}")
    print(f"Port:   {args.device}")
    print(f"Wallet: {args.app}")
    print(f"Bundle: {args.bundle}")

    wait_for_device(args.device, args.dry_run)
    prompt(
        "Start with the TKey freshly replugged in firmware mode. "
        "Do not load the Ethereum wallet app yet.",
        args.dry_run,
    )
    run_step(
        "Phase 1: capture Tillitis identity state",
        [
            args.bin,
            "bind-two-key-init",
            "--device",
            args.device,
            "--out",
            args.bundle,
        ],
        args.dry_run,
    )

    prompt(
        "Replug the TKey so it returns to firmware mode, then be ready for the wallet phase. "
        "The next command will load the Ethereum app and ask for touch when the app signs.",
        args.dry_run,
    )
    run_step(
        "Phase 2: capture wallet identity and Ethereum signature",
        [
            args.bin,
            "bind-two-key-wallet",
            "--device",
            args.device,
            "--app",
            args.app,
            "--bundle",
            args.bundle,
        ],
        args.dry_run,
    )

    prompt(
        "Replug the TKey again so it returns to firmware mode. "
        "The next command will reload the Tillitis signer and finalize the binding.",
        args.dry_run,
    )
    run_retryable_step(
        "Phase 3: finalize Tillitis-side signature",
        [
            args.bin,
            "bind-two-key-finalize",
            "--device",
            args.device,
            "--bundle",
            args.bundle,
        ],
        "Are you sure it replugged? Replug the TKey back into firmware mode, then continue.",
        args.dry_run,
        retry_on=("device not in firmware mode",),
    )

    if not args.skip_verify:
        run_step(
            "Phase 4: offline verification of completed bundle",
            [args.bin, "verify-two-key", "--bundle", args.bundle],
            args.dry_run,
        )

    print("\nCeremony complete.")
    print(f"Bundle: {args.bundle}")
    if args.skip_verify:
        print(f"Next: {shell_join([args.bin, 'verify-two-key', '--bundle', args.bundle])}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CeremonyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
