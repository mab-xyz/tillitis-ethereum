"""Extract BIP-32 test vectors 1-4 from bip-0032.mediawiki into a flat text file.

Usage: python3 -I gen_vectors.py bip-0032.mediawiki > vectors.txt
Each line: <seed hex> <path> <chaincode hex> <private key hex>, decoded from the spec's xprv strings.
"""
from __future__ import annotations

import hashlib
import re
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes(82, "big")
    payload, check = raw[:-4], raw[-4:]
    assert hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == check
    return payload


def main() -> None:
    text = open(sys.argv[1]).read()
    seed = path = None
    for line in text.splitlines():
        if line.startswith("===Test vector 5"):
            break
        if m := re.match(r"Seed \(hex\): ([0-9a-f]+)", line):
            seed = m.group(1)
        elif m := re.match(r"\* Chain (\S+)", line):
            path = m.group(1).replace("<sub>H</sub>", "'")
        elif m := re.match(r"\*\* ext prv: (\w+)", line):
            p = b58check(m.group(1))
            assert p[45] == 0
            print(seed, path, p[13:45].hex(), p[46:78].hex())


main()
