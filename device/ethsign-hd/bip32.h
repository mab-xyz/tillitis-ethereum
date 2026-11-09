// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

// BIP-32 private derivation on secp256k1. No TKey dependency, so the same
// code is compiled natively by tests/bip32 against the official vectors.

#ifndef BIP32_H
#define BIP32_H

#include <stddef.h>
#include <stdint.h>

#define BIP32_HARDENED 0x80000000u
#define BIP32_MAX_DEPTH 10

struct bip32_node {
	uint8_t key[32];       // private key, big-endian
	uint8_t chaincode[32];
};

// Master node from seed (16..64 bytes). Returns 0, or -1 if the seed yields an invalid key.
int bip32_master(const uint8_t *seed, size_t seed_len, struct bip32_node *out);

// CKDpriv. Returns 0, or -1 if this index yields an invalid child (BIP-32: caller skips it).
int bip32_ckd_priv(const struct bip32_node *parent, uint32_t index, struct bip32_node *child);

// Master + CKDpriv along path[0..depth). depth <= BIP32_MAX_DEPTH. Returns 0 or -1.
int bip32_derive(const uint8_t *seed, size_t seed_len, const uint32_t *path, size_t depth,
		 struct bip32_node *out);

void bip32_wipe(void *p, size_t n);

#endif
