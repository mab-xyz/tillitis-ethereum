// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

// One-entry cache of the last derived BIP-32 node and its public key. Repeated
// requests for the same path skip derivation (and the ~2.3 s per scalar mult on
// the TKey). No TKey dependency, so tests/bip32 tests it natively.

#ifndef KEYCACHE_H
#define KEYCACHE_H

#include <stddef.h>
#include <stdint.h>

#include "bip32.h"

// Writes the 32-byte seed. Called only on a cache miss.
typedef void (*keycache_seed_fn)(uint8_t seed[32]);

// Returns the node at path (and, when pub64 != NULL, its 64-byte X||Y public key),
// deriving only on a miss. The returned pointers stay valid until the next call.
// Returns 0, or -1 on an invalid path/child (the cache is then empty).
int keycache_get(keycache_seed_fn seed_fn, const uint32_t *path, size_t depth,
		 const struct bip32_node **node, const uint8_t **pub64);

void keycache_clear(void);

// Number of derivations / public-key computations performed (for tests).
extern unsigned keycache_derivations, keycache_pubkeys;

#endif
