// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

#include <string.h>

#include "keycache.h"
#include "uECC.h"

static struct {
	int valid;
	int pub_valid;
	size_t depth;
	uint32_t path[BIP32_MAX_DEPTH];
	struct bip32_node node;
	uint8_t pub[64];
} cache;

unsigned keycache_derivations, keycache_pubkeys;

void keycache_clear(void)
{
	bip32_wipe(&cache, sizeof(cache));
}

int keycache_get(keycache_seed_fn seed_fn, const uint32_t *path, size_t depth,
		 const struct bip32_node **node, const uint8_t **pub64)
{
	if (depth > BIP32_MAX_DEPTH) {
		return -1;
	}
	if (!cache.valid || cache.depth != depth ||
	    memcmp(cache.path, path, depth * sizeof(path[0])) != 0) {
		uint8_t seed[32];
		int rc;

		keycache_clear();
		seed_fn(seed);
		rc = bip32_derive(seed, sizeof(seed), path, depth, &cache.node);
		bip32_wipe(seed, sizeof(seed));
		keycache_derivations++;
		if (rc != 0) {
			keycache_clear();
			return -1;
		}
		memcpy(cache.path, path, depth * sizeof(path[0]));
		cache.depth = depth;
		cache.valid = 1;
	}
	if (pub64 != NULL) {
		if (!cache.pub_valid) {
			if (uECC_compute_public_key(cache.node.key, cache.pub, uECC_secp256k1()) != 1) {
				keycache_clear();
				return -1;
			}
			keycache_pubkeys++;
			cache.pub_valid = 1;
		}
		*pub64 = cache.pub;
	}
	*node = &cache.node;
	return 0;
}
