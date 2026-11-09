// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

// Native test of device/ethsign-hd/keycache.c: same results as direct
// bip32_derive, derivation and pubkey computed only on a miss.
// Silent and exit 0 on success.

#include <stdio.h>
#include <string.h>

#include "../../device/ethsign-hd/keycache.h"
#include "uECC.h"

static int failures;
static unsigned seed_calls;
static const uint8_t SEED[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

static void seed_fn(uint8_t seed[32])
{
	seed_calls++;
	memcpy(seed, SEED, 32);
}

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("FAIL %s\n", what);
		failures++;
	}
}

// Fetches path via the cache and compares node and pubkey with a direct derivation.
static void get_and_compare(const uint32_t *path, size_t depth, int want_pub, const char *what)
{
	const struct bip32_node *node;
	const uint8_t *pub = NULL;
	struct bip32_node direct;
	uint8_t direct_pub[64];

	check(keycache_get(seed_fn, path, depth, &node, want_pub ? &pub : NULL) == 0, what);
	check(bip32_derive(SEED, 32, path, depth, &direct) == 0, what);
	check(memcmp(node, &direct, sizeof(direct)) == 0, what);
	if (want_pub) {
		check(uECC_compute_public_key(direct.key, direct_pub, uECC_secp256k1()) == 1, what);
		check(memcmp(pub, direct_pub, 64) == 0, what);
	}
}

int main(void)
{
	const uint32_t std0[] = {44 | BIP32_HARDENED, 60 | BIP32_HARDENED, BIP32_HARDENED, 0, 0};
	const uint32_t std1[] = {44 | BIP32_HARDENED, 60 | BIP32_HARDENED, BIP32_HARDENED, 0, 1};
	const uint32_t too_deep[BIP32_MAX_DEPTH + 1] = {0};
	const struct bip32_node *node;

	get_and_compare(std0, 5, 0, "miss without pub");
	check(keycache_derivations == 1 && keycache_pubkeys == 0 && seed_calls == 1, "1 derivation, 0 pubkeys");

	get_and_compare(std0, 5, 1, "hit, pub computed lazily");
	check(keycache_derivations == 1 && keycache_pubkeys == 1, "still 1 derivation, now 1 pubkey");

	get_and_compare(std0, 5, 1, "hit with cached pub");
	check(keycache_derivations == 1 && keycache_pubkeys == 1 && seed_calls == 1, "no extra work on full hit");

	get_and_compare(std1, 5, 1, "different last index misses");
	check(keycache_derivations == 2 && keycache_pubkeys == 2, "path change derives again");

	get_and_compare(std1, 4, 1, "prefix of cached path misses");
	check(keycache_derivations == 3, "depth change derives again");

	get_and_compare(std0, 0, 1, "master node");
	check(keycache_derivations == 4, "depth 0 derives");

	check(keycache_get(seed_fn, too_deep, BIP32_MAX_DEPTH + 1, &node, NULL) == -1, "too deep rejected");
	get_and_compare(std0, 0, 1, "too-deep request did not poison the cache");

	keycache_clear();
	get_and_compare(std0, 0, 1, "after clear");
	check(keycache_derivations == 5, "clear forces derivation");

	return failures ? 1 : 0;
}
