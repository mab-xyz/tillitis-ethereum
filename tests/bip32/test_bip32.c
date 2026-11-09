// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

// Native test of device/ethsign-hd/bip32.c against the BIP-32 spec vectors
// (vectors.txt, extracted by gen_vectors.py from bip-0032.mediawiki).
// Silent and exit 0 on success; prints each failure and exits 1 otherwise.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../device/ethsign-hd/bip32.c"

static int failures;

static size_t unhex(const char *s, uint8_t *out, size_t max)
{
	size_t n = strlen(s) / 2;
	if (n > max) {
		abort();
	}
	for (size_t i = 0; i < n; i++) {
		sscanf(s + 2 * i, "%2hhx", &out[i]);
	}
	return n;
}

static size_t parse_path(const char *s, uint32_t *path)
{
	size_t depth = 0;
	if (*s++ != 'm') {
		abort();
	}
	while (*s == '/') {
		char *end;
		path[depth] = (uint32_t)strtoul(s + 1, &end, 10);
		if (*end == '\'') {
			path[depth] |= BIP32_HARDENED;
			end++;
		}
		depth++;
		s = end;
	}
	return depth;
}

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("FAIL %s\n", what);
		failures++;
	}
}

static void test_add_mod_n_boundaries(void)
{
	uint8_t a[32], b[32], out[32], expect[32];

	// (n-1) + 1 = 0 mod n
	memcpy(a, secp256k1_n, 32);
	a[31] -= 1;
	memset(b, 0, 32);
	b[31] = 1;
	add_mod_n(out, a, b);
	check(is_zero(out), "add_mod_n (n-1)+1 == 0");

	// (n-1) + (n-1) = n-2 (exercises carry out of 256 bits)
	add_mod_n(out, a, a);
	memcpy(expect, secp256k1_n, 32);
	expect[31] -= 2;
	check(memcmp(out, expect, 32) == 0, "add_mod_n (n-1)+(n-1) == n-2");

	// 2 + 3 = 5 (no reduction)
	memset(a, 0, 32);
	a[31] = 2;
	b[31] = 3;
	add_mod_n(out, a, b);
	memset(expect, 0, 32);
	expect[31] = 5;
	check(memcmp(out, expect, 32) == 0, "add_mod_n 2+3 == 5");
}

int main(int argc, char **argv)
{
	char seed_hex[160], path_s[128], cc_hex[80], key_hex[80];
	int n = 0;
	FILE *f = fopen(argc > 1 ? argv[1] : "vectors.txt", "r");

	if (!f) {
		perror("vectors");
		return 2;
	}
	while (fscanf(f, "%159s %127s %79s %79s", seed_hex, path_s, cc_hex, key_hex) == 4) {
		uint8_t seed[64], cc[32], key[32];
		uint32_t path[BIP32_MAX_DEPTH];
		struct bip32_node node;
		size_t seed_len = unhex(seed_hex, seed, sizeof(seed));
		size_t depth = parse_path(path_s, path);
		char what[256];

		unhex(cc_hex, cc, 32);
		unhex(key_hex, key, 32);
		snprintf(what, sizeof(what), "seed=%.8s… %s", seed_hex, path_s);
		int rc = bip32_derive(seed, seed_len, path, depth, &node);
		check(rc == 0 && memcmp(node.key, key, 32) == 0 && memcmp(node.chaincode, cc, 32) == 0,
		      what);

		// known-negative: a one-bit change in the expected key must be detected
		key[31] ^= 1;
		check(memcmp(node.key, key, 32) != 0, "comparator detects mismatch");
		n++;
	}
	fclose(f);
	check(n == 17, "17 vectors read");
	test_add_mod_n_boundaries();
	return failures ? 1 : 0;
}
