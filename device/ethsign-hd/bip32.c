// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

#include <string.h>

#include "bip32.h"
#include "monocypher-ed25519.h"
#include "uECC.h"

static const uint8_t secp256k1_n[32] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

void bip32_wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;
	while (n--) {
		*v++ = 0;
	}
}

static int is_zero(const uint8_t a[32])
{
	uint8_t acc = 0;
	for (size_t i = 0; i < 32; i++) {
		acc |= a[i];
	}
	return acc == 0;
}

// a < n, as big-endian 256-bit integers
static int lt_n(const uint8_t a[32])
{
	return memcmp(a, secp256k1_n, 32) < 0;
}

// out = (a + b) mod n, for a, b < n. Constant-time conditional subtract.
static void add_mod_n(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
	uint8_t sum[32], diff[32];
	uint32_t carry = 0, borrow = 0;

	for (int i = 31; i >= 0; i--) {
		uint32_t s = (uint32_t)a[i] + b[i] + carry;
		sum[i] = (uint8_t)s;
		carry = s >> 8;
	}
	for (int i = 31; i >= 0; i--) {
		uint32_t d = (uint32_t)sum[i] - secp256k1_n[i] - borrow;
		diff[i] = (uint8_t)d;
		borrow = (d >> 8) & 1;
	}
	// sum >= n  <=>  carry out, or no borrow in sum - n
	uint8_t use_diff = (uint8_t)(0 - (carry | (borrow ^ 1)));
	for (int i = 0; i < 32; i++) {
		out[i] = (uint8_t)((diff[i] & use_diff) | (sum[i] & ~use_diff));
	}
	bip32_wipe(sum, sizeof(sum));
	bip32_wipe(diff, sizeof(diff));
}

int bip32_master(const uint8_t *seed, size_t seed_len, struct bip32_node *out)
{
	static const uint8_t key[] = "Bitcoin seed";
	uint8_t I[64];

	crypto_sha512_hmac(I, key, sizeof(key) - 1, seed, seed_len);
	if (is_zero(I) || !lt_n(I)) {
		bip32_wipe(I, sizeof(I));
		return -1;
	}
	memcpy(out->key, I, 32);
	memcpy(out->chaincode, I + 32, 32);
	bip32_wipe(I, sizeof(I));
	return 0;
}

int bip32_ckd_priv(const struct bip32_node *parent, uint32_t index, struct bip32_node *child)
{
	uint8_t data[37];
	uint8_t I[64];
	int rc = -1;

	if (index & BIP32_HARDENED) {
		data[0] = 0;
		memcpy(data + 1, parent->key, 32);
	} else {
		uint8_t pub[64];
		uECC_Curve curve = uECC_secp256k1();
		if (uECC_compute_public_key(parent->key, pub, curve) != 1) {
			return -1;
		}
		uECC_compress(pub, data, curve);
	}
	data[33] = (uint8_t)(index >> 24);
	data[34] = (uint8_t)(index >> 16);
	data[35] = (uint8_t)(index >> 8);
	data[36] = (uint8_t)index;

	crypto_sha512_hmac(I, parent->chaincode, 32, data, sizeof(data));
	if (lt_n(I)) {
		add_mod_n(child->key, I, parent->key);
		if (!is_zero(child->key)) {
			memcpy(child->chaincode, I + 32, 32);
			rc = 0;
		}
	}
	bip32_wipe(I, sizeof(I));
	bip32_wipe(data, sizeof(data));
	return rc;
}

int bip32_derive(const uint8_t *seed, size_t seed_len, const uint32_t *path, size_t depth,
		 struct bip32_node *out)
{
	struct bip32_node node, next;

	if (depth > BIP32_MAX_DEPTH || bip32_master(seed, seed_len, &node) != 0) {
		return -1;
	}
	for (size_t i = 0; i < depth; i++) {
		if (bip32_ckd_priv(&node, path[i], &next) != 0) {
			bip32_wipe(&node, sizeof(node));
			bip32_wipe(&next, sizeof(next));
			return -1;
		}
		node = next;
	}
	*out = node;
	bip32_wipe(&node, sizeof(node));
	bip32_wipe(&next, sizeof(next));
	return 0;
}
