// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <tkey/assert.h>
#include <tkey/debug.h>
#include <tkey/io.h>
#include <tkey/led.h>
#include <tkey/proto.h>
#include <tkey/tk1_mem.h>
#include <tkey/touch.h>

#include "../../../research/upstream/tkey-fido2/crypto/micro-ecc/uECC.h"
#include "../../../research/upstream/tkey-libs/blake2s/blake2s.h"

#include "app_proto.h"
#include "platform.h"

static volatile uint32_t *cdi = (volatile uint32_t *)TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl = (volatile uint32_t *)TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *)TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last = (volatile uint32_t *)TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr = (volatile uint32_t *)TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size = (volatile uint32_t *)TK1_MMIO_TK1_APP_SIZE;
static volatile uint32_t *trng_status = (volatile uint32_t *)TK1_MMIO_TRNG_STATUS;
static volatile uint32_t *trng_entropy = (volatile uint32_t *)TK1_MMIO_TRNG_ENTROPY;

#define TOUCH_TIMEOUT 30

static const uint8_t app_name0[4] = "eth ";
static const uint8_t app_name1[4] = "sign";
static const uint32_t app_version = 0x00000001;

static const char derivation_domain[] = "tkey-eth-sign-v1";
static const uint8_t secp256k1_n[32] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
};

struct packet {
	struct frame_header hdr;
	uint8_t cmd[CMDLEN_MAXBYTES];
};

static uint32_t entropy_get(void)
{
	while ((*trng_status & (1 << TK1_MMIO_TRNG_STATUS_READY_BIT)) == 0) {
	}
	return *trng_entropy;
}

static int tkey_rng(uint8_t *dest, unsigned size)
{
	unsigned off = 0;

	while (off < size) {
		uint32_t word = entropy_get();
		for (unsigned i = 0; i < 4 && off < size; i++) {
			dest[off++] = (uint8_t)(word >> (8 * i));
		}
	}

	return 1;
}

static int scalar_is_valid(const uint8_t *scalar)
{
	for (size_t i = 0; i < 32; i++) {
		if (scalar[i] != 0) {
			return memcmp(scalar, secp256k1_n, 32) < 0;
		}
	}

	return 0;
}

static void derive_private_key(uint8_t privkey[32])
{
	uint8_t material[32 + sizeof(derivation_domain)];
	uint8_t digest[32];
	blake2s_ctx state;

	memcpy(material, (const uint8_t *)cdi, 32);
	memcpy(material + 32, derivation_domain, sizeof(derivation_domain));

	for (uint8_t counter = 0;; counter++) {
		blake2s_init(&state, sizeof(digest), NULL, 0);
		blake2s_update(&state, material, sizeof(material));
		blake2s_update(&state, &counter, 1);
		blake2s_final(&state, digest);

		if (scalar_is_valid(digest)) {
			memcpy(privkey, digest, 32);
			memset(digest, 0, sizeof(digest));
			return;
		}
	}
}

static int read_command(struct frame_header *hdr, uint8_t *cmd)
{
	memset(hdr, 0, sizeof(struct frame_header));
	memset(cmd, 0, CMDLEN_MAXBYTES);

	if (frame_read(cmd, CMDLEN_MAXBYTES, hdr) < 0) {
		return -1;
	}

	if (hdr->f_domain == DST_FW) {
		appreply_nok(*hdr);
		cmd[0] = CMD_FW_PROBE;
		return 0;
	}

	if (hdr->f_domain != DST_SW) {
		return -1;
	}

	return 0;
}

static void handle_get_nameversion(const struct packet *pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};

	memcpy(rsp, app_name0, sizeof(app_name0));
	memcpy(rsp + 4, app_name1, sizeof(app_name1));
	memcpy(rsp + 8, &app_version, sizeof(app_version));
	appreply(pkt->hdr, RSP_GET_NAMEVERSION, rsp);
}

static void handle_get_pubkey(const struct packet *pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	uint8_t privkey[32];
	uint8_t pubkey[64];
	uECC_Curve curve = uECC_secp256k1();

	derive_private_key(privkey);
	if (uECC_compute_public_key(privkey, pubkey, curve) != 1) {
		appreply_nok(pkt->hdr);
		memset(privkey, 0, sizeof(privkey));
		return;
	}

	memcpy(rsp, pubkey, sizeof(pubkey));
	appreply(pkt->hdr, RSP_GET_PUBKEY, rsp);

	memset(privkey, 0, sizeof(privkey));
	memset(pubkey, 0, sizeof(pubkey));
}

static void handle_get_app_digest(const struct packet *pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	uint8_t digest[32];

	if (blake2s(digest, sizeof(digest), NULL, 0, (const void *)*app_addr,
		    *app_size) != 0) {
		appreply_nok(pkt->hdr);
		return;
	}

	memcpy(rsp, digest, sizeof(digest));
	appreply(pkt->hdr, RSP_GET_APP_DIGEST, rsp);
	memset(digest, 0, sizeof(digest));
}

static void handle_sign_digest(const struct packet *pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	uint8_t privkey[32];
	uint8_t sig[64];
	uECC_Curve curve = uECC_secp256k1();
#ifdef TKEY_ETH_APP_TOUCH
	bool touched = false;
#endif

	if (pkt->hdr.len != 128) {
		appreply_nok(pkt->hdr);
		return;
	}

#ifdef TKEY_ETH_APP_TOUCH
	touched = touch_wait(LED_GREEN, TOUCH_TIMEOUT);
	if (!touched) {
		rsp[0] = 1;
		appreply(pkt->hdr, RSP_SIGN_DIGEST, rsp);
		return;
	}
#endif

	derive_private_key(privkey);
	if (uECC_sign(privkey, &pkt->cmd[1], 32, sig, curve) != 1) {
		rsp[0] = 1;
		appreply(pkt->hdr, RSP_SIGN_DIGEST, rsp);
		memset(privkey, 0, sizeof(privkey));
		return;
	}

	rsp[0] = 0;
	memcpy(rsp + 1, sig, sizeof(sig));
	appreply(pkt->hdr, RSP_SIGN_DIGEST, rsp);

	memset(privkey, 0, sizeof(privkey));
	memset(sig, 0, sizeof(sig));
}

int main(void)
{
	struct packet pkt = {0};

	*cpu_mon_first = *app_addr + *app_size;
	*cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
	*cpu_mon_ctrl = 1;

	led_set(LED_BLUE);
	uECC_set_rng(tkey_rng);

	for (;;) {
		if (read_command(&pkt.hdr, pkt.cmd) != 0) {
			continue;
		}

		switch (pkt.cmd[0]) {
		case CMD_FW_PROBE:
			break;
		case CMD_GET_NAMEVERSION:
			if (pkt.hdr.len == 1) {
				handle_get_nameversion(&pkt);
			} else {
				appreply_nok(pkt.hdr);
			}
			break;
		case CMD_GET_PUBKEY:
			if (pkt.hdr.len == 1) {
				handle_get_pubkey(&pkt);
			} else {
				appreply_nok(pkt.hdr);
			}
			break;
		case CMD_GET_APP_DIGEST:
			if (pkt.hdr.len == 1) {
				handle_get_app_digest(&pkt);
			} else {
				appreply_nok(pkt.hdr);
			}
			break;
		case CMD_SIGN_DIGEST:
			handle_sign_digest(&pkt);
			break;
		default:
			appreply_nok(pkt.hdr);
			break;
		}
	}

	assert(0);
	return 0;
}
