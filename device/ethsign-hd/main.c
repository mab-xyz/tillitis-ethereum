// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

// TKey app: BIP-32 HD Ethereum signer. Seed = BLAKE2s(CDI || domain), so the
// key tree is bound to (device, this app binary, USS) and never leaves the TKey.
//
// Same command codes as device/ethsign, but GET_PUBKEY and SIGN_DIGEST take a
// path in a 128-byte frame: cmd[1] = depth (0..10), cmd[2..2+4*depth) = indices
// (u32 big-endian, bit 31 = hardened), then for SIGN_DIGEST the 32-byte digest.
// GET_PUBKEY replies pubkey (64, X||Y) || chaincode (32).
// The last derived node and its pubkey stay cached in RAM (keycache.c), so
// repeated requests for one path skip derivation.

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <tkey/led.h>
#include <tkey/proto.h>
#include <tkey/tk1_mem.h>
#include <tkey/touch.h>

#include "../../../research/upstream/tkey-fido2/crypto/micro-ecc/uECC.h"
#include "../../../research/upstream/tkey-libs/blake2s/blake2s.h"

#include "../ethsign/app_proto.h"
#include "bip32.h"
#include "keycache.h"

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
static const uint8_t app_name1[4] = "hd32";
static const uint32_t app_version = 0x00000001;

static const char seed_domain[] = "tkey-eth-bip32-v1";

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

static void cdi_seed(uint8_t seed[32])
{
	uint8_t material[32 + sizeof(seed_domain)];

	memcpy(material, (const uint8_t *)cdi, 32);
	memcpy(material + 32, seed_domain, sizeof(seed_domain));
	blake2s(seed, 32, NULL, 0, material, sizeof(material));
	bip32_wipe(material, sizeof(material));
}

// Parses the path at cmd[1..] and fetches its node (and pubkey if pub64 != NULL)
// from the cache. Returns the offset just after the path, or 0 on a malformed
// path or invalid child.
static size_t node_from_cmd(const uint8_t *cmd, const struct bip32_node **node,
			    const uint8_t **pub64)
{
	uint32_t path[BIP32_MAX_DEPTH];
	size_t depth = cmd[1];

	if (depth > BIP32_MAX_DEPTH) {
		return 0;
	}
	for (size_t i = 0; i < depth; i++) {
		const uint8_t *p = cmd + 2 + 4 * i;
		path[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
			  ((uint32_t)p[2] << 8) | p[3];
	}
	if (keycache_get(cdi_seed, path, depth, node, pub64) != 0) {
		return 0;
	}
	return 2 + 4 * depth;
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
	const struct bip32_node *node;
	const uint8_t *pub;

	if (pkt->hdr.len != 128 || node_from_cmd(pkt->cmd, &node, &pub) == 0) {
		appreply_nok(pkt->hdr);
		return;
	}
	memcpy(rsp, pub, 64);
	memcpy(rsp + 64, node->chaincode, 32);
	appreply(pkt->hdr, RSP_GET_PUBKEY, rsp);
}

static void handle_get_app_digest(const struct packet *pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};

	if (blake2s(rsp, 32, NULL, 0, (const void *)*app_addr, *app_size) != 0) {
		appreply_nok(pkt->hdr);
		return;
	}
	appreply(pkt->hdr, RSP_GET_APP_DIGEST, rsp);
}

static void handle_sign_digest(const struct packet *pkt)
{
	uint8_t rsp[CMDLEN_MAXBYTES] = {0};
	const struct bip32_node *node;
	size_t off;

	if (pkt->hdr.len != 128 || pkt->cmd[1] > BIP32_MAX_DEPTH) {
		appreply_nok(pkt->hdr);
		return;
	}

#ifdef TKEY_ETH_APP_TOUCH
	if (!touch_wait(LED_GREEN, TOUCH_TIMEOUT)) {
		rsp[0] = 1;
		appreply(pkt->hdr, RSP_SIGN_DIGEST, rsp);
		return;
	}
#endif

	off = node_from_cmd(pkt->cmd, &node, NULL);
	if (off == 0 || uECC_sign(node->key, pkt->cmd + off, 32, rsp + 1, uECC_secp256k1()) != 1) {
		rsp[0] = 1;
		memset(rsp + 1, 0, 64);
	}
	appreply(pkt->hdr, RSP_SIGN_DIGEST, rsp);
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
			handle_get_pubkey(&pkt);
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
}
