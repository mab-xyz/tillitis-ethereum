// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

#ifndef APP_PROTO_H
#define APP_PROTO_H

#include <tkey/io.h>
#include <tkey/lib.h>
#include <tkey/proto.h>

enum appcmd {
	CMD_GET_PUBKEY = 0x01,
	RSP_GET_PUBKEY = 0x02,
	CMD_SIGN_DIGEST = 0x03,
	RSP_SIGN_DIGEST = 0x04,
	CMD_GET_NAMEVERSION = 0x05,
	RSP_GET_NAMEVERSION = 0x06,
	CMD_GET_APP_DIGEST = 0x07,
	RSP_GET_APP_DIGEST = 0x08,

	CMD_FW_PROBE = 0xff,
};

void appreply_nok(struct frame_header hdr);
void appreply(struct frame_header hdr, enum appcmd rspcode, void *buf);

#endif
