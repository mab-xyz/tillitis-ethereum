// SPDX-FileCopyrightText: 2026 Tillitis experiment
// SPDX-License-Identifier: BSD-2-Clause

#include <string.h>

#include "app_proto.h"

void appreply_nok(struct frame_header hdr)
{
	uint8_t buf[1] = {0};
	frame_write(FRAME_STATUS_NOK, hdr.id, hdr.f_domain, buf, sizeof(buf));
}

void appreply(struct frame_header hdr, enum appcmd rspcode, void *buf)
{
	size_t nbytes = 0;
	uint8_t frame[128] = {0};

	switch (rspcode) {
	case RSP_GET_PUBKEY:
	case RSP_SIGN_DIGEST:
	case RSP_GET_APP_DIGEST:
		nbytes = 128;
		break;
	case RSP_GET_NAMEVERSION:
		nbytes = 32;
		break;
	default:
		return;
	}

	frame[0] = rspcode;
	memcpy(&frame[1], buf, nbytes - 1);
	frame_write(FRAME_STATUS_OK, hdr.id, hdr.f_domain, frame, nbytes);
}
