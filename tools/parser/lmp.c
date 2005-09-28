/*
 *
 *  Bluetooth packet analyzer - LMP parser
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  $Id$
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "parser.h"

#define LMP_U8(frm)  (get_u8(frm))
#define LMP_U16(frm) (btohs(htons(get_u16(frm))))
#define LMP_U32(frm) (btohl(htonl(get_u32(frm))))

static enum {
	IN_RAND,
	COMB_KEY_M,
	COMB_KEY_S,
	AU_RAND_M,
	AU_RAND_S,
	SRES_M,
	SRES_S,
} pairing_state = IN_RAND;

static struct {
	uint8_t in_rand[16];
	uint8_t comb_key_m[16];
	uint8_t comb_key_s[16];
	uint8_t au_rand_m[16];
	uint8_t au_rand_s[16];
	uint8_t sres_m[4];
	uint8_t sres_s[4];
} pairing_data;

static inline void pairing_data_dump(void)
{
	int i;

	p_indent(6, NULL);
	printf("IN_RAND  ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", pairing_data.in_rand[i]);
	printf("\n");

	p_indent(6, NULL);
	printf("COMB_KEY ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", pairing_data.comb_key_m[i]);
	printf(" (M)\n");

	p_indent(6, NULL);
	printf("COMB_KEY ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", pairing_data.comb_key_s[i]);
	printf(" (S)\n");

	p_indent(6, NULL);
	printf("AU_RAND  ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", pairing_data.au_rand_m[i]);
	printf(" SRES ");
	for (i = 0; i < 4; i++)
		printf("%2.2x", pairing_data.sres_m[i]);
	printf(" (M)\n");

	p_indent(6, NULL);
	printf("AU_RAND  ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", pairing_data.au_rand_s[i]);
	printf(" SRES ");
	for (i = 0; i < 4; i++)
		printf("%2.2x", pairing_data.sres_s[i]);
	printf(" (S)\n");
}

static inline void in_rand(struct frame *frm)
{
	uint8_t *val = frm->ptr;

	memcpy(pairing_data.in_rand, val, 16);
	pairing_state = COMB_KEY_M;
}

static inline void comb_key(struct frame *frm)
{
	uint8_t *val = frm->ptr;

	switch (pairing_state) {
	case COMB_KEY_M:
		memcpy(pairing_data.comb_key_m, val, 16);
		pairing_state = COMB_KEY_S;
		break;
	case COMB_KEY_S:
		memcpy(pairing_data.comb_key_s, val, 16);
		pairing_state = AU_RAND_M;
		break;
	default:
		pairing_state = IN_RAND;
		break;
	}
}

static inline void au_rand(struct frame *frm)
{
	uint8_t *val = frm->ptr;

	switch (pairing_state) {
	case AU_RAND_M:
		memcpy(pairing_data.au_rand_m, val, 16);
		pairing_state = SRES_M;
		break;
	case AU_RAND_S:
		memcpy(pairing_data.au_rand_s, val, 16);
		pairing_state = SRES_S;
		break;
	default:
		pairing_state = IN_RAND;
		break;
	}
}

static inline void sres(struct frame *frm)
{
	uint8_t *val = frm->ptr;

	switch (pairing_state) {
	case SRES_M:
		memcpy(pairing_data.sres_m, val, 4);
		pairing_state = AU_RAND_S;
		break;
	case SRES_S:
		memcpy(pairing_data.sres_s, val, 4);
		pairing_state = IN_RAND;
		pairing_data_dump();
		break;
	default:
		pairing_state = IN_RAND;
		break;
	}
}

static char *opcode2str(uint16_t opcode)
{
	switch (opcode) {
	case 1:
		return "name_req";
	case 2:
		return "name_res";
	case 3:
		return "accepted";
	case 4:
		return "not_accepted";
	case 5:
		return "clkoffset_req";
	case 6:
		return "clkoffset_res";
	case 7:
		return "detach";
	case 8:
		return "in_rand";
	case 9:
		return "comb_key";
	case 10:
		return "unit_key";
	case 11:
		return "au_rand";
	case 12:
		return "sres";
	case 13:
		return "temp_rand";
	case 14:
		return "temp_key";
	case 15:
		return "encryption_mode_req";
	case 16:
		return "encryption_key_size_req";
	case 17:
		return "start_encryption_req";
	case 18:
		return "stop_encryption_req";
	case 19:
		return "switch_req";
	case 20:
		return "hold";
	case 21:
		return "hold_req";
	case 22:
		return "sniff";
	case 23:
		return "sniff_req";
	case 24:
		return "unsniff_req";
	case 25:
		return "park_req";
	case 26:
		return "park";
	case 27:
		return "set_broadcast_scan_window";
	case 28:
		return "modify_beacon";
	case 29:
		return "unpark_BD_ADDR_req";
	case 30:
		return "unpark_PM_ADDR_req";
	case 31:
		return "incr_power_req";
	case 32:
		return "decr_power_req";
	case 33:
		return "max_power";
	case 34:
		return "min_power";
	case 35:
		return "auto_rate";
	case 36:
		return "preferred_rate";
	case 37:
		return "version_req";
	case 38:
		return "version_res";
	case 39:
		return "feature_req";
	case 40:
		return "feature_res";
	case 41:
		return "quality_of_service";
	case 42:
		return "quality_of_service_req";
	case 43:
		return "SCO_link_req";
	case 44:
		return "remove_SCO_link_req";
	case 45:
		return "max_slot";
	case 46:
		return "max_slot_req";
	case 47:
		return "timing_accuracy_req";
	case 48:
		return "timing_accuracy_res";
	case 49:
		return "setup_complete";
	case 50:
		return "use_semi_permanent_key";
	case 51:
		return "host_connection_req";
	case 52:
		return "slot_offset";
	case 53:
		return "page_mode_req";
	case 54:
		return "page_scan_mode_req";
	case 55:
		return "supervision_timeout";
	case 56:
		return "test_activate";
	case 57:
		return "test_control";
	case 58:
		return "encryption_key_size_mask_req";
	case 59:
		return "encryption_key_size_mask_res";
	case 60:
		return "set_AFH";
	case 127 + (1 << 7):
		return "accepted_ext";
	case 127 + (2 << 7):
		return "not_accepted_ext";
	case 127 + (3 << 7):
		return "features_req_ext";
	case 127 + (4 << 7):
		return "features_res_ext";
	case 127 + (11 << 7):
		return "packet_type_table_req";
	case 127 + (12 << 7):
		return "eSCO_link_req";
	case 127 + (13 << 7):
		return "remove_eSCO_link_req";
	case 127 + (16 << 7):
		return "channel_classification_req";
	case 127 + (17 << 7):
		return "channel_classification";
	default:
		return "unknown";
	}
}

static inline void name_req_dump(int level, struct frame *frm)
{
	uint8_t offset = LMP_U8(frm);

	p_indent(level, frm);
	printf("name offset %d\n", offset);
}

static inline void name_res_dump(int level, struct frame *frm)
{
	uint8_t offset = LMP_U8(frm);
	uint8_t length = LMP_U8(frm);
	uint8_t *name = frm->ptr;
	int i, size;

	frm->ptr += 14;
	frm->len -= 14;

	p_indent(level, frm);
	printf("name offset %d\n", offset);

	p_indent(level, frm);
	printf("name length %d\n", length);

	size = length - offset;
	if (size > 14)
		size = 14;

	p_indent(level, frm);
	printf("name fragment '");
	for (i = 0; i < size; i++)
		if (isprint(name[i]))
			printf("%c", name[i]);
		else
			printf(".");
	printf("'\n");
}

static inline void accepted_dump(int level, struct frame *frm)
{
	uint8_t opcode = LMP_U8(frm);

	p_indent(level, frm);
	printf("op code %d (%s)\n", opcode, opcode2str(opcode));
}

static inline void not_accepted_dump(int level, struct frame *frm)
{
	uint8_t opcode = LMP_U8(frm);
	uint8_t error = LMP_U8(frm);

	p_indent(level, frm);
	printf("op code %d (%s)\n", opcode, opcode2str(opcode));

	p_indent(level, frm);
	printf("error code 0x%2.2x\n", error);
}

static inline void detach_dump(int level, struct frame *frm)
{
	uint8_t error = LMP_U8(frm);

	p_indent(level, frm);
	printf("error code 0x%2.2x\n", error);
}

static inline void random_number_dump(int level, struct frame *frm)
{
	uint8_t *number = frm->ptr;
	int i;

	frm->ptr += 16;
	frm->len -= 16;

	p_indent(level, frm);
	printf("random number ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", number[i]);
	printf("\n");
}

static inline void key_dump(int level, struct frame *frm)
{
	uint8_t *key = frm->ptr;
	int i;

	frm->ptr += 16;
	frm->len -= 16;

	p_indent(level, frm);
	printf("key ");
	for (i = 0; i < 16; i++)
		printf("%2.2x", key[i]);
	printf("\n");
}

static inline void auth_resp_dump(int level, struct frame *frm)
{
	uint8_t *resp = frm->ptr;
	int i;

	frm->ptr += 4;
	frm->ptr -= 4;

	p_indent(level, frm);
	printf("authentication response ");
	for (i = 0; i < 4; i++)
		printf("%2.2x", resp[i]);
	printf("\n");
}

static inline void preferred_rate_dump(int level, struct frame *frm)
{
	uint8_t rate = LMP_U8(frm);

	p_indent(level, frm);
	printf("data rate 0x%2.2x\n", rate);
}

static inline void version_dump(int level, struct frame *frm)
{
	uint8_t ver = LMP_U8(frm);
	uint16_t compid = LMP_U16(frm);
	uint16_t subver = LMP_U16(frm);

	p_indent(level, frm);
	printf("VersNr %d (%s)\n", ver, lmp_vertostr(ver));

	p_indent(level, frm);
	printf("CompId %d (%s)\n", compid, bt_compidtostr(compid));

	p_indent(level, frm);
	printf("SubVersNr %d\n", subver);
}

static inline void features_dump(int level, struct frame *frm)
{
	uint8_t *features = frm->ptr;
	int i;

	frm->ptr += 8;
	frm->len -= 8;

	p_indent(level, frm);
	printf("features");
	for (i = 0; i < 8; i++)
		printf(" 0x%2.2x", features[i]);
	printf("\n");
}

static inline void set_afh_dump(int level, struct frame *frm)
{
	uint32_t instant = LMP_U32(frm);
	uint8_t mode = LMP_U8(frm);
	uint8_t *map = frm->ptr;
	int i;

	frm->ptr += 10;
	frm->len -= 10;

	p_indent(level, frm);
	printf("AFH_instant 0x%04x\n", instant);

	p_indent(level, frm);
	printf("AFH_mode %d\n", mode);

	p_indent(level, frm);
	printf("AFH_channel_map 0x");
	for (i = 0; i < 10; i++)
		printf("%2.2x", map[i]);
	printf("\n");
}

static inline void accepted_ext_dump(int level, struct frame *frm)
{
	uint16_t opcode = LMP_U8(frm) + (LMP_U8(frm) << 7);

	p_indent(level, frm);
	printf("op code %d/%d (%s)\n", opcode & 0x7f, opcode >> 7, opcode2str(opcode));
}

static inline void not_accepted_ext_dump(int level, struct frame *frm)
{
	uint16_t opcode = LMP_U8(frm) + (LMP_U8(frm) << 7);
	uint8_t error = LMP_U8(frm);

	p_indent(level, frm);
	printf("op code %d/%d (%s)\n", opcode & 0x7f, opcode >> 7, opcode2str(opcode));

	p_indent(level, frm);
	printf("error code 0x%2.2x\n", error);
}

static inline void features_ext_dump(int level, struct frame *frm)
{
	uint8_t page = LMP_U8(frm);
	uint8_t max = LMP_U8(frm);
	uint8_t *features = frm->ptr;
	int i;

	frm->ptr += 8;
	frm->len -= 8;

	p_indent(level, frm);
	printf("features page %d\n", page);

	p_indent(level, frm);
	printf("max supported page %d\n", max);

	p_indent(level, frm);
	printf("extended features");
	for (i = 0; i < 8; i++)
		printf(" 0x%2.2x", features[i]);
	printf("\n");
}

static inline void max_slots_dump(int level, struct frame *frm)
{
	uint8_t slots = LMP_U8(frm);

	p_indent(level, frm);
	printf("max slots %d\n", slots);
}

static inline void timing_accuracy_dump(int level, struct frame *frm)
{
	uint8_t drift = LMP_U8(frm);
	uint8_t jitter = LMP_U8(frm);

	p_indent(level, frm);
	printf("drift %d\n", drift);

	p_indent(level, frm);
	printf("jitter %d\n", jitter);
}

static inline void page_mode_dump(int level, struct frame *frm)
{
	uint8_t scheme = LMP_U8(frm);
	uint8_t settings = LMP_U8(frm);

	p_indent(level, frm);
	printf("page scheme %d\n", scheme);

	p_indent(level, frm);
	printf("page scheme settings %d\n", settings);
}

static inline void packet_type_table_dump(int level, struct frame *frm)
{
	uint8_t type = LMP_U8(frm);

	p_indent(level, frm);
	printf("packet type table %d ", type);
	switch (type) {
	case 0:
		printf("(1Mbps only)\n");
		break;
	case 1:
		printf("(2/3Mbps)\n");
		break;
	default:
		printf("(Reserved)\n");
		break;
	}
}

static inline void channel_classification_req_dump(int level, struct frame *frm)
{
	uint8_t mode = LMP_U8(frm);
	uint16_t min = LMP_U16(frm);
	uint16_t max = LMP_U16(frm);

	p_indent(level, frm);
	printf("AFH_reporting_mode %d\n", mode);

	p_indent(level, frm);
	printf("AFH_min_interval 0x%4.4x\n", min);

	p_indent(level, frm);
	printf("AFH_max_interval 0x%4.4x\n", max);
}

static inline void channel_classification_dump(int level, struct frame *frm)
{
	uint8_t *map = frm->ptr;
	int i;

	frm->ptr += 10;
	frm->len -= 10;

	p_indent(level, frm);
	printf("AFH_channel_classification 0x");
	for (i = 0; i < 10; i++)
		printf("%2.2x", map[i]);
	printf("\n");
}

void lmp_dump(int level, struct frame *frm)
{
	uint8_t tmp, tid;
	uint16_t opcode;

	p_indent(level, frm);

	tmp = get_u8(frm);
	tid = tmp & 0x01;
	opcode = (tmp & 0xfe) >> 1;
	if (opcode > 123) {
		tmp = get_u8(frm);
		opcode += tmp << 7;
	}

	printf("LMP(%c): %s(%c): ", frm->master ? 's' : 'r',
				opcode2str(opcode), tid ? 's' : 'm');

	if (opcode > 123)
		printf("op code %d/%d", opcode & 0x7f, opcode >> 7);
	else
		printf("op code %d", opcode);

	if (frm->handle > 17)
		printf(" handle %d\n", frm->handle);
	else
		printf("\n");

	if (!(parser.flags & DUMP_VERBOSE)) {
		raw_dump(level, frm);
		return;
	}

	switch (opcode) {
	case 1:
		name_req_dump(level + 1, frm);
		return;
	case 2:
		name_res_dump(level + 1, frm);
		return;
	case 3:
		accepted_dump(level + 1, frm);
		return;
	case 4:
		not_accepted_dump(level + 1, frm);
		return;
	case 7:
		detach_dump(level + 1, frm);
		return;
	case 8:
		in_rand(frm);
		random_number_dump(level + 1, frm);
		return;
	case 9:
		comb_key(frm);
		random_number_dump(level + 1, frm);
		return;
	case 11:
		au_rand(frm);
		random_number_dump(level + 1, frm);
		return;
	case 12:
		sres(frm);
		auth_resp_dump(level + 1, frm);
		return;
	case 13:
	case 17:
		random_number_dump(level + 1, frm);
		return;
	case 10:
	case 14:
		key_dump(level + 1, frm);
		return;
	case 36:
		preferred_rate_dump(level + 1, frm);
		return;
	case 37:
	case 38:
		version_dump(level + 1, frm);
		return;
	case 39:
	case 40:
		features_dump(level + 1, frm);
		return;
	case 45:
	case 46:
		max_slots_dump(level + 1, frm);
		return;
	case 48:
		timing_accuracy_dump(level + 1, frm);
		return;
	case 53:
	case 54:
		page_mode_dump(level + 1, frm);
		return;
	case 5:
	case 18:
	case 24:
	case 33:
	case 34:
	case 35:
	case 47:
	case 49:
	case 50:
	case 51:
	case 56:
	case 58:
		return;
	case 60:
		set_afh_dump(level + 1, frm);
		return;
	case 127 + (1 << 7):
		accepted_ext_dump(level + 1, frm);
		return;
	case 127 + (2 << 7):
		not_accepted_ext_dump(level + 1, frm);
		return;
	case 127 + (3 << 7):
	case 127 + (4 << 7):
		features_ext_dump(level + 1, frm);
		return;
	case 127 + (11 << 7):
		packet_type_table_dump(level + 1, frm);
		return;
	case 127 + (16 << 7):
		channel_classification_req_dump(level + 1, frm);
		return;
	case 127 + (17 << 7):
		channel_classification_dump(level + 1, frm);
		return;
	}

	raw_dump(level, frm);
}
