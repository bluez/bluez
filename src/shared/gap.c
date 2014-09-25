/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/util.h"
#include "src/shared/mgmt.h"
#include "src/shared/gap.h"

#define FLAG_MGMT_CONN_CONTROL	(0 << 1)

struct bt_gap {
	int ref_count;
	struct mgmt *mgmt;

	uint8_t mgmt_version;
	uint16_t mgmt_revision;
	bool mgmt_ready;

	unsigned long flags;

	bt_gap_ready_func_t ready_handler;
	bt_gap_destroy_func_t ready_destroy;
	void *ready_data;
};

static void ready_status(struct bt_gap *gap, bool status)
{
	gap->mgmt_ready = status;

	if (gap->ready_handler)
		gap->ready_handler(status, gap->ready_data);
}

static void read_commands_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct bt_gap *gap = user_data;
	const struct mgmt_rp_read_commands *rp = param;
	uint16_t num_commands, num_events;
	const uint16_t *opcode;
	size_t expected_len;
	int i;

	if (status != MGMT_STATUS_SUCCESS) {
		ready_status(gap, false);
		return;
	}

	if (length < sizeof(*rp)) {
		ready_status(gap, false);
		return;
	}

	num_commands = le16_to_cpu(rp->num_commands);
	num_events = le16_to_cpu(rp->num_events);

	expected_len = sizeof(*rp) + num_commands * sizeof(uint16_t) +
						num_events * sizeof(uint16_t);

	if (length < expected_len) {
		ready_status(gap, false);
		return;
	}

	opcode = rp->opcodes;

	for (i = 0; i < num_commands; i++) {
		uint16_t op = get_le16(opcode++);

		if (op == MGMT_OP_ADD_DEVICE)
			gap->flags |= FLAG_MGMT_CONN_CONTROL;
	}

	ready_status(gap, true);
}

static void read_version_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct bt_gap *gap = user_data;
	const struct mgmt_rp_read_version *rp = param;

	if (status != MGMT_STATUS_SUCCESS) {
		ready_status(gap, false);
		return;
	}

	if (length < sizeof(*rp)) {
		ready_status(gap, false);
		return;
	}

	gap->mgmt_version = rp->version;
	gap->mgmt_revision = le16_to_cpu(rp->revision);

	if (!mgmt_send(gap->mgmt, MGMT_OP_READ_COMMANDS,
				MGMT_INDEX_NONE, 0, NULL,
				read_commands_complete, gap, NULL)) {
		ready_status(gap, false);
		return;
	}
}

struct bt_gap *bt_gap_new(void)
{
	struct bt_gap *gap;

	gap = new0(struct bt_gap, 1);
	if (!gap)
		return NULL;

	gap->mgmt = mgmt_new_default();
	if (!gap->mgmt) {
		free(gap);
		return NULL;
	}

	gap->mgmt_ready = false;

	if (!mgmt_send(gap->mgmt, MGMT_OP_READ_VERSION,
					MGMT_INDEX_NONE, 0, NULL,
					read_version_complete, gap, NULL)) {
		mgmt_unref(gap->mgmt);
		return NULL;
	}

	return bt_gap_ref(gap);
}

struct bt_gap *bt_gap_ref(struct bt_gap *gap)
{
	if (!gap)
		return NULL;

	__sync_fetch_and_add(&gap->ref_count, 1);

	return gap;
}

void bt_gap_unref(struct bt_gap *gap)
{
	if (!gap)
		return;

	if (__sync_sub_and_fetch(&gap->ref_count, 1))
		return;

	gap->mgmt_ready = false;

	mgmt_cancel_all(gap->mgmt);
	mgmt_unregister_all(gap->mgmt);

	if (gap->ready_destroy)
		gap->ready_destroy(gap->ready_data);

	mgmt_unref(gap->mgmt);

	free(gap);
}

bool bt_gap_set_ready_handler(struct bt_gap *gap,
				bt_gap_ready_func_t handler, void *user_data,
				bt_gap_destroy_func_t destroy)
{
	if (!gap)
		return false;

	if (gap->ready_destroy)
		gap->ready_destroy(gap->ready_data);

	gap->ready_handler = handler;
	gap->ready_destroy = destroy;
	gap->ready_data = user_data;

	return true;
}
