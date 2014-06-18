/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
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

#include <unistd.h>

#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "lib/uuid.h"
#include "src/shared/att.h"

#define ATT_DEFAULT_LE_MTU		23
#define ATT_MIN_PDU_LEN			1  /* At least 1 byte for the opcode. */

struct att_send_op;

struct bt_att {
	int ref_count;
	int fd;
	bool close_on_unref;
	struct io *io;
	bool invalid;  /* bt_att becomes invalid when a request times out */

	struct queue *req_queue;	/* Queued ATT protocol requests */
	struct att_send_op *pending_req;
	struct queue *ind_queue;	/* Queued ATT protocol indications */
	struct att_send_op *pending_ind;
	struct queue *write_queue;	/* Queue of PDUs ready to send */
	bool writer_active;

	/* TODO Add notify queue */

	uint8_t *buf;
	uint16_t mtu;

	unsigned int next_send_id;	/* IDs for "send" ops */
	unsigned int next_reg_id;	/* IDs for registered callbacks */

	bt_att_timeout_func_t timeout_callback;
	bt_att_destroy_func_t timeout_destroy;
	void *timeout_data;

	bt_att_debug_func_t debug_callback;
	bt_att_destroy_func_t debug_destroy;
	void *debug_data;
};

struct att_send_op {
	unsigned int id;
	uint16_t opcode;
	void *pdu;
	uint16_t len;
	bt_att_request_func_t callback;
	bt_att_destroy_func_t destroy;
	void *user_data;
};

struct bt_att *bt_att_new(int fd)
{
	/* TODO */
	return NULL;
}

struct bt_att *bt_att_ref(struct bt_att *att)
{
	/* TODO */
	return NULL;
}

void bt_att_unref(struct bt_att *att)
{
	/* TODO */
}

bool bt_att_set_close_on_unref(struct bt_att *att, bool do_close)
{
	/* TODO */
	return false;
}

bool bt_att_set_debug(struct bt_att *att, bt_att_debug_func_t callback,
				void *user_data, bt_att_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

uint16_t bt_att_get_mtu(struct bt_att *att)
{
	/* TODO */
	return 0;
}

bool bt_att_set_mtu(struct bt_att *att, uint16_t mtu)
{
	/* TODO */
	return false;
}

bool bt_att_set_timeout_cb(struct bt_att *att, bt_att_timeout_func_t callback,
						void *user_data,
						bt_att_destroy_func_t destroy)
{
	/* TODO */
	return false;
}

unsigned int bt_att_send(struct bt_att *att, uint8_t opcode,
				const void *param, uint16_t length,
				bt_att_request_func_t callback, void *user_data,
				bt_att_destroy_func_t destroy)
{
	/* TODO */
	return 0;
}

bool bt_att_cancel(struct bt_att *att, unsigned int id)
{
	/* TODO */
	return false;
}

bool bt_att_cancel_all(struct bt_att *att)
{
	/* TODO */
	return false;
}

unsigned int bt_att_register(struct bt_att *att, uint8_t opcode,
				bt_att_request_func_t callback,
				void *user_data, bt_att_destroy_func_t destroy)
{
	/* TODO */
	return 0;
}

bool bt_att_unregister(struct bt_att *att, unsigned int id)
{
	/* TODO */
	return false;
}

bool bt_att_unregister_all(struct bt_att *att)
{
	/* TODO */
	return false;
}
