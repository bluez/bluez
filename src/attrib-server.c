/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "log.h"
#include "btio.h"
#include "att.h"
#include "gattrib.h"

#include "attrib-server.h"

#define GATT_UNIX_PATH "/var/run/gatt"
#define GATT_PSM 27

static GSList *database = NULL;

struct attribute {
	uint16_t handle;
	uuid_t uuid;
	int len;
	uint8_t data[0];
};

struct gatt_channel {
	bdaddr_t src;
	bdaddr_t dst;
	GAttrib *attrib;
	guint id;
};

struct gatt_server {
	GIOChannel *listen;
	GSList *channels;
};

struct gatt_server *attrib_server = NULL;
struct gatt_server *unix_server = NULL;

static uuid_t prim_uuid = { .type = SDP_UUID16, .value.uuid16 = GATT_PRIM_SVC_UUID };
static uuid_t snd_uuid = { .type = SDP_UUID16, .value.uuid16 = GATT_SND_SVC_UUID };

static uint16_t read_by_group(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	struct att_data_list *adl;
	struct attribute *a;
	GSList *l, *groups;
	uint16_t length, last = 0;
	int i;

	/*
	 * Only <<Primary Service>> and <<Secondary Service>> grouping
	 * types may be used in the Read By Group Type Request.
	 * FIXME: Attribute types shall be compared as 128-bit UUID.
	 */

	if (sdp_uuid_cmp(uuid, &prim_uuid) != 0 &&
		sdp_uuid_cmp(uuid, &snd_uuid) != 0)
		return enc_error_resp(ATT_OP_READ_BY_GROUP_REQ, 0x0000,
					ATT_ECODE_UNSUPP_GRP_TYPE, pdu, len);

	for (l = database, groups = NULL; l; l = l->next) {
		a = l->data;

		if (a->handle < start)
			continue;

		last = a->handle;
		if (a->handle >= end)
			break;

		if (sdp_uuid_cmp(&a->uuid, &prim_uuid)  != 0 &&
				sdp_uuid_cmp(&a->uuid, &snd_uuid) != 0)
			continue;

		if (sdp_uuid_cmp(&a->uuid, uuid) != 0)
			continue;

		/* Attribute Grouping Type found */
		groups = g_slist_append(groups, a);
	}

	if (groups == NULL)
		return enc_error_resp(ATT_OP_READ_BY_GROUP_REQ, 0x0000,
					ATT_ECODE_ATTR_NOT_FOUND, pdu, len);

	length = g_slist_length(groups);

	adl = g_new0(struct att_data_list, 1);
	adl->len = 6;		/* Length of each element */
	adl->num = length;	/* Number of primary or secondary services */
	adl->data = g_malloc(length * sizeof(uint8_t *));

	for (i = 0, l = groups; l; l = l->next, i++) {
		struct attribute *next;
		uint16_t *u16;

		adl->data[i] = g_malloc(adl->len);
		u16 = (void *) adl->data[i];
		a = l->data;

		/* Attribute Handle */
		*u16 = htobs(a->handle);
		u16++;

		/* End Group Handle */
		if (l->next == NULL) {
			*u16 = htobs(last);
		} else {
			next = l->next->data;
			*u16 = htobs(next->handle - 1);
		}

		u16++;

		/* Attribute Value */
		memcpy(u16, a->data, a->len);
	}

	length = enc_read_by_grp_resp(adl, pdu, len);

	att_data_list_free(adl);
	g_slist_free(groups);

	return length;
}

static void channel_destroy(void *user_data)
{
	struct gatt_channel *channel = user_data;

	g_attrib_unregister_all(channel->attrib);
	g_attrib_unref(channel->attrib);

	attrib_server->channels = g_slist_remove(attrib_server->channels,
								channel);
	g_free(channel);
}

static void server_free(struct gatt_server *server)
{
	GSList *l;

	DBG("server %p", server);

	if (server->listen)
		g_io_channel_unref(server->listen);

	for (l = server->channels; l; l = l->next) {
		struct gatt_channel *channel = l->data;

		g_attrib_unregister_all(channel->attrib);
		g_attrib_unref(channel->attrib);
	}

	g_slist_free(server->channels);
	g_free(server);
}

static int handle_cmp(struct attribute *a, uint16_t *handle)
{
	return a->handle - *handle;
}

static void channel_handler(const uint8_t *ipdu, uint16_t len,
							gpointer user_data)
{
	struct gatt_channel *channel = user_data;
	uint8_t opdu[ATT_MTU];
	uint16_t length, start, end;
	uuid_t uuid;
	uint8_t status = 0;

	switch(ipdu[0]) {
	case ATT_OP_READ_BY_GROUP_REQ:
		length = dec_read_by_grp_req(ipdu, len, &start, &end, &uuid);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = read_by_group(start, end, &uuid, opdu, sizeof(opdu));
		break;
	case ATT_OP_MTU_REQ:
	case ATT_OP_FIND_INFO_REQ:
	case ATT_OP_FIND_BY_TYPE_REQ:
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_WRITE_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	default:
		status = ATT_ECODE_REQ_NOT_SUPP;
		goto done;
	}

done:
	if (status)
		length = enc_error_resp(ipdu[0], 0x0000, status, opdu, sizeof(opdu));

	g_attrib_send(channel->attrib, opdu[0], opdu, length,
							NULL, NULL, NULL);
}

static void connect_event(GIOChannel *io, GError *err, void *user_data)
{
	struct gatt_server *server = user_data;
	struct gatt_channel *channel;
	GError *gerr = NULL;

	if (err) {
		error("%s", err->message);
		return;
	}

	channel = g_new0(struct gatt_channel, 1);

	bt_io_get(io, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &channel->src,
			BT_IO_OPT_DEST_BDADDR, &channel->dst,
			BT_IO_OPT_INVALID);

	channel->attrib = g_attrib_new(io);
	channel->id = g_attrib_register(channel->attrib, GATTRIB_ALL_EVENTS,
				channel_handler, channel, channel_destroy);

	server->channels = g_slist_append(server->channels, channel);
}

static void confirm_event(GIOChannel *io, void *user_data)
{
	struct gatt_server *server = user_data;
	GError *gerr = NULL;

	if (bt_io_accept(io, connect_event, server, NULL,
							&gerr) == FALSE) {
		error("bt_io_accept: %s", gerr->message);
		g_error_free(gerr);
		g_io_channel_unref(io);
	}

	return;
}

static gboolean unix_io_accept(GIOChannel *chan, GIOCondition cond,
							gpointer user_data)
{
	struct gatt_server *server = user_data;
	struct gatt_channel *channel;
	struct sockaddr_un addr;
	GIOChannel *io;
	socklen_t len;
	int sk, nsk;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	len = sizeof(addr);
	sk = g_io_channel_unix_get_fd(chan);
	nsk = accept(sk, (struct sockaddr *) &addr, &len);
	if (nsk < 0) {
		int err = errno;
		error("GATT UNIX socket connection failed: %s(%d)",
							strerror(err), err);
		return TRUE;
	}

	channel = g_new0(struct gatt_channel, 1);

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);
	bacpy(&channel->src, BDADDR_ANY);
	bacpy(&channel->dst, BDADDR_ANY);
	channel->attrib = g_attrib_new(io);
	channel->id = g_attrib_register(channel->attrib, GATTRIB_ALL_EVENTS,
				channel_handler, channel, channel_destroy);

	server->channels = g_slist_append(server->channels, channel);

	return TRUE;
}

int attrib_server_init(void)
{
	GIOChannel *io;
	GError *gerr = NULL;
	struct sockaddr_un unaddr;
	int err, sk;

	/* BR/EDR socket */
	attrib_server = g_new0(struct gatt_server, 1);
	attrib_server->listen = bt_io_listen(BT_IO_L2CAP, NULL, confirm_event,
					attrib_server, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_PSM, GATT_PSM,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);

	if (attrib_server->listen == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		return -1;
	}

	/* Unix socket */
	sk = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		error("opening GATT UNIX socket: %s(%d)", strerror(err), err);
		return -1;
	}

	memset(&unaddr, 0, sizeof(unaddr));
	unaddr.sun_family = AF_UNIX;
	strcpy(unaddr.sun_path, GATT_UNIX_PATH);

	unlink(unaddr.sun_path);

	if (bind(sk, (struct sockaddr *) &unaddr, sizeof(unaddr)) < 0) {
		err = errno;
		error("binding GATT UNIX socket: %s(%d)", strerror(err), err);
		goto fail;
	}

	if (listen(sk, 5) < 0) {
		err = errno;
		error("listen GATT UNIX socket: %s(%d)", strerror(err), err);
		goto fail;
	}

	chmod(GATT_UNIX_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
							S_IROTH | S_IWOTH);

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	unix_server = g_new0(struct gatt_server, 1);
	unix_server->listen = io;
	g_io_add_watch(io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						unix_io_accept, unix_server);

	return 0;

fail:
	close(sk);

	return -1;

}

void attrib_server_exit(void)
{
	g_slist_foreach(database, (GFunc) g_free, NULL);
	g_slist_free(database);

	server_free(attrib_server);
	server_free(unix_server);
}

int attrib_db_add(uint16_t handle, uuid_t *uuid, const uint8_t *value, int len)
{
	struct attribute *a;

	/* FIXME: handle conflicts */

	a = g_malloc0(sizeof(struct attribute) + len);
	a->handle = handle;
	memcpy(&a->uuid, uuid, sizeof(uuid_t));
	a->len = len;
	memcpy(a->data, value, len);

	database = g_slist_append(database, a);

	return 0;
}

int attrib_db_del(uint16_t handle)
{
	struct attribute *a;
	GSList *l;

	l = g_slist_find_custom(database, &handle, (GCompareFunc) handle_cmp);
	if (!l)
		return -ENOENT;

	a = l->data;
	database = g_slist_remove(database, a);
	g_free(a);

	return 0;
}
