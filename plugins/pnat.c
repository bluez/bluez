/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <gdbus.h>

#include "plugin.h"
#include "sdpd.h"
#include "btio.h"
#include "adapter.h"
#include "logging.h"

#define DUN_CHANNEL 1
#define DUN_UUID "00001103-0000-1000-8000-00805F9B34FB"

struct dun_server {
	bdaddr_t src;		/* Local adapter address */
	bdaddr_t dst;		/* Remote address (only meaningful when
					there's a client connected) */
	uint32_t record_handle; /* Local SDP record handle */
	GIOChannel *server;	/* Server socket */
	GIOChannel *client;	/* Client socket */
	guint client_id;	/* Client IO watch id */
};

static GSList *servers = NULL;

static void disconnect(struct dun_server *server)
{
	g_io_channel_unref(server->client);
	server->client = NULL;
	if (server->client_id > 0)
		g_source_remove(server->client_id);
	server->client_id = 0;
}

static gboolean session_event(GIOChannel *chan,
					GIOCondition cond, gpointer data)
{
	struct dun_server *server = data;
	unsigned char buf[672];
	gsize len, written;
	GIOError err;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		goto disconnected;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err == G_IO_ERROR_AGAIN)
		return TRUE;

	g_io_channel_write(chan, (const gchar *) buf, len, &written);

	return TRUE;

disconnected:
	server->client_id = 0;
	disconnect(server);
	return FALSE;
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct dun_server *server = user_data;
	guint id;

	g_source_remove(server->client_id);
	server->client_id = 0;

	if (err) {
		error("Accepting DUN connection failed: %s", err->message);
		disconnect(server);
		return;
	}

	id = g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							session_event, server);
	server->client_id = id;
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct dun_server *server = user_data;
	GError *err = NULL;

	if (derr && dbus_error_is_set(derr)) {
		error("DUN access denied: %s", derr->message);
		goto drop;
	}

	if (!bt_io_accept(server->client, connect_cb, server, NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		goto drop;
	}

	return;

drop:
	disconnect(server);
}

static gboolean auth_watch(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct dun_server *server = data;

	error("DUN client disconnected while waiting for authorization");

	btd_cancel_authorization(&server->src, &server->dst);

	disconnect(server);

	return FALSE;
}

static void confirm_cb(GIOChannel *io, gpointer user_data)
{
	struct dun_server *server = user_data;
	GError *err = NULL;

	if (server->client) {
		error("Rejecting DUN connection since one already exists");
		return;
	}

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_DEST_BDADDR, &server->dst,
			BT_IO_OPT_INVALID);
	if (err != NULL) {
		error("Unable to get DUN source and dest address: %s",
								err->message);
		g_error_free(err);
		return;
	}

	if (btd_request_authorization(&server->src, &server->dst, DUN_UUID,
						auth_cb, user_data) < 0) {
		error("Requesting DUN authorization failed");
		return;
	}

	server->client_id = g_io_add_watch(io, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) auth_watch, server);
	server->client = g_io_channel_ref(io);
}

static sdp_record_t *dun_record(uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root, *aproto;
	uuid_t root_uuid, dun, gn, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_list_t *proto[2];
	sdp_record_t *record;
	sdp_data_t *channel;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&dun, DIALUP_NET_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &dun);
	sdp_uuid16_create(&gn,  GENERIC_NETWORKING_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &gn);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, DIALUP_NET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Dial-Up Networking", 0, 0);

	sdp_data_free(channel);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	return record;
}

static gint server_cmp(gconstpointer a, gconstpointer b)
{
	const struct dun_server *server = a;
	const bdaddr_t *src = b;

	return bacmp(src, &server->src);
}

static int pnat_probe(struct btd_adapter *adapter)
{
	struct dun_server *server;
	GIOChannel *io;
	GError *err = NULL;
	sdp_record_t *record;
	bdaddr_t src;

	adapter_get_address(adapter, &src);

	server = g_new0(struct dun_server, 1);

	io = bt_io_listen(BT_IO_RFCOMM, NULL, confirm_cb, server, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &src,
				BT_IO_OPT_CHANNEL, DUN_CHANNEL,
				BT_IO_OPT_INVALID);
	if (err != NULL) {
		error("Failed to start DUN server: %s", err->message);
		g_error_free(err);
		g_free(server);
		return -EIO;
	}

	record = dun_record(DUN_CHANNEL);
	if (!record) {
		error("Unable to allocate new service record");
		goto fail;
	}

	if (add_record_to_server(&src, record) < 0) {
		error("Unable to register DUN service record");
		goto fail;
	}

	server->server = io;
	server->record_handle = record->handle;
	bacpy(&server->src, &src);

	servers = g_slist_append(servers, server);

	return 0;

fail:
	if (io != NULL)
		g_io_channel_unref(io);
	g_free(server);
	return -EIO;
}

static void pnat_remove(struct btd_adapter *adapter)
{
	struct dun_server *server;
	GSList *match;
	bdaddr_t src;

	adapter_get_address(adapter, &src);

	match = g_slist_find_custom(servers, &src, server_cmp);
	if (match == NULL)
		return;

	server = match->data;

	servers = g_slist_delete_link(servers, match);

	if (server->client)
		disconnect(server);

	remove_record_from_server(server->record_handle);
	g_io_channel_shutdown(server->server, TRUE, NULL);
	g_io_channel_unref(server->server);
	g_free(server);
}

static struct btd_adapter_driver pnat_server = {
	.name	= "pnat-server",
	.probe	= pnat_probe,
	.remove	= pnat_remove,
};

static int pnat_init(void)
{
	debug("Setup Phonet AT (DUN) plugin");

	return btd_register_adapter_driver(&pnat_server);
}

static void pnat_exit(void)
{
	debug("Cleanup Phonet AT (DUN) plugin");

	btd_unregister_adapter_driver(&pnat_server);
}

BLUETOOTH_PLUGIN_DEFINE(pnat, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			pnat_init, pnat_exit)
