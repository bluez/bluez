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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

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
#include "log.h"

/* FIXME: This location should be build-time configurable */
#define PNATD "/usr/bin/phonet-at"

#define DUN_CHANNEL 1
#define DUN_UUID "00001103-0000-1000-8000-00805F9B34FB"

#define TTY_TIMEOUT 100
#define TTY_TRIES 10

struct dun_client {
	bdaddr_t bda;

	GIOChannel *io;	/* Client socket */
	guint io_watch;	/* Client IO watch id */

	guint tty_timer;
	int tty_tries;
	gboolean tty_open;
	int tty_id;
	char tty_name[PATH_MAX];

	GPid pnatd_pid;
	guint pnatd_watch;
};

struct dun_server {
	bdaddr_t bda;		/* Local adapter address */

	uint32_t record_handle; /* Local SDP record handle */
	GIOChannel *server;	/* Server socket */

	int rfcomm_ctl;

	struct dun_client client;
};

static GSList *servers = NULL;

static void disconnect(struct dun_server *server)
{
	struct dun_client *client = &server->client;

	if (!client->io)
		return;

	g_io_channel_unref(client->io);
	client->io = NULL;

	if (client->io_watch > 0) {
		g_source_remove(client->io_watch);
		client->io_watch = 0;
	}

	if (client->pnatd_watch > 0) {
		g_source_remove(client->pnatd_watch);
		client->pnatd_watch = 0;
		if (client->pnatd_pid > 0)
			kill(client->pnatd_pid, SIGTERM);
	}

	if (client->pnatd_pid > 0) {
		g_spawn_close_pid(client->pnatd_pid);
		client->pnatd_pid = 0;
	}

	if (client->tty_timer > 0) {
		g_source_remove(client->tty_timer);
		client->tty_timer = 0;
	}

	if (client->tty_id >= 0) {
		struct rfcomm_dev_req req;

		memset(&req, 0, sizeof(req));
		req.dev_id = client->tty_id;
		req.flags = (1 << RFCOMM_HANGUP_NOW);
		ioctl(server->rfcomm_ctl, RFCOMMRELEASEDEV, &req);

		client->tty_name[0] = '\0';
		client->tty_open = FALSE;
		client->tty_id = -1;
	}
}

static gboolean client_event(GIOChannel *chan,
					GIOCondition cond, gpointer data)
{
	struct dun_server *server = data;
	struct dun_client *client = &server->client;
	char addr[18];

	ba2str(&client->bda, addr);

	DBG("Disconnected DUN from %s (%s)", addr, client->tty_name);

	client->io_watch = 0;
	disconnect(server);

	return FALSE;
}

static void pnatd_exit(GPid pid, gint status, gpointer user_data)
{
	struct dun_server *server = user_data;
	struct dun_client *client = &server->client;

        if (WIFEXITED(status))
                DBG("pnatd (%d) exited with status %d", pid,
							WEXITSTATUS(status));
        else
                DBG("pnatd (%d) was killed by signal %d", pid,
							WTERMSIG(status));

	client->pnatd_watch = 0;

	disconnect(server);
}

static gboolean start_pnatd(struct dun_server *server)
{
	struct dun_client *client = &server->client;
	GSpawnFlags flags = G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH;
	char *argv[] = { PNATD, client->tty_name, NULL };
	GError *err = NULL;
	GPid pid;

	g_spawn_async(NULL, argv, NULL, flags, NULL, NULL, &pid, &err);
	if (err != NULL) {
		error("Unable to spawn pnatd: %s", err->message);
		g_error_free(err);
		return FALSE;
	}

	DBG("pnatd started for %s with pid %d", client->tty_name, pid);

	client->pnatd_pid = pid;
	client->pnatd_watch = g_child_watch_add(pid, pnatd_exit, server);

	return TRUE;
}

static gboolean tty_try_open(gpointer user_data)
{
	struct dun_server *server = user_data;
	struct dun_client *client = &server->client;
	int tty_fd;

	tty_fd = open(client->tty_name, O_RDONLY | O_NOCTTY);
	if (tty_fd < 0) {
		if (errno == EACCES)
			goto disconnect;

		client->tty_tries--;

		if (client->tty_tries <= 0)
			goto disconnect;

		return TRUE;
	}

	DBG("%s created for DUN", client->tty_name);

	client->tty_open = TRUE;
	client->tty_timer = 0;

	g_io_channel_unref(client->io);
	g_source_remove(client->io_watch);

	client->io = g_io_channel_unix_new(tty_fd);
	client->io_watch = g_io_add_watch(client->io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					client_event, server);

	if (!start_pnatd(server))
		goto disconnect;

	return FALSE;

disconnect:
	client->tty_timer = 0;
	disconnect(server);
	return FALSE;
}

static gboolean create_tty(struct dun_server *server)
{
	struct dun_client *client = &server->client;
	struct rfcomm_dev_req req;
	int dev, sk = g_io_channel_unix_get_fd(client->io);

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);

	bacpy(&req.src, &server->bda);
	bacpy(&req.dst, &client->bda);

	bt_io_get(client->io, BT_IO_RFCOMM, NULL,
			BT_IO_OPT_DEST_CHANNEL, &req.channel,
			BT_IO_OPT_INVALID);

	dev = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (dev < 0) {
		error("Can't create RFCOMM TTY: %s", strerror(errno));
		return FALSE;
	}

	snprintf(client->tty_name, PATH_MAX - 1, "/dev/rfcomm%d", dev);

	client->tty_tries = TTY_TRIES;

	tty_try_open(server);
	if (!client->tty_open && client->tty_tries > 0)
		client->tty_timer = g_timeout_add(TTY_TIMEOUT,
							tty_try_open, server);

	return TRUE;
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct dun_server *server = user_data;

	if (err) {
		error("Accepting DUN connection failed: %s", err->message);
		disconnect(server);
		return;
	}

	if (!create_tty(server)) {
		error("Device creation failed");
		disconnect(server);
	}
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct dun_server *server = user_data;
	struct dun_client *client = &server->client;
	GError *err = NULL;

	if (derr && dbus_error_is_set(derr)) {
		error("DUN access denied: %s", derr->message);
		goto drop;
	}

	if (!bt_io_accept(client->io, connect_cb, server, NULL, &err)) {
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
	struct dun_client *client = &server->client;

	error("DUN client disconnected while waiting for authorization");

	btd_cancel_authorization(&server->bda, &client->bda);

	disconnect(server);

	return FALSE;
}

static void confirm_cb(GIOChannel *io, gpointer user_data)
{
	struct dun_server *server = user_data;
	struct dun_client *client = &server->client;
	GError *err = NULL;

	if (client->io) {
		error("Rejecting DUN connection since one already exists");
		return;
	}

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_DEST_BDADDR, &client->bda,
			BT_IO_OPT_INVALID);
	if (err != NULL) {
		error("Unable to get DUN source and dest address: %s",
								err->message);
		g_error_free(err);
		return;
	}

	if (btd_request_authorization(&server->bda, &client->bda, DUN_UUID,
						auth_cb, user_data) < 0) {
		error("Requesting DUN authorization failed");
		return;
	}

	client->io_watch = g_io_add_watch(io, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) auth_watch, server);
	client->io = g_io_channel_ref(io);
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

	return bacmp(src, &server->bda);
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
		goto fail;
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

	server->rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
	if (server->rfcomm_ctl < 0) {
		error("Unable to create RFCOMM control socket: %s (%d)",
						strerror(errno), errno);
		goto fail;
	}

	server->server = io;
	server->record_handle = record->handle;
	bacpy(&server->bda, &src);

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

	disconnect(server);

	remove_record_from_server(server->record_handle);
	close(server->rfcomm_ctl);
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
	DBG("Setup Phonet AT (DUN) plugin");

	return btd_register_adapter_driver(&pnat_server);
}

static void pnat_exit(void)
{
	DBG("Cleanup Phonet AT (DUN) plugin");

	btd_unregister_adapter_driver(&pnat_server);
}

BLUETOOTH_PLUGIN_DEFINE(pnat, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			pnat_init, pnat_exit)
