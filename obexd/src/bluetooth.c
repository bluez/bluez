/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"

static GSList *handles = NULL;
static sdp_session_t *session = NULL;

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	/* UTF-8 MIBenum (http://www.iana.org/assignments/character-sets) */
	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

static uint32_t register_record(const gchar *name,
				guint16 service, guint8 channel)
{
	uuid_t root_uuid, uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_list_t *root, *svclass_id, *apseq, *profiles, *aproto, *proto[3];
	sdp_data_t *sdp_data;
	sdp_profile_desc_t profile;
	sdp_record_t record;
	uint8_t formats = 0xFF;
	int ret;

	switch (service) {
	case OBEX_OPUSH:
		sdp_uuid16_create(&uuid, OBEX_OBJPUSH_SVCLASS_ID);
		sdp_uuid16_create(&profile.uuid, OBEX_OBJPUSH_PROFILE_ID);
		break;
	case OBEX_FTP:
		sdp_uuid16_create(&uuid, OBEX_FILETRANS_SVCLASS_ID);
		sdp_uuid16_create(&profile.uuid, OBEX_FILETRANS_PROFILE_ID);
		break;
	default:
		return 0;
	}

	/* Browse Groups */
	memset(&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(&record, root);
	sdp_list_free(root, NULL);

	/* Service Class */
	svclass_id = sdp_list_append(NULL, &uuid);
	sdp_set_service_classes(&record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	/* Profile Descriptor */
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(&record, profiles);
	sdp_list_free(profiles, NULL);

	/* Protocol Descriptor */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	sdp_data = sdp_data_alloc(SDP_UINT8, &channel);
	proto[1] = sdp_list_append(proto[1], sdp_data);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(NULL, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_data_free(sdp_data);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(proto[2], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	/* Suported Repositories */
	if (service == OBEX_OPUSH)
		sdp_attr_add_new(&record, SDP_ATTR_SUPPORTED_FORMATS_LIST,
				SDP_UINT8, &formats);

	/* Service Name */
	sdp_set_info_attr(&record, name, NULL, NULL);

	add_lang_attr(&record);

	ret = sdp_record_register(session, &record, SDP_RECORD_PERSIST);

	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return (ret < 0 ? 0 : record.handle);
}

static gboolean connect_event(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct sockaddr_rc raddr;
	socklen_t alen;
	struct server *server = user_data;
	gchar address[18];
	gint err, sk, nsk;

	sk = g_io_channel_unix_get_fd(io);
	alen = sizeof(raddr);
	nsk = accept(sk, (struct sockaddr *) &raddr, &alen);
	if (nsk < 0)
		return TRUE;

	alen = sizeof(raddr);
	if (getpeername(nsk, (struct sockaddr *)&raddr, &alen) < 0) {
		err = errno;
		error("getpeername(): %s(%d)", strerror(err), err);
		close(nsk);
		return TRUE;
	}

	ba2str(&raddr.rc_bdaddr, address);
	info("New connection from: %s channel: %d", address, raddr.rc_channel);

	if (obex_session_start(nsk, server) < 0)
		close(nsk);

	return TRUE;
}

static void server_destroyed(gpointer user_data)
{
	struct server *server = user_data;

	error("Server destroyed");

	g_free(server->folder);
	g_free(server);
}

static gint server_register(guint16 service, const gchar *name,
		guint8 channel, const gchar *folder, gboolean auto_accept)
{
	struct sockaddr_rc laddr;
	GIOChannel *io;
	gint err, sk, arg;
	struct server *server;
	uint32_t *handle;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		err = errno;
		error("socket(): %s(%d)", strerror(err), err);
		return -err;
	}

	arg = fcntl(sk, F_GETFL);
	if (arg < 0) {
		err = errno;
		goto failed;
	}

	arg |= O_NONBLOCK;
	if (fcntl(sk, F_SETFL, arg) < 0) {
		err = errno;
		goto failed;
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.rc_family = AF_BLUETOOTH;
	bacpy(&laddr.rc_bdaddr, BDADDR_ANY);
	laddr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		err = errno;
		goto failed;
	}

	if (listen(sk, 10) < 0) {
		err = errno;
		goto failed;
	}

	handle = malloc(sizeof(uint32_t));
	*handle = register_record(name, service, channel);
	if (*handle == 0) {
		g_free(handle);
		err = EIO;
		goto failed;
	}

	handles = g_slist_prepend(handles, handle);

	server = g_malloc0(sizeof(struct server));
	server->service = service;
	server->folder = g_strdup(folder);
	server->auto_accept = auto_accept;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_event, server, server_destroyed);
	g_io_channel_unref(io);

	debug("Registered: %s, record handle: 0x%x, folder: %s", name, *handle, folder);

	return 0;

failed:
	error("Bluetooth server register failed: %s(%d)", strerror(err), err);
	close(sk);

	return -err;
}

gint bluetooth_init(guint service, const gchar *name, const gchar *folder,
					guint8 channel, gboolean auto_accept)
{
	if (!session) {
		session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
		if (!session) {
			gint err = errno;
			error("sdp_connect(): %s(%d)", strerror(err), err);
			return -err;
		}
	}

	return server_register(service, name, channel, folder, auto_accept);
}

static void unregister_record(gpointer rec_handle, gpointer user_data)
{
	uint32_t *handle = rec_handle;

	sdp_device_record_unregister_binary(session, BDADDR_ANY, *handle);
	g_free(handle);
}

void bluetooth_exit(void)
{
	g_slist_foreach(handles, unregister_record, NULL);
	g_slist_free(handles);

	sdp_close(session);
}
