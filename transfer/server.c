/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <unistd.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "logging.h"
#include "server.h"

static sdp_session_t *sdp_session = NULL;

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	debug("Incoming data session");

	return FALSE;
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	GIOChannel *io;
	struct sockaddr_rc addr;
	socklen_t optlen;
	int sk, nsk;

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0)
		return TRUE;

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR,
						session_event, NULL);

	g_io_channel_unref(io);

	return TRUE;
}

static GIOChannel *setup_rfcomm(uint8_t channel)
{
	GIOChannel *io;
	struct sockaddr_rc addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return NULL;
	}

	if (listen(sk, 10) < 0) {
		close(sk);
		return NULL;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN, connect_event, NULL);

	return io;
}

static int setup_sdp_for_push(uint8_t channel)
{
	sdp_record_t *record;
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, opush_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_data_t *chan;
	uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xFF };
	void *dtds[sizeof(formats)], *values[sizeof(formats)];
	int i;
	uint8_t dtd = SDP_UINT8;
	sdp_data_t *sflist;

	if (!sdp_session) {
		sdp_session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
		if (!sdp_session) {
			error("Connection to SDP server failed");
			return -1;
		}
	}

	record = sdp_record_alloc();
	if (!record) {
		error("Allocation of service record failed");
		return -1;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&opush_uuid, OBEX_OBJPUSH_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &opush_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_OBJPUSH_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	chan = sdp_data_alloc(SDP_UINT8, &channel);
	proto[1] = sdp_list_append(proto[1], chan);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(0, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	for (i = 0; i < sizeof(formats); i++) {
		dtds[i] = &dtd;
		values[i] = &formats[i];
	}
	sflist = sdp_seq_alloc(dtds, values, sizeof(formats));
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FORMATS_LIST, sflist);

	sdp_set_info_attr(record, "OBEX Object Push", 0, 0);

	if (sdp_record_register(sdp_session, record, 0) < 0) {
		error("Registration of service record failed");
		sdp_record_free(record);
		return -1;
	}

	sdp_record_free(record);

	return 0;
}

static int setup_sdp_for_ftp(uint8_t channel)
{
	sdp_record_t *record;
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, opush_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_data_t *chan;

	if (!sdp_session) {
		sdp_session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, 0);
		if (!sdp_session) {
			error("Connection to SDP server failed");
			return -1;
		}
	}

	record = sdp_record_alloc();
	if (!record) {
		error("Allocation of service record failed");
		return -1;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&opush_uuid, OBEX_FILETRANS_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &opush_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_FILETRANS_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	chan = sdp_data_alloc(SDP_UINT8, &channel);
	proto[1] = sdp_list_append(proto[1], chan);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(0, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "OBEX File Transfer", 0, 0);

	if (sdp_record_register(sdp_session, record, 0) < 0) {
		error("Registration of service record failed");
		sdp_record_free(record);
		return -1;
	}

	sdp_record_free(record);

	return 0;
}

static GIOChannel *server_io = NULL;

int start_server(uint8_t channel)
{
	server_io = setup_rfcomm(channel);
	if (!server_io)
		return -1;

	if (setup_sdp_for_push(channel) < 0) {
		g_io_channel_unref(server_io);
		server_io = NULL;
	}

	setup_sdp_for_ftp(channel);

	return 0;
}

void stop_server(void)
{
	sdp_close(sdp_session);

	if (server_io)
		g_io_channel_unref(server_io);
}
