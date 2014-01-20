/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <glib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "btio/btio.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/sdp-client.h"
#include "src/sdpd.h"

#include "bluetooth.h"
#include "log.h"
#include "hal-msg.h"
#include "hal-ipc.h"
#include "ipc.h"
#include "utils.h"
#include "socket.h"

#define SPP_DEFAULT_CHANNEL	3
#define OPP_DEFAULT_CHANNEL	9
#define PBAP_DEFAULT_CHANNEL	15
#define MAS_DEFAULT_CHANNEL	16

#define SVC_HINT_OBEX 0x10

/* Hardcoded MAP stuff needed for MAS SMS Instance.*/
#define DEFAULT_MAS_INSTANCE	0x00

#define MAP_MSG_TYPE_SMS_GSM	0x02
#define MAP_MSG_TYPE_SMS_CDMA	0x04
#define DEFAULT_MAS_MSG_TYPE	(MAP_MSG_TYPE_SMS_GSM | MAP_MSG_TYPE_SMS_CDMA)


static bdaddr_t adapter_addr;

static const uint8_t zero_uuid[16] = { 0 };

/* Simple list of RFCOMM server sockets */
GList *servers = NULL;

/* Simple list of RFCOMM connected sockets */
GList *connections = NULL;

struct rfcomm_sock {
	int fd;		/* descriptor for communication with Java framework */
	int real_sock;	/* real RFCOMM socket */
	int channel;	/* RFCOMM channel */

	guint rfcomm_watch;
	guint stack_watch;

	bdaddr_t dst;
	uint32_t service_handle;

	uint8_t *buf;
	int buf_size;

	const struct profile_info *profile;
};

static int rfsock_set_buffer(struct rfcomm_sock *rfsock)
{
	socklen_t len = sizeof(int);
	int rcv, snd, size, err;

	err = getsockopt(rfsock->real_sock, SOL_SOCKET, SO_RCVBUF, &rcv, &len);
	if (err < 0) {
		error("getsockopt(SO_RCVBUF): %s", strerror(errno));
		return -errno;
	}

	err = getsockopt(rfsock->real_sock, SOL_SOCKET, SO_SNDBUF, &snd, &len);
	if (err < 0) {
		error("getsockopt(SO_SNDBUF): %s", strerror(errno));
		return -errno;
	}

	size = MAX(rcv, snd);

	DBG("Set buffer size %d", size);

	rfsock->buf = g_malloc(size);
	rfsock->buf_size = size;

	return 0;
}

static void cleanup_rfsock(gpointer data)
{
	struct rfcomm_sock *rfsock = data;

	DBG("rfsock: %p fd %d real_sock %d chan %u",
		rfsock, rfsock->fd, rfsock->real_sock, rfsock->channel);

	if (rfsock->fd >= 0)
		if (close(rfsock->fd) < 0)
			error("close() fd %d failed: %s", rfsock->fd,
							strerror(errno));

	if (rfsock->real_sock >= 0)
		if (close(rfsock->real_sock) < 0)
			error("close() fd %d: failed: %s", rfsock->real_sock,
							strerror(errno));

	if (rfsock->rfcomm_watch > 0)
		if (!g_source_remove(rfsock->rfcomm_watch))
			error("rfcomm_watch source was not found");

	if (rfsock->stack_watch > 0)
		if (!g_source_remove(rfsock->stack_watch))
			error("stack_watch source was not found");

	if (rfsock->service_handle)
		bt_adapter_remove_record(rfsock->service_handle);

	if (rfsock->buf)
		g_free(rfsock->buf);

	g_free(rfsock);
}

static struct rfcomm_sock *create_rfsock(int sock, int *hal_fd)
{
	int fds[2] = {-1, -1};
	struct rfcomm_sock *rfsock;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) < 0) {
		error("socketpair(): %s", strerror(errno));
		*hal_fd = -1;
		return NULL;
	}

	rfsock = g_new0(struct rfcomm_sock, 1);
	rfsock->fd = fds[0];
	*hal_fd = fds[1];
	rfsock->real_sock = sock;

	if (sock < 0)
		return rfsock;

	if (rfsock_set_buffer(rfsock) < 0) {
		cleanup_rfsock(rfsock);
		return NULL;
	}

	return rfsock;
}

static sdp_record_t *create_opp_record(uint8_t chan, const char *svc_name)
{
	const char *service_name = "OBEX Object Push";
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, opush_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	uint8_t formats[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
	void *dtds[sizeof(formats)], *values[sizeof(formats)];
	unsigned int i;
	uint8_t dtd = SDP_UINT8;
	sdp_data_t *sflist;
	sdp_data_t *channel;
	sdp_record_t *record;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	record->handle =  sdp_next_handle();

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&opush_uuid, OBEX_OBJPUSH_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &opush_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, OBEX_OBJPUSH_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(NULL, profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &chan);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(NULL, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	for (i = 0; i < sizeof(formats); i++) {
		dtds[i] = &dtd;
		values[i] = &formats[i];
	}
	sflist = sdp_seq_alloc(dtds, values, sizeof(formats));
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FORMATS_LIST, sflist);

	if (svc_name)
		service_name = svc_name;

	sdp_set_info_attr(record, service_name, NULL, NULL);

	sdp_data_free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(proto[2], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static sdp_record_t *create_pbap_record(uint8_t chan, const char *svc_name)
{
	const char *service_name = "OBEX Phonebook Access Server";
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, pbap_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_data_t *channel;
	uint8_t formats[] = { 0x01 };
	uint8_t dtd = SDP_UINT8;
	sdp_data_t *sflist;
	sdp_record_t *record;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	record->handle =  sdp_next_handle();

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&pbap_uuid, PBAP_PSE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &pbap_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, PBAP_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(NULL, profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &chan);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(NULL, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	sflist = sdp_data_alloc(dtd, formats);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_REPOSITORIES, sflist);

	if (svc_name)
		service_name = svc_name;

	sdp_set_info_attr(record, service_name, NULL, NULL);

	sdp_data_free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(proto[2], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static sdp_record_t *create_mas_record(uint8_t chan, const char *svc_name)
{
	const char *service_name = "MAP MAS SMS";
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, mse_uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[3];
	sdp_data_t *channel;
	uint8_t minst = DEFAULT_MAS_INSTANCE;
	uint8_t mtype = DEFAULT_MAS_MSG_TYPE;
	sdp_record_t *record;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	record->handle =  sdp_next_handle();

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&mse_uuid, MAP_MSE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &mse_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, MAP_PROFILE_ID);
	profile[0].version = 0x0101;
	pfseq = sdp_list_append(NULL, profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_attr_add_new(record, SDP_ATTR_MAS_INSTANCE_ID, SDP_UINT8, &minst);
	sdp_attr_add_new(record, SDP_ATTR_SUPPORTED_MESSAGE_TYPES, SDP_UINT8,
									&mtype);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &chan);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(NULL, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	if (svc_name)
		service_name = svc_name;

	sdp_set_info_attr(record, service_name, NULL, NULL);

	sdp_data_free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(proto[2], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static sdp_record_t *create_spp_record(uint8_t chan, const char *svc_name)
{
	const char *service_name = "Serial Port";
	sdp_list_t *svclass_id, *apseq, *profiles, *root;
	uuid_t root_uuid, sp_uuid, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_data_t *channel;
	sdp_record_t *record;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	record->handle =  sdp_next_handle();

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&sp_uuid, SERIAL_PORT_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &sp_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, profiles);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &chan);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_add_lang_attr(record);

	if (svc_name)
		service_name = svc_name;

	sdp_set_info_attr(record, service_name, "BlueZ", "COM Port");

	sdp_set_url_attr(record, "http://www.bluez.org/",
			"http://www.bluez.org/", "http://www.bluez.org/");

	sdp_set_service_id(record, sp_uuid);
	sdp_set_service_ttl(record, 0xffff);
	sdp_set_service_avail(record, 0xff);
	sdp_set_record_state(record, 0x00001234);

	sdp_data_free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);
	sdp_list_free(profiles, NULL);

	return record;
}

static const struct profile_info {
	uint8_t		uuid[16];
	uint8_t		channel;
	uint8_t		svc_hint;
	BtIOSecLevel	sec_level;
	sdp_record_t *	(*create_record)(uint8_t chan, const char *svc_name);
} profiles[] = {
	{
		.uuid = {
			0x00, 0x00, 0x11, 0x2F, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		},
		.channel = PBAP_DEFAULT_CHANNEL,
		.svc_hint = SVC_HINT_OBEX,
		.sec_level = BT_IO_SEC_MEDIUM,
		.create_record = create_pbap_record
	}, {
		.uuid = {
			0x00, 0x00, 0x11, 0x05, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		  },
		.channel = OPP_DEFAULT_CHANNEL,
		.svc_hint = SVC_HINT_OBEX,
		.sec_level = BT_IO_SEC_LOW,
		.create_record = create_opp_record
	}, {
		.uuid = {
			0x00, 0x00, 0x11, 0x32, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		},
		.channel = MAS_DEFAULT_CHANNEL,
		.svc_hint = SVC_HINT_OBEX,
		.sec_level = BT_IO_SEC_MEDIUM,
		.create_record = create_mas_record
	}, {
		.uuid = {
			0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		},
		.channel = SPP_DEFAULT_CHANNEL,
		.svc_hint = 0,
		.sec_level = BT_IO_SEC_MEDIUM,
		.create_record = create_spp_record
	},
};

static uint32_t sdp_service_register(const struct profile_info *profile,
							const void *svc_name)
{
	sdp_record_t *record;

	if (!profile || !profile->create_record)
		return 0;

	record = profile->create_record(profile->channel, svc_name);
	if (!record)
		return 0;

	if (bt_adapter_add_record(record, profile->svc_hint) < 0) {
		error("Failed to register on SDP record");
		sdp_record_free(record);
		return 0;
	}

	return record->handle;
}

static int bt_sock_send_fd(int sock_fd, const void *buf, int len, int send_fd)
{
	ssize_t ret;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iv;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];

	DBG("len %d sock_fd %d send_fd %d", len, sock_fd, send_fd);

	if (sock_fd == -1 || send_fd == -1)
		return -1;

	memset(&msg, 0, sizeof(msg));
	memset(cmsgbuf, 0, sizeof(cmsgbuf));

	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));

	memcpy(CMSG_DATA(cmsg), &send_fd, sizeof(send_fd));

	iv.iov_base = (unsigned char *) buf;
	iv.iov_len = len;

	msg.msg_iov = &iv;
	msg.msg_iovlen = 1;

	ret = sendmsg(sock_fd, &msg, MSG_NOSIGNAL);
	if (ret < 0) {
		error("sendmsg(): sock_fd %d send_fd %d: %s",
					sock_fd, send_fd, strerror(errno));
		return ret;
	}

	return ret;
}

static const struct profile_info *get_profile_by_uuid(const uint8_t *uuid)
{
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(profiles); i++) {
		if (!memcmp(profiles[i].uuid, uuid, 16))
			return &profiles[i];
	}

	return NULL;
}

static int try_write_all(int fd, unsigned char *buf, int len)
{
	int sent = 0;

	while (len > 0) {
		int written;

		written = write(fd, buf, len);
		if (written < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}

		if (!written)
			return 0;

		len -= written; buf += written; sent += written;
	}

	return sent;
}

static gboolean sock_stack_event_cb(GIOChannel *io, GIOCondition cond,
								gpointer data)
{
	struct rfcomm_sock *rfsock = data;
	int len, sent;

	if (cond & G_IO_HUP) {
		DBG("Socket %d hang up", g_io_channel_unix_get_fd(io));
		goto fail;
	}

	if (cond & (G_IO_ERR | G_IO_NVAL)) {
		error("Socket error: sock %d cond %d",
					g_io_channel_unix_get_fd(io), cond);
		goto fail;
	}

	len = read(rfsock->fd, rfsock->buf, rfsock->buf_size);
	if (len <= 0) {
		error("read(): %s", strerror(errno));
		/* Read again */
		return TRUE;
	}

	sent = try_write_all(rfsock->real_sock, rfsock->buf, len);
	if (sent < 0) {
		error("write(): %s", strerror(errno));
		goto fail;
	}

	return TRUE;
fail:
	connections = g_list_remove(connections, rfsock);
	cleanup_rfsock(rfsock);

	return FALSE;
}

static gboolean sock_rfcomm_event_cb(GIOChannel *io, GIOCondition cond,
								gpointer data)
{
	struct rfcomm_sock *rfsock = data;
	int len, sent;

	if (cond & G_IO_HUP) {
		DBG("Socket %d hang up", g_io_channel_unix_get_fd(io));
		goto fail;
	}

	if (cond & (G_IO_ERR | G_IO_NVAL)) {
		error("Socket error: sock %d cond %d",
					g_io_channel_unix_get_fd(io), cond);
		goto fail;
	}

	len = read(rfsock->real_sock, rfsock->buf, rfsock->buf_size);
	if (len <= 0) {
		error("read(): %s", strerror(errno));
		/* Read again */
		return TRUE;
	}

	sent = try_write_all(rfsock->fd, rfsock->buf, len);
	if (sent < 0) {
		error("write(): %s", strerror(errno));
		goto fail;
	}

	return TRUE;
fail:
	connections = g_list_remove(connections, rfsock);
	cleanup_rfsock(rfsock);

	return FALSE;
}

static bool sock_send_accept(struct rfcomm_sock *rfsock, bdaddr_t *bdaddr,
							int fd_accepted)
{
	struct hal_sock_connect_signal cmd;
	int len;

	DBG("");

	cmd.size = sizeof(cmd);
	bdaddr2android(bdaddr, cmd.bdaddr);
	cmd.channel = rfsock->channel;
	cmd.status = 0;

	len = bt_sock_send_fd(rfsock->fd, &cmd, sizeof(cmd), fd_accepted);
	if (len != sizeof(cmd)) {
		error("Error sending accept signal");
		return false;
	}

	return true;
}

static gboolean sock_server_stack_event_cb(GIOChannel *io, GIOCondition cond,
								gpointer data)
{
	struct rfcomm_sock *rfsock = data;

	DBG("sock %d cond %d", g_io_channel_unix_get_fd(io), cond);

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP )) {
		servers = g_list_remove(servers, rfsock);
		cleanup_rfsock(rfsock);
	}

	return FALSE;
}

static void accept_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct rfcomm_sock *rfsock = user_data;
	struct rfcomm_sock *rfsock_acc;
	GIOChannel *io_stack;
	GError *gerr = NULL;
	bdaddr_t dst;
	char address[18];
	int sock_acc;
	int hal_fd;
	guint id;
	GIOCondition cond;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(io, &gerr,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	ba2str(&dst, address);
	DBG("Incoming connection from %s rfsock %p", address, rfsock);

	sock_acc = g_io_channel_unix_get_fd(io);
	rfsock_acc = create_rfsock(sock_acc, &hal_fd);
	if (!rfsock_acc) {
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	DBG("rfsock: fd %d real_sock %d chan %u sock %d",
		rfsock->fd, rfsock->real_sock, rfsock->channel,
		sock_acc);

	if (!sock_send_accept(rfsock, &dst, hal_fd)) {
		cleanup_rfsock(rfsock_acc);
		return;
	}

	connections = g_list_append(connections, rfsock_acc);

	/* Handle events from Android */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_stack = g_io_channel_unix_new(rfsock_acc->fd);
	id = g_io_add_watch(io_stack, cond, sock_stack_event_cb, rfsock_acc);
	g_io_channel_unref(io_stack);

	rfsock_acc->stack_watch = id;

	/* Handle rfcomm events */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	id = g_io_add_watch(io, cond, sock_rfcomm_event_cb, rfsock_acc);
	g_io_channel_set_close_on_unref(io, FALSE);

	rfsock_acc->rfcomm_watch = id;

	DBG("rfsock %p rfsock_acc %p stack_watch %d rfcomm_watch %d",
		rfsock, rfsock_acc, rfsock_acc->stack_watch,
		rfsock_acc->rfcomm_watch);
}

static uint8_t rfcomm_listen(int chan, const uint8_t *name, const uint8_t *uuid,
						uint8_t flags, int *hal_fd)
{
	const struct profile_info *profile;
	struct rfcomm_sock *rfsock = NULL;
	BtIOSecLevel sec_level;
	GIOChannel *io, *io_stack;
	GIOCondition cond;
	GError *err = NULL;
	guint id;

	DBG("");

	if (!memcmp(uuid, zero_uuid, sizeof(zero_uuid)) && chan <= 0) {
		error("Invalid rfcomm listen params");
		return HAL_STATUS_INVALID;
	}

	profile = get_profile_by_uuid(uuid);
	if (!profile) {
		if (chan <= 0)
			return HAL_STATUS_INVALID;

		sec_level = BT_IO_SEC_MEDIUM;
	} else {
		chan = profile->channel;
		sec_level = profile->sec_level;
	}

	DBG("rfcomm channel %d svc_name %s", chan, name);

	rfsock = create_rfsock(-1, hal_fd);
	if (!rfsock)
		return HAL_STATUS_FAILED;

	io = bt_io_listen(accept_cb, NULL, rfsock, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_SEC_LEVEL, sec_level,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Failed listen: %s", err->message);
		g_error_free(err);
		goto failed;
	}

	rfsock->real_sock = g_io_channel_unix_get_fd(io);

	g_io_channel_set_close_on_unref(io, FALSE);
	g_io_channel_unref(io);

	/* Handle events from Android */
	cond = G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_stack = g_io_channel_unix_new(rfsock->fd);
	id = g_io_add_watch_full(io_stack, G_PRIORITY_HIGH, cond,
					sock_server_stack_event_cb, rfsock,
					NULL);
	g_io_channel_unref(io_stack);

	rfsock->stack_watch = id;

	DBG("real_sock %d fd %d hal_fd %d", rfsock->real_sock, rfsock->fd,
								*hal_fd);

	if (write(rfsock->fd, &chan, sizeof(chan)) != sizeof(chan)) {
		error("Error sending RFCOMM channel");
		goto failed;
	}

	rfsock->service_handle = sdp_service_register(profile, name);

	servers = g_list_append(servers, rfsock);

	return HAL_STATUS_SUCCESS;

failed:

	cleanup_rfsock(rfsock);
	close(*hal_fd);
	return HAL_STATUS_FAILED;
}

static void handle_listen(const void *buf, uint16_t len)
{
	const struct hal_cmd_sock_listen *cmd = buf;
	uint8_t status;
	int hal_fd;

	switch (cmd->type) {
	case HAL_SOCK_RFCOMM:
		status = rfcomm_listen(cmd->channel, cmd->name, cmd->uuid,
							cmd->flags, &hal_fd);
		break;
	case HAL_SOCK_SCO:
	case HAL_SOCK_L2CAP:
		status = HAL_STATUS_UNSUPPORTED;
		break;
	default:
		status = HAL_STATUS_INVALID;
		break;
	}

	if (status != HAL_STATUS_SUCCESS)
		goto failed;

	ipc_send_rsp_full(HAL_SERVICE_ID_SOCK, HAL_OP_SOCK_LISTEN, 0, NULL,
									hal_fd);
	close(hal_fd);
	return ;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_SOCK, HAL_OP_SOCK_LISTEN, status);
}

static bool sock_send_connect(struct rfcomm_sock *rfsock, bdaddr_t *bdaddr)
{
	struct hal_sock_connect_signal cmd;
	int len;

	DBG("");

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	bdaddr2android(bdaddr, cmd.bdaddr);
	cmd.channel = rfsock->channel;
	cmd.status = 0;

	len = write(rfsock->fd, &cmd, sizeof(cmd));
	if (len < 0) {
		error("%s", strerror(errno));
		return false;
	}

	if (len != sizeof(cmd)) {
		error("Error sending connect signal");
		return false;
	}

	return true;
}

static void connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct rfcomm_sock *rfsock = user_data;
	bdaddr_t *dst = &rfsock->dst;
	GIOChannel *io_stack;
	char address[18];
	guint id;
	GIOCondition cond;

	if (err) {
		error("%s", err->message);
		goto fail;
	}

	ba2str(dst, address);
	DBG("Connected to %s", address);

	DBG("rfsock: fd %d real_sock %d chan %u sock %d",
		rfsock->fd, rfsock->real_sock, rfsock->channel,
		g_io_channel_unix_get_fd(io));

	if (!sock_send_connect(rfsock, dst))
		goto fail;

	/* Handle events from Android */
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	io_stack = g_io_channel_unix_new(rfsock->fd);
	id = g_io_add_watch(io_stack, cond, sock_stack_event_cb, rfsock);
	g_io_channel_unref(io_stack);

	rfsock->stack_watch = id;

	/* Handle rfcomm events */
	cond = G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	id = g_io_add_watch(io, cond, sock_rfcomm_event_cb, rfsock);
	g_io_channel_set_close_on_unref(io, FALSE);

	rfsock->rfcomm_watch = id;

	return;
fail:
	connections = g_list_remove(connections, rfsock);
	cleanup_rfsock(rfsock);
}

static bool do_rfcomm_connect(struct rfcomm_sock *rfsock, int chan)
{
	BtIOSecLevel sec_level = BT_IO_SEC_MEDIUM;
	GIOChannel *io;
	GError *gerr = NULL;

	if (rfsock->profile)
		sec_level = rfsock->profile->sec_level;

	io = bt_io_connect(connect_cb, rfsock, NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_DEST_BDADDR, &rfsock->dst,
				BT_IO_OPT_CHANNEL, chan,
				BT_IO_OPT_SEC_LEVEL, sec_level,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("Failed connect: %s", gerr->message);
		g_error_free(gerr);
		return false;
	}

	g_io_channel_set_close_on_unref(io, FALSE);
	g_io_channel_unref(io);

	if (write(rfsock->fd, &chan, sizeof(chan)) != sizeof(chan)) {
		error("Error sending RFCOMM channel");
		return false;
	}

	rfsock->real_sock = g_io_channel_unix_get_fd(io);
	rfsock_set_buffer(rfsock);
	rfsock->channel = chan;
	connections = g_list_append(connections, rfsock);

	return true;
}

static void sdp_search_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct rfcomm_sock *rfsock = data;
	sdp_list_t *list;
	int chan;

	DBG("");

	if (err < 0) {
		error("Unable to get SDP record: %s", strerror(-err));
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No SDP records found");
		goto fail;
	}

	for (list = recs; list != NULL; list = list->next) {
		sdp_record_t *rec = list->data;
		sdp_list_t *protos;

		if (sdp_get_access_protos(rec, &protos) < 0) {
			error("Unable to get proto list");
			goto fail;
		}

		chan = sdp_get_proto_port(protos, RFCOMM_UUID);

		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free,
									NULL);
		sdp_list_free(protos, NULL);

		if (chan)
			break;
	}

	if (chan <= 0) {
		error("Could not get RFCOMM channel %d", chan);
		goto fail;
	}

	DBG("Got RFCOMM channel %d", chan);

	if (do_rfcomm_connect(rfsock, chan))
		return;
fail:
	cleanup_rfsock(rfsock);
}

static uint8_t connect_rfcomm(const bdaddr_t *addr, int chan,
				const uint8_t *uuid, uint8_t flags, int *hal_fd)
{
	struct rfcomm_sock *rfsock;
	uuid_t uu;

	if ((!memcmp(uuid, zero_uuid, sizeof(zero_uuid)) && chan <= 0) ||
						!bacmp(addr, BDADDR_ANY)) {
		error("Invalid rfcomm connect params");
		return HAL_STATUS_INVALID;
	}

	rfsock = create_rfsock(-1, hal_fd);
	if (!rfsock)
		return HAL_STATUS_FAILED;

	bacpy(&rfsock->dst, addr);

	if (!memcmp(uuid, zero_uuid, sizeof(zero_uuid))) {
		if (!do_rfcomm_connect(rfsock, chan))
			goto failed;
	} else {
		memset(&uu, 0, sizeof(uu));
		uu.type = SDP_UUID128;
		memcpy(&uu.value.uuid128, uuid, sizeof(uint128_t));

		rfsock->profile = get_profile_by_uuid(uuid);

		if (bt_search_service(&adapter_addr, &rfsock->dst, &uu,
					sdp_search_cb, rfsock, NULL, 0) < 0) {
			error("Failed to search SDP records");
			goto failed;
		}
	}

	return HAL_STATUS_SUCCESS;

failed:
	cleanup_rfsock(rfsock);
	close(*hal_fd);
	return HAL_STATUS_FAILED;
}

static void handle_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_sock_connect *cmd = buf;
	bdaddr_t bdaddr;
	uint8_t status;
	int hal_fd;

	DBG("");

	android2bdaddr(cmd->bdaddr, &bdaddr);

	switch (cmd->type) {
	case HAL_SOCK_RFCOMM:
		status = connect_rfcomm(&bdaddr, cmd->channel, cmd->uuid,
							cmd->flags, &hal_fd);
		break;
	case HAL_SOCK_SCO:
	case HAL_SOCK_L2CAP:
		status = HAL_STATUS_UNSUPPORTED;
		break;
	default:
		status = HAL_STATUS_INVALID;
		break;
	}

	if (status != HAL_STATUS_SUCCESS)
		goto failed;

	ipc_send_rsp_full(HAL_SERVICE_ID_SOCK, HAL_OP_SOCK_CONNECT, 0, NULL,
									hal_fd);
	close(hal_fd);
	return;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_SOCK, HAL_OP_SOCK_CONNECT, status);

}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_SOCK_LISTEN */
	{ handle_listen, false, sizeof(struct hal_cmd_sock_listen) },
	/* HAL_OP_SOCK_CONNECT */
	{ handle_connect, false, sizeof(struct hal_cmd_sock_connect) },
};

void bt_socket_register(const bdaddr_t *addr)
{
	DBG("");

	bacpy(&adapter_addr, addr);
	ipc_register(HAL_SERVICE_ID_SOCK, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));
}

void bt_socket_unregister(void)
{
	DBG("");

	g_list_free_full(connections, cleanup_rfsock);
	g_list_free_full(servers, cleanup_rfsock);

	ipc_unregister(HAL_SERVICE_ID_SOCK);
}
