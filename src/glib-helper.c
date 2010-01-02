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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sco.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "glib-helper.h"

/* Number of seconds to keep a sdp_session_t in the cache */
#define CACHE_TIMEOUT 2

struct cached_sdp_session {
	bdaddr_t src;
	bdaddr_t dst;
	sdp_session_t *session;
	guint timer;
};

static GSList *cached_sdp_sessions = NULL;

struct hci_cmd_data {
	bt_hci_result_t		cb;
	uint16_t		handle;
	uint16_t		ocf;
	gpointer		caller_data;
};

static gboolean cached_session_expired(gpointer user_data)
{
	struct cached_sdp_session *cached = user_data;

	cached_sdp_sessions = g_slist_remove(cached_sdp_sessions, cached);

	sdp_close(cached->session);

	g_free(cached);

	return FALSE;
}

static sdp_session_t *get_sdp_session(const bdaddr_t *src, const bdaddr_t *dst)
{
	GSList *l;

	for (l = cached_sdp_sessions; l != NULL; l = l->next) {
		struct cached_sdp_session *c = l->data;
		sdp_session_t *session;

		if (bacmp(&c->src, src) || bacmp(&c->dst, dst))
			continue;

		g_source_remove(c->timer);

		session = c->session;

		cached_sdp_sessions = g_slist_remove(cached_sdp_sessions, c);
		g_free(c);

		return session;
	}

	return sdp_connect(src, dst, SDP_NON_BLOCKING);
}

static void cache_sdp_session(bdaddr_t *src, bdaddr_t *dst,
				sdp_session_t *session)
{
	struct cached_sdp_session *cached;

	cached = g_new0(struct cached_sdp_session, 1);

	bacpy(&cached->src, src);
	bacpy(&cached->dst, dst);

	cached->session = session;

	cached_sdp_sessions = g_slist_append(cached_sdp_sessions, cached);

	cached->timer = g_timeout_add_seconds(CACHE_TIMEOUT,
						cached_session_expired,
						cached);
}

int set_nonblocking(int fd)
{
	long arg;

	arg = fcntl(fd, F_GETFL);
	if (arg < 0)
		return -errno;

	/* Return if already nonblocking */
	if (arg & O_NONBLOCK)
		return 0;

	arg |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, arg) < 0)
		return -errno;

	return 0;
}

struct search_context {
	bdaddr_t		src;
	bdaddr_t		dst;
	sdp_session_t		*session;
	bt_callback_t		cb;
	bt_destroy_t		destroy;
	gpointer		user_data;
	uuid_t			uuid;
	guint			io_id;
};

static GSList *context_list = NULL;

static void search_context_cleanup(struct search_context *ctxt)
{
	context_list = g_slist_remove(context_list, ctxt);

	if (ctxt->destroy)
		ctxt->destroy(ctxt->user_data);

	g_free(ctxt);
}

static void search_completed_cb(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *recs = NULL;
	int scanned, seqlen = 0, bytesleft = size;
	uint8_t dataType;
	int err = 0;

	if (status || type != SDP_SVC_SEARCH_ATTR_RSP) {
		err = -EPROTO;
		goto done;
	}

	scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
	if (!scanned || !seqlen)
		goto done;

	rsp += scanned;
	bytesleft -= scanned;
	do {
		sdp_record_t *rec;
		int recsize;

		recsize = 0;
		rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free(rec);
			break;
		}

		scanned += recsize;
		rsp += recsize;
		bytesleft -= recsize;

		recs = sdp_list_append(recs, rec);
	} while (scanned < (ssize_t) size && bytesleft > 0);

done:
	cache_sdp_session(&ctxt->src, &ctxt->dst, ctxt->session);

	if (ctxt->cb)
		ctxt->cb(recs, err, ctxt->user_data);

	if (recs)
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);

	search_context_cleanup(ctxt);
}

static gboolean search_process_cb(GIOChannel *chan,
			GIOCondition cond, void *user_data)
{
	struct search_context *ctxt = user_data;
	int err = 0;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL)) {
		err = EIO;
		goto failed;
	}

	if (sdp_process(ctxt->session) < 0)
		goto failed;

	return TRUE;

failed:
	if (err) {
		sdp_close(ctxt->session);
		ctxt->session = NULL;

		if (ctxt->cb)
			ctxt->cb(NULL, err, ctxt->user_data);

		search_context_cleanup(ctxt);
	}

	return FALSE;
}

static gboolean connect_watch(GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	struct search_context *ctxt = user_data;
	sdp_list_t *search, *attrids;
	uint32_t range = 0x0000ffff;
	socklen_t len;
	int sk, err = 0;

	sk = g_io_channel_unix_get_fd(chan);
	ctxt->io_id = 0;

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		err = errno;
		goto failed;
	}

	if (err != 0)
		goto failed;

	if (sdp_set_notify(ctxt->session, search_completed_cb, ctxt) < 0) {
		err = EIO;
		goto failed;
	}

	search = sdp_list_append(NULL, &ctxt->uuid);
	attrids = sdp_list_append(NULL, &range);
	if (sdp_service_search_attr_async(ctxt->session,
				search, SDP_ATTR_REQ_RANGE, attrids) < 0) {
		sdp_list_free(attrids, NULL);
		sdp_list_free(search, NULL);
		err = EIO;
		goto failed;
	}

	sdp_list_free(attrids, NULL);
	sdp_list_free(search, NULL);

	/* Set callback responsible for update the internal SDP transaction */
	ctxt->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				search_process_cb, ctxt);
	return FALSE;

failed:
	sdp_close(ctxt->session);
	ctxt->session = NULL;

	if (ctxt->cb)
		ctxt->cb(NULL, -err, ctxt->user_data);

	search_context_cleanup(ctxt);

	return FALSE;
}

static int create_search_context(struct search_context **ctxt,
				const bdaddr_t *src, const bdaddr_t *dst,
				uuid_t *uuid)
{
	sdp_session_t *s;
	GIOChannel *chan;

	if (!ctxt)
		return -EINVAL;

	s = get_sdp_session(src, dst);
	if (!s)
		return -errno;

	*ctxt = g_try_malloc0(sizeof(struct search_context));
	if (!*ctxt) {
		sdp_close(s);
		return -ENOMEM;
	}

	bacpy(&(*ctxt)->src, src);
	bacpy(&(*ctxt)->dst, dst);
	(*ctxt)->session = s;
	(*ctxt)->uuid = *uuid;

	chan = g_io_channel_unix_new(sdp_get_socket(s));
	(*ctxt)->io_id = g_io_add_watch(chan,
				G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				connect_watch, *ctxt);
	g_io_channel_unref(chan);

	return 0;
}

int bt_search_service(const bdaddr_t *src, const bdaddr_t *dst,
			uuid_t *uuid, bt_callback_t cb, void *user_data,
			bt_destroy_t destroy)
{
	struct search_context *ctxt = NULL;
	int err;

	if (!cb)
		return -EINVAL;

	err = create_search_context(&ctxt, src, dst, uuid);
	if (err < 0)
		return err;

	ctxt->cb	= cb;
	ctxt->destroy	= destroy;
	ctxt->user_data	= user_data;

	context_list = g_slist_append(context_list, ctxt);

	return 0;
}

int bt_discover_services(const bdaddr_t *src, const bdaddr_t *dst,
		bt_callback_t cb, void *user_data, bt_destroy_t destroy)
{
	uuid_t uuid;

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);

	return bt_search_service(src, dst, &uuid, cb, user_data, destroy);
}

static int find_by_bdaddr(const void *data, const void *user_data)
{
	const struct search_context *ctxt = data, *search = user_data;

	return (bacmp(&ctxt->dst, &search->dst) &&
					bacmp(&ctxt->src, &search->src));
}

int bt_cancel_discovery(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct search_context search, *ctxt;
	GSList *match;

	memset(&search, 0, sizeof(search));
	bacpy(&search.src, src);
	bacpy(&search.dst, dst);

	/* Ongoing SDP Discovery */
	match = g_slist_find_custom(context_list, &search, find_by_bdaddr);
	if (!match)
		return -ENODATA;

	ctxt = match->data;
	if (!ctxt->session)
		return -ENOTCONN;

	if (ctxt->io_id)
		g_source_remove(ctxt->io_id);

	if (ctxt->session)
		sdp_close(ctxt->session);

	search_context_cleanup(ctxt);
	return 0;
}

char *bt_uuid2string(uuid_t *uuid)
{
	gchar *str;
	uuid_t uuid128;
	unsigned int data0;
	unsigned short data1;
	unsigned short data2;
	unsigned short data3;
	unsigned int data4;
	unsigned short data5;

	if (!uuid)
		return NULL;

	switch (uuid->type) {
	case SDP_UUID16:
		sdp_uuid16_to_uuid128(&uuid128, uuid);
		break;
	case SDP_UUID32:
		sdp_uuid32_to_uuid128(&uuid128, uuid);
		break;
	case SDP_UUID128:
		memcpy(&uuid128, uuid, sizeof(uuid_t));
		break;
	default:
		/* Type of UUID unknown */
		return NULL;
	}

	memcpy(&data0, &uuid128.value.uuid128.data[0], 4);
	memcpy(&data1, &uuid128.value.uuid128.data[4], 2);
	memcpy(&data2, &uuid128.value.uuid128.data[6], 2);
	memcpy(&data3, &uuid128.value.uuid128.data[8], 2);
	memcpy(&data4, &uuid128.value.uuid128.data[10], 4);
	memcpy(&data5, &uuid128.value.uuid128.data[14], 2);

	str = g_try_malloc0(MAX_LEN_UUID_STR);
	if (!str)
		return NULL;

	sprintf(str, "%.8x-%.4x-%.4x-%.4x-%.8x%.4x",
			g_ntohl(data0), g_ntohs(data1),
			g_ntohs(data2), g_ntohs(data3),
			g_ntohl(data4), g_ntohs(data5));

	return str;
}

static struct {
	const char	*name;
	uint16_t	class;
} bt_services[] = {
	{ "vcp",	VIDEO_CONF_SVCLASS_ID		},
	{ "pbap",	PBAP_SVCLASS_ID			},
	{ "sap",	SAP_SVCLASS_ID			},
	{ "ftp",	OBEX_FILETRANS_SVCLASS_ID	},
	{ "bpp",	BASIC_PRINTING_SVCLASS_ID	},
	{ "bip",	IMAGING_SVCLASS_ID		},
	{ "synch",	IRMC_SYNC_SVCLASS_ID		},
	{ "dun",	DIALUP_NET_SVCLASS_ID		},
	{ "opp",	OBEX_OBJPUSH_SVCLASS_ID		},
	{ "fax",	FAX_SVCLASS_ID			},
	{ "spp",	SERIAL_PORT_SVCLASS_ID		},
	{ "hsp",	HEADSET_SVCLASS_ID		},
	{ "hfp",	HANDSFREE_SVCLASS_ID		},
	{ }
};

uint16_t bt_name2class(const char *pattern)
{
	int i;

	for (i = 0; bt_services[i].name; i++) {
		if (strcasecmp(bt_services[i].name, pattern) == 0)
			return bt_services[i].class;
	}

	return 0;
}

static inline gboolean is_uuid128(const char *string)
{
	return (strlen(string) == 36 &&
			string[8] == '-' &&
			string[13] == '-' &&
			string[18] == '-' &&
			string[23] == '-');
}

char *bt_name2string(const char *pattern)
{
	uuid_t uuid;
	uint16_t uuid16;
	int i;

	/* UUID 128 string format */
	if (is_uuid128(pattern))
		return g_strdup(pattern);

	/* Friendly service name format */
	uuid16 = bt_name2class(pattern);
	if (uuid16)
		goto proceed;

	/* HEX format */
	uuid16 = strtol(pattern, NULL, 16);
	for (i = 0; bt_services[i].class; i++) {
		if (bt_services[i].class == uuid16)
			goto proceed;
	}

	return NULL;

proceed:
	sdp_uuid16_create(&uuid, uuid16);

	return bt_uuid2string(&uuid);
}

int bt_string2uuid(uuid_t *uuid, const char *string)
{
	uint32_t data0, data4;
	uint16_t data1, data2, data3, data5;

	if (is_uuid128(string) &&
			sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = g_htonl(data0);
		data1 = g_htons(data1);
		data2 = g_htons(data2);
		data3 = g_htons(data3);
		data4 = g_htonl(data4);
		data5 = g_htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create(uuid, val);

		return 0;
	} else {
		uint16_t class = bt_name2class(string);
		if (class) {
			sdp_uuid16_create(uuid, class);
			return 0;
		}
	}

	return -1;
}

gchar *bt_list2string(GSList *list)
{
	GSList *l;
	gchar *str, *tmp;

	if (!list)
		return NULL;

	str = g_strdup((const gchar *) list->data);

	for (l = list->next; l; l = l->next) {
		tmp = g_strconcat(str, " " , (const gchar *) l->data, NULL);
		g_free(str);
		str = tmp;
	}

	return str;
}

GSList *bt_string2list(const gchar *str)
{
	GSList *l = NULL;
	gchar **uuids;
	int i = 0;

	if (!str)
		return NULL;

	/* FIXME: eglib doesn't support g_strsplit */
	uuids = g_strsplit(str, " ", 0);
	if (!uuids)
		return NULL;

	while (uuids[i]) {
		l = g_slist_append(l, uuids[i]);
		i++;
	}

	g_free(uuids);

	return l;
}

static gboolean hci_event_watch(GIOChannel *io,
			GIOCondition cond, gpointer user_data)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *body;
	struct hci_cmd_data *cmd = user_data;
	evt_cmd_status *evt_status;
	evt_auth_complete *evt_auth;
	evt_encrypt_change *evt_enc;
	hci_event_hdr *hdr;
	set_conn_encrypt_cp cp;
	int dd;
	uint16_t ocf;
	uint8_t status = HCI_OE_POWER_OFF;

	if (cond & G_IO_NVAL) {
		cmd->cb(status, cmd->caller_data);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	dd = g_io_channel_unix_get_fd(io);

	if (read(dd, buf, sizeof(buf)) < 0)
		goto failed;

	hdr = (hci_event_hdr *) (buf + 1);
	body = buf + (1 + HCI_EVENT_HDR_SIZE);

	switch (hdr->evt) {
	case EVT_CMD_STATUS:
		evt_status = (evt_cmd_status *) body;
		ocf = cmd_opcode_ocf(evt_status->opcode);
		if (ocf != cmd->ocf)
			return TRUE;
		switch (ocf) {
		case OCF_AUTH_REQUESTED:
		case OCF_SET_CONN_ENCRYPT:
			if (evt_status->status != 0) {
				/* Baseband rejected command */
				status = evt_status->status;
				goto failed;
			}
			break;
		default:
			return TRUE;
		}
		/* Wait for the next event */
		return TRUE;
	case EVT_AUTH_COMPLETE:
		evt_auth = (evt_auth_complete *) body;
		if (evt_auth->handle != cmd->handle) {
			/* Skipping */
			return TRUE;
		}

		if (evt_auth->status != 0x00) {
			status = evt_auth->status;
			/* Abort encryption */
			goto failed;
		}

		memset(&cp, 0, sizeof(cp));
		cp.handle  = cmd->handle;
		cp.encrypt = 1;

		cmd->ocf = OCF_SET_CONN_ENCRYPT;

		if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_SET_CONN_ENCRYPT,
					SET_CONN_ENCRYPT_CP_SIZE, &cp) < 0) {
			status = HCI_COMMAND_DISALLOWED;
			goto failed;
		}
		/* Wait for encrypt change event */
		return TRUE;
	case EVT_ENCRYPT_CHANGE:
		evt_enc = (evt_encrypt_change *) body;
		if (evt_enc->handle != cmd->handle)
			return TRUE;

		/* Procedure finished: reporting status */
		status = evt_enc->status;
		break;
	default:
		/* Skipping */
		return TRUE;
	}

failed:
	cmd->cb(status, cmd->caller_data);
	g_io_channel_shutdown(io, TRUE, NULL);

	return FALSE;
}

int bt_acl_encrypt(const bdaddr_t *src, const bdaddr_t *dst,
			bt_hci_result_t cb, gpointer user_data)
{
	GIOChannel *io;
	struct hci_cmd_data *cmd;
	struct hci_conn_info_req *cr;
	auth_requested_cp cp;
	struct hci_filter nf;
	int dd, dev_id, err;
	char src_addr[18];
	uint32_t link_mode;
	uint16_t handle;

	ba2str(src, src_addr);
	dev_id = hci_devid(src_addr);
	if (dev_id < 0)
		return -errno;

	dd = hci_open_dev(dev_id);
	if (dd < 0)
		return -errno;

	cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	cr->type = ACL_LINK;
	bacpy(&cr->bdaddr, dst);

	err = ioctl(dd, HCIGETCONNINFO, cr);
	link_mode = cr->conn_info->link_mode;
	handle = cr->conn_info->handle;
	g_free(cr);

	if (err < 0) {
		err = errno;
		goto failed;
	}

	if (link_mode & HCI_LM_ENCRYPT) {
		/* Already encrypted */
		err = EALREADY;
		goto failed;
	}

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_AUTH_REQUESTED,
				AUTH_REQUESTED_CP_SIZE, &cp) < 0) {
		err = errno;
		goto failed;
	}

	cmd = g_new0(struct hci_cmd_data, 1);
	cmd->handle = handle;
	cmd->ocf = OCF_AUTH_REQUESTED;
	cmd->cb	= cb;
	cmd->caller_data = user_data;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_AUTH_COMPLETE, &nf);
	hci_filter_set_event(EVT_ENCRYPT_CHANGE, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		err = errno;
		g_free(cmd);
		goto failed;
	}

	io = g_io_channel_unix_new(dd);
	g_io_channel_set_close_on_unref(io, FALSE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_HUP | G_IO_ERR | G_IO_NVAL | G_IO_IN,
			hci_event_watch, cmd, g_free);
	g_io_channel_unref(io);

	return 0;

failed:
	close(dd);

	return -err;
}
