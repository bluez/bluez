/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "hcid.h"
#include "textfile.h"

#define MAX_IDENTIFIER_LEN	29	/* "XX:XX:XX:XX:XX:XX/0xYYYYYYYY\0" */

struct service_provider {
	char *owner;	/* null for remote services or unique name if local */
	char *prov;	/* remote Bluetooth address that provides the service */
	struct slist *lrec;
};

struct service_record {
	int ttl;	/* time to live */
	sdp_record_t *record;
};

struct transaction_context {
	DBusConnection *conn;
	DBusMessage *rq;
	sdp_session_t *session;

	/* Used for internal async get remote service record implementation */
	void *priv;
};

typedef int connect_cb_t(struct transaction_context *t);
struct pending_connect {
	DBusConnection *conn;
	DBusMessage *rq;

	char *dst;
	sdp_session_t *session;
	connect_cb_t *conn_cb;

	/* Used for internal async get remote service record implementation */
	void *priv;
};

/* FIXME:  move to a common file */
typedef struct {
	char            *name;
	uint16_t        class;
	char            *info_name;
} sdp_service_t;

/* FIXME:  move to a common file */
sdp_service_t sdp_service[] = {
	{ "vcp",	VIDEO_CONF_SVCLASS_ID,		NULL			},
	{ "map",	0,				NULL			},
	{ "pbap",	0,				NULL			},
	{ "sap",	SAP_SVCLASS_ID,			"SIM Access"		},
	{ "ftp",	OBEX_FILETRANS_SVCLASS_ID,	"OBEX File Transfer"	},
	{ "bpp",	DIRECT_PRINTING_SVCLASS_ID,	"Direct Printing"	},
	{ "bip",	0,				NULL			},
	{ "synch",	0,				NULL			},
	{ "dun",	DIALUP_NET_SVCLASS_ID,		"Dial-Up Networking"	},
	{ "opp",	OBEX_OBJPUSH_SVCLASS_ID,	"OBEX Object Push"	},
	{ "fax",	FAX_SVCLASS_ID,			"Fax"			},
	{ "spp",	SERIAL_PORT_SVCLASS_ID,		"Serial Port"		},
	{ NULL }
};

/* FIXME:  move to a common file */
uint16_t sdp_str2svclass(const char *str)
{
	sdp_service_t *s;

	for (s = sdp_service; s->name; s++) {
		if (strcasecmp(s->name, str) == 0)
			return s->class;
	}

	return 0;
}

/* FIXME:  move to a common file */
const char* sdp_svclass2str(uint16_t class)
{
	sdp_service_t *s;

	for (s = sdp_service; s->name; s++) {
		if (s->class == class)
			return s->name;
	}

	return NULL;
}

/* FIXME: stub for service registration. Shared with sdptool */
static inline sdp_record_t *sdp_service_register(const char *name, bdaddr_t *interface,
		                                   uint8_t channel, int *err)
{
	if (err)
		*err = ENOSYS;

	return NULL;
}

/* FIXME: stub for service registration. Shared with sdptool */
static inline int sdp_service_unregister(bdaddr_t *interface, sdp_record_t *rec, int *err)
{
	if (err)
		*err = ENOSYS;

	return -1;
}

/* list of remote and local service records */
static struct slist *sdp_cache = NULL;
static struct slist *pending_connects  = NULL;

static struct pending_connect *pending_connect_new(DBusConnection *conn, DBusMessage *msg,
							const char *dst, connect_cb_t *cb)
{
	struct pending_connect *c;

	if (!dst)
		return NULL;

	c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));

	if (dst) {
		c->dst = strdup(dst);
		if (!c->dst) {
			free(c);
			return NULL;
		}
	}

	c->conn = dbus_connection_ref(conn);
	c->rq = dbus_message_ref(msg);
	c->conn_cb = cb;

	return c;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (!c)
		return;

	if (c->dst)
		free(c->dst);

	if (c->rq)
		dbus_message_unref(c->rq);

	if (c->conn)
		dbus_connection_unref(c->conn);

	free(c);
}

static struct pending_connect *find_pending_connect(const char *dst)
{
	struct slist *l;

	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!strcmp(dst, pending->dst))
			return pending;
	}

	return NULL;
}

static int str2identifier(const char *identifier, char *address,
			  uint32_t *handle)
{
	if (!identifier || !address)
		return -1;

	if (strlen(identifier) < 19)
		return -1;

	memset(address, 0, 18);
	snprintf(address, 18, "%s", identifier);

	return (sscanf(identifier + 18, "%x", handle) > 0 ? 0 : -1);
}

static struct service_record *service_record_new(sdp_record_t *rec)
{
	struct service_record *r;

	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	memset(r, 0, sizeof(*r));
	r->record = rec;

	return r;
}

static void service_record_free(void *data, void *udata)
{
	struct service_record *r = data;

	if (!r)
		return;

	if (r->record)
		sdp_record_free(r->record);

	free(r);
}

/*
 * This function doesn't check service record pattern
 */
static int service_record_cmp(const void *data, const void *udata)
{
	const struct service_record *a = data;
	const struct service_record *b = udata;

	if (b->record) {
		if (b->record->handle != 0xffffffff &&
		    b->record->handle != a->record->handle)
			return -1;
	}

	return 0;
}

static void service_provider_free(void *data, void *udata)
{
	struct service_provider *p1 = data;
	struct service_provider *p2 = udata;

	if (!p1)
		return;

	/* Check if the provider match */
	if (p2) {
		if (p2->owner && strcmp(p2->owner, p1->owner))
			return;
		if (p2->prov && strcmp(p2->prov, p1->prov))
			return;
	}

	if (p1->owner)
		free(p1->owner);

	if (p1->prov)
		free(p1->prov);

	if (p1->lrec) {
		slist_foreach(p1->lrec, service_record_free, NULL);
		slist_free(p1->lrec);
	}

	free(p1);
}

static struct service_provider *service_provider_new(const char *owner, const char *prov)
{
	struct service_provider *p;

	if (!prov)
		return NULL;

	p = malloc(sizeof(struct service_provider));
	if (!p)
		return NULL;

	memset(p, 0, sizeof(*p));
	if (owner) {
		p->owner = strdup(owner);
		if (!p->owner)
			goto fail;
	}

	if (prov) {
		p->prov = strdup(prov);
		if (!p->prov)
			goto fail;
	}

	return p;

fail:
	service_provider_free(p, NULL);
	return NULL;
}

static int service_provider_cmp(const void *data, const void *udata)
{
	const struct service_provider *a = data;
	const struct service_provider *b = udata;
	int ret;

	if (b->owner) {
		if (!a->owner)
			return -1;
		ret = strcmp(a->owner, b->owner);
		if (ret)
			return ret;
	}

	if (b->prov) {
		if (!a->prov)
			return -1;
		ret = strcmp(a->prov, b->prov);
		if (ret)
			return ret;
	}

	return 0;
}

static int sdp_cache_append(const char *owner, const char *prov, sdp_record_t *rec)
{
	struct slist *lp, *lr;
	struct service_provider *p;
	struct service_provider psearch;
	struct service_record r, *sr;

	if (!prov || !rec)
		return -1;

	memset(&psearch, 0, sizeof(psearch));
	psearch.owner = (char *) owner;
	psearch.prov = (char *) prov;

	lp = slist_find(sdp_cache, &psearch, service_provider_cmp);
	if (!lp) {
		p = service_provider_new(owner, prov);
		sdp_cache = slist_append(sdp_cache, p);
	} else
		p = lp->data;

	/* check if the service record already belongs to the cache */
	r.record = sdp_record_alloc();
	r.record->handle = rec->handle;
	lr = slist_find(p->lrec, &r, service_record_cmp);
	sdp_record_free(r.record);

	if (lr) {
		/* overwrite the record instead of compare */
		sr = lr->data;
		sdp_record_free(sr->record);
		sr->record = rec;
	} else {
		/* create a new entry */
		sr = service_record_new(rec);
		p->lrec = slist_append(p->lrec, sr);
	}

	return 0;
}

static void transaction_context_free(void *udata)
{
	struct transaction_context *ctxt = udata;

	if (!ctxt)
		return;

	if (ctxt->conn)
		dbus_connection_unref(ctxt->conn);

	if (ctxt->rq)
		dbus_message_unref(ctxt->rq);

	if (ctxt->session)
		sdp_close(ctxt->session);

	free(ctxt);
}

typedef struct {
	uint16_t dev_id;
	char *dst;
	void *search_data;
	get_record_cb_t *cb;
	void *data;
} get_record_data_t;

static get_record_data_t *get_record_data_new(uint16_t dev_id, const char *dst,
					void *search_data,
					get_record_cb_t *cb, void *data)
{
	get_record_data_t *n;

	n = malloc(sizeof(*n));
	if (!n)
		return NULL;

	n->dst = strdup(dst);
	if (!n->dst) {
		free(n);
		return NULL;
	}

	n->dev_id = dev_id;
	n->search_data = search_data;
	n->cb = cb;
	n->data = data;

	return n;
}

static void get_record_data_free(get_record_data_t *d)
{
	free(d->dst);
	free(d);
}

static inline void get_record_data_call_cb(get_record_data_t *d,
						sdp_record_t *rec, int err)
{
	d->cb(rec, d->data, err);
}

static void owner_exited(const char *owner, struct hci_dbus_data *dbus_data)
{
	struct slist *lp, *next, *lr;
	struct service_provider *p;
	bdaddr_t sba;
	int err = 0;
	debug("SDP provider owner %s exited", owner);

	for (lp = sdp_cache; lp; lp = next) {

		next = lp->next;
		p = lp->data;

		if (!p->owner || strcmp(p->owner, owner))
			continue;

		/*
		 * Unregister all service records related to this owner.
		 * One owner can use multiple local adapter(provider)
		 */
		str2ba(dbus_data->address, &sba);
		for (lr = p->lrec; lr; lr = lr->next) {
			struct service_record *r = lr->data;
			if (sdp_service_unregister(&sba, r->record, &err) < 0)
				error("unregister error: %s (%d)", strerror(err), err);
			else
				/* free inside the library */
				r->record = NULL;
		}

		/* remove from the cache */
		sdp_cache = slist_remove(sdp_cache, p);

		service_provider_free(p, NULL);
	}
}

static gboolean search_process_cb(GIOChannel *chan,
				GIOCondition cond, void *udata)
{
	struct transaction_context *ctxt = udata;
	int sk, err = 0;
	socklen_t len;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s (%d)", strerror(errno), errno);
		err = errno;
		goto failed;
	}
	if (err != 0) {
		error("sock error: %s (%d)", strerror(err), err);
		goto failed;
	}

	if (!sdp_process(ctxt->session))
		return TRUE;

failed:
	if (err) {
		if (ctxt->priv) {
			get_record_data_call_cb(ctxt->priv, NULL, err);
			get_record_data_free(ctxt->priv);
		} else
			error_failed(ctxt->conn, ctxt->rq, err);
	}
	g_io_channel_unref(chan);
	return FALSE;
}

static void remote_svc_rec_completed_cb(uint8_t type, uint16_t err, uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	char identifier[MAX_IDENTIFIER_LEN];
	sdp_record_t *rec = NULL;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	const char *dst;
	int i, scanned;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed(ctxt->conn, ctxt->rq, EINVAL);
			return;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed(ctxt->conn, ctxt->rq, sdp_err);
		return;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		return;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed(ctxt->conn, ctxt->rq, EPROTO);
		return;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_BYTE_AS_STRING, &array_iter);

	rec = sdp_extract_pdu(rsp, &scanned);
	if (rec == NULL) {
		error("SVC REC is null");
		goto done;
	}

	sdp_cache_append(NULL, dst, rec);
	snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/0x%x", dst, rec->handle);

	/* FIXME: avoid seg fault / out of bound */
	for (i = 0; i < size; i++)
		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_BYTE, &rsp[i]);

done:
	dbus_message_iter_close_container(&iter, &array_iter);
	send_reply_and_unref(ctxt->conn, reply);
}

static void remote_svc_handles_completed_cb(uint8_t type, uint16_t err, uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	uint8_t *pdata;
	int scanned, csrc, tsrc;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed(ctxt->conn, ctxt->rq, EINVAL);
			return;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed(ctxt->conn, ctxt->rq, sdp_err);
		return;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		return;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_SEARCH_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed(ctxt->conn, ctxt->rq, EPROTO);
		return;
	}

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_UINT32_AS_STRING, &array_iter);

	pdata = rsp;

	tsrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (tsrc <= 0)
		goto done;

	pdata += sizeof(uint16_t);
	scanned = sizeof(uint16_t);

	csrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (csrc <= 0) 
		goto done;

	pdata += sizeof(uint16_t);
	scanned += sizeof(uint16_t);

	do {
		uint32_t handle = ntohl(bt_get_unaligned((uint32_t*)pdata));
		scanned += sizeof(uint32_t);
		pdata += sizeof(uint32_t);

		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_UINT32, &handle);
	} while (--tsrc);


done:
	dbus_message_iter_close_container(&iter, &array_iter);
	send_reply_and_unref(ctxt->conn, reply);
}

static void search_completed_cb(uint8_t type, uint16_t err, uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	char identifier[MAX_IDENTIFIER_LEN];
	const char *ptr = identifier;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	const char *dst;
	uint8_t *pdata;
	int scanned, csrc, tsrc;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed(ctxt->conn, ctxt->rq, EINVAL);
			return;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed(ctxt->conn, ctxt->rq, sdp_err);
		return;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		return;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_SEARCH_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed(ctxt->conn, ctxt->rq, EPROTO);
		return;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array_iter);

	pdata = rsp;

	tsrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (tsrc <= 0)
		goto done;

	pdata += sizeof(uint16_t);
	scanned = sizeof(uint16_t);

	csrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (csrc <= 0) 
		goto done;

	pdata += sizeof(uint16_t);
	scanned += sizeof(uint16_t);

	do {
		uint32_t handle = ntohl(bt_get_unaligned((uint32_t*)pdata));
		scanned += sizeof(uint32_t);
		pdata += sizeof(uint32_t);

		snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/0x%x", dst, handle);

		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_STRING, &ptr);
	} while (--tsrc);

done:
	dbus_message_iter_close_container(&iter, &array_iter);
	send_reply_and_unref(ctxt->conn, reply);
}

static gboolean sdp_client_connect_cb(GIOChannel *chan,
					GIOCondition cond, void *udata)
{
	struct pending_connect *c = udata;
	struct transaction_context *ctxt = NULL;
	int sdp_err, err = 0, sk;
	socklen_t len;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s (%d)", strerror(errno), errno);
		err = errno;
		goto failed;
	}
	if (err != 0) {
		error("connect(): %s (%d)", strerror(err), err);
		goto failed;
	}

	ctxt = malloc(sizeof(*ctxt));
	if (!ctxt) {
		err = ENOMEM;
		goto failed;
	}
	memset(ctxt, 0, sizeof(*ctxt));

	ctxt->conn = dbus_connection_ref(c->conn);
	ctxt->rq = dbus_message_ref(c->rq);
	ctxt->session = c->session;
	if (c->priv)
		ctxt->priv = c->priv;

	/* set the complete transaction callback and send the search request */
	sdp_err = c->conn_cb(ctxt);
	if (sdp_err < 0) {
		err = -sdp_err;
		error("search failed: %s (%d)", strerror(err), err);
		goto failed;
	}

	/* set the callback responsible for update the transaction data */
	g_io_add_watch_full(chan, 0, G_IO_IN,
			search_process_cb, ctxt, transaction_context_free);
	goto done;

failed:
	if (err) {
		if (c->priv)
			get_record_data_call_cb(c->priv, NULL, err);
		else
			error_connection_attempt_failed(c->conn, c->rq, err);
	}
	if (c->priv)
		get_record_data_free(c->priv);
	if (ctxt)
		transaction_context_free(ctxt);
	g_io_channel_unref(chan);
done:
	pending_connects = slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static struct pending_connect *connect_request(DBusConnection *conn,
					DBusMessage *msg,
					uint16_t dev_id,
					const char *dst,
					connect_cb_t *cb, int *err)
{
	struct pending_connect *c;
	bdaddr_t srcba, dstba;
	GIOChannel *chan;

	c = pending_connect_new(conn, msg, dst, cb);
	if (!c) {
		if (err)
			*err = ENOMEM;
		return NULL;
	}

	hci_devba(dev_id, &srcba);
	str2ba(dst, &dstba);

	c->session = sdp_connect(&srcba, &dstba, SDP_NON_BLOCKING);
	if (!c->session) {
		if (err)
			*err = errno;
		error("sdp_connect() failed: %s (%d)", strerror(errno), errno);
		pending_connect_free(c);
		return NULL;
	}

	chan = g_io_channel_unix_new(sdp_get_socket(c->session));
	g_io_channel_set_close_on_unref(chan, TRUE);

	g_io_add_watch(chan, G_IO_OUT, sdp_client_connect_cb, c);
	pending_connects = slist_append(pending_connects, c);

	return c;
}

static int remote_svc_rec_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *attrids = NULL;
	uint32_t range = 0x0000ffff;
	const char *dst;
	uint32_t handle;
	int err = 0;

	if (sdp_set_notify(ctxt->session, remote_svc_rec_completed_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	attrids = sdp_list_append(NULL, &range);
	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_attr_async(ctxt->session, handle, SDP_ATTR_REQ_RANGE, attrids) < 0) {
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (attrids)
		sdp_list_free(attrids, NULL);

	return err;
}

DBusHandlerResult get_remote_svc_rec(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	const char *dst;
	uint32_t handle;
	int err = 0;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	if (!connect_request(conn, msg, dbus_data->dev_id,
				dst, remote_svc_rec_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int remote_svc_handles_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *search = NULL;
	uuid_t uuid;
	int err = 0;

	if (sdp_set_notify(ctxt->session, remote_svc_handles_completed_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
	search = sdp_list_append(0, &uuid);

	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_search_async(ctxt->session, search, 64) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (search)
		sdp_list_free(search, NULL);

	return err;
}

DBusHandlerResult get_remote_svc_handles(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	const char *dst;
	int err = 0;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	if (!connect_request(conn, msg, dbus_data->dev_id,
				dst, remote_svc_handles_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int get_identifiers_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *search = NULL;
	uuid_t uuid;
	int err = 0;

	if (sdp_set_notify(ctxt->session, search_completed_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
	search = sdp_list_append(0, &uuid);

	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_search_async(ctxt->session, search, 64) < 0) {
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (search)
		sdp_list_free(search, NULL);

	return err;
}

static DBusHandlerResult get_identifiers(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	const char *dst;
	int err = 0;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	/* in progress is not working properly */
	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	if (!connect_request(conn, msg, dbus_data->dev_id,
				dst, get_identifiers_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int get_identifiers_by_service_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *search = NULL;
	const char *dst, *svc;
	uuid_t uuid;
	uint16_t class;
	int err = 0;

	if (sdp_set_notify(ctxt->session, search_completed_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	dbus_message_get_args(ctxt->rq, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_STRING, &svc,
				DBUS_TYPE_INVALID);

	class = sdp_str2svclass(svc);
	sdp_uuid16_create(&uuid, class);
	search = sdp_list_append(0, &uuid);

	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_search_async(ctxt->session, search, 64) < 0) {
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (search)
		sdp_list_free(search, NULL);

	return err;
}

static DBusHandlerResult get_identifiers_by_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	struct slist *lp;
	struct slist *lr;
	struct service_provider *p;
	struct service_record *r;
	char identifier[MAX_IDENTIFIER_LEN];
	const char *ptr = identifier;
	const char *dst, *svc;
	int err = 0, nrec = 0;
	uint32_t class;
	uuid_t uuid;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_STRING, &svc,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	class = sdp_str2svclass(svc);
	if (!class) {
		error("Invalid service class name");
		return error_invalid_arguments(conn, msg);
	}

	sdp_uuid16_create(&uuid, class);

	p = service_provider_new(NULL, dst);
	if (!p)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* FIXME: return cache entry or query again? */
	lp = slist_find(sdp_cache, p, service_provider_cmp);
	service_provider_free(p, NULL);

	if (!lp)
		goto search_request;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array_iter);

	p = lp->data;
	for (lr = p->lrec; lr; lr = lr->next) {
		sdp_list_t *ls;
		uuid_t *puuid;
		r = lr->data;
		/* check if the pattern match */
		if (sdp_get_service_classes(r->record, &ls))
			continue;

		puuid = (uuid_t *) ls->data;

		if (sdp_uuid16_cmp(puuid, &uuid) == 0) {
			snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/0x%x", p->prov, r->record->handle);
			dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_STRING, &ptr);
			nrec++;
		}

		sdp_list_free(ls, free);

	}

	dbus_message_iter_close_container(&iter, &array_iter);

	if (nrec > 0)
		return send_reply_and_unref(conn, reply);

	/* no record found: request search */
	dbus_message_unref(reply);

search_request:
	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	if (!connect_request(conn, msg, dbus_data->dev_id,
			dst, get_identifiers_by_service_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;

}

static int uuid_cmp(const void *key1, const void *key2)
{
	uuid_t *a, *b;
	int ret_val;

	/* converting to uuid128 */
	a = sdp_uuid_to_uuid128((uuid_t *) key1);
	b = sdp_uuid_to_uuid128((uuid_t *) key2);

	ret_val = sdp_uuid128_cmp(a, b);

	bt_free(a);
	bt_free(b);

	return ret_val;
}

static sdp_record_t *find_record_by_uuid(const char *address, uuid_t *uuid)
{
	struct slist *lp, *lr;
	struct service_provider *p;
	struct service_record *r;
	sdp_list_t *list = NULL;

	for (lp = sdp_cache; lp; lp = lp->next) {
		p = lp->data;
		if (strcmp(p->prov, address))
			continue;

		for (lr = p->lrec; lr; lr = lr->next) {
			r = lr->data;
			/* Check whether the record has the correct uuid */
			if (sdp_get_service_classes(r->record, &list) != 0)
				continue;

			if (sdp_list_find(list, uuid, uuid_cmp))
				return r->record;
		}
	}

	return NULL;
}

static sdp_record_t *find_record_by_handle(const char *address,
						uint32_t handle)
{
	struct slist *lp, *lr;
	struct service_provider *p;
	struct service_record *r;

	for (lp = sdp_cache; lp; lp = lp->next) {
		p = lp->data;
		if (strcmp(p->prov, address))
			continue;

		for (lr = p->lrec; lr; lr = lr->next) {
			r = lr->data;
			if (r->record->handle == handle)
				return r->record;
		}
	}

	return NULL;
}

static DBusHandlerResult get_uuid(DBusConnection *conn,
					 DBusMessage *msg, void *data)
{
	char uuid_str[MAX_LEN_UUID_STR];
	char address[18];
	sdp_list_t *ls;
	DBusMessage *reply;
	sdp_record_t *rec;
	char *ptr = uuid_str;
	const char *identifier;
	uint32_t handle;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &identifier,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (str2identifier(identifier, address, &handle) != 0)
		return error_invalid_arguments(conn, msg);

	rec = find_record_by_handle(address, handle);
	if (!rec)
		return error_record_does_not_exist(conn, msg);

	memset(uuid_str, 0, MAX_LEN_UUID_STR);

	reply = dbus_message_new_method_return(msg);

	if (sdp_get_service_classes(rec, &ls) == 0) {
		char tmp_str[MAX_LEN_UUID_STR];
		uuid_t *uuid = (uuid_t *) ls->data;

		if (sdp_uuid2strn(uuid, tmp_str, MAX_LEN_UUID_STR) != 0)
			error("Can't convert UUID to string!");
		else
			snprintf(uuid_str, MAX_LEN_UUID_STR, "0x%s", tmp_str);

		sdp_list_free(ls, free);
	}

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ptr,
			DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	char address[18];
	DBusMessage *reply;
	sdp_record_t *rec;
	sdp_list_t *ls;
	char name[] = "";
	const char *ptr = name;
	const char *identifier;
	uuid_t *puuid;
	uint32_t handle;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &identifier,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (str2identifier(identifier, address, &handle) != 0)
		return error_invalid_arguments(conn, msg);

	rec = find_record_by_handle(address, handle);
	if (!rec)
		return error_record_does_not_exist(conn, msg);

	if ((sdp_get_service_classes(rec, &ls)) < 0) {
		return error_failed(conn, msg, errno);
	}

	puuid = (uuid_t *) ls->data;

	ptr = sdp_svclass2str(puuid->value.uuid16);
	sdp_list_free(ls, free);

	/* return empty string for non supported services */
	if (!ptr)
		ptr = name;

	/* FIXME: it should return the service name attribute instead of the short service name */
	reply = dbus_message_new_method_return(msg);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ptr,
			DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult register_rfcomm(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct service_provider psearch;
	DBusMessage *reply;
	sdp_record_t *rec;
	const char *owner, *name;
	char identifier[MAX_IDENTIFIER_LEN];
	const char *ptr = identifier;
	bdaddr_t sba;
	int err = 0;
	uint8_t channel;

	owner = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_BYTE, &channel,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(dbus_data->address, &sba);
	/* register service */
	if (!(rec = sdp_service_register(name, &sba, channel, &err))) {
		dbus_message_unref(reply);
		error("service register error: %s (%d)", strerror(err), err);
		if (err == EINVAL)
			return error_invalid_arguments(conn, msg);
		else
			return error_failed(conn, msg, err);
	}

	/* Only add a D-Bus unique name listener if there isn't one already registered */
	memset(&psearch, 0, sizeof(psearch));
	psearch.owner = (char *) owner;

	if (!slist_find(sdp_cache, &psearch, service_provider_cmp))
		name_listener_add(conn, owner, (name_cb_t) owner_exited, dbus_data);

	/* add record in the cache */
	sdp_cache_append(owner, dbus_data->address, rec);
	snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/0x%x", dbus_data->address, rec->handle);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ptr,
			DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult unregister_rfcomm(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char address[18];
	struct hci_dbus_data *dbus_data = data;
	struct service_provider *p, psearch;
	struct service_record rsearch, *r;
	sdp_record_t record;
	struct slist *lp, *lr;
	DBusMessage *reply;
	const char *owner, *identifier;
	bdaddr_t sba;
	int err = 0;
	uint32_t handle;

	owner = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &identifier,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (str2identifier(identifier, address, &handle) != 0)
		return error_invalid_arguments(conn, msg);

	/* check if the local adapter match */
	if (strcmp(address, dbus_data->address))
		return error_not_authorized(conn, msg);

	memset(&psearch, 0, sizeof(psearch));

	psearch.prov = address;
	psearch.owner = (char *) owner;

	lp = slist_find(sdp_cache, &psearch, service_provider_cmp);
	if (!lp)
		return error_service_does_not_exist(conn, msg);

	p = lp->data;

	rsearch.record = &record;
	record.handle = handle;
	lr = slist_find(p->lrec, &rsearch, service_record_cmp);
	if (!lr)
		return error_service_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	r = lr->data;
	str2ba(dbus_data->address, &sba);
	if (sdp_service_unregister(&sba, r->record, &err) < 0)
		error("service unregister error: %s (%d)", strerror(err), err);
	else
		r->record = NULL;

	/* Remove the service record */
	service_record_free(r, NULL);
	p->lrec = slist_remove(p->lrec, r);

	/* if the service record is empty remove the provider */
	if (!p->lrec) {
		sdp_cache = slist_remove(sdp_cache, p);
		service_provider_free(p, NULL);
	}

	psearch.prov = NULL;

	/* Only remove the D-Bus unique name listener if there are no more record using this name */
	if (!slist_find(sdp_cache, &psearch, service_provider_cmp))
		name_listener_remove(conn, owner, (name_cb_t) owner_exited, dbus_data);

	return send_reply_and_unref(conn, reply);
}

static struct service_data sdp_services[] = {
	{ "GetIdentifiers",		get_identifiers			},
	{ "GetIdentifiersByService",	get_identifiers_by_service	},
	{ "GetUUID",			get_uuid			},
	{ "GetName",			get_name			},
	{ "RegisterRFCOMM",		register_rfcomm			},
	{ "UnregisterRFCOMM",		unregister_rfcomm		},
	{ NULL, NULL }
};

DBusHandlerResult handle_sdp_method(DBusConnection *conn, DBusMessage *msg, void *data)
{
	const struct hci_dbus_data *pdata = data;
	service_handler_func_t handler;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!pdata->up)
		return error_not_ready(conn, msg);

	handler = find_service_handler(sdp_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return error_unknown_method(conn, msg);
}

void dbus_sdp_cache_free()
{
	slist_foreach(sdp_cache, service_provider_free, NULL);
}

/*
 * Internal async get remote service record implementation
 */

static void get_rec_with_handle_comp_cb(uint8_t type, uint16_t err,
					uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	int scanned, cb_err = 0;
	sdp_record_t *rec = NULL;

	if (err == 0xffff) {
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			cb_err = EINVAL;
			goto failed;
		}
		error("search failed :%s (%d)", strerror(sdp_err), sdp_err);
		cb_err = sdp_err;
		goto failed;
	}

	if (type == SDP_ERROR_RSP || type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s(%d)", strerror(EPROTO), EPROTO);
		cb_err = EPROTO;
		goto failed;
	}

	rec = sdp_extract_pdu(rsp, &scanned);
	if (!rec) {
		error("Service record is NULL");
		cb_err = EPROTO;
		goto failed;
	}

	/* FIXME: add record to the cache! */

failed:
	get_record_data_call_cb(ctxt->priv, rec, cb_err);
	get_record_data_free(ctxt->priv);
}

static int get_rec_with_handle_conn_cb(struct transaction_context *ctxt)
{
	get_record_data_t *d = ctxt->priv;
	uint32_t range = 0x0000ffff;
	sdp_list_t *attrids = NULL;
	uint32_t handle;
	int err = 0;

	if (sdp_set_notify(ctxt->session,
				get_rec_with_handle_comp_cb, ctxt) < 0) {
		error("Invalid session data!");
		err = -EINVAL;
		goto failed;
	}

	handle = *((uint32_t *)d->search_data);
	attrids = sdp_list_append(NULL, &range);

	if (sdp_service_attr_async(ctxt->session, handle,
					SDP_ATTR_REQ_RANGE, attrids) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		err = -errno;
		goto failed;
	}

failed:
	free(d->search_data);
	if (attrids)
		sdp_list_free(attrids, NULL);

	return err;
}

int get_record_with_handle(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			uint32_t *handle, get_record_cb_t *cb, void *data)
{
	struct pending_connect *c;
	get_record_data_t *d;
	int err;

	/* FIXME: search the cache first! */

	if (find_pending_connect(dst)) {
		error("SDP search in progress!");
		return -EINPROGRESS;
	}

	d = get_record_data_new(dev_id, dst, handle, cb, data);
	if (!d)
		return -ENOMEM;

	if (!(c = connect_request(conn, msg, dev_id, dst,
				get_rec_with_handle_conn_cb, &err))) {
		error("Search request failed: %s (%d)", strerror(err), err);
		get_record_data_free(d);
		return -err;
	}

	c->priv = d;

	return 0;
}

static void get_rec_with_uuid_comp_cb(uint8_t type, uint16_t err,
					uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	get_record_data_t *d = ctxt->priv;
	int csrc, tsrc, cb_err = 0;
	sdp_record_t *rec = NULL;
	uint32_t *handle;
	uint8_t *pdata;

	if (err == 0xffff) {
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			cb_err = EINVAL;
			goto failed;
		}
		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		cb_err = sdp_err;
		goto failed;
	}

	if (type == SDP_ERROR_RSP || type != SDP_SVC_SEARCH_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		cb_err = EPROTO;
		goto failed;
	}

	pdata = rsp;
	tsrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (tsrc <= 0)
		goto failed;
	pdata += sizeof(uint16_t);

	csrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (csrc <= 0)
		goto failed;
	pdata += sizeof(uint16_t);

	/* FIXME: what should we do with the other handles?? */
	handle = malloc(sizeof(*handle));
	if (!handle) {
		cb_err = ENOMEM;
		goto failed;
	}

	*handle = ntohl(bt_get_unaligned((uint32_t*)pdata));
	get_record_with_handle(ctxt->conn, ctxt->rq, d->dev_id,
				d->dst, handle, d->cb, d->data);
	get_record_data_free(ctxt->priv);
	return;

failed:
	get_record_data_call_cb(ctxt->priv, rec, cb_err);
	get_record_data_free(ctxt->priv);
}

static int get_rec_with_uuid_conn_cb(struct transaction_context *ctxt)
{
	get_record_data_t *d = ctxt->priv;
	sdp_list_t *search = NULL;
	uuid_t *uuid;
	int err = 0;

	if (sdp_set_notify(ctxt->session,
			get_rec_with_uuid_comp_cb, ctxt) < 0) {
		err = -EINVAL;
		goto failed;
	}

	uuid = (uuid_t *)d->search_data;
	search = sdp_list_append(NULL, uuid);

	if (sdp_service_search_async(ctxt->session, search, 64) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		err = -sdp_get_error(ctxt->session);
	}

failed:
	free(d->search_data);
	if (search)
		sdp_list_free(search, NULL);

	return err;
}

int get_record_with_uuid(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			uuid_t *uuid, get_record_cb_t *cb, void *data)
{
	struct pending_connect *c;
	get_record_data_t *d;
	int err;

	/* FIXME: search the cache first! */

	if (find_pending_connect(dst)) {
		error("SDP search in progress!");
		return -EINPROGRESS;
	}

	d = get_record_data_new(dev_id, dst, uuid, cb, data);
	if (!d)
		return -ENOMEM;

	if (!(c = connect_request(conn, msg, dev_id, dst,
				get_rec_with_uuid_conn_cb, &err))) {
		error("Search request failed: %s (%d)", strerror(err), err);
		get_record_data_free(d);
		return -err;
	}

	c->priv = d;

	return 0;
}
