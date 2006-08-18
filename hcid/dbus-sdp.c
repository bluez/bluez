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

#define MAX_IDENTIFIER_LEN	24

struct service_provider {
	char *owner;	/* null for remote services or unique name if local */
	char *prov;	/* remote Bluetooth address thar provides the service  */
	int ttl;	/* time to live */
	struct slist *lrec;
};

struct service_record {
	int id;
	sdp_record_t *record;
};

struct pending_connect {
	DBusConnection *conn;
	DBusMessage *rq;
	char *svc;
	char *dst;
};

struct transaction_context {
	DBusConnection *conn;
	DBusMessage *rq;
	sdp_session_t *session;
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

/* FIXME: stub for bluez-libs changes */
static inline sdp_session_t *sdp_session_new(int sk)
{
	errno = ENOSYS;
	return NULL;
}

/* FIXME: stub for bluez-libs changes */
static inline int sdp_service_search_handle(sdp_session_t *session)
{
	return ENODATA;
}

/* FIXME: stub for bluez-libs changes */
typedef void sdp_transaction_cb_t(sdp_list_t *rsp, void *udata, int err);
static inline int sdp_service_search_attr_req_async(sdp_session_t *session, const sdp_list_t *search,
		sdp_transaction_cb_t *f, void *udata)
{
	return 0;
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
							const char *dst, const char *svc)
{
	struct pending_connect *c;

	if (!dst)
		return NULL;

	c = malloc(sizeof(*c));

	memset(c, 0, sizeof(*c));

	if (svc) {
		c->svc = strdup(svc);
		if (!c->svc)
			goto fail;
	}
	if (dst) {
		c->dst = strdup(dst);
		if (!c->dst)
			goto fail;
	}

	c->conn = dbus_connection_ref(conn);
	c->rq = dbus_message_ref(msg);

	return c;

fail:
	if (c->svc)
		free(c->svc);
	if (c->dst)
		free(c->dst);
	free(c);

	return NULL;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (!c)
		return;

	if (c->svc)
		free(c->svc);

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

static int str2identifier(const char *identifier, char *address, int *id)
{
	if (!identifier || !address)
		return -1;

	if (strlen(identifier) < 19)
		return -1;

	memset(address, 0, 18);

	snprintf(address, 18, "%s", identifier);

	return (sscanf(identifier + 18, "%d", id) > 0? 0: -1);
}

static inline int gen_next_record_id()
{
	static int id = 0;
	return id++;
}

static struct service_record *service_record_new(sdp_record_t *rec)
{
	struct service_record *r;

	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	memset(r, 0, sizeof(*r));
	r->id = gen_next_record_id();
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
	if (b->id >= 0) {
		if (a->id != b->id)
			return -1;
	}

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
	struct service_record *r;

	if (!prov || !rec)
		return -1;

	memset(&psearch, 0, sizeof(psearch));
	psearch.owner = (char *)owner;
	psearch.prov = (char *)prov;
	
	lp = slist_find(sdp_cache, &psearch, service_provider_cmp);
	if (!lp) {
		p = service_provider_new(owner, prov);
		sdp_cache = slist_append(sdp_cache, p);
	} else
		p = lp->data;

	/* check if there is service record already belongs to the cache */
	r = malloc(sizeof(*r));
	memset(r, 0, sizeof(*r));
	r->id = -1;
	r->record = sdp_record_alloc();
	r->record->handle = rec->handle;
	lr = slist_find(p->lrec, r, service_record_cmp);
	service_record_free(r, NULL);

	if (lr) {
		/* overwrite the record instead of compare */
		r = lr->data;
		sdp_record_free(r->record);
		r->record = rec;
	} else {
		/* create a new entry */
		r = service_record_new(rec);
		p->lrec = slist_append(p->lrec, r);
	}

	return r->id;
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

static gboolean search_session_handle_cb(GIOChannel *chan, GIOCondition cond, void *udata)
{
	struct transaction_context *ctxt = udata;
	int sk, err = 0;
	socklen_t len;
	const char *dst;
	int retval = FALSE;

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID);

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s, (%d)", strerror(errno), errno);
		error_failed(ctxt->conn, ctxt->rq, errno);
		goto fail;
	}

	if (err != 0) {
		error_failed(ctxt->conn, ctxt->rq, err);
		error("sock error:s(%d)", strerror(err), err);
		goto fail;
	}
	if (!sdp_service_search_handle(ctxt->session))
		return TRUE;

fail:
	g_io_channel_close(chan);
	return retval;
}

static void search_transaction_completed_cb(sdp_list_t *rsp, struct transaction_context *ctxt, int err)
{
	char identifier[MAX_IDENTIFIER_LEN];
	const char *ptr = identifier;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	sdp_list_t *next;
	const char *dst;
	int id;

	if (!ctxt)
		return;
		
	if (err) {
		error_failed(ctxt->conn, ctxt->rq, err);
		return;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array_iter);

	/* add in the cache */
	for ( ;rsp; rsp = next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;

		id = sdp_cache_append(NULL, dst, rec);
		snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/%d", dst, id);
		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_STRING, &ptr);

		next = rsp->next;
		free(rsp);
		/* Don't free the record */
	}

	dbus_message_iter_close_container(&iter, &array_iter);
	send_reply_and_unref(ctxt->conn, reply);
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

static gboolean sdp_client_connect_cb(GIOChannel *chan, GIOCondition cond, void *udata)
{
	struct pending_connect *c = udata;
	struct transaction_context *ctxt = NULL;
	sdp_list_t *search = NULL;
	uint16_t class;
	int err = 0, sk = 0;
	socklen_t len;
	uuid_t uuid;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s, (%d)", strerror(errno), errno);
		error_connection_attempt_failed(c->conn, c->rq, errno);
		goto fail;
	}

	if (err != 0) {
		error("connect(): %s(%d)", strerror(err), err);
		error_connection_attempt_failed(c->conn, c->rq, err);
		goto fail;
	}

	ctxt = malloc(sizeof(*ctxt));
	if (!ctxt) {
		error_failed(c->conn, c->rq, ENOMEM);
		goto fail;
	}
	memset(ctxt, 0, sizeof(*ctxt));

	/* FIXME: the sdp search list pattern should be created outside */
	if (!c->svc) {
		sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
		search = sdp_list_append(0, &uuid);
	} else {
		class = sdp_str2svclass(c->svc);
		sdp_uuid16_create(&uuid, class);
		search = sdp_list_append(0, &uuid);
	}

	ctxt->conn = dbus_connection_ref(c->conn);
	ctxt->rq = dbus_message_ref(c->rq);
	ctxt->session = sdp_session_new(sk);
	if (!ctxt->session) {
		error("error: %s (%d)", strerror(errno), errno);
		error_failed(c->conn, c->rq, errno);
		goto fail;
	}

	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_search_attr_req_async(ctxt->session, search,
			(sdp_transaction_cb_t *)search_transaction_completed_cb, ctxt) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		error_failed(c->conn, c->rq, errno);
		goto fail;
	}

	/* set the callback responsible for update the transaction data */
	g_io_add_watch_full(chan, 0, G_IO_IN, search_session_handle_cb,
				ctxt, transaction_context_free);
	goto done;

fail:
	if (ctxt)
		transaction_context_free(ctxt);
done:
	if (search)
		sdp_list_free(search, 0);

	pending_connects = slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static int search_request(DBusConnection *conn, DBusMessage *msg, uint16_t dev_id,
				const char *dst, const char *svc, int *err)
{
	struct pending_connect *c = NULL;
	GIOChannel *chan = NULL;
	struct sockaddr_l2 sa;
	int sk, watch = 0;

	// create L2CAP connection
	/* FIXME: use set_nonblocking */
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		if (err)
			*err = errno;

		return -1;
	}

	chan = g_io_channel_unix_new(sk);

	sa.l2_family = AF_BLUETOOTH;
	sa.l2_psm = 0;

	hci_devba(dev_id, &sa.l2_bdaddr);

	if (bind(sk, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		if (err)
			*err = errno;
		goto fail;
	}

	sa.l2_psm = htobs(SDP_PSM);
	str2ba(dst, &sa.l2_bdaddr);

	c = pending_connect_new(conn, msg, dst, svc);
	if (!c) {
		if (err)
			*err = ENOMEM;
		goto fail;
	}

	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL, 0)|O_NONBLOCK);
	if (connect(sk, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed:%s (%d)", strerror(errno), errno);
			goto fail;
		}

		watch = g_io_add_watch(chan, G_IO_OUT,
					sdp_client_connect_cb, c);
		pending_connects = slist_append(pending_connects, c);
	} else {
		sdp_client_connect_cb(chan, G_IO_OUT, c);
	}

	return 0;
fail:
	if (chan)
		g_io_channel_close(chan);

	if (c)
		pending_connect_free(c);

	return -1;
}

static DBusHandlerResult get_identifiers(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
	struct hci_dbus_data *dbus_data = data;
	const char *dst;
	char *str;
	int err = 0;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	/* check if it is a unknown address */
	snprintf(filename, PATH_MAX, "%s/%s/lastseen", STORAGEDIR, dbus_data->address);

	str = textfile_get(filename, dst);
	if (!str)
		return error_unknown_address(conn, msg);

	free(str);

	if (search_request(conn, msg, dbus_data->dev_id, dst, NULL, &err) < 0) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult get_identifiers_by_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char filename[PATH_MAX + 1];
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
	char *str;
	int err = 0, nrec = 0;
	uint32_t class;
	uuid_t uuid;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_STRING, &svc,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	/* check if it is a unknown address */
	create_name(filename, PATH_MAX, STORAGEDIR, dbus_data->address, "lastseen");

	str = textfile_get(filename, dst);
	if (!str)
		return error_unknown_address(conn, msg);

	free(str);

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

		puuid = (uuid_t *)ls->data;

		if (sdp_uuid16_cmp(puuid, &uuid) == 0) {
			snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/%d", p->prov, r->id);
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

	if (search_request(conn, msg, dbus_data->dev_id, dst, svc, &err) < 0) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;

}

static sdp_record_t *find_record(const char *address, int id)
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
			if (r->id == id)
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
	int id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &identifier,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (str2identifier(identifier, address, &id) != 0)
		return error_invalid_arguments(conn, msg);

	rec = find_record(address, id);
	if (!rec)
		return error_record_does_not_exist(conn, msg);

	memset(uuid_str, 0, MAX_LEN_UUID_STR);

	reply = dbus_message_new_method_return(msg);

	if (sdp_get_service_classes(rec, &ls) == 0) {
		char tmp_str[MAX_LEN_UUID_STR];
		uuid_t *uuid = (uuid_t *)ls->data;

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
	int id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &identifier,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (str2identifier(identifier, address, &id) != 0)
		return error_invalid_arguments(conn, msg);

	rec = find_record(address, id);
	if (!rec)
		return error_record_does_not_exist(conn, msg);

	if ((sdp_get_service_classes(rec, &ls)) < 0) {
		return error_failed(conn, msg, errno);
	}

	puuid = (uuid_t *)ls->data;

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
	int id = 0, err = 0;
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
	psearch.owner = (char *)owner;

	if (!slist_find(sdp_cache, &psearch, service_provider_cmp))
		name_listener_add(conn, owner, (name_cb_t)owner_exited, dbus_data);

	/* add record in the cache */
	id = sdp_cache_append(owner, dbus_data->address, rec);

	snprintf(identifier, MAX_IDENTIFIER_LEN, "%s/%d", dbus_data->address, id);
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
	struct slist *lp, *lr;
	DBusMessage *reply;
	const char *owner, *identifier;
	bdaddr_t sba;
	int id = 0, err = 0;

	owner = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &identifier,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (str2identifier(identifier, address, &id) != 0)
		return error_invalid_arguments(conn, msg);

	/* check if the local adapter match */
	if (strcmp(address, dbus_data->address))
		return error_not_authorized(conn, msg);

	memset(&psearch, 0, sizeof(psearch));

	psearch.prov = address;
	psearch.owner = (char *)owner;

	lp = slist_find(sdp_cache, &psearch, service_provider_cmp);
	if (!lp)
		return error_service_does_not_exist(conn, msg);

	p = lp->data;

	memset(&rsearch, 0, sizeof(rsearch));
	rsearch.id = id;
	str2ba(dbus_data->address, &sba);
	lr = slist_find(p->lrec, &rsearch, service_record_cmp);
	if (!lr)
		return error_service_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	r = lr->data;
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
		name_listener_remove(conn, owner, (name_cb_t)owner_exited, dbus_data);

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
