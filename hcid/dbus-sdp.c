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

#define SDP_UUID_SEQ_SIZE 256
#define SDP_MAX_ATTR_LEN 65535


struct service_provider {
	char *owner;	/* null for remote services or unique name if local */
	bdaddr_t prov;	/* remote Bluetooth address or local address */
	struct slist *lrec;
};

struct service_record {
	uint32_t identifier;
	sdp_record_t *record;
};

struct pending_connect {
	DBusConnection *conn;
	DBusMessage *rq;
	char *svc;
	bdaddr_t dba;
};

struct transaction_context {
	DBusConnection *conn;
	DBusMessage *rq;
	char *svc;
	sdp_session_t *session;
	sdp_cstate_t *cstate;
	uint8_t *reqbuf;
	bdaddr_t dba;
	sdp_buf_t rspbuf;
	uint32_t reqsize;
	int attr_list_len;
};

/* FIXME: store the arguments or just the pointer to the message */

/* list of remote and local service records
 * FIXME: free the cache when the local sock(sdpd) is closed
 */

static struct slist *sdp_cache = NULL;
static struct slist *pending_connects  = NULL;

static const char *ecode2str(uint16_t ecode)
{
	switch (ecode) {
	case 0x0000:
		return "Reserved";
	case 0x0001:
		return "Invalid/Unsupported SDP version";
	case 0x0002:
		return "Invalid Service Record Handle";
	case 0x0003:
		return "Invalid request syntax";
	case 0x0004:
		return "Invalid PDU size";
	case 0x0005:
		return "Invalid Continuation State";
	case 0x0006:
		return "Insufficient Resources to satisfy Request";
	default:
		return "Reserved";
	}
}

static struct pending_connect *pending_connect_new(DBusConnection *conn, DBusMessage *msg,
							const bdaddr_t *bda, const char *svc)
{
	struct pending_connect *c;

	if (!bda)
		return NULL;

	c = malloc(sizeof(*c));

	memset(c, 0, sizeof(*c));

	if (svc) {
		c->svc = strdup(svc);
		if (!c->svc)
			goto failed;
	}

	bacpy(&c->dba, bda);
	c->conn = dbus_connection_ref(conn);
	c->rq = dbus_message_ref(msg);

	return c;

failed:
	if (c)
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

static struct pending_connect *find_pending_connect(const bdaddr_t *bda)
{
	struct slist *l;

	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!bacmp(bda, &pending->dba))
			return pending;
	}

	return NULL;
}
/* FIXME: duplicated function. Make this function public on bluez-libs */
static int gen_dataseq_pdu(uint8_t *dst, const sdp_list_t *seq, uint8_t dtd)
{
	sdp_data_t *dataseq;
	void **types, **values;
	sdp_buf_t buf;
	int i, seqlen = sdp_list_len(seq);

	// Fill up the value and the dtd arrays
	memset(&buf, 0, sizeof(sdp_buf_t));
	buf.data = malloc(SDP_UUID_SEQ_SIZE);
	buf.buf_size = SDP_UUID_SEQ_SIZE;

	types = malloc(seqlen * sizeof(void *));
	values = malloc(seqlen * sizeof(void *));
	for (i = 0; i < seqlen; i++) {
		void *data = seq->data;
		types[i] = &dtd;
		if (SDP_IS_UUID(dtd))
			data = &((uuid_t *)data)->value;
		values[i] = data;
		seq = seq->next;
	}

	dataseq = sdp_seq_alloc(types, values, seqlen);
	seqlen = sdp_gen_pdu(&buf, dataseq);
	memcpy(dst, buf.data, buf.data_size);

	sdp_data_free(dataseq);

	free(types);
	free(values);
	free(buf.data);
	return seqlen;
}

/* FIXME: duplicated function */
static int gen_searchseq_pdu(uint8_t *dst, const sdp_list_t *seq)
{
	uuid_t *uuid = (uuid_t *) seq->data;
	return gen_dataseq_pdu(dst, seq, uuid->type);
}

/* FIXME: duplicated function */
static int gen_attridseq_pdu(uint8_t *dst, const sdp_list_t *seq, uint8_t dataType)
{
	return gen_dataseq_pdu(dst, seq, dataType);
}

struct transaction_context *transaction_context_new(DBusConnection *conn, DBusMessage *msg, bdaddr_t *dba,
							const char *svc, int sock, uint32_t flags)
{
	struct transaction_context *ctxt;
	sdp_pdu_hdr_t *reqhdr;
	sdp_list_t *pattern = NULL;
	sdp_list_t *attrids = NULL;
	uint8_t *pdata;
	uuid_t uuid;
	uint32_t range = 0x0000ffff;
	int seqlen;

	ctxt = malloc(sizeof(*ctxt));
	if (!ctxt)
		return NULL;

	memset(ctxt, 0, sizeof(*ctxt));

	if (svc) {
		ctxt->svc = strdup(svc);
		if (!ctxt->svc)
			goto failed;
	}

	if (dba)
		bacpy(&ctxt->dba, dba);

	ctxt->session = malloc(sizeof(sdp_session_t));
	if (!ctxt->session)
		goto failed;

	memset(ctxt->session, 0, sizeof(sdp_session_t));

	ctxt->conn = dbus_connection_ref(conn);
	ctxt->rq = dbus_message_ref(msg);
	ctxt->session->sock = sock;
	ctxt->session->flags = flags;

	ctxt->reqbuf = malloc(SDP_REQ_BUFFER_SIZE);
	if (!ctxt->reqbuf)
		goto failed;

	memset(ctxt->reqbuf, 0, SDP_REQ_BUFFER_SIZE);

	reqhdr = (sdp_pdu_hdr_t *) ctxt->reqbuf;

	reqhdr->pdu_id = SDP_SVC_SEARCH_ATTR_REQ; 
	reqhdr->tid = 0;

	// Generate PDU
	pdata = ctxt->reqbuf + sizeof(sdp_pdu_hdr_t);
	ctxt->reqsize = sizeof(sdp_pdu_hdr_t);

	/* FIXME: it should be generic to handle other kind of search requests */
	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);
	pattern = sdp_list_append(0, &uuid);
	attrids = sdp_list_append(0, &range);

	seqlen = gen_searchseq_pdu(pdata, pattern);
	
	// set the length and increment the pointer
	ctxt->reqsize += seqlen;
	pdata +=seqlen;

	bt_put_unaligned(htons(SDP_MAX_ATTR_LEN), (uint16_t *) pdata);
	ctxt->reqsize += sizeof(uint16_t);
	pdata += sizeof(uint16_t);

	if (attrids) {
		seqlen = gen_attridseq_pdu(pdata, attrids, SDP_UINT32);
		if (seqlen == -1)
			goto failed;

	}
	if (pattern)
		sdp_list_free(pattern, 0);
	if (attrids)
		sdp_list_free(attrids, 0);

	pdata += seqlen;
	ctxt->reqsize += seqlen;

	reqhdr->plen = htons(ctxt->reqsize - sizeof(sdp_pdu_hdr_t));

	return ctxt;

failed:
	if (ctxt->session)
		free(ctxt->session);
	if (ctxt->reqbuf)
		free(ctxt->reqbuf);
	free(ctxt);
	
	return NULL;
}

void transaction_context_free(struct transaction_context *ctxt)
{
	if (!ctxt)
		return;

	if (ctxt->conn)
		dbus_connection_unref(ctxt->conn);

	if (ctxt->rq)
		dbus_message_unref(ctxt->rq);

	if (ctxt->svc)
		free(ctxt->svc);

	if (ctxt->session)
		free(ctxt->session);

	if (ctxt->reqbuf)
		free(ctxt->reqbuf);

	if (ctxt->rspbuf.data)
		free(ctxt->rspbuf.data);

	free(ctxt);
}

/* FIXME: generate the pseudo random id */
static uint32_t gen_next_id(const bdaddr_t *prov, uint32_t handle)
{
	static uint32_t id;
	return ++id;
}

static struct service_record *service_record_new(const bdaddr_t *prov, sdp_record_t *rec)
{
	struct service_record *r;
	
	if (!prov)
		return NULL;

	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	memset(r, 0, sizeof(*r));
	r->identifier = gen_next_id(prov, rec->handle);
	r->record = rec;

	return r;
}

static void service_record_free(struct service_record *r, void *data)
{
	if (!r)
		return;

	sdp_record_free(r->record);
	free(r);
}

static void service_provider_free(struct service_provider *p)
{
	if (p->owner)
		free(p->owner);

	if (p->lrec) {
		slist_foreach(p->lrec, (slist_func_t)service_record_free, NULL);
		slist_free(p->lrec);
	}

	free(p);
}

static struct service_provider *service_provider_new(const char *owner, const bdaddr_t *prov)
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

	bacpy(&p->prov, prov);

	return p;

fail:
	service_provider_free(p);
	return NULL;
}

static int service_provider_cmp(const struct service_provider *a, const struct service_provider *b)
{
	int ret;
	
	if (b->owner) {
		if (!a->owner)
			return -1;
		ret = strcmp(a->owner, b->owner);
		if (ret)
			return ret;
	}

	if (bacmp(&b->prov, BDADDR_ANY)) {
		if (!bacmp(&a->prov, BDADDR_ANY))
			return -1;
		ret = bacmp(&a->prov, &b->prov);
		if (ret)
			return ret;
	}

	return 0;
}

static uint32_t sdp_cache_append(const char *owner, const bdaddr_t *prov, sdp_record_t *rec)
{
	struct slist *l;
	struct service_provider *p;
	struct service_provider *ref;
	struct service_record *r;
	
	if (!prov || !rec)
		return 0;

	ref = service_provider_new(owner, prov);
	if (!ref)
		return 0;

	l = slist_find(sdp_cache, (const void*)ref, (cmp_func_t)service_provider_cmp);
	if (!l) {
		p = service_provider_new(owner, prov);
		sdp_cache = slist_append(sdp_cache, p);
	} else
		p = l->data;

	r = service_record_new(prov, rec);
	p->lrec = slist_append(p->lrec, r);

	if (ref)
		service_provider_free(ref);

	return r->identifier;
}

static void owner_exited(const char *owner, struct hci_dbus_data *dbus_data)
{
	struct slist *cur, *next;

	debug("SDP provider owner %s exited", owner);

	for (cur = sdp_cache; cur != NULL; cur = next) {
		struct service_provider *p = cur->data;

		next = cur->next;

		if(!p->owner)
			continue;

		if (strcmp(p->owner, owner))
			continue;

		sdp_cache = slist_remove(sdp_cache, p);
		service_provider_free(p);
	}
}

/* FIXME: duplicated function */
static int copy_cstate(uint8_t *pdata, const sdp_cstate_t *cstate)
{
	if (cstate) {
		*pdata++ = cstate->length;
		memcpy(pdata, cstate->data, cstate->length);
		return cstate->length + 1;
	}
	*pdata = 0;
	return 1;
}

static int sdp_send_req(struct transaction_context *ctxt, int *err)
{
	sdp_pdu_hdr_t *reqhdr = (sdp_pdu_hdr_t *) ctxt->reqbuf;
	uint32_t sent = 0;
	uint32_t reqsize;

	reqhdr->tid = htons(sdp_gen_tid(ctxt->session));
	reqsize = ctxt->reqsize + copy_cstate(ctxt->reqbuf + ctxt->reqsize, ctxt->cstate);
	reqhdr->plen = htons(reqsize - sizeof(sdp_pdu_hdr_t));

	while (sent < reqsize) {
		int n = send(ctxt->session->sock, ctxt->reqbuf + sent, reqsize - sent, 0);
		if (n < 0) {
			*err = errno;
			return -1;
		}
		sent += n;
	}

	return 0;
}

static DBusMessage *parse_response(struct transaction_context *ctxt)
{
	DBusMessage *reply = NULL;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	int scanned, seqlen;
	uint8_t dataType;
	uint8_t *pdata;
	const char *owner;

	owner = dbus_message_get_sender(ctxt->rq);

	reply = dbus_message_new_method_return(ctxt->rq);

	if ((ctxt->attr_list_len <= 0) || (ctxt->rspbuf.data_size == 0))
		return dbus_message_new_error(ctxt->rq, ERROR_INTERFACE ".DoesNotExist",
						"Record does not exist");

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_UINT32_AS_STRING, &array_iter);

	pdata = ctxt->rspbuf.data;

	scanned = sdp_extract_seqtype(pdata, &dataType, &seqlen);

	if (scanned && seqlen) {
		pdata += scanned;
		do {
			uint32_t id;
			int recsize = 0;
			sdp_record_t *rec = sdp_extract_pdu(pdata, &recsize);
			if (rec == NULL)
				break;

			if (!recsize) {
				sdp_record_free(rec);
				break;
			}

			scanned += recsize;
			pdata += recsize;

			id = sdp_cache_append(owner, &ctxt->dba, rec);
			dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_UINT32, &id);

		} while (scanned < ctxt->attr_list_len);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static gboolean svc_search_attr_req_cb(GIOChannel *chan, GIOCondition cond, struct transaction_context *ctxt)
{
	int sk, err, n;
	uint32_t rsp_count;
	gboolean ret_val = FALSE;
	socklen_t len;
	uint8_t cstate_len;
	uint8_t *pdata;
	uint8_t *rsp = NULL;
	sdp_pdu_hdr_t *reqhdr = (sdp_pdu_hdr_t *) ctxt->reqbuf;
	sdp_pdu_hdr_t *rsphdr;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s, (%d)", strerror(errno), errno);
		goto failed;
	}

	if (err != 0) {
		error("connect(): %s(%d)", strerror(err), err);
		error_connection_attempt_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	rsp = malloc(SDP_RSP_BUFFER_SIZE);
	memset(rsp, 0, SDP_RSP_BUFFER_SIZE);

	n = recv(sk, rsp, SDP_RSP_BUFFER_SIZE, 0);
	if (n <= 0) {
		err = errno;
		goto failed;
	}

	rsphdr = (sdp_pdu_hdr_t *)rsp;
	if (n == 0 || reqhdr->tid != rsphdr->tid) {
		err = EPROTO;
		goto failed;
	}

	pdata = rsp + sizeof(sdp_pdu_hdr_t);

	if (rsphdr->pdu_id == SDP_ERROR_RSP) {
		uint16_t ecode = ntohs(bt_get_unaligned((uint16_t *) pdata));
		error("Received SDP error response PDU: %s (%d)", ecode2str(ecode), ecode);
		err = EPROTO;
		goto failed;
	}

	rsp_count = ntohs(bt_get_unaligned((uint16_t *) pdata));
	ctxt->attr_list_len += rsp_count;
	pdata += sizeof(uint16_t);

	// if continuation state set need to re-issue request before parsing
	cstate_len = *(uint8_t *) (pdata + rsp_count);

	if (rsp_count > 0) {
		uint8_t *targetPtr = NULL;

		ctxt->cstate = cstate_len > 0 ? (sdp_cstate_t *) (pdata + rsp_count) : 0;

		// build concatenated response buffer
		ctxt->rspbuf.data = realloc(ctxt->rspbuf.data, ctxt->rspbuf.data_size + rsp_count);
		ctxt->rspbuf.buf_size = ctxt->rspbuf.data_size + rsp_count;
		targetPtr = ctxt->rspbuf.data + ctxt->rspbuf.data_size;
		memcpy(targetPtr, pdata, rsp_count);
		ctxt->rspbuf.data_size += rsp_count;
	}

	if (ctxt->cstate) {
		if (!sdp_send_req(ctxt, &err))
			ret_val = TRUE;
	} else {
		/* parse the response PDU */
		send_reply_and_unref(ctxt->conn, parse_response(ctxt));
	}
failed:
	if (rsp)
		free(rsp);

	if (err) {
		error_failed(ctxt->conn, ctxt->rq, err);
		error("SDP transaction error: %s (%d)", strerror(err), err);
	}

	return ret_val;
}

static gboolean sdp_client_connect_cb(GIOChannel *chan, GIOCondition cond, struct pending_connect *c)
{
	int err, sk = 0;
	socklen_t len;
	GIOChannel *tchan;
	struct transaction_context *ctxt;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s, (%d)", strerror(errno), errno);
		goto failed;
	}

	if (err != 0) {
		error("connect(): %s(%d)", strerror(err), err);
		error_connection_attempt_failed(c->conn, c->rq, err);
		goto failed;
	}

	ctxt = transaction_context_new(c->conn, c->rq, &c->dba, c->svc, sk, 0);

	if (!ctxt) {
		error_failed(c->conn, c->rq, ENOMEM);
		goto failed;
	}

	tchan = g_io_channel_unix_new(sk);

	g_io_add_watch_full(tchan, 0, G_IO_IN, (GIOFunc)svc_search_attr_req_cb,
			ctxt, (GDestroyNotify)transaction_context_free);

	if (sdp_send_req(ctxt, &err) < 0) {
		error("Can't send PDU: %s (%d)", strerror(err), err);
		error_failed(c->conn, c->rq, err);
		goto failed;
	}
failed:
	pending_connects = slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static int search_request(DBusConnection *conn, DBusMessage *msg, uint16_t dev_id,
				const char *dst, const char *svc, int *err)
{
	struct pending_connect *c = NULL;
	GIOChannel *chan = NULL;
	bdaddr_t sba;
	struct sockaddr_l2 sa;
	int sk, watch = 0;

	// create L2CAP connection
	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		if (err)
			*err = errno;

		return -1;
	}

	chan = g_io_channel_unix_new(sk);

	sa.l2_family = AF_BLUETOOTH;
	sa.l2_psm = 0;

	hci_devba(dev_id, &sba);

	if (bacmp(&sba, BDADDR_ANY) != 0) {
		bacpy(&sa.l2_bdaddr, &sba);
		if (bind(sk, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
			if (err)
				*err = errno;
			goto fail;
		}
	}

	sa.l2_psm = htobs(SDP_PSM);
	str2ba(dst, &sa.l2_bdaddr);

	c = pending_connect_new(conn, msg, &sa.l2_bdaddr, svc);
	if (!c) {
		if (err)
			*err = ENOMEM;
		goto fail;
	}

	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL, 0)|O_NONBLOCK);
	if (connect(sk, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		if ( !(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed:%s (%d)", strerror(errno), errno);
			goto fail;
		}

		watch = g_io_add_watch(chan, G_IO_OUT,
				(GIOFunc)sdp_client_connect_cb, c);
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
	struct service_provider *p;
	struct slist *l;
	const char *dst;
	char *str;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	bdaddr_t dba;
	int err = 0;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);
	
	/* FIXME: validate Bluetooth address(dst) */

	str2ba(dst, &dba);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	p = service_provider_new(NULL, &dba);
	if (!p) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
	
	l = slist_find(sdp_cache, p, (cmp_func_t)service_provider_cmp);
	service_provider_free(p);

	if (l) {
		struct slist *lr;
		struct service_record *r;

		/* check the cache */
		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_UINT32_AS_STRING, &array_iter);

		p = l->data;
		for (lr = p->lrec; lr; lr = lr->next) {
			r = lr->data;
			dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_UINT32, &r->identifier);
		}

		dbus_message_iter_close_container(&iter, &array_iter);

		return send_reply_and_unref(conn, reply);
	}

	if (find_pending_connect(&dba))
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
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

sdp_record_t *find_record(uint32_t identifier)
{
	struct slist *lp, *lr;
	struct service_provider *p;
	struct service_record *r;

	for (lp = sdp_cache; lp; lp = lp->next) {
		p = lp->data;
		for (lr = p->lrec; lr; lr = lr->next) {
			r = lr->data;
			if (r->identifier == identifier)
				return r->record;
		}
	}

	return NULL;
}

static DBusHandlerResult get_uuid(DBusConnection *conn,
					 DBusMessage *msg, void *data)
{
	char uuid_str[MAX_LEN_UUID_STR];
	sdp_list_t *l;
	DBusMessage *reply;
	sdp_record_t *rec;
	char *ptr = uuid_str;
	uint32_t identifier;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_UINT32, &identifier,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	rec = find_record(identifier);
	if (!rec)
		return error_record_does_not_exist(conn, msg);

	memset(uuid_str, 0, MAX_LEN_UUID_STR);

	reply = dbus_message_new_method_return(msg);

	if (sdp_get_profile_descs(rec, &l) == 0) {
		sdp_profile_desc_t *desc = (sdp_profile_desc_t *)l->data;

		sdp_uuid2strn(&desc->uuid, uuid_str, MAX_LEN_UUID_STR);
		sdp_list_free(l, free);
	}

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ptr,
			DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	sdp_record_t *rec;
	sdp_data_t *d;
	char name[] = "";
	char *ptr = name;
	uint32_t identifier;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_UINT32, &identifier,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	rec = find_record(identifier);
	if (!rec)
		return error_record_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	d = sdp_data_get(rec, SDP_ATTR_SVCNAME_PRIMARY);
	if (d && d->val.str)
		ptr = d->val.str;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ptr,
			DBUS_TYPE_INVALID);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult register_rfcomm(DBusConnection *conn,
		DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct service_provider ref;
	DBusMessage *reply;
	const char *owner, *name;
	bdaddr_t sba;
	uint32_t identifier = 0, handle = 0;
	uint8_t channel;

	owner = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_BYTE, &channel,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	/* FIXME: register the service */

	hci_devba(dbus_data->dev_id, &sba);
	identifier = gen_next_id(&sba, handle);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(msg,
			DBUS_TYPE_UINT32, &identifier,
			DBUS_TYPE_INVALID);

	/* Only add a D-Bus unique name listener if there isn't one already registered */
	memset(&ref, 0, sizeof(ref));
	bacpy(&ref.prov, BDADDR_ANY);

	if (!slist_find(sdp_cache, &ref, (cmp_func_t)service_provider_cmp))
		name_listener_add(conn, owner, (name_cb_t)owner_exited, dbus_data);

	/* FIXME: register the RFCOMM service */
	
	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult unregister_rfcomm(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct hci_dbus_data *dbus_data = data;
	struct service_provider *p, ref;
	struct slist *match;
	DBusMessage *reply;
	const char *owner, *identifier;

	owner = dbus_message_get_sender(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &identifier,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	memset(&ref, 0, sizeof(ref));
	
	hci_devba(dbus_data->dev_id, &ref.prov);
	ref.owner = (char *) owner;

	match = slist_find(sdp_cache, &ref, (cmp_func_t)service_provider_cmp);
	if (!match)
		return error_service_does_not_exist(conn, msg);

	/* FIXME: find the RFCOMM UUID in the list */
	p = match->data;
	
	if (strcmp(p->owner, owner))
		return error_not_authorized(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* FIXME: unregister the service */

	sdp_cache = slist_remove(sdp_cache, p);
	service_provider_free(p);

	bacpy(&ref.prov, BDADDR_ANY);

	/* Only remove the D-Bus unique name listener if there are no more record using this name */
	if (!slist_find(sdp_cache, &ref, (cmp_func_t)service_provider_cmp))
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
	service_handler_func_t handler;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	handler = find_service_handler(sdp_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return error_unknown_method(conn, msg);
}
