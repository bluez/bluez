/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#include "log.h"
#include "error.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "btio.h"
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

#define RESPONSE_TIMER	6	/* seconds */
#define MAX_CACHED	10	/* 10 devices */

#define MCAP_ERROR g_quark_from_static_string("mcap-error-quark")

#define RELEASE_TIMER(__mcl) do {		\
	if (__mcl->tid) {			\
		g_source_remove(__mcl->tid);	\
		__mcl->tid = 0;			\
	}					\
} while(0)

struct connect_mcl {
	struct mcap_mcl		*mcl;		/* MCL for this operation */
	mcap_mcl_connect_cb	connect_cb;	/* Connect callback */
	GDestroyNotify		destroy;	/* Destroy callback */
	gpointer		user_data;	/* Callback user data */
};

typedef union {
	mcap_mdl_operation_cb		op;
	mcap_mdl_operation_conf_cb	op_conf;
	mcap_mdl_notify_cb		notify;
} mcap_cb_type;

struct mcap_mdl_op_cb {
	struct mcap_mdl		*mdl;		/* MDL for this operation */
	mcap_cb_type		cb;		/* Operation callback */
	GDestroyNotify		destroy;	/* Destroy callback */
	gpointer		user_data;	/* Callback user data */
};

/* MCAP finite state machine functions */
static void proc_req_connected(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t l);
static void proc_req_pending(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t l);
static void proc_req_active(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t l);

static void (*proc_req[])(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len) = {
	proc_req_connected,
	proc_req_pending,
	proc_req_active
};

static void mcap_cache_mcl(struct mcap_mcl *mcl);

static void default_mdl_connected_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl connection");
}

static void default_mdl_closed_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl closed");
}

static void default_mdl_deleted_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl deleted");
}

static void default_mdl_aborted_cb(struct mcap_mdl *mdl, gpointer data)
{
	DBG("MCAP Unmanaged mdl aborted");
}

static uint8_t default_mdl_conn_req_cb(struct mcap_mcl *mcl,
						uint8_t mdepid, uint16_t mdlid,
						uint8_t *conf, gpointer data)
{
	DBG("MCAP mdl remote connection aborted");
	/* Due to this callback isn't managed this request won't be supported */
	return MCAP_REQUEST_NOT_SUPPORTED;
}

static uint8_t default_mdl_reconn_req_cb(struct mcap_mdl *mdl,
						gpointer data)
{
	DBG("MCAP mdl remote reconnection aborted");
	/* Due to this callback isn't managed this request won't be supported */
	return MCAP_REQUEST_NOT_SUPPORTED;
}

static void set_default_cb(struct mcap_mcl *mcl)
{
	if (!mcl->cb)
		mcl->cb = g_new0(struct mcap_mdl_cb, 1);

	mcl->cb->mdl_connected = default_mdl_connected_cb;
	mcl->cb->mdl_closed = default_mdl_closed_cb;
	mcl->cb->mdl_deleted = default_mdl_deleted_cb;
	mcl->cb->mdl_aborted = default_mdl_aborted_cb;
	mcl->cb->mdl_conn_req = default_mdl_conn_req_cb;
	mcl->cb->mdl_reconn_req = default_mdl_reconn_req_cb;
}

static char *error2str(uint8_t rc)
{
	switch (rc) {
	case MCAP_SUCCESS:
		return "Success";
	case MCAP_INVALID_OP_CODE:
		return "Invalid Op Code";
	case MCAP_INVALID_PARAM_VALUE:
		return "Invalid Parameter Value";
	case MCAP_INVALID_MDEP:
		return "Invalid MDEP";
	case MCAP_MDEP_BUSY:
		return "MDEP Busy";
	case MCAP_INVALID_MDL:
		return "Invalid MDL";
	case MCAP_MDL_BUSY:
		return "MDL Busy";
	case MCAP_INVALID_OPERATION:
		return "Invalid Operation";
	case MCAP_RESOURCE_UNAVAILABLE:
		return "Resource Unavailable";
	case MCAP_UNSPECIFIED_ERROR:
		return "Unspecified Error";
	case MCAP_REQUEST_NOT_SUPPORTED:
		return "Request Not Supported";
	case MCAP_CONFIGURATION_REJECTED:
		return "Configuration Rejected";
	default:
		return "Unknown Response Code";
	}
}

static gboolean mcap_send_std_opcode(struct mcap_mcl *mcl, void *cmd,
						uint32_t size, GError **err)
{
	if (mcl->state == MCL_IDLE) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
							"MCL is not connected");
		return FALSE;
	}

	if (mcl->req != MCL_AVAILABLE) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_RESOURCE_UNAVAILABLE,
							"Pending request");
		return FALSE;
	}

	if (!(mcl->ctrl & MCAP_CTRL_STD_OP)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_REQUEST_NOT_SUPPORTED,
				"Remote does not support standard opcodes");
		return FALSE;
	}

	if (mcl->state == MCL_PENDING) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_OPERATION,
			"Not Std Op. Codes can be sent in PENDING State");
		return FALSE;
	}

	if (mcap_send_data(g_io_channel_unix_get_fd(mcl->cc), cmd, size) < 0) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
					"Command can't be sent, write error");
		return FALSE;
	}

	mcl->lcmd = cmd;
	mcl->req = MCL_WAITING_RSP;

	return TRUE;
}

static void update_mcl_state(struct mcap_mcl *mcl)
{
	GSList *l;
	struct mcap_mdl *mdl;

	if (mcl->state == MCL_PENDING)
		return;

	for (l = mcl->mdls; l; l = l->next) {
		mdl = l->data;

		if (mdl->state == MDL_CONNECTED) {
			mcl->state = MCL_ACTIVE;
			return;
		}
	}

	mcl->state = MCL_CONNECTED;
}

static void shutdown_mdl(struct mcap_mdl *mdl)
{
	mdl->state = MDL_CLOSED;

	if (mdl->wid) {
		g_source_remove(mdl->wid);
		mdl->wid = 0;
	}

	if (mdl->dc) {
		g_io_channel_shutdown(mdl->dc, TRUE, NULL);
		g_io_channel_unref(mdl->dc);
		mdl->dc = NULL;
	}
}

static void free_mdl(struct mcap_mdl *mdl)
{
	if (!mdl)
		return;

	mcap_mcl_unref(mdl->mcl);
	g_free(mdl);
}

static gint cmp_mdl_state(gconstpointer a, gconstpointer b)
{
	const struct mcap_mdl *mdl = a;
	const MDLState *st = b;

	if (mdl->state == *st)
		return 0;
	else if (mdl->state < *st)
		return -1;
	else
		return 1;
}

static void free_mcap_mdl_op(struct mcap_mdl_op_cb *op)
{
	if (op->destroy)
		op->destroy(op->user_data);

	if (op->mdl)
		mcap_mdl_unref(op->mdl);

	g_free(op);
}

static void free_mcl_priv_data(struct mcap_mcl *mcl)
{
	free_mcap_mdl_op(mcl->priv_data);
	mcl->priv_data = NULL;
}

static void mcap_notify_error(struct mcap_mcl *mcl, GError *err)
{
	struct mcap_mdl_op_cb *con = mcl->priv_data;
	struct mcap_mdl *mdl;
	MDLState st;
	GSList *l;

	if (!con || !mcl->lcmd)
		return;

	switch (mcl->lcmd[0]) {
	case MCAP_MD_CREATE_MDL_REQ:
		st = MDL_WAITING;
		l = g_slist_find_custom(mcl->mdls, &st, cmp_mdl_state);
		mdl = l->data;
		mcl->mdls = g_slist_remove(mcl->mdls, mdl);
		mcap_mdl_unref(mdl);
		update_mcl_state(mcl);
		con->cb.op_conf(NULL, 0, err, con->user_data);
		break;
	case MCAP_MD_ABORT_MDL_REQ:
		st = MDL_WAITING;
		l = g_slist_find_custom(mcl->mdls, &st, cmp_mdl_state);
		shutdown_mdl(l->data);
		update_mcl_state(mcl);
		con->cb.notify(err, con->user_data);
		break;
	case MCAP_MD_DELETE_MDL_REQ:
		for (l = mcl->mdls; l; l = l->next) {
			mdl = l->data;
			if (mdl->state == MDL_DELETING)
				mdl->state = (mdl->dc) ? MDL_CONNECTED :
								MDL_CLOSED;
		}
		update_mcl_state(mcl);
		con->cb.notify(err, con->user_data);
		break;
	case MCAP_MD_RECONNECT_MDL_REQ:
		st = MDL_WAITING;
		l = g_slist_find_custom(mcl->mdls, &st, cmp_mdl_state);
		shutdown_mdl(l->data);
		update_mcl_state(mcl);
		con->cb.op(NULL, err, con->user_data);
		break;
	}

	free_mcl_priv_data(mcl);
	g_free(mcl->lcmd);
	mcl->lcmd = NULL;
}

int mcap_send_data(int sock, const void *buf, uint32_t size)
{
	const uint8_t *buf_b = buf;
	uint32_t sent = 0;

	while (sent < size) {
		int n = write(sock, buf_b + sent, size - sent);
		if (n < 0)
			return -1;
		sent += n;
	}

	return 0;
}

static int mcap_send_cmd(struct mcap_mcl *mcl, uint8_t oc, uint8_t rc,
					uint16_t mdl, uint8_t *data, size_t len)
{
	mcap_rsp *cmd;
	int sock, sent;

	if (mcl->cc == NULL)
		return -1;

	sock = g_io_channel_unix_get_fd(mcl->cc);

	cmd = g_malloc(sizeof(mcap_rsp) + len);
	cmd->op = oc;
	cmd->rc = rc;
	cmd->mdl = htons(mdl);

	if (data && len > 0)
		memcpy(cmd->data, data, len);

	sent = mcap_send_data(sock, cmd, sizeof(mcap_rsp) + len);
	g_free(cmd);

	return sent;
}

static struct mcap_mdl *get_mdl(struct mcap_mcl *mcl, uint16_t mdlid)
{
	GSList *l;
	struct mcap_mdl *mdl;

	for (l = mcl->mdls; l; l = l->next) {
		mdl = l->data;
		if (mdlid == mdl->mdlid)
			return mdl;
	}

	return NULL;
}

static uint16_t generate_mdlid(struct mcap_mcl *mcl)
{
	uint16_t mdlid = mcl->next_mdl;
	struct mcap_mdl *mdl;

	do {
		mdl = get_mdl(mcl, mdlid);
		if (!mdl) {
			mcl->next_mdl = (mdlid % MCAP_MDLID_FINAL) + 1;
			return mdlid;
		} else
			mdlid = (mdlid % MCAP_MDLID_FINAL) + 1;
	} while (mdlid != mcl->next_mdl);

	/* No more mdlids availables */
	return 0;
}

static mcap_md_req *create_req(uint8_t op, uint16_t mdl_id)
{
	mcap_md_req *req_cmd;

	req_cmd = g_new0(mcap_md_req, 1);

	req_cmd->op = op;
	req_cmd->mdl = htons(mdl_id);

	return req_cmd;
}

static mcap_md_create_mdl_req *create_mdl_req(uint16_t mdl_id, uint8_t mdep,
								uint8_t conf)
{
	mcap_md_create_mdl_req *req_mdl;

	req_mdl = g_new0(mcap_md_create_mdl_req, 1);

	req_mdl->op = MCAP_MD_CREATE_MDL_REQ;
	req_mdl->mdl = htons(mdl_id);
	req_mdl->mdep = mdep;
	req_mdl->conf = conf;

	return req_mdl;
}

static gint compare_mdl(gconstpointer a, gconstpointer b)
{
	const struct mcap_mdl *mdla = a;
	const struct mcap_mdl *mdlb = b;

	if (mdla->mdlid == mdlb->mdlid)
		return 0;
	else if (mdla->mdlid < mdlb->mdlid)
		return -1;
	else
		return 1;
}

static gboolean wait_response_timer(gpointer data)
{
	struct mcap_mcl *mcl = data;

	GError *gerr = NULL;

	RELEASE_TIMER(mcl);

	g_set_error(&gerr, MCAP_ERROR, MCAP_ERROR_FAILED,
					"Timeout waiting response");

	mcap_notify_error(mcl, gerr);

	g_error_free(gerr);
	mcl->mi->mcl_disconnected_cb(mcl, mcl->mi->user_data);
	mcap_cache_mcl(mcl);

	return FALSE;
}

gboolean mcap_create_mdl(struct mcap_mcl *mcl,
				uint8_t mdepid,
				uint8_t conf,
				mcap_mdl_operation_conf_cb connect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err)
{
	struct mcap_mdl *mdl;
	struct mcap_mdl_op_cb *con;
	mcap_md_create_mdl_req *cmd;
	uint16_t id;

	id = generate_mdlid(mcl);
	if (!id) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
					"Not more mdlids available");
		return FALSE;
	}

	mdl = g_new0(struct mcap_mdl, 1);
	mdl->mcl = mcap_mcl_ref(mcl);
	mdl->mdlid = id;
	mdl->mdep_id = mdepid;
	mdl->state = MDL_WAITING;

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = mcap_mdl_ref(mdl);
	con->cb.op_conf = connect_cb;
	con->destroy = destroy;
	con->user_data = user_data;

	cmd = create_mdl_req(id, mdepid, conf);
	if (!mcap_send_std_opcode(mcl, cmd, sizeof(mcap_md_create_mdl_req),
									err)) {
		mcap_mdl_unref(con->mdl);
		g_free(con);
		g_free(cmd);
		return FALSE;
	}

	mcl->state = MCL_ACTIVE;
	mcl->priv_data = con;

	mcl->mdls = g_slist_insert_sorted(mcl->mdls, mcap_mdl_ref(mdl),
								compare_mdl);
	mcl->tid = g_timeout_add_seconds(RESPONSE_TIMER, wait_response_timer,
									mcl);
	return TRUE;
}

gboolean mcap_reconnect_mdl(struct mcap_mdl *mdl,
				mcap_mdl_operation_cb reconnect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err)
{
	struct mcap_mdl_op_cb *con;
	struct mcap_mcl *mcl = mdl->mcl;
	mcap_md_req *cmd;

	if (mdl->state != MDL_CLOSED) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
					"MDL is not closed");
		return FALSE;
	}

	cmd = create_req(MCAP_MD_RECONNECT_MDL_REQ, mdl->mdlid);
	if (!mcap_send_std_opcode(mcl, cmd, sizeof(mcap_md_req), err)) {
		g_free(cmd);
		return FALSE;
	}

	mdl->state = MDL_WAITING;

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = mcap_mdl_ref(mdl);
	con->cb.op = reconnect_cb;
	con->destroy = destroy;
	con->user_data = user_data;

	mcl->state = MCL_ACTIVE;
	mcl->priv_data = con;

	mcl->tid = g_timeout_add_seconds(RESPONSE_TIMER, wait_response_timer,
									mcl);
	return TRUE;
}

static gboolean send_delete_req(struct mcap_mcl *mcl,
						struct mcap_mdl_op_cb *con,
						uint16_t mdlid,
						GError **err)
{
	mcap_md_req *cmd;

	cmd = create_req(MCAP_MD_DELETE_MDL_REQ, mdlid);
	if (!mcap_send_std_opcode(mcl, cmd, sizeof(mcap_md_req), err)) {
		g_free(cmd);
		return FALSE;
	}

	mcl->priv_data = con;

	mcl->tid = g_timeout_add_seconds(RESPONSE_TIMER, wait_response_timer,
									mcl);
	return TRUE;
}

gboolean mcap_delete_all_mdls(struct mcap_mcl *mcl,
					mcap_mdl_notify_cb delete_cb,
					gpointer user_data,
					GDestroyNotify destroy,
					GError **err)
{
	GSList *l;
	struct mcap_mdl *mdl;
	struct mcap_mdl_op_cb *con;

	DBG("MCL in state: %d", mcl->state);
	if (!mcl->mdls) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
				"There are not MDLs created");
		return FALSE;
	}

	for (l = mcl->mdls; l; l = l->next) {
		mdl = l->data;
		if (mdl->state != MDL_WAITING)
			mdl->state = MDL_DELETING;
	}

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = NULL;
	con->cb.notify = delete_cb;
	con->destroy = destroy;
	con->user_data = user_data;


	if (!send_delete_req(mcl, con, MCAP_ALL_MDLIDS, err)) {
		g_free(con);
		return FALSE;
	}

	return TRUE;
}

gboolean mcap_delete_mdl(struct mcap_mdl *mdl, mcap_mdl_notify_cb delete_cb,
							gpointer user_data,
							GDestroyNotify destroy,
							GError **err)
{
	struct mcap_mcl *mcl= mdl->mcl;
	struct mcap_mdl_op_cb *con;
	GSList *l;

	l = g_slist_find(mcl->mdls, mdl);

	if (!l) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_MDL,
					"%s" , error2str(MCAP_INVALID_MDEP));
		return FALSE;
	}

	if (mdl->state == MDL_WAITING) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
							"Mdl is not created");
		return FALSE;
	}

	mdl->state = MDL_DELETING;

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = mcap_mdl_ref(mdl);
	con->cb.notify = delete_cb;
	con->destroy = destroy;
	con->user_data = user_data;

	if (!send_delete_req(mcl, con, mdl->mdlid, err)) {
		mcap_mdl_unref(con->mdl);
		g_free(con);
		return FALSE;
	}

	return TRUE;
}

gboolean mcap_mdl_abort(struct mcap_mdl *mdl, mcap_mdl_notify_cb abort_cb,
							gpointer user_data,
							GDestroyNotify destroy,
							GError **err)
{
	struct mcap_mdl_op_cb *con;
	struct mcap_mcl *mcl = mdl->mcl;
	mcap_md_req *cmd;

	if (mdl->state != MDL_WAITING) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_FAILED,
							"Mdl in invalid state");
		return FALSE;
	}

	cmd = create_req(MCAP_MD_ABORT_MDL_REQ, mdl->mdlid);
	if (!mcap_send_std_opcode(mcl, cmd, sizeof(mcap_md_req), err)) {
		g_free(cmd);
		return FALSE;
	}

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = mcap_mdl_ref(mdl);
	con->cb.notify = abort_cb;
	con->destroy = destroy;
	con->user_data = user_data;

	mcl->priv_data = con;
	mcl->tid = g_timeout_add_seconds(RESPONSE_TIMER, wait_response_timer,
									mcl);
	return TRUE;
}

static struct mcap_mcl *find_mcl(GSList *list, const bdaddr_t *addr)
{
	struct mcap_mcl *mcl;

	for (; list; list = list->next) {
		mcl = list->data;

		if (!bacmp(&mcl->addr, addr))
			return mcl;
	}

	return NULL;
}

int mcap_mdl_get_fd(struct mcap_mdl *mdl)
{
	if (!mdl || mdl->state != MDL_CONNECTED)
		return -ENOTCONN;

	return g_io_channel_unix_get_fd(mdl->dc);
}

uint16_t mcap_mdl_get_mdlid(struct mcap_mdl *mdl)
{
	if (!mdl)
		return MCAP_MDLID_RESERVED;

	return mdl->mdlid;
}

static void close_mcl(struct mcap_mcl *mcl, gboolean cache_requested)
{
	gboolean save = ((!(mcl->ctrl & MCAP_CTRL_FREE)) && cache_requested);

	RELEASE_TIMER(mcl);

	if (mcl->cc) {
		g_io_channel_shutdown(mcl->cc, TRUE, NULL);
		g_io_channel_unref(mcl->cc);
		mcl->cc = NULL;
	}

	if (mcl->wid) {
		g_source_remove(mcl->wid);
		mcl->wid = 0;
	}

	if (mcl->lcmd) {
		g_free(mcl->lcmd);
		mcl->lcmd = NULL;
	}

	if (mcl->priv_data)
		free_mcl_priv_data(mcl);

	g_slist_foreach(mcl->mdls, (GFunc) shutdown_mdl, NULL);

	mcap_sync_stop(mcl);

	mcl->state = MCL_IDLE;

	if (save)
		return;

	g_slist_foreach(mcl->mdls, (GFunc) mcap_mdl_unref, NULL);
	g_slist_free(mcl->mdls);
	mcl->mdls = NULL;
}

static void mcap_mcl_shutdown(struct mcap_mcl *mcl)
{
	close_mcl(mcl, TRUE);
}

static void mcap_mcl_release(struct mcap_mcl *mcl)
{
	close_mcl(mcl, FALSE);
}

static void mcap_cache_mcl(struct mcap_mcl *mcl)
{
	GSList *l;
	struct mcap_mcl *last;
	int len;

	if (mcl->ctrl & MCAP_CTRL_CACHED)
		return;

	mcl->mi->mcls = g_slist_remove(mcl->mi->mcls, mcl);

	if (mcl->ctrl & MCAP_CTRL_NOCACHE) {
		mcl->mi->cached = g_slist_remove(mcl->mi->cached, mcl);
		mcap_mcl_release(mcl);
		mcap_mcl_unref(mcl);
		return;
	}

	DBG("Caching MCL");

	len = g_slist_length(mcl->mi->cached);
	if (len == MAX_CACHED) {
		/* Remove the latest cached mcl */
		l = g_slist_last(mcl->mi->cached);
		last = l->data;
		mcl->mi->cached = g_slist_remove(mcl->mi->cached, last);
		last->ctrl &= ~MCAP_CTRL_CACHED;
		if (last->ctrl & MCAP_CTRL_CONN) {
			/* We have to release this MCL if */
			/* connection is not succesful    */
			last->ctrl |= MCAP_CTRL_FREE;
		} else {
			mcap_mcl_release(last);
			last->mi->mcl_uncached_cb(last, last->mi->user_data);
		}
		mcap_mcl_unref(last);
	}

	mcl->mi->cached = g_slist_prepend(mcl->mi->cached, mcl);
	mcl->ctrl |= MCAP_CTRL_CACHED;
	mcap_mcl_shutdown(mcl);
}

static void mcap_uncache_mcl(struct mcap_mcl *mcl)
{
	if (!(mcl->ctrl & MCAP_CTRL_CACHED))
		return;

	DBG("Got MCL from cache");

	mcl->mi->cached = g_slist_remove(mcl->mi->cached, mcl);
	mcl->mi->mcls = g_slist_prepend(mcl->mi->mcls, mcl);
	mcl->ctrl &= ~MCAP_CTRL_CACHED;
	mcl->ctrl &= ~MCAP_CTRL_FREE;
}

void mcap_close_mcl(struct mcap_mcl *mcl, gboolean cache)
{
	if (!mcl)
		return;

	if (mcl->ctrl & MCAP_CTRL_FREE) {
		mcap_mcl_release(mcl);
		return;
	}

	if (!cache)
		mcl->ctrl |= MCAP_CTRL_NOCACHE;

	if (mcl->cc) {
		g_io_channel_shutdown(mcl->cc, TRUE, NULL);
		g_io_channel_unref(mcl->cc);
		mcl->cc = NULL;
		mcl->state = MCL_IDLE;
	} else if ((mcl->ctrl & MCAP_CTRL_CACHED) &&
					(mcl->ctrl & MCAP_CTRL_NOCACHE)) {
		mcl->ctrl &= ~MCAP_CTRL_CACHED;
		mcl->mi->cached = g_slist_remove(mcl->mi->cached, mcl);
		mcap_mcl_release(mcl);
		mcap_mcl_unref(mcl);
	}
}

struct mcap_mcl *mcap_mcl_ref(struct mcap_mcl *mcl)
{
	mcl->ref++;

	DBG("mcap_mcl_ref(%p): ref=%d", mcl, mcl->ref);

	return mcl;
}

void mcap_mcl_unref(struct mcap_mcl *mcl)
{
	mcl->ref--;

	DBG("mcap_mcl_unref(%p): ref=%d", mcl, mcl->ref);

	if (mcl->ref > 0)
		return;

	mcap_mcl_release(mcl);
	mcap_instance_unref(mcl->mi);
	g_free(mcl->cb);
	g_free(mcl);
}

static gboolean parse_set_opts(struct mcap_mdl_cb *mdl_cb, GError **err,
						McapMclCb cb1, va_list args)
{
	McapMclCb cb = cb1;
	struct mcap_mdl_cb *c;

	c = g_new0(struct mcap_mdl_cb, 1);

	while (cb != MCAP_MDL_CB_INVALID) {
		switch (cb) {
		case MCAP_MDL_CB_CONNECTED:
			c->mdl_connected = va_arg(args, mcap_mdl_event_cb);
			break;
		case MCAP_MDL_CB_CLOSED:
			c->mdl_closed = va_arg(args, mcap_mdl_event_cb);
			break;
		case MCAP_MDL_CB_DELETED:
			c->mdl_deleted = va_arg(args, mcap_mdl_event_cb);
			break;
		case MCAP_MDL_CB_ABORTED:
			c->mdl_aborted = va_arg(args, mcap_mdl_event_cb);
			break;
		case MCAP_MDL_CB_REMOTE_CONN_REQ:
			c->mdl_conn_req = va_arg(args,
						mcap_remote_mdl_conn_req_cb);
			break;
		case MCAP_MDL_CB_REMOTE_RECONN_REQ:
			c->mdl_reconn_req = va_arg(args,
						mcap_remote_mdl_reconn_req_cb);
			break;
		default:
			g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
						"Unknown option %d", cb);
			return FALSE;
		}
		cb = va_arg(args, int);
	}

	/* Set new callbacks */
	if (c->mdl_connected)
		mdl_cb->mdl_connected = c->mdl_connected;
	if (c->mdl_closed)
		mdl_cb->mdl_closed = c->mdl_closed;
	if (c->mdl_deleted)
		mdl_cb->mdl_deleted = c->mdl_deleted;
	if (c->mdl_aborted)
		mdl_cb->mdl_aborted = c->mdl_aborted;
	if (c->mdl_conn_req)
		mdl_cb->mdl_conn_req = c->mdl_conn_req;
	if (c->mdl_reconn_req)
		mdl_cb->mdl_reconn_req = c->mdl_reconn_req;

	g_free(c);

	return TRUE;
}

gboolean mcap_mcl_set_cb(struct mcap_mcl *mcl, gpointer user_data,
					GError **gerr, McapMclCb cb1, ...)
{
	va_list args;
	gboolean ret;

	va_start(args, cb1);
	ret = parse_set_opts(mcl->cb, gerr, cb1, args);
	va_end(args);

	if (!ret)
		return FALSE;

	mcl->cb->user_data = user_data;
	return TRUE;
}

void mcap_mcl_get_addr(struct mcap_mcl *mcl, bdaddr_t *addr)
{
	bacpy(addr, &mcl->addr);
}

static void mcap_del_mdl(gpointer elem, gpointer user_data)
{
	struct mcap_mdl *mdl = elem;
	gboolean notify = *(gboolean *) user_data;

	shutdown_mdl(mdl);
	if (notify)
		mdl->mcl->cb->mdl_deleted(mdl, mdl->mcl->cb->user_data);

	mcap_mdl_unref(mdl);
}

static gboolean check_cmd_req_length(struct mcap_mcl *mcl, void *cmd,
				uint32_t rlen, uint32_t explen, uint8_t rspcod)
{
	mcap_md_req *req;
	uint16_t mdl_id;

	if (rlen != explen) {
		if (rlen >= sizeof(mcap_md_req)) {
			req = cmd;
			mdl_id = ntohs(req->mdl);
		} else {
			/* We can't get mdlid */
			mdl_id = MCAP_MDLID_RESERVED;
		}
		mcap_send_cmd(mcl, rspcod, MCAP_INVALID_PARAM_VALUE, mdl_id,
								NULL, 0);
		return FALSE;
	}
	return TRUE;
}

static void process_md_create_mdl_req(struct mcap_mcl *mcl, void *cmd,
								uint32_t len)
{
	mcap_md_create_mdl_req *req;
	struct mcap_mdl *mdl;
	uint16_t mdl_id;
	uint8_t mdep_id;
	uint8_t cfga, conf;
	uint8_t rsp;

	if (!check_cmd_req_length(mcl, cmd, len, sizeof(mcap_md_create_mdl_req),
							MCAP_MD_CREATE_MDL_RSP))
		return;

	req = cmd;
	mdl_id = ntohs(req->mdl);
	if (mdl_id < MCAP_MDLID_INITIAL || mdl_id > MCAP_MDLID_FINAL) {
		mcap_send_cmd(mcl, MCAP_MD_CREATE_MDL_RSP, MCAP_INVALID_MDL,
							mdl_id, NULL, 0);
		return;
	}

	mdep_id = req->mdep;
	if (mdep_id > MCAP_MDEPID_FINAL) {
		mcap_send_cmd(mcl, MCAP_MD_CREATE_MDL_RSP, MCAP_INVALID_MDEP,
							mdl_id, NULL, 0);
		return;
	}

	mdl = get_mdl(mcl, mdl_id);
	if (mdl && (mdl->state == MDL_WAITING || mdl->state == MDL_DELETING )) {
		/* Creation request arrives for a MDL that is being managed
		* at current moment */
		mcap_send_cmd(mcl, MCAP_MD_CREATE_MDL_RSP, MCAP_MDL_BUSY,
							mdl_id, NULL, 0);
		return;
	}

	cfga = conf = req->conf;
	/* Callback to upper layer */
	rsp = mcl->cb->mdl_conn_req(mcl, mdep_id, mdl_id, &conf,
							mcl->cb->user_data);
	if (mcl->state == MCL_IDLE) {
		/* MCL has been closed int the callback */
		return;
	}

	if (cfga != 0 && cfga != conf) {
		/* Remote device set default configuration but upper profile */
		/* has changed it. Protocol Error: force closing the MCL by */
		/* remote device using UNSPECIFIED_ERROR response */
		mcap_send_cmd(mcl, MCAP_MD_CREATE_MDL_RSP,
				MCAP_UNSPECIFIED_ERROR, mdl_id, NULL, 0);
		return;
	}
	if (rsp != MCAP_SUCCESS) {
		mcap_send_cmd(mcl, MCAP_MD_CREATE_MDL_RSP, rsp, mdl_id,
								NULL, 0);
		return;
	}

	if (!mdl) {
		mdl = g_new0(struct mcap_mdl, 1);
		mdl->mcl = mcap_mcl_ref(mcl);
		mdl->mdlid = mdl_id;
		mcl->mdls = g_slist_insert_sorted(mcl->mdls, mcap_mdl_ref(mdl),
								compare_mdl);
	} else if (mdl->state == MDL_CONNECTED) {
		/* MCAP specification says that we should close the MCL if
		 * it is open when we receive a MD_CREATE_MDL_REQ */
		shutdown_mdl(mdl);
	}

	mdl->mdep_id = mdep_id;
	mdl->state = MDL_WAITING;

	mcl->state = MCL_PENDING;
	mcap_send_cmd(mcl, MCAP_MD_CREATE_MDL_RSP, MCAP_SUCCESS, mdl_id,
								&conf, 1);
}

static void process_md_reconnect_mdl_req(struct mcap_mcl *mcl, void *cmd,
								uint32_t len)
{
	mcap_md_req *req;
	struct mcap_mdl *mdl;
	uint16_t mdl_id;
	uint8_t rsp;

	if (!check_cmd_req_length(mcl, cmd, len, sizeof(mcap_md_req),
						MCAP_MD_RECONNECT_MDL_RSP))
		return;

	req = cmd;
	mdl_id = ntohs(req->mdl);

	mdl = get_mdl(mcl, mdl_id);
	if (!mdl) {
		mcap_send_cmd(mcl, MCAP_MD_RECONNECT_MDL_RSP, MCAP_INVALID_MDL,
							mdl_id, NULL, 0);
		return;
	} else if (mdl->state == MDL_WAITING || mdl->state == MDL_DELETING ) {
		/* Creation request arrives for a MDL that is being managed
		* at current moment */
		mcap_send_cmd(mcl, MCAP_MD_RECONNECT_MDL_RSP, MCAP_MDL_BUSY,
							mdl_id, NULL, 0);
		return;
	}

	/* Callback to upper layer */
	rsp = mcl->cb->mdl_reconn_req(mdl, mcl->cb->user_data);
	if (mcl->state == MCL_IDLE)
		return;

	if (rsp != MCAP_SUCCESS) {
		mcap_send_cmd(mcl, MCAP_MD_RECONNECT_MDL_RSP, rsp, mdl_id,
								NULL, 0);
		return;
	}

	if (mdl->state == MDL_CONNECTED)
		shutdown_mdl(mdl);

	mdl->state = MDL_WAITING;
	mcl->state = MCL_PENDING;
	mcap_send_cmd(mcl, MCAP_MD_RECONNECT_MDL_RSP, MCAP_SUCCESS, mdl_id,
								NULL, 0);
}

static void process_md_abort_mdl_req(struct mcap_mcl *mcl, void *cmd,
								uint32_t len)
{
	mcap_md_req *req;
	GSList *l;
	struct mcap_mdl *mdl, *abrt;
	uint16_t mdl_id;

	if (!check_cmd_req_length(mcl, cmd, len, sizeof(mcap_md_req),
							MCAP_MD_ABORT_MDL_RSP))
		return;

	req = cmd;
	mdl_id = ntohs(req->mdl);
	mcl->state = MCL_CONNECTED;
	abrt = NULL;
	for (l = mcl->mdls; l; l = l->next) {
		mdl = l->data;
		if (mdl_id == mdl->mdlid && mdl->state == MDL_WAITING) {
			abrt = mdl;
			if (mcl->state != MCL_CONNECTED)
				break;
			continue;
		}
		if (mdl->state == MDL_CONNECTED && mcl->state != MCL_ACTIVE)
			mcl->state = MCL_ACTIVE;

		if (abrt && mcl->state == MCL_ACTIVE)
			break;
	}

	if (!abrt) {
		mcap_send_cmd(mcl, MCAP_MD_ABORT_MDL_RSP, MCAP_INVALID_MDL,
							mdl_id, NULL, 0);
		return;
	}

	mcl->cb->mdl_aborted(abrt, mcl->cb->user_data);
	abrt->state = MDL_CLOSED;
	mcap_send_cmd(mcl, MCAP_MD_ABORT_MDL_RSP, MCAP_SUCCESS, mdl_id,
								NULL, 0);
}

static void process_md_delete_mdl_req(struct mcap_mcl *mcl, void *cmd,
								uint32_t len)
{
	mcap_md_req *req;
	struct mcap_mdl *mdl, *aux;
	uint16_t mdlid;
	gboolean notify;
	GSList *l;

	if (!check_cmd_req_length(mcl, cmd, len, sizeof(mcap_md_req),
							MCAP_MD_DELETE_MDL_RSP))
		return;

	req = cmd;
	mdlid = ntohs(req->mdl);
	if (mdlid == MCAP_ALL_MDLIDS) {
		notify = FALSE;
		g_slist_foreach(mcl->mdls, mcap_del_mdl, &notify);
		g_slist_free(mcl->mdls);
		mcl->mdls = NULL;
		mcl->state = MCL_CONNECTED;
		/* NULL mdl means ALL_MDLS */
		mcl->cb->mdl_deleted(NULL, mcl->cb->user_data);
		goto resp;
	}

	if (mdlid < MCAP_MDLID_INITIAL || mdlid > MCAP_MDLID_FINAL) {
		mcap_send_cmd(mcl, MCAP_MD_DELETE_MDL_RSP, MCAP_INVALID_MDL,
								mdlid, NULL, 0);
		return;
	}

	for (l = mcl->mdls, mdl = NULL; l; l = l->next) {
		aux = l->data;
		if (aux->mdlid == mdlid) {
			mdl = aux;
			break;
		}
	}

	if (!mdl || mdl->state == MDL_WAITING) {
		mcap_send_cmd(mcl, MCAP_MD_DELETE_MDL_RSP, MCAP_INVALID_MDL,
								mdlid, NULL, 0);
		return;
	}

	mcl->mdls = g_slist_remove(mcl->mdls, mdl);
	update_mcl_state(mcl);
	notify = TRUE;
	mcap_del_mdl(mdl, &notify);

resp:
	mcap_send_cmd(mcl, MCAP_MD_DELETE_MDL_RSP, MCAP_SUCCESS, mdlid,
								NULL, 0);
}

static void invalid_req_state(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	uint16_t mdlr;

	error("Invalid cmd received (op code = %d) in state %d", cmd[0],
								mcl->state);
	/* Get previously mdlid sent to generate an appropriate
	 * response if it is possible */
	mdlr = len < sizeof(mcap_md_req) ? MCAP_MDLID_RESERVED :
					ntohs(((mcap_md_req *) cmd)->mdl);
	mcap_send_cmd(mcl, cmd[0]+1, MCAP_INVALID_OPERATION, mdlr, NULL, 0);
}

/* Function used to process commands depending of MCL state */
static void proc_req_connected(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	switch (cmd[0]) {
	case MCAP_MD_CREATE_MDL_REQ:
		process_md_create_mdl_req(mcl, cmd, len);
		break;
	case MCAP_MD_RECONNECT_MDL_REQ:
		process_md_reconnect_mdl_req(mcl, cmd, len);
		break;
	case MCAP_MD_DELETE_MDL_REQ:
		process_md_delete_mdl_req(mcl, cmd, len);
		break;
	default:
		invalid_req_state(mcl, cmd, len);
	}
}

static void proc_req_pending(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	if (cmd[0] == MCAP_MD_ABORT_MDL_REQ)
		process_md_abort_mdl_req(mcl, cmd, len);
	else
		invalid_req_state(mcl, cmd, len);
}

static void proc_req_active(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	switch (cmd[0]) {
	case MCAP_MD_CREATE_MDL_REQ:
		process_md_create_mdl_req(mcl, cmd, len);
		break;
	case MCAP_MD_RECONNECT_MDL_REQ:
		process_md_reconnect_mdl_req(mcl, cmd, len);
		break;
	case MCAP_MD_DELETE_MDL_REQ:
		process_md_delete_mdl_req(mcl, cmd, len);
		break;
	default:
		invalid_req_state(mcl, cmd, len);
	}
}

/* Function used to process replies */
static gboolean check_err_rsp(struct mcap_mcl *mcl, mcap_rsp *rsp,
				uint32_t rlen, uint32_t len, GError **gerr)
{
	mcap_md_req *cmdlast = (mcap_md_req *) mcl->lcmd;
	gint err = MCAP_ERROR_FAILED;
	gboolean close = FALSE;
	char *msg;

	if (rsp->op == MCAP_ERROR_RSP) {
		msg = "MCAP_ERROR_RSP received";
		close = FALSE;
		goto fail;
	}

	/* Check if the response matches with the last request */
	if (rlen < sizeof(mcap_rsp) || (mcl->lcmd[0] + 1) != rsp->op) {
		msg = "Protocol error";
		close = FALSE;
		goto fail;
	}

	if (rlen < len) {
		msg = "Protocol error";
		close = FALSE;
		goto fail;
	}

	if (rsp->mdl != cmdlast->mdl) {
		msg = "MDLID received doesn't match with MDLID sent";
		close = TRUE;
		goto fail;
	}

	if (rsp->rc == MCAP_REQUEST_NOT_SUPPORTED) {
		msg = "Remote does not support opcodes";
		mcl->ctrl &= ~MCAP_CTRL_STD_OP;
		goto fail;
	}

	if (rsp->rc == MCAP_UNSPECIFIED_ERROR) {
		msg = "Unspecified error";
		close = TRUE;
		goto fail;
	}

	if (rsp->rc != MCAP_SUCCESS) {
		msg = error2str(rsp->rc);
		err = rsp->rc;
		goto fail;
	}

	return FALSE;

fail:
	g_set_error(gerr, MCAP_ERROR, err, "%s", msg);
	return close;
}

static gboolean process_md_create_mdl_rsp(struct mcap_mcl *mcl,
						mcap_rsp *rsp, uint32_t len)
{
	mcap_md_create_mdl_req *cmdlast = (mcap_md_create_mdl_req *) mcl->lcmd;
	struct mcap_mdl_op_cb *conn = mcl->priv_data;
	mcap_mdl_operation_conf_cb connect_cb = conn->cb.op_conf;
	gpointer user_data = conn->user_data;
	struct mcap_mdl *mdl = conn->mdl;
	uint8_t conf = cmdlast->conf;
	gboolean close;
	GError *gerr = NULL;

	close = check_err_rsp(mcl, rsp, len, sizeof(mcap_rsp) + 1, &gerr);
	g_free(mcl->lcmd);
	mcl->lcmd = NULL;
	mcl->req = MCL_AVAILABLE;

	if (gerr)
		goto fail;

	/* Check if preferences changed */
	if (conf != 0x00 && rsp->data[0] != conf) {
		g_set_error(&gerr, MCAP_ERROR, MCAP_ERROR_FAILED,
						"Configuration changed");
		close = TRUE;
		goto fail;
	}

	connect_cb(mdl, rsp->data[0], gerr, user_data);
	return close;

fail:
	connect_cb(NULL, 0, gerr, user_data);
	mcl->mdls = g_slist_remove(mcl->mdls, mdl);
	mcap_mdl_unref(mdl);
	g_error_free(gerr);
	update_mcl_state(mcl);
	return close;
}

static gboolean process_md_reconnect_mdl_rsp(struct mcap_mcl *mcl,
						mcap_rsp *rsp, uint32_t len)
{
	struct mcap_mdl_op_cb *reconn = mcl->priv_data;
	mcap_mdl_operation_cb reconn_cb = reconn->cb.op;
	gpointer user_data = reconn->user_data;
	struct mcap_mdl *mdl = reconn->mdl;
	GError *gerr = NULL;
	gboolean close;

	close = check_err_rsp(mcl, rsp, len, sizeof(mcap_rsp), &gerr);

	g_free(mcl->lcmd);
	mcl->lcmd = NULL;
	mcl->req = MCL_AVAILABLE;

	reconn_cb(mdl, gerr, user_data);
	if (!gerr)
		return close;

	g_error_free(gerr);
	shutdown_mdl(mdl);
	update_mcl_state(mcl);

	if (rsp->rc != MCAP_INVALID_MDL)
		return close;

	/* Remove cached mdlid */
	mcl->mdls = g_slist_remove(mcl->mdls, mdl);
	mcl->cb->mdl_deleted(mdl, mcl->cb->user_data);
	mcap_mdl_unref(mdl);

	return close;
}

static gboolean process_md_abort_mdl_rsp(struct mcap_mcl *mcl,
						mcap_rsp *rsp, uint32_t len)
{
	struct mcap_mdl_op_cb *abrt = mcl->priv_data;
	mcap_mdl_notify_cb abrt_cb = abrt->cb.notify;
	gpointer user_data = abrt->user_data;
	struct mcap_mdl *mdl = abrt->mdl;
	GError *gerr = NULL;
	gboolean close;

	close = check_err_rsp(mcl, rsp, len, sizeof(mcap_rsp), &gerr);

	g_free(mcl->lcmd);
	mcl->lcmd = NULL;
	mcl->req = MCL_AVAILABLE;

	abrt_cb(gerr, user_data);
	shutdown_mdl(mdl);

	if (len >= sizeof(mcap_rsp) && rsp->rc == MCAP_INVALID_MDL) {
		mcl->mdls = g_slist_remove(mcl->mdls, mdl);
		mcl->cb->mdl_deleted(mdl, mcl->cb->user_data);
		mcap_mdl_unref(mdl);
	}

	if (gerr)
		g_error_free(gerr);

	update_mcl_state(mcl);

	return close;
}

static void restore_mdl(gpointer elem, gpointer data)
{
	struct mcap_mdl *mdl = elem;

	if (mdl->state == MDL_DELETING) {
		if (mdl->dc)
			mdl->state = MDL_CONNECTED;
		else
			mdl->state = MDL_CLOSED;
	} else if (mdl->state == MDL_CLOSED)
		mdl->mcl->cb->mdl_closed(mdl, mdl->mcl->cb->user_data);
}

static void check_mdl_del_err(struct mcap_mdl *mdl, mcap_rsp *rsp)
{
	if (rsp->rc != MCAP_ERROR_INVALID_MDL) {
		restore_mdl(mdl, NULL);
		return;
	}

	/* MDL does not exist in remote side, we can delete it */
	mdl->mcl->mdls = g_slist_remove(mdl->mcl->mdls, mdl);
	mcap_mdl_unref(mdl);
}

static gboolean process_md_delete_mdl_rsp(struct mcap_mcl *mcl, mcap_rsp *rsp,
								uint32_t len)
{
	struct mcap_mdl_op_cb *del = mcl->priv_data;
	struct mcap_mdl *mdl = del->mdl;
	mcap_mdl_notify_cb deleted_cb = del->cb.notify;
	gpointer user_data = del->user_data;
	mcap_md_req *cmdlast = (mcap_md_req *) mcl->lcmd;
	uint16_t mdlid = ntohs(cmdlast->mdl);
	GError *gerr = NULL;
	gboolean close;
	gboolean notify = FALSE;

	close = check_err_rsp(mcl, rsp, len, sizeof(mcap_rsp), &gerr);

	g_free(mcl->lcmd);
	mcl->lcmd = NULL;
	mcl->req = MCL_AVAILABLE;

	if (gerr) {
		if (mdl)
			check_mdl_del_err(mdl, rsp);
		else
			g_slist_foreach(mcl->mdls, restore_mdl, NULL);
		deleted_cb(gerr, user_data);
		g_error_free(gerr);
		return close;
	}

	if (mdlid == MCAP_ALL_MDLIDS) {
		g_slist_foreach(mcl->mdls, mcap_del_mdl, &notify);
		g_slist_free(mcl->mdls);
		mcl->mdls = NULL;
		mcl->state = MCL_CONNECTED;
	} else {
		mcl->mdls = g_slist_remove(mcl->mdls, mdl);
		update_mcl_state(mcl);
		mcap_del_mdl(mdl, &notify);
	}

	deleted_cb(gerr, user_data);

	return close;
}

static void post_process_rsp(struct mcap_mcl *mcl, struct mcap_mdl_op_cb *op)
{
	if (mcl->priv_data != op) {
		/* Queued MCAP request in some callback. */
		/* We should not delete the mcl private data */
		free_mcap_mdl_op(op);
	} else {
		/* This is not a queued request. It's safe */
		/* delete the mcl private data here. */
		free_mcl_priv_data(mcl);
	}
}

static void proc_response(struct mcap_mcl *mcl, void *buf, uint32_t len)
{
	struct mcap_mdl_op_cb *op = mcl->priv_data;
	mcap_rsp *rsp = buf;
	gboolean close;

	RELEASE_TIMER(mcl);

	switch (mcl->lcmd[0] + 1) {
	case MCAP_MD_CREATE_MDL_RSP:
		close = process_md_create_mdl_rsp(mcl, rsp, len);
		post_process_rsp(mcl, op);
		break;
	case MCAP_MD_RECONNECT_MDL_RSP:
		close = process_md_reconnect_mdl_rsp(mcl, rsp, len);
		post_process_rsp(mcl, op);
		break;
	case MCAP_MD_ABORT_MDL_RSP:
		close = process_md_abort_mdl_rsp(mcl, rsp, len);
		post_process_rsp(mcl, op);
		break;
	case MCAP_MD_DELETE_MDL_RSP:
		close = process_md_delete_mdl_rsp(mcl, rsp, len);
		post_process_rsp(mcl, op);
		break;
	default:
		DBG("Unknown cmd response received (op code = %d)", rsp->op);
		close = TRUE;
		break;
	}

	if (close) {
		mcl->mi->mcl_disconnected_cb(mcl, mcl->mi->user_data);
		mcap_cache_mcl(mcl);
	}
}

static void proc_cmd(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	GError *gerr = NULL;

	if (cmd[0] > MCAP_MD_SYNC_INFO_IND ||
					(cmd[0] > MCAP_MD_DELETE_MDL_RSP &&
					cmd[0] < MCAP_MD_SYNC_CAP_REQ)) {
		error("Unknown cmd received (op code = %d)", cmd[0]);
		mcap_send_cmd(mcl, MCAP_ERROR_RSP, MCAP_INVALID_OP_CODE,
						MCAP_MDLID_RESERVED, NULL, 0);
		return;
	}

	if (cmd[0] >= MCAP_MD_SYNC_CAP_REQ &&
					cmd[0] <= MCAP_MD_SYNC_INFO_IND) {
		proc_sync_cmd(mcl, cmd, len);
		return;
	}

	if (!(mcl->ctrl & MCAP_CTRL_STD_OP)) {
		/* In case the remote device doesn't work correctly */
		error("Remote device does not support opcodes, cmd ignored");
		return;
	}

	if (mcl->req == MCL_WAITING_RSP) {
		if (cmd[0] & 0x01) {
			/* Request arrived when a response is expected */
			if (mcl->role == MCL_INITIATOR)
				/* ignore */
				return;
			/* Initiator will ignore our last request */
			RELEASE_TIMER(mcl);
			mcl->req = MCL_AVAILABLE;
			g_set_error(&gerr, MCAP_ERROR, MCAP_ERROR_REQ_IGNORED,
				"Initiator sent a request with more priority");
			mcap_notify_error(mcl, gerr);
			proc_req[mcl->state](mcl, cmd, len);
			return;
		}
		proc_response(mcl, cmd, len);
	} else if (cmd[0] & 0x01)
		proc_req[mcl->state](mcl, cmd, len);
}

static gboolean mdl_event_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{

	struct mcap_mdl *mdl = data;
	gboolean notify;

	DBG("Close MDL %d", mdl->mdlid);

	notify = (mdl->state == MDL_CONNECTED);
	shutdown_mdl(mdl);

	update_mcl_state(mdl->mcl);

	if (notify) {
		/*Callback to upper layer */
		mdl->mcl->cb->mdl_closed(mdl, mdl->mcl->cb->user_data);
	}

	return FALSE;
}

static void mcap_connect_mdl_cb(GIOChannel *chan, GError *conn_err,
								gpointer data)
{
	struct mcap_mdl_op_cb *con = data;
	struct mcap_mdl *mdl = con->mdl;
	mcap_mdl_operation_cb cb = con->cb.op;
	gpointer user_data = con->user_data;

	DBG("mdl connect callback");

	if (conn_err) {
		DBG("ERROR: mdl connect callback");
		mdl->state = MDL_CLOSED;
		g_io_channel_unref(mdl->dc);
		mdl->dc = NULL;
		cb(mdl, conn_err, user_data);
		return;
	}

	mdl->state = MDL_CONNECTED;
	mdl->wid = g_io_add_watch_full(mdl->dc, G_PRIORITY_DEFAULT,
					G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) mdl_event_cb,
					mcap_mdl_ref(mdl),
					(GDestroyNotify) mcap_mdl_unref);

	cb(mdl, conn_err, user_data);
}

gboolean mcap_connect_mdl(struct mcap_mdl *mdl, uint8_t mode,
					uint16_t dcpsm,
					mcap_mdl_operation_cb connect_cb,
					gpointer user_data,
					GDestroyNotify destroy,
					GError **err)
{
	struct mcap_mdl_op_cb *con;

	if (mdl->state != MDL_WAITING) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_MDL,
					"%s", error2str(MCAP_INVALID_MDL));
		return FALSE;
	}

	if ((mode != L2CAP_MODE_ERTM) && (mode != L2CAP_MODE_STREAMING)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
						"Invalid MDL configuration");
		return FALSE;
	}

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = mcap_mdl_ref(mdl);
	con->cb.op = connect_cb;
	con->destroy = destroy;
	con->user_data = user_data;

	mdl->dc = bt_io_connect(BT_IO_L2CAP, mcap_connect_mdl_cb, con,
				(GDestroyNotify) free_mcap_mdl_op, err,
				BT_IO_OPT_SOURCE_BDADDR, &mdl->mcl->mi->src,
				BT_IO_OPT_DEST_BDADDR, &mdl->mcl->addr,
				BT_IO_OPT_PSM, dcpsm,
				BT_IO_OPT_MTU, MCAP_DC_MTU,
				BT_IO_OPT_SEC_LEVEL, mdl->mcl->mi->sec,
				BT_IO_OPT_MODE, mode,
				BT_IO_OPT_INVALID);
	if (!mdl->dc) {
		DBG("MDL Connection error");
		mdl->state = MDL_CLOSED;
		mcap_mdl_unref(con->mdl);
		g_free(con);
		return FALSE;
	}

	return TRUE;
}

static gboolean mcl_control_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	GError *gerr = NULL;
	struct mcap_mcl *mcl = data;
	int sk, len;
	uint8_t buf[MCAP_CC_MTU];

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		goto fail;

	sk = g_io_channel_unix_get_fd(chan);
	len = read(sk, buf, sizeof(buf));
	if (len < 0)
		goto fail;

	proc_cmd(mcl, buf, (uint32_t) len);
	return TRUE;

fail:
	if (mcl->state != MCL_IDLE) {
		if (mcl->req == MCL_WAITING_RSP) {
			/* notify error in pending callback */
			g_set_error(&gerr, MCAP_ERROR, MCAP_ERROR_MCL_CLOSED,
								"MCL closed");
			mcap_notify_error(mcl, gerr);
			g_error_free(gerr);
		}
		mcl->mi->mcl_disconnected_cb(mcl, mcl->mi->user_data);
	}
	mcap_cache_mcl(mcl);
	return FALSE;
}

static void mcap_connect_mcl_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	char dstaddr[18];
	struct connect_mcl *con = user_data;
	struct mcap_mcl *aux, *mcl = con->mcl;
	mcap_mcl_connect_cb connect_cb = con->connect_cb;
	gpointer data = con->user_data;
	GError *gerr = NULL;

	mcl->ctrl &= ~MCAP_CTRL_CONN;

	if (conn_err) {
		if (mcl->ctrl & MCAP_CTRL_FREE) {
			mcap_mcl_release(mcl);
			mcl->mi->mcl_uncached_cb(mcl, mcl->mi->user_data);
		}
		connect_cb(NULL, conn_err, data);
		return;
	}

	ba2str(&mcl->addr, dstaddr);

	aux = find_mcl(mcl->mi->mcls, &mcl->addr);
	if (aux) {
		/* Double MCL connection case */
		error("MCL error: Device %s is already connected", dstaddr);
		g_set_error(&gerr, MCAP_ERROR, MCAP_ERROR_ALREADY_EXISTS,
					"MCL %s is already connected", dstaddr);
		connect_cb(NULL, gerr, data);
		g_error_free(gerr);
		return;
	}

	mcl->state = MCL_CONNECTED;
	mcl->role = MCL_INITIATOR;
	mcl->req = MCL_AVAILABLE;
	mcl->ctrl |= MCAP_CTRL_STD_OP;

	mcap_sync_init(mcl);

	if (mcl->ctrl & MCAP_CTRL_CACHED)
		mcap_uncache_mcl(mcl);
	else {
		mcl->ctrl &= ~MCAP_CTRL_FREE;
		mcl->mi->mcls = g_slist_prepend(mcl->mi->mcls,
							mcap_mcl_ref(mcl));
	}

	mcl->wid = g_io_add_watch_full(mcl->cc, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) mcl_control_cb,
				mcap_mcl_ref(mcl),
				(GDestroyNotify) mcap_mcl_unref);
	connect_cb(mcl, gerr, data);
}

static void set_mdl_properties(GIOChannel *chan, struct mcap_mdl *mdl)
{
	struct mcap_mcl *mcl = mdl->mcl;

	mdl->state = MDL_CONNECTED;
	mdl->dc = g_io_channel_ref(chan);
	mdl->wid = g_io_add_watch_full(mdl->dc, G_PRIORITY_DEFAULT,
					G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) mdl_event_cb,
					mcap_mdl_ref(mdl),
					(GDestroyNotify) mcap_mdl_unref);

	mcl->state = MCL_ACTIVE;
	mcl->cb->mdl_connected(mdl, mcl->cb->user_data);
}

static void mcl_io_destroy(gpointer data)
{
	struct connect_mcl *con = data;

	mcap_mcl_unref(con->mcl);
	if (con->destroy)
		con->destroy(con->user_data);
	g_free(con);
}

gboolean mcap_create_mcl(struct mcap_instance *mi,
				const bdaddr_t *addr,
				uint16_t ccpsm,
				mcap_mcl_connect_cb connect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err)
{
	struct mcap_mcl *mcl;
	struct connect_mcl *con;

	mcl = find_mcl(mi->mcls, addr);
	if (mcl) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_ALREADY_EXISTS,
					"MCL is already connected.");
		return FALSE;
	}

	mcl = find_mcl(mi->cached, addr);
	if (!mcl) {
		mcl = g_new0(struct mcap_mcl, 1);
		mcl->mi = mcap_instance_ref(mi);
		mcl->state = MCL_IDLE;
		bacpy(&mcl->addr, addr);
		set_default_cb(mcl);
		mcl->next_mdl = (rand() % MCAP_MDLID_FINAL) + 1;
	}

	mcl->ctrl |= MCAP_CTRL_CONN;

	con = g_new0(struct connect_mcl, 1);
	con->mcl = mcap_mcl_ref(mcl);
	con->connect_cb = connect_cb;
	con->destroy = destroy;
	con->user_data = user_data;

	mcl->cc = bt_io_connect(BT_IO_L2CAP, mcap_connect_mcl_cb, con,
				mcl_io_destroy, err,
				BT_IO_OPT_SOURCE_BDADDR, &mi->src,
				BT_IO_OPT_DEST_BDADDR, addr,
				BT_IO_OPT_PSM, ccpsm,
				BT_IO_OPT_MTU, MCAP_CC_MTU,
				BT_IO_OPT_SEC_LEVEL, mi->sec,
				BT_IO_OPT_MODE, L2CAP_MODE_ERTM,
				BT_IO_OPT_INVALID);
	if (!mcl->cc) {
		mcl->ctrl &= ~MCAP_CTRL_CONN;
		if (mcl->ctrl & MCAP_CTRL_FREE) {
			mcap_mcl_release(mcl);
			mcl->mi->mcl_uncached_cb(mcl, mcl->mi->user_data);
		}
		mcap_mcl_unref(con->mcl);
		g_free(con);
		return FALSE;
	}

	return TRUE;
}

static void connect_dc_event_cb(GIOChannel *chan, GError *gerr,
							gpointer user_data)
{
	struct mcap_instance *mi = user_data;
	struct mcap_mcl *mcl;
	struct mcap_mdl *mdl;
	GError *err = NULL;
	bdaddr_t dst;
	GSList *l;

	if (gerr)
		return;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	mcl = find_mcl(mi->mcls, &dst);
	if (!mcl || mcl->state != MCL_PENDING)
		goto drop;

	for (l = mcl->mdls; l; l = l->next) {
		mdl = l->data;
		if (mdl->state == MDL_WAITING) {
			set_mdl_properties(chan, mdl);
			return;
		}
	}

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

static void set_mcl_conf(GIOChannel *chan, struct mcap_mcl *mcl)
{
	gboolean reconn;

	mcl->state = MCL_CONNECTED;
	mcl->role = MCL_ACCEPTOR;
	mcl->req = MCL_AVAILABLE;
	mcl->cc = g_io_channel_ref(chan);
	mcl->ctrl |= MCAP_CTRL_STD_OP;

	mcap_sync_init(mcl);

	reconn = (mcl->ctrl & MCAP_CTRL_CACHED);
	if (reconn)
		mcap_uncache_mcl(mcl);
	else
		mcl->mi->mcls = g_slist_prepend(mcl->mi->mcls,
							mcap_mcl_ref(mcl));

	mcl->wid = g_io_add_watch_full(mcl->cc, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) mcl_control_cb,
				mcap_mcl_ref(mcl),
				(GDestroyNotify) mcap_mcl_unref);

	/* Callback to report new MCL */
	if (reconn)
		mcl->mi->mcl_reconnected_cb(mcl, mcl->mi->user_data);
	else
		mcl->mi->mcl_connected_cb(mcl, mcl->mi->user_data);
}

static void connect_mcl_event_cb(GIOChannel *chan, GError *gerr,
							gpointer user_data)
{
	struct mcap_instance *mi = user_data;
	struct mcap_mcl *mcl;
	bdaddr_t dst;
	char address[18], srcstr[18];
	GError *err = NULL;

	if (gerr)
		return;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	ba2str(&mi->src, srcstr);
	mcl = find_mcl(mi->mcls, &dst);
	if (mcl) {
		error("Control channel already created with %s on adapter %s",
				address, srcstr);
		goto drop;
	}

	mcl = find_mcl(mi->cached, &dst);
	if (!mcl) {
		mcl = g_new0(struct mcap_mcl, 1);
		mcl->mi = mcap_instance_ref(mi);
		bacpy(&mcl->addr, &dst);
		set_default_cb(mcl);
		mcl->next_mdl = (rand() % MCAP_MDLID_FINAL) + 1;
	}

	set_mcl_conf(chan, mcl);

	return;
drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

struct mcap_instance *mcap_create_instance(bdaddr_t *src,
					BtIOSecLevel sec,
					uint16_t ccpsm,
					uint16_t dcpsm,
					mcap_mcl_event_cb mcl_connected,
					mcap_mcl_event_cb mcl_reconnected,
					mcap_mcl_event_cb mcl_disconnected,
					mcap_mcl_event_cb mcl_uncached,
					mcap_info_ind_event_cb mcl_sync_info_ind,
					gpointer user_data,
					GError **gerr)
{
	struct mcap_instance *mi;

	if (sec < BT_IO_SEC_MEDIUM) {
		g_set_error(gerr, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
				"Security level can't be minor of %d",
				BT_IO_SEC_MEDIUM);
		return NULL;
	}

	if (!(mcl_connected && mcl_reconnected &&
			mcl_disconnected && mcl_uncached)) {
		g_set_error(gerr, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
				"The callbacks can't be null");
		return NULL;
	}

	mi = g_new0(struct mcap_instance, 1);

	bacpy(&mi->src, src);

	mi->sec = sec;
	mi->mcl_connected_cb = mcl_connected;
	mi->mcl_reconnected_cb = mcl_reconnected;
	mi->mcl_disconnected_cb = mcl_disconnected;
	mi->mcl_uncached_cb = mcl_uncached;
	mi->mcl_sync_infoind_cb = mcl_sync_info_ind;
	mi->user_data = user_data;
	mi->csp_enabled = FALSE;

	/* Listen incoming connections in control channel */
	mi->ccio = bt_io_listen(BT_IO_L2CAP, connect_mcl_event_cb, NULL, mi,
				NULL, gerr,
				BT_IO_OPT_SOURCE_BDADDR, &mi->src,
				BT_IO_OPT_PSM, ccpsm,
				BT_IO_OPT_MTU, MCAP_CC_MTU,
				BT_IO_OPT_SEC_LEVEL, sec,
				BT_IO_OPT_MODE, L2CAP_MODE_ERTM,
				BT_IO_OPT_INVALID);
	if (!mi->ccio) {
		error("%s", (*gerr)->message);
		g_free(mi);
		return NULL;
	}

	/* Listen incoming connections in data channels */
	mi->dcio = bt_io_listen(BT_IO_L2CAP, connect_dc_event_cb, NULL, mi,
				NULL, gerr,
				BT_IO_OPT_SOURCE_BDADDR, &mi->src,
				BT_IO_OPT_PSM, dcpsm,
				BT_IO_OPT_MTU, MCAP_DC_MTU,
				BT_IO_OPT_SEC_LEVEL, sec,
				BT_IO_OPT_INVALID);
	if (!mi->dcio) {
		g_io_channel_shutdown(mi->ccio, TRUE, NULL);
		g_io_channel_unref(mi->ccio);
		mi->ccio = NULL;
		error("%s", (*gerr)->message);
		g_free(mi);
		return NULL;
	}

	/* Initialize random seed to generate mdlids for this instance */
	srand(time(NULL));

	return mcap_instance_ref(mi);;
}

void mcap_release_instance(struct mcap_instance *mi)
{
	GSList *l;

	if (!mi)
		return;

	if (mi->ccio) {
		g_io_channel_shutdown(mi->ccio, TRUE, NULL);
		g_io_channel_unref(mi->ccio);
		mi->ccio = NULL;
	}

	if (mi->dcio) {
		g_io_channel_shutdown(mi->dcio, TRUE, NULL);
		g_io_channel_unref(mi->dcio);
		mi->dcio = NULL;
	}

	for (l = mi->mcls; l; l = l->next) {
		mcap_mcl_release(l->data);
		mcap_mcl_unref(l->data);
	}

	g_slist_free(mi->mcls);
	mi->mcls = NULL;

	for (l = mi->cached; l; l = l->next) {
		mcap_mcl_release(l->data);
		mcap_mcl_unref(l->data);
	}

	g_slist_free(mi->cached);
	mi->cached = NULL;
}

struct mcap_instance *mcap_instance_ref(struct mcap_instance *mi)
{
	mi->ref++;

	DBG("mcap_instance_ref(%p): ref=%d", mi, mi->ref);

	return mi;
}

void mcap_instance_unref(struct mcap_instance *mi)
{
	mi->ref--;

	DBG("mcap_instance_unref(%p): ref=%d", mi, mi->ref);

	if (mi->ref > 0)
		return;

	mcap_release_instance(mi);
	g_free(mi);
}

uint16_t mcap_get_ctrl_psm(struct mcap_instance *mi, GError **err)
{
	uint16_t lpsm;

	if (!(mi && mi->ccio)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
			"Invalid MCAP instance");
		return 0;
	}

	if (!bt_io_get(mi->ccio, BT_IO_L2CAP, err,
			BT_IO_OPT_PSM, &lpsm,
			BT_IO_OPT_INVALID))
		return 0;

	return lpsm;
}

uint16_t mcap_get_data_psm(struct mcap_instance *mi, GError **err)
{
	uint16_t lpsm;

	if (!(mi && mi->dcio)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
			"Invalid MCAP instance");
		return 0;
	}

	if (!bt_io_get(mi->dcio, BT_IO_L2CAP, err,
			BT_IO_OPT_PSM, &lpsm,
			BT_IO_OPT_INVALID))
		return 0;

	return lpsm;
}

gboolean mcap_set_data_chan_mode(struct mcap_instance *mi, uint8_t mode,
								GError **err)
{
	if (!(mi && mi->dcio)) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_INVALID_ARGS,
						"Invalid MCAP instance");
		return FALSE;
	}

	return bt_io_set(mi->dcio, BT_IO_L2CAP, err, BT_IO_OPT_MODE, mode,
							BT_IO_OPT_INVALID);
}

struct mcap_mdl *mcap_mdl_ref(struct mcap_mdl *mdl)
{
	mdl->ref++;

	DBG("mcap_mdl_ref(%p): ref=%d", mdl, mdl->ref);

	return mdl;
}

void mcap_mdl_unref(struct mcap_mdl *mdl)
{
	mdl->ref--;

	DBG("mcap_mdl_unref(%p): ref=%d", mdl, mdl->ref);

	if (mdl->ref > 0)
		return;

	free_mdl(mdl);
}
