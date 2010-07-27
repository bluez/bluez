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

#define RELEASE_TIMER(__mcl) do {	\
	g_source_remove(__mcl->tid);	\
	__mcl->tid = 0;			\
} while(0)

struct connect_mcl {
	struct mcap_mcl		*mcl;		/* MCL for this operation */
	mcap_mcl_connect_cb	connect_cb;	/* Connect callback */
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

static void mcap_notify_error(struct mcap_mcl *mcl, GError *err)
{
	/* TODO: implement mcap_notify_error */
}

int mcap_send_data(int sock, const uint8_t *buf, uint32_t size)
{
	uint32_t sent = 0;

	while (sent < size) {
		int n = write(sock, buf + sent, size - sent);
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
	uint8_t *rsp;
	int sock, sent;

	if (mcl->cc == NULL)
		return -1;

	sock = g_io_channel_unix_get_fd(mcl->cc);

	rsp = g_malloc(sizeof(mcap_rsp) + len);
	cmd = (mcap_rsp *) rsp;
	cmd->op = oc;
	cmd->rc = rc;
	cmd->mdl = htons(mdl);

	if (data && len > 0)
		memcpy(rsp + sizeof(mcap_rsp), data, len);

	sent = mcap_send_data(sock, rsp, sizeof(mcap_rsp) + len);
	g_free(rsp);
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
	mcl->ms->mcl_disconnected_cb(mcl, mcl->ms->user_data);
	mcap_cache_mcl(mcl);
	return FALSE;
}

gboolean mcap_create_mdl(struct mcap_mcl *mcl,
				uint8_t mdepid,
				uint8_t conf,
				mcap_mdl_operation_conf_cb connect_cb,
				gpointer user_data,
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
	mdl->mcl = mcl;
	mdl->mdlid = id;
	mdl->mdep_id = mdepid;
	mdl->state = MDL_WAITING;

	con = g_new0(struct mcap_mdl_op_cb, 1);
	con->mdl = mdl;
	con->cb.op_conf = connect_cb;
	con->user_data = user_data;

	cmd = create_mdl_req(id, mdepid, conf);
	if (!mcap_send_std_opcode(mcl, cmd, sizeof(mcap_md_create_mdl_req),
									err)) {
		g_free(mdl);
		g_free(con);
		g_free(cmd);
		return FALSE;
	}

	mcl->state = MCL_ACTIVE;
	mcl->priv_data = con;

	mcl->mdls = g_slist_insert_sorted(mcl->mdls, mdl, compare_mdl);
	mcl->tid = g_timeout_add_seconds(RESPONSE_TIMER, wait_response_timer,
									mcl);
	return TRUE;
}

static struct mcap_mcl *find_mcl(GSList *list, const bdaddr_t *addr)
{
	GSList *l;
	struct mcap_mcl *mcl;

	for (l = list; l; l = l->next) {
		mcl = l->data;

		if (!bacmp(&mcl->addr, addr))
			return mcl;
	}

	return NULL;
}

static void close_mcl(struct mcap_mcl *mcl, gboolean cache_requested)
{
	gboolean save = ((!(mcl->ctrl & MCAP_CTRL_FREE)) && cache_requested);

	if (mcl->tid) {
		RELEASE_TIMER(mcl);
	}

	if (mcl->cc) {
		g_io_channel_shutdown(mcl->cc, TRUE, NULL);
		g_io_channel_unref(mcl->cc);
		mcl->cc = NULL;
	}

	g_source_remove(mcl->wid);
	if (mcl->lcmd) {
		g_free(mcl->lcmd);
		mcl->lcmd = NULL;
	}

	if (mcl->priv_data) {
		g_free(mcl->priv_data);
		mcl->priv_data = NULL;
	}

	/* TODO: shutdown mdls and free if needed */

	if (mcl->cb && !save) {
		g_free(mcl->cb);
		mcl->cb = NULL;
	}

	mcl->state = MCL_IDLE;

	if (save)
		return;

	g_free(mcl);
}

static void mcap_mcl_shutdown(struct mcap_mcl *mcl)
{
	close_mcl(mcl, TRUE);
}

static void mcap_mcl_release(struct mcap_mcl *mcl)
{
	close_mcl(mcl, FALSE);
}

static void mcap_mcl_check_del(struct mcap_mcl *mcl)
{
	if (mcl->ctrl & MCAP_CTRL_CACHED)
		mcap_mcl_shutdown(mcl);
	else
		mcap_mcl_unref(mcl);
}

static void mcap_cache_mcl(struct mcap_mcl *mcl)
{
	GSList *l;
	struct mcap_mcl *last;
	int len;

	if (mcl->ctrl & MCAP_CTRL_CACHED)
		return;

	mcl->ms->mcls = g_slist_remove(mcl->ms->mcls, mcl);

	if ((mcl->ctrl & MCAP_CTRL_NOCACHE) || (mcl->ref < 2)) {
		mcap_mcl_unref(mcl);
		return;
	}

	DBG("Caching MCL");

	len = g_slist_length(mcl->ms->cached);
	if (len == MAX_CACHED) {
		/* Remove the latest cached mcl */
		l = g_slist_last(mcl->ms->cached);
		last = l->data;
		mcl->ms->cached = g_slist_remove(mcl->ms->cached, last);
		last->ctrl &= ~MCAP_CTRL_CACHED;
		if (last->ctrl & MCAP_CTRL_CONN) {
			/* If connection process is not success this MCL will be
			 * freed next time that close_mcl is invoked */
			last->ctrl |= MCAP_CTRL_FREE;
		} else {
			last->ms->mcl_uncached_cb(last, last->ms->user_data);
			mcap_mcl_unref(last);
		}
	}

	mcl->ms->cached = g_slist_prepend(mcl->ms->cached, mcl);
	mcl->ctrl |= MCAP_CTRL_CACHED;
	mcap_mcl_shutdown(mcl);
}

static void mcap_uncache_mcl(struct mcap_mcl *mcl)
{
	if (!(mcl->ctrl & MCAP_CTRL_CACHED))
		return;

	DBG("Got MCL from cache");

	mcl->ms->cached = g_slist_remove(mcl->ms->cached, mcl);
	mcl->ms->mcls = g_slist_prepend(mcl->ms->mcls, mcl);
	mcl->ctrl &= ~MCAP_CTRL_CACHED;
	mcl->ctrl &= ~MCAP_CTRL_FREE;
}

void mcap_close_mcl(struct mcap_mcl *mcl, gboolean cache)
{
	if (!mcl)
		return;

	if (mcl->cc) {
		g_io_channel_shutdown(mcl->cc, TRUE, NULL);
		g_io_channel_unref(mcl->cc);
		mcl->cc = NULL;
	}

	mcl->state = MCL_IDLE;

	if (!cache)
		mcl->ctrl |= MCAP_CTRL_NOCACHE;
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

	if ((mcl->ctrl & MCAP_CTRL_CACHED) && (mcl->ref < 2)) {
		/* Free space in cache memory due any other profile has a local
		 * copy of current MCL stored in cache */
		DBG("Remove from cache (%p): ref=%d", mcl, mcl->ref);
		mcl->ms->cached = g_slist_remove(mcl->ms->cached, mcl);
		mcap_mcl_release(mcl);
		return;
	}

	if (mcl->ref > 0)
		return;

	mcap_mcl_release(mcl);
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

/* Function used to process commands depending of MCL state */
static void proc_req_connected(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	/* TODO: Implement proc_req_connected */
}

static void proc_req_pending(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	/* TODO: Implement proc_req_pending */
}

static void proc_req_active(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	/* TODO: Implement proc_req_active */
}

static void proc_response(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	/* TODO: Implement proc_response */
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
		/* TODO: proc_sync_cmd(mcl, cmd, len);*/
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
		mcl->ms->mcl_disconnected_cb(mcl, mcl->ms->user_data);
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

	g_free(con);

	mcl->ctrl &= ~MCAP_CTRL_CONN;

	if (conn_err) {
		if (mcl->ctrl & MCAP_CTRL_FREE)
			mcl->ms->mcl_uncached_cb(mcl, mcl->ms->user_data);
		mcap_mcl_check_del(mcl);
		connect_cb(NULL, conn_err, data);
		return;
	}

	ba2str(&mcl->addr, dstaddr);

	aux = find_mcl(mcl->ms->mcls, &mcl->addr);
	if (aux) {
		/* Double MCL connection case */
		if (aux != mcl) {
			/* This MCL was not in cache */
			mcap_mcl_unref(mcl);
		}
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

	if (mcl->ctrl & MCAP_CTRL_CACHED)
		mcap_uncache_mcl(mcl);
	else
		mcl->ms->mcls = g_slist_prepend(mcl->ms->mcls, mcl);

	mcl->wid = g_io_add_watch(mcl->cc,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) mcl_control_cb, mcl);
	connect_cb(mcl, gerr, data);

	if (mcl->ref == 1) {
		mcl->ms->mcls = g_slist_remove(mcl->ms->mcls, mcl);
		mcap_mcl_unref(mcl);
	}
}

gboolean mcap_create_mcl(struct mcap_instance *ms,
				const bdaddr_t *addr,
				uint16_t ccpsm,
				mcap_mcl_connect_cb connect_cb,
				gpointer user_data,
				GError **err)
{
	struct mcap_mcl *mcl;
	struct connect_mcl *con;

	mcl = find_mcl(ms->mcls, addr);
	if (mcl) {
		g_set_error(err, MCAP_ERROR, MCAP_ERROR_ALREADY_EXISTS,
					"MCL is already connected.");
		return FALSE;
	}

	mcl = find_mcl(ms->cached, addr);
	if (!mcl) {
		mcl = g_new0(struct mcap_mcl, 1);
		mcl->ms = ms;
		mcl->state = MCL_IDLE;
		bacpy(&mcl->addr, addr);
		set_default_cb(mcl);
		mcl->next_mdl = (rand() % MCAP_MDLID_FINAL) + 1;
		mcl = mcap_mcl_ref(mcl);
	} else
		mcl->ctrl |= MCAP_CTRL_CONN;

	con = g_new0(struct connect_mcl, 1);
	con->mcl = mcl;
	con->connect_cb = connect_cb;
	con->user_data = user_data;

	mcl->cc = bt_io_connect(BT_IO_L2CAP, mcap_connect_mcl_cb, con,
				NULL, err,
				BT_IO_OPT_SOURCE_BDADDR, &ms->src,
				BT_IO_OPT_DEST_BDADDR, addr,
				BT_IO_OPT_PSM, ccpsm,
				BT_IO_OPT_MTU, MCAP_CC_MTU,
				BT_IO_OPT_SEC_LEVEL, ms->sec,
				BT_IO_OPT_INVALID);
	if (!mcl->cc) {
		g_free(con);
		mcl->ctrl &= ~MCAP_CTRL_CONN;
		if (mcl->ctrl & MCAP_CTRL_FREE)
			mcl->ms->mcl_uncached_cb(mcl, mcl->ms->user_data);
		mcap_mcl_check_del(mcl);
		return FALSE;
	}
	return TRUE;
}

static void confirm_dc_event_cb(GIOChannel *chan, gpointer user_data)
{
	/* TODO: implement confirm_dc_event_cb */
}

static void connect_mcl_event_cb(GIOChannel *chan, GError *err,
							gpointer user_data)
{
	struct mcap_mcl *mcl = user_data;
	gboolean reconn;

	if (err) {
		mcap_mcl_check_del(mcl);
		return;
	}

	mcl->state = MCL_CONNECTED;
	mcl->role = MCL_ACCEPTOR;
	mcl->req = MCL_AVAILABLE;
	mcl->cc = g_io_channel_ref(chan);
	mcl->ctrl |= MCAP_CTRL_STD_OP;

	reconn = (mcl->ctrl & MCAP_CTRL_CACHED);
	if (reconn)
		mcap_uncache_mcl(mcl);
	else
		mcl->ms->mcls = g_slist_prepend(mcl->ms->mcls, mcl);

	mcl->wid = g_io_add_watch(mcl->cc,
			G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) mcl_control_cb, mcl);

	/* Callback to report new MCL */
	if (reconn)
		mcl->ms->mcl_reconnected_cb(mcl, mcl->ms->user_data);
	else
		mcl->ms->mcl_connected_cb(mcl, mcl->ms->user_data);

	if (mcl->ref == 1) {
		mcl->ms->mcls = g_slist_remove(mcl->ms->mcls, mcl);
		mcap_mcl_unref(mcl);
	}
}

static void confirm_mcl_event_cb(GIOChannel *chan, gpointer user_data)
{
	struct mcap_instance *ms = user_data;
	struct mcap_mcl *mcl;
	bdaddr_t dst;
	char address[18], srcstr[18];
	GError *err = NULL;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	ba2str(&ms->src, srcstr);
	mcl = find_mcl(ms->mcls, &dst);
	if (mcl) {
		error("Control channel already created with %s on adapter %s",
				address, srcstr);
		goto drop;
	}

	mcl = find_mcl(ms->cached, &dst);
	if (!mcl) {
		mcl = g_new0(struct mcap_mcl, 1);
		mcl->ms = ms;
		bacpy(&mcl->addr, &dst);
		set_default_cb(mcl);
		mcl->next_mdl = (rand() % MCAP_MDLID_FINAL) + 1;
		mcl = mcap_mcl_ref(mcl);
	}

	if (!bt_io_accept(chan, connect_mcl_event_cb, mcl, NULL, &err)) {
		error("mcap accept error: %s", err->message);
		if (!(mcl->ctrl & MCAP_CTRL_CACHED))
			mcap_mcl_unref(mcl);
		g_error_free(err);
		goto drop;
	}

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
					gpointer user_data,
					GError **gerr)
{
	struct mcap_instance *ms;

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

	ms = g_new0(struct mcap_instance, 1);

	bacpy(&ms->src, src);

	ms->sec = sec;
	ms->mcl_connected_cb = mcl_connected;
	ms->mcl_reconnected_cb = mcl_reconnected;
	ms->mcl_disconnected_cb = mcl_disconnected;
	ms->mcl_uncached_cb = mcl_uncached;
	ms->user_data = user_data;

	/* Listen incoming connections in control channel */
	ms->ccio = bt_io_listen(BT_IO_L2CAP, NULL, confirm_mcl_event_cb, ms,
				NULL, gerr,
				BT_IO_OPT_SOURCE_BDADDR, &ms->src,
				BT_IO_OPT_PSM, ccpsm,
				BT_IO_OPT_MTU, MCAP_CC_MTU,
				BT_IO_OPT_SEC_LEVEL, sec,
				BT_IO_OPT_INVALID);
	if (!ms->ccio) {
		error("%s", (*gerr)->message);
		g_free(ms);
		return NULL;
	}

	/* Listen incoming connections in data channels */
	ms->dcio = bt_io_listen(BT_IO_L2CAP, NULL, confirm_dc_event_cb, ms,
				NULL, gerr,
				BT_IO_OPT_SOURCE_BDADDR, &ms->src,
				BT_IO_OPT_PSM, dcpsm,
				BT_IO_OPT_MTU, MCAP_DC_MTU,
				BT_IO_OPT_SEC_LEVEL, sec,
				BT_IO_OPT_INVALID);
	if (!ms->dcio) {
		g_io_channel_shutdown(ms->ccio, TRUE, NULL);
		g_io_channel_unref(ms->ccio);
		ms->ccio = NULL;
		error("%s", (*gerr)->message);
		g_free(ms);
		return NULL;
	}
	/* Initialize random seed to generate mdlids for this instance */
	srand(time(NULL));
	return ms;
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
		mcap_mcl_shutdown(l->data);
		mcap_mcl_unref(l->data);
	}
	g_slist_free(mi->mcls);
	mi->mcls = NULL;

	for (l = mi->cached; l; l = l->next)
		mcap_mcl_unref(l->data);
	g_slist_free(mi->cached);
	mi->cached = NULL;

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

	bt_io_get(mi->ccio, BT_IO_L2CAP, err,
			BT_IO_OPT_PSM, &lpsm,
			BT_IO_OPT_INVALID);
	if (*err)
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

	bt_io_get(mi->dcio, BT_IO_L2CAP, err,
			BT_IO_OPT_PSM, &lpsm,
			BT_IO_OPT_INVALID);
	if (*err)
		return 0;
	return lpsm;
}
