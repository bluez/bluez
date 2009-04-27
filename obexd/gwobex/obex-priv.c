/**
  @file obex-priv.c

  Private functions for the GW OBEX Library

  @author Johan Hedberg <johan.hedberg@nokia.com>

  Copyright (C) 2004-2006 Nokia Corporation. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License, version 2.1, as published by the Free Software Foundation.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.

*/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <utime.h>
#include <fcntl.h>
#include <strings.h>
#include <glib.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <openobex/obex.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "log.h"
#include "gw-obex.h"
#include "utils.h"
#include "obex-xfer.h"
#include "obex-priv.h"

#define MAX_TIMEOUTS 20
#define MAX_TIMEOUTS_FIRST 60

static gboolean file_is_dir(const char *filename) {
    struct stat st;

    if (stat(filename, &st) < 0)
        return FALSE;

    if (S_ISDIR(st.st_mode))
        return TRUE;

    return FALSE;
}

static void idle_callback(obex_t *handle, obex_object_t *object, int mode,
                    int event, int obex_cmd, int obex_rsp) {
    debug("idle_callback() called\n");
    sleep(1);
}

static gboolean gw_obex_request_async(GwObex *ctx, obex_object_t *object) {
    ctx->done = FALSE;

    /* If this is a put, the first request can only be sent after we
     * have some data in the outgoing buffer */
    if (ctx->obex_op == OBEX_CMD_PUT) {
        ctx->xfer->object = object;
        return TRUE;
    }

    if (OBEX_Request(ctx->handle, object) < 0) {
        debug("OBEX_Request() failed\n");
        ctx->error = GW_OBEX_ERROR_INTERNAL;
        return FALSE;
    }

    return TRUE;
}

static gboolean gw_obex_request_sync(GwObex *ctx, obex_object_t *object) {
    int timeouts = 0, first = 1;

    /* Set sensible start values */
    ctx->done       = FALSE;

    if (OBEX_Request(ctx->handle, object) < 0) {
        debug("OBEX_Request() failed\n");
        ctx->error = GW_OBEX_ERROR_INTERNAL;
        return FALSE;
    }

    while (TRUE) {
        int ret, max_timeouts;

        ret = OBEX_HandleInput(ctx->handle, 1);

        if (ctx->done)
            break;

        if (ctx->cancel_cb && ctx->cancel_cb(ctx->cancel_data)) {
            debug("cancel_cb() returned TRUE, aborting.\n");
            if (ctx->xfer->abort)
                continue;
            if (!gw_obex_xfer_do_abort(ctx->xfer))
                break;
            /* Must continue to receive the abort reply */
            continue;
        }

        if (ret < 0) {
            debug("OBEX_HandleInput() failed\n");
            ctx->error = GW_OBEX_ERROR_INTERNAL;
            return FALSE;
        }

        /* Timeout */
        if (ret == 0)
            timeouts++;
        else {
            timeouts = 0;
            if (first)
                first = 0;
        }

        max_timeouts = first ? MAX_TIMEOUTS_FIRST : MAX_TIMEOUTS;

        if (timeouts > max_timeouts) {
            debug("OBEX_HandleInput(): timeout\n");
            ctx->error = GW_OBEX_ERROR_TIMEOUT;
            obex_link_error(ctx);
            return FALSE;
        }

        debug("gw_obex_request_sync(): looping\n");
    }

    gw_obex_set_error(ctx);

    if (ctx->error == OBEX_RSP_SUCCESS) {
        /* It is possible that a EV_PROGRESS doesn't arrive after all data has
         * been transfered. Call pr_cb here to ensure app gets 100% progress */
        if (ctx->report_progress && ctx->pr_cb)
            ctx->pr_cb(ctx, ctx->obex_op, ctx->xfer->counter, ctx->xfer->counter, ctx->pr_data);
        return TRUE;
    }
    else
        return FALSE;
}

#ifdef DEBUG
static const char *optostr(uint8_t op) {
    switch (op) {
        case OBEX_CMD_CONNECT:
            return "Connect";
        case OBEX_CMD_DISCONNECT:
            return "Disconnect";
        case OBEX_CMD_PUT:
            return "Put";
        case OBEX_CMD_GET:
            return "Get";
        case OBEX_CMD_SETPATH:
            return "SetPath";
        case OBEX_CMD_ABORT:
            return "Abort";
        case OBEX_CMD_ACTION:
            return "Action";
        default:
            return "(unknown)";
    }
}
#endif

static void obex_connect_done(GwObex *ctx, obex_object_t *object, int obex_rsp) {
    obex_headerdata_t hv;
    uint8_t hi;
    unsigned int hlen;
    uint8_t *ptr;

    if (OBEX_ObjectGetNonHdrData(object, &ptr)
            != sizeof(obex_connect_hdr_t)) {
        debug("Invalid packet content.\n");
    }
    else {
        obex_connect_hdr_t *nonhdrdata = (obex_connect_hdr_t *)ptr;
        uint16_t mtu = g_ntohs(nonhdrdata->mtu);
        int new_size;
        debug("Version: 0x%02x. Flags: 0x%02x  OBEX packet length: %d\n",
                nonhdrdata->version, nonhdrdata->flags, mtu);
        /* Leave space for headers */
        new_size = mtu - 200;
        if (new_size < ctx->tx_max) {
            debug("Resizing stream chunks to %d\n", new_size);
            ctx->tx_max = new_size;
        }
    }

    while (OBEX_ObjectGetNextHeader(ctx->handle, object, &hi, &hv, &hlen)) {
        switch (hi) {
#ifdef DEBUG
            case OBEX_HDR_WHO:
                {
                    char *str;
                    str = bytestr(hv.bs, hlen);
                    debug("WHO header (UUID): %s\n", str);
                    g_free(str);
                }
                break;
#endif
            case OBEX_HDR_CONNECTION:
                ctx->conid = hv.bq4;
                debug("got Conection ID: %#x\n", hv.bq4);
                break;
            default:
                debug("Skipped header %02x\n", hi);
                break;
        }
    }
}

#ifdef DEBUG
static void show_headers(obex_t *handle, obex_object_t *object) {
    obex_headerdata_t hv;
    uint8_t hi;
    unsigned int hlen;

    while (OBEX_ObjectGetNextHeader(handle, object, &hi, &hv, &hlen)) {
        char *str;

        switch (hi) {
            case OBEX_HDR_WHO:
                debug("OBEX_HDR_WHO\n");
                break;
            case OBEX_HDR_CONNECTION:
                debug("OBEX_HDR_CONNECTION: %#x\n", hv.bq4);
                break;
            case OBEX_HDR_LENGTH:
                debug("OBEX_HDR_LENGTH: %d\n", hv.bq4);
                break;
            case OBEX_HDR_NAME:
                str = g_utf16_to_utf8((gunichar2 *)hv.bs, hlen, NULL, NULL, NULL);
                if (str) {
                    debug("OBEX_HDR_NAME: %s\n", str);
                    g_free(str);
                }
                break;
            case OBEX_HDR_AUTHCHAL:
                str = bytestr(hv.bs, hlen);
                debug("OBEX_HDR_AUTHCHAL: %s\n", str);
                g_free(str);
                break;
            case OBEX_HDR_TIME:
		str = g_new0(char, hlen + 1);
		memcpy(str, hv.bs, hlen);
                debug("OBEX_HDR_TIME: %s\n", str);
                g_free(str);
                break;
            case OBEX_HDR_TYPE:
                debug("OBEX_HDR_TYPE: %s\n", hv.bs);
                break;
            default:
                debug("Skipped header 0x%02x\n", hi);
                break;
        }
    }

    OBEX_ObjectReParseHeaders(handle, object);
}
#else
static inline void show_headers(obex_t *handle, obex_object_t *object) {}
#endif

static void obex_abort_done(GwObex *ctx, obex_object_t *object,
                            int obex_cmd, int obex_rsp) {
    ctx->done = TRUE;
    if (ctx->xfer)
        ctx->xfer->do_cb = TRUE;

    if (obex_rsp != OBEX_RSP_SUCCESS)
        debug("ABORT of %s command (0x%02x) failed: %s (0x%02x)\n",
                optostr((uint8_t)obex_cmd), (uint8_t)obex_cmd,
                OBEX_ResponseToString(obex_rsp), (uint8_t)obex_rsp);
    else
        debug("ABORT of %s command (0x%02x) succeeded.\n",
                optostr((uint8_t)obex_cmd), (uint8_t)obex_cmd);
}

static void obex_request_done(GwObex *ctx, obex_object_t *object,
                              int obex_cmd, int obex_rsp) {
    ctx->done = TRUE;
    if (ctx->xfer)
        ctx->xfer->do_cb = TRUE;

    ctx->obex_rsp = obex_rsp;

    if (obex_rsp != OBEX_RSP_SUCCESS) {
        debug("%s command (0x%02x) failed: %s (0x%02x)\n",
                optostr((uint8_t)obex_cmd), (uint8_t)obex_cmd,
                OBEX_ResponseToString(obex_rsp), (uint8_t)obex_rsp);
#ifdef DEBUG
        if (obex_rsp == OBEX_RSP_UNAUTHORIZED) {
            debug("Showing headers..\n");
            show_headers(ctx->handle, object);
        }
#endif
        return;
    }

    debug("%s command (0x%02x) succeeded.\n", optostr((uint8_t)obex_cmd),
            (uint8_t)obex_cmd);

    switch (obex_cmd) {
        case OBEX_CMD_CONNECT:
            obex_connect_done(ctx, object, obex_rsp);
            break;
        default:
            break;
    }
}

static void get_non_body_headers(obex_t *handle, obex_object_t *object,
                                     struct gw_obex_xfer *xfer) {
    obex_headerdata_t hv;
    uint8_t hi;
    unsigned int hlen;

    xfer->target_size = GW_OBEX_UNKNOWN_LENGTH;
    xfer->modtime = -1;

    while (OBEX_ObjectGetNextHeader(handle, object, &hi, &hv, &hlen)) {
        switch (hi) {
            case OBEX_HDR_LENGTH:
                xfer->target_size = hv.bq4; //(gint) g_ntohl(hv.bq4);
                break;
            case OBEX_HDR_TIME:
                xfer->modtime = parse_iso8601((char *)hv.bs, hlen);
                break;
            case OBEX_HDR_APPARAM:
                g_free(xfer->apparam_buf);
                xfer->apparam_buf = g_try_malloc(hlen);
		if (xfer->apparam_buf) {
                    memcpy(xfer->apparam_buf, hv.bs, hlen);
                    xfer->apparam_size = hlen;
                }
                else
                    xfer->apparam_size = 0;
                break;
            default:
                break;
        }
    }

    OBEX_ObjectReParseHeaders(handle, object);
}

static void obex_readstream(GwObex *ctx, obex_object_t *object) {
    struct gw_obex_xfer *xfer = ctx->xfer;
    const uint8_t *buf;
    int actual;

    if (!xfer) {
        debug("Incomming data even though no xfer active!\n");
        /* Flush incomming stream */
        actual = OBEX_ObjectReadStream(ctx->handle, object, &buf);
        if (actual > 0)
            debug("Ignored %d bytes\n", actual);
        return;
    }

    if (ctx->xfer->counter == 0) {
        get_non_body_headers(ctx->handle, object, xfer);
        show_headers(ctx->handle, object);
    }

    actual = OBEX_ObjectReadStream(ctx->handle, object, &buf);
    if (actual > 0) {
        xfer->counter += actual;

        debug("obex_readstream: got %d bytes (%zd in total)\n", actual, xfer->counter);

        if (xfer->async) {
            gint free_space = xfer->buf_size - (xfer->data_start + xfer->data_length);
            if (actual > free_space) {
                /* This should never happen */
                debug("Out of buffer space: actual=%d, free=%d\n", actual, free_space);
                return;
            }

            memcpy(&xfer->buf[xfer->data_start], buf, actual);
            xfer->data_length += actual;

            debug("OBEX_SuspendRequest at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
            OBEX_SuspendRequest(ctx->handle, object);

            xfer->do_cb = TRUE;
        }
        else if (xfer->stream_fd >= 0) {
            int written = 0;

            while (written < actual) {
                int ret;

                ret = write(xfer->stream_fd, buf + written, actual - written);
                if (ret < 0 && errno == EINTR)
                    continue;

                if (ret < 0) {
                    debug("Could not write: %s (%d)", g_strerror(errno), errno);
                    break;
                }

                written += ret;
            }
        }
        else {
            xfer->buf = g_realloc(xfer->buf, xfer->counter);
            memcpy(&xfer->buf[xfer->buf_size], buf, actual);
            xfer->buf_size = xfer->counter;
        }
    }
    else
        debug("Error or no data on OBEX stream\n");
}

static void obex_writestream(GwObex *ctx, obex_object_t *object) {
    struct gw_obex_xfer *xfer = ctx->xfer;
    obex_headerdata_t hv;
    int actual = -1;

    if (!xfer) {
        debug("Request to provide data even though no active xfer!");
        hv.bs = NULL;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                hv, 0, OBEX_FL_STREAM_DATAEND);
        return;
    }

    if (xfer->async) {
        if (xfer->data_length > 0) {
            gint send_size = xfer->data_length > ctx->tx_max ? ctx->tx_max : xfer->data_length;

            hv.bs = &xfer->buf[xfer->data_start];
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                    hv, send_size, OBEX_FL_STREAM_DATA);
            actual = send_size;
            xfer->data_length -= send_size;
            if (xfer->data_length == 0)
                xfer->data_start = 0;
            else
                xfer->data_start += send_size;

            xfer->do_cb = TRUE;
	    if (!xfer->close) {
                debug("OBEX_SuspendRequest at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
                OBEX_SuspendRequest(ctx->handle, object);
            }
        }
        else {
            hv.bs = NULL;
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                    hv, 0, OBEX_FL_STREAM_DATAEND);
        }
    }
    else if (xfer->stream_fd >= 0) {
        actual = read(xfer->stream_fd, xfer->buf, ctx->tx_max);
        hv.bs = xfer->buf;
#ifdef TEST_ABORT
        if (xfer->counter > 4000)
            actual = -1;
#endif
        if (actual > 0)
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                    hv, actual, OBEX_FL_STREAM_DATA);
        else if (actual == 0) /* EOF */
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                    hv, 0, OBEX_FL_STREAM_DATAEND);
        else { /* error reading file */
            debug("read(): %s\n", strerror(errno));
            gw_obex_xfer_do_abort(xfer);
        }
    }
    else {
        if (xfer->counter < xfer->buf_size) {
            if (xfer->buf_size > xfer->counter + ctx->tx_max)
                actual = ctx->tx_max;
            else
                actual = xfer->buf_size - xfer->counter;
            hv.bs = &xfer->buf[xfer->counter];
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                    hv, actual, OBEX_FL_STREAM_DATA);
        }
        else {
            hv.bs = NULL;
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY,
                    hv, 0, OBEX_FL_STREAM_DATAEND);
        }
    }

    if (actual > 0)
        xfer->counter += actual;
}

static void obex_event_handler(obex_t *handle, obex_object_t *object, int mode,
                               int event, int obex_cmd, int obex_rsp) {
    GwObex *ctx = OBEX_GetCustomData(handle);
    switch (event) {
        case OBEX_EV_ABORT:
            debug("OBEX_EV_ABORT\n");
            obex_abort_done(ctx, object, obex_cmd, obex_rsp);
            break;
        case OBEX_EV_PROGRESS:
            debug("OBEX_EV_PROGRESS\n");
            if (ctx->report_progress && ctx->pr_cb)
                ctx->pr_cb(ctx, ctx->obex_op, ctx->xfer->counter, ctx->xfer->target_size, ctx->pr_data);
            break;
        case OBEX_EV_REQDONE:
            debug("OBEX_EV_REQDONE\n");
            obex_request_done(ctx, object, obex_cmd, obex_rsp);
            break;
        case OBEX_EV_REQ:
            debug("OBEX_EV_REQ: %s (0x%02x)\n",
                    optostr((uint8_t)obex_cmd), (uint8_t)obex_cmd);
            OBEX_ObjectSetRsp(object, OBEX_RSP_NOT_IMPLEMENTED,
                    OBEX_RSP_NOT_IMPLEMENTED);
            break;
        case OBEX_EV_REQHINT:
            debug("OBEX_EV_REQHINT: %s (0x%02x)\n",
                    optostr((uint8_t)obex_cmd), (uint8_t)obex_cmd);
            OBEX_ObjectSetRsp(object, OBEX_RSP_NOT_IMPLEMENTED,
                    OBEX_RSP_NOT_IMPLEMENTED);
            break;
        case OBEX_EV_LINKERR:
            debug("OBEX_EV_LINKERR\n");
            obex_link_error(ctx);
            break;
        case OBEX_EV_STREAMEMPTY:
            debug("OBEX_EV_STREAMEMPTY\n");
            obex_writestream(ctx, object);
            break;
        case OBEX_EV_STREAMAVAIL:
            debug("OBEX_EV_STREAMAVAIL\n");
            obex_readstream(ctx, object);
            break;
        case OBEX_EV_PARSEERR:
            debug("OBEX_EV_PARSEERR\n");
            break;
        default:
            debug("Unknown event %d\n", event);
            break;
    }
}

gboolean gw_obex_set_error(GwObex *ctx) {
    ctx->error = 0;

    if (!ctx->done)
        return FALSE;

    if (ctx->xfer && ctx->xfer->abort)
        ctx->error = GW_OBEX_ERROR_ABORT;
    else if (ctx->conn_fd < 0 || ctx->link_err)
        ctx->error = GW_OBEX_ERROR_DISCONNECT;
    else
        ctx->error = (gint)ctx->obex_rsp;

    if (ctx->error == OBEX_RSP_SUCCESS)
        return FALSE;

    return TRUE;
}

void obex_link_error(GwObex *ctx) {
    if (ctx->link_err)
        return;
    ctx->link_err = TRUE;
    OBEX_SetUserCallBack(ctx->handle, idle_callback, NULL);
    ctx->done = TRUE;
    ctx->conid = CONID_INVALID;
    if (ctx->conn_fd >= 0) {
        OBEX_TransportDisconnect(ctx->handle);
        close(ctx->conn_fd);
        ctx->conn_fd = -1;
    }
    if (ctx->gio) {
        g_io_channel_unref(ctx->gio);
        ctx->gio = NULL;
    }
    if (ctx->gio_source) {
        g_source_destroy(ctx->gio_source);
        ctx->gio_source = NULL;
    }
    if (ctx->xfer) {
        /* Check that buffer is owned by us */
        if (!(ctx->obex_op == OBEX_CMD_PUT && ctx->xfer->stream_fd < 0)) {
            g_free(ctx->xfer->buf);
            ctx->xfer->buf = NULL;
            ctx->xfer->buf_size = 0;
	}
	ctx->xfer->do_cb = TRUE;
    }
}

gboolean gw_obex_transport_setup(int fd, obex_t **handle) {
    *handle = OBEX_Init(OBEX_TRANS_FD, obex_event_handler, 0);
    if (*handle == NULL) {
        debug("OBEX_Init() failed\n");
        return FALSE;
    }

    (void) OBEX_SetTransportMTU(*handle, GW_OBEX_RX_MTU, GW_OBEX_TX_MTU);

    if (FdOBEX_TransportSetup(*handle, fd, fd, 0) < 0) {
        debug("FdOBEX_TransportSetup() failed\n");
        OBEX_Cleanup(*handle);
        return FALSE;
    }

    return TRUE;
}

void gw_obex_get_error(GwObex *ctx, gint *error) {
    if (error)
        *error = ctx->error;
    ctx->error = OBEX_RSP_SUCCESS;
}

gboolean gw_obex_cb(GIOChannel *chan, GIOCondition cond, gpointer data) {
    GwObex *ctx = (GwObex *)data;

    debug("gw_obex_cb(): entered\n");

    GW_OBEX_LOCK(ctx);

    if (ctx->conn_fd < 0 || (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))) {
        debug("gw_obex_cb: error or connection closed\n");
        obex_link_error(ctx);
        GW_OBEX_UNLOCK(ctx);
        if (ctx->xfer && ctx->xfer->cb)
            ctx->xfer->cb(ctx->xfer, ctx->xfer->cb_data);
	else if (ctx->dc_cb)
            ctx->dc_cb(ctx, ctx->dc_data);
        return FALSE;
    }

    debug("Calling OBEX_HandleInput\n");
    OBEX_HandleInput(ctx->handle, 0);
    debug("Returned from OBEX_HandleInput\n");

    if (ctx->xfer && ctx->xfer->cb && ctx->xfer->do_cb) {
        ctx->xfer->do_cb = FALSE;
        GW_OBEX_UNLOCK(ctx);
        ctx->xfer->cb(ctx->xfer, ctx->xfer->cb_data);
        GW_OBEX_LOCK(ctx);
    }

    GW_OBEX_UNLOCK(ctx);

    return TRUE;
}

gboolean gw_obex_disconnect(GwObex *ctx) {
    obex_object_t *object;

    g_assert(!ctx->xfer);

    if (!ctx->done) {
        ctx->error = GW_OBEX_ERROR_BUSY;
        return FALSE;
    }

    object = OBEX_ObjectNew(ctx->handle, OBEX_CMD_DISCONNECT);

    if (ctx->conid != CONID_INVALID) {
        obex_headerdata_t hv;
        hv.bq4 = ctx->conid;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_CONNECTION, hv, 4, 0);
    }

    return gw_obex_request_sync(ctx, object);
}

gboolean gw_obex_connect(GwObex *ctx, const char *target, size_t target_len) {
    gboolean ret;
    obex_object_t *object;

    g_assert(ctx->done && !ctx->xfer);

    ctx->obex_op = OBEX_CMD_CONNECT;

    object = OBEX_ObjectNew(ctx->handle, OBEX_CMD_CONNECT);
    if (target) {
        obex_headerdata_t hv;
        hv.bs = (const unsigned char *)target;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_TARGET, hv, target_len, OBEX_FL_FIT_ONE_PACKET);
    }

    ret = gw_obex_request_sync(ctx, object);
    ctx->obex_op = OBEX_CMD_NONE;
    return ret;
}

GwObex *make_context(obex_t *handle) {
    GwObex *context;

    context = g_new0(GwObex, 1);

    context->handle      = handle;
    context->conn_fd     = OBEX_GetFD(handle);
    context->conid       = CONID_INVALID;
    context->tx_max      = GW_OBEX_TX_MTU - 200;
    context->rx_max      = GW_OBEX_RX_MTU;
    context->obex_op     = OBEX_CMD_NONE;
    context->obex_rsp    = OBEX_RSP_SUCCESS;
    context->done        = TRUE;

    return context;
}

gboolean gw_obex_action_op(GwObex *ctx, const gchar *src, const gchar *dst,
                           uint8_t action) {
    gboolean ret = FALSE;
    obex_object_t *object;
    obex_headerdata_t hv;
    gunichar2 *uname;
    glong uname_len;

    g_assert(src && dst);

    if (!ctx->done || ctx->xfer) {
        ctx->error = GW_OBEX_ERROR_BUSY;
        return FALSE;
    }

    ctx->obex_op = OBEX_CMD_ACTION;

    object = OBEX_ObjectNew(ctx->handle, OBEX_CMD_ACTION);

    if (ctx->conid != CONID_INVALID) {
        hv.bq4 = ctx->conid;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_CONNECTION, hv, 4, 0);
    }

    hv.bq1 = action;
    OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_ACTION_ID, hv, 1, 0);

    uname_len = get_uname(&uname, src);
    if (uname_len < 0) {
        OBEX_ObjectDelete(ctx->handle, object);
        goto out;
    }
    hv.bs = (unsigned char *)uname;
    OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_NAME, hv, uname_len, 0);
    g_free(uname);

    uname_len = get_uname(&uname, dst);
    if (uname_len < 0) {
        OBEX_ObjectDelete(ctx->handle, object);
        goto out;
    }
    hv.bs = (unsigned char *)uname;
    OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_DESTNAME, hv, uname_len, 0);
    g_free(uname);

    ret = gw_obex_request_sync(ctx, object);

out:
    ctx->obex_op = OBEX_CMD_NONE;
    return ret;
}

gboolean gw_obex_setpath(GwObex *ctx, const gchar *path, int flags) {
    gboolean ret = FALSE;
    obex_headerdata_t hv;
    obex_object_t *object;
    obex_setpath_hdr_t nonhdrdata;
    gunichar2 *uname;
    glong uname_len;

    if (!ctx->done || ctx->xfer) {
        ctx->error = GW_OBEX_ERROR_BUSY;
        return FALSE;
    }

    ctx->obex_op = OBEX_CMD_SETPATH;

    nonhdrdata.flags = 0x02;
    nonhdrdata.constants = 0;

    if (strcmp(path, "..") == 0) {
        /* move up one directory */
        nonhdrdata.flags = 0x03;
        uname_len = -1;
    }
    else {
        /* normal directory change */
        uname_len = get_uname(&uname, path);
        if (uname_len < 0) {
            ctx->error = GW_OBEX_ERROR_INVALID_PARAMS;
            goto out;
        }
    }

    if (flags & SETPATH_CREATE)
        nonhdrdata.flags &= ~0x02;

    object = OBEX_ObjectNew(ctx->handle, OBEX_CMD_SETPATH);
    OBEX_ObjectSetNonHdrData(object, (uint8_t*)&nonhdrdata, 2);

    if (ctx->conid != CONID_INVALID) {
        hv.bq4 = ctx->conid;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_CONNECTION, hv, 4, 0);
    }

    if (uname_len >= 0) {
        hv.bs = (unsigned char *) (uname ? (char *)uname : "");
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_NAME, hv, uname_len, 0);
        g_free(uname);
    }

    ret = gw_obex_request_sync(ctx, object);

out:
    ctx->obex_op = OBEX_CMD_NONE;
    return ret;
}

gboolean gw_obex_get(GwObex *ctx,
                     const gchar *local, const gchar *remote, const gchar *type,
                     const guint8 *apparam, gint apparam_size,
                     gchar **buf, gint *buf_size, int stream_fd,
                     gboolean async) {
    gboolean ret = FALSE;
    obex_headerdata_t hv;
    obex_object_t *object;

    g_assert(local || buf || stream_fd > 0 || async);
    g_assert(remote || type);

    if (!ctx->done || ctx->xfer) {
        ctx->error = GW_OBEX_ERROR_BUSY;
        return ret;
    }

    ctx->obex_op = OBEX_CMD_GET;

    ctx->xfer = gw_obex_xfer_new(ctx, async, stream_fd);

    object = OBEX_ObjectNew(ctx->handle, OBEX_CMD_GET);

    if (ctx->conid != CONID_INVALID) {
        hv.bq4 = ctx->conid;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_CONNECTION, hv, 4, 0);
    }

    if (apparam && apparam_size > 0) {
        hv.bs = (unsigned char *)apparam;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_APPARAM, hv, apparam_size, 0);
    }

    if (type) {
        hv.bs = (unsigned char *)type;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_TYPE, hv, strlen(type) + 1, 0);
    }

    if (remote) {
        gunichar2 *uname;
        glong uname_len;

        uname_len = get_uname(&uname, remote);
        if (uname_len < 0) {
            OBEX_ObjectDelete(ctx->handle, object);
            ctx->error = GW_OBEX_ERROR_INVALID_PARAMS;
            goto out;
        }

        /* OpenOBEX is buggy and won't append the header unless hv.bs != NULL */
        hv.bs = (unsigned char *) (uname ? (char *)uname : "");

        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_NAME, hv, uname_len, 0);
        g_free(uname);
    }

    if (local) {
        ctx->xfer->stream_fd = open(local, O_WRONLY | O_CREAT, 0600);
        if (ctx->xfer->stream_fd < 0) {
            if (errno == ENOENT || errno == ENODEV)
                ctx->error = GW_OBEX_ERROR_INVALID_PARAMS;
            else
                ctx->error = GW_OBEX_ERROR_LOCAL_ACCESS;
            debug("open(%s): %s", local, strerror(errno));
            OBEX_ObjectDelete(ctx->handle, object);
            goto out;
        }
    }

    OBEX_ObjectReadStream(ctx->handle, object, NULL);

    if (async) {
        ret = gw_obex_request_async(ctx, object);
        if (ret)
            return ret;
    }
    else {
        ctx->report_progress = TRUE;
        ret = gw_obex_request_sync(ctx, object);
    }

    if (ctx->xfer->stream_fd >= 0 && stream_fd < 0)
        close(ctx->xfer->stream_fd);

    if (ret == FALSE) {
        if (local)
            unlink(local);
    }
    else {
        if (local) {
            debug("%s stored in %s\n", remote ? remote : type, local);
            if (ctx->xfer->modtime != -1) {
                struct utimbuf ubuf;
                ubuf.actime = time(NULL);
                ubuf.modtime = ctx->xfer->modtime;
                if (utime(local, &ubuf) < 0)
                    debug("utime(%s): %s\n", local, g_strerror(errno));
            }
        }
        if (buf) {
            *buf = (gchar *)ctx->xfer->buf;
            *buf_size = ctx->xfer->buf_size;
            /* Make sure gw_obex_xfer_free doesn't free the buffer */
            ctx->xfer->buf = NULL;
        }
    }

out:
    _gw_obex_xfer_free(ctx->xfer);
    ctx->xfer = NULL;

    ctx->report_progress = FALSE;
    ctx->obex_op = OBEX_CMD_NONE;

    return ret;
}

gboolean gw_obex_put(GwObex *ctx,
                     const gchar *local, const gchar *remote, const gchar *type,
                     const guint8 *apparam, gint apparam_size,
                     const gchar *buf, gint object_size, time_t object_time,
                     int stream_fd, gboolean async) {
    gboolean ret = FALSE;
    obex_headerdata_t hv;
    obex_object_t *object;
    gunichar2 *uname = NULL;
    glong uname_len = 0;

    g_assert(remote || type);

    if (!ctx->done || ctx->xfer) {
        ctx->error = GW_OBEX_ERROR_BUSY;
        return FALSE;
    }

    if (remote) {
        uname_len = get_uname(&uname, remote);
        if (uname_len < 0) {
            ctx->error = GW_OBEX_ERROR_INVALID_PARAMS;
            return FALSE;
        }
    }

    ctx->obex_op = OBEX_CMD_PUT;
    ctx->xfer = gw_obex_xfer_new(ctx, async, stream_fd);

    if (local) {
        if (file_is_dir(local)) {
            debug("Trying to PUT a directory\n");
            ctx->error = GW_OBEX_ERROR_INVALID_PARAMS;
            goto out;
        }

        ctx->xfer->stream_fd = open(local, O_RDONLY);
        if (ctx->xfer->stream_fd < 0) {
            if (errno == ENOENT || errno == ENODEV)
                ctx->error = GW_OBEX_ERROR_INVALID_PARAMS;
            else
                ctx->error = GW_OBEX_ERROR_LOCAL_ACCESS;
            debug("open(%s): %s", local, strerror(errno));
            goto out;
        }
        ctx->xfer->buf = g_malloc(ctx->tx_max);
        ctx->xfer->buf_size = ctx->tx_max;
        debug("Sending %s to %s\n", local, remote ? remote : type);
    }
    else if (buf) {
        ctx->xfer->buf = (unsigned char *)buf;
        ctx->xfer->buf_size = object_size;
        debug("Sending to %s\n", remote ? remote : type);
    }
    else if (stream_fd < 0 && !async) { /* Delete */
        ctx->report_progress = FALSE;
        debug("Deleting %s\n", remote ? remote : type);
    }

    object = OBEX_ObjectNew(ctx->handle, OBEX_CMD_PUT);

    if (ctx->conid != CONID_INVALID) {
        hv.bq4 = ctx->conid;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_CONNECTION, hv, 4, 0);
    }

    if (uname) {
        hv.bs = (unsigned char *)uname;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_NAME, hv, uname_len, 0);
        g_free(uname);
        uname = NULL;
    }

    if (type) {
        hv.bs = (unsigned char *)type;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_TYPE, hv, strlen(type) + 1, 0);
    }

    if (apparam && apparam_size > 0) {
        hv.bs = (unsigned char *)apparam;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_APPARAM, hv, apparam_size, 0);
    }

    /* Try to figure out modification time if none was given */
    if (ctx->xfer->stream_fd >= 0) {
        struct stat stats;
        if (fstat(ctx->xfer->stream_fd, &stats) == 0) {
            object_size = stats.st_size;
            if (object_time < 0)
                object_time = stats.st_mtime;
        }
    }

    /* Add a time header if possible */
    if (object_time >= 0) {
        char tstr[17];
        int len;

        len = make_iso8601(object_time, tstr, sizeof(tstr));

        if (len >= 0) {
            debug("Adding time header: %s\n", tstr);
            hv.bs = (unsigned char *)tstr;
            OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_TIME, hv, len, 0);
        }
    }

    /* Add a length header if possible */
    if (object_size > 0) {
        ctx->xfer->target_size = object_size;
        debug("Adding size header: %d\n", object_size);
        hv.bq4 = (uint32_t)object_size;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_LENGTH, hv, 4, 0);
    }
    else
        ctx->xfer->target_size = GW_OBEX_UNKNOWN_LENGTH;

    if (ctx->xfer->stream_fd >= 0 || buf || async) {
        hv.bs = NULL;
        OBEX_ObjectAddHeader(ctx->handle, object, OBEX_HDR_BODY, hv, 0, OBEX_FL_STREAM_START);
    }

    if (async) {
        ret = gw_obex_request_async(ctx, object);
        if (ret)
            return ret;
    }
    else {
        ctx->report_progress = TRUE;
        ret = gw_obex_request_sync(ctx, object);
    }

out:
    g_free(uname);

    if (ctx->xfer->stream_fd >= 0 && stream_fd < 0)
        close(ctx->xfer->stream_fd);

    if (buf)
        ctx->xfer->buf = NULL;

    _gw_obex_xfer_free(ctx->xfer);
    ctx->xfer = NULL;

    ctx->report_progress = FALSE;
    ctx->obex_op = OBEX_CMD_NONE;

    return ret;
}

