/**
  @file obex-xfer.c

  Object transfer related functions for the GW OBEX Library

  @author Johan Hedberg <johan.hedberg@nokia.com>

  Copyright (C) 2004-2006 Nokia Corporation. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License, version 2.1 as published by the Free Software Foundation.

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
#include <string.h>
#include <errno.h>

#include <openobex/obex.h>

#include "obex-priv.h"
#include "obex-xfer.h"

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "log.h"
#include "obex-priv.h"
#include "obex-xfer.h"
#include "gw-obex.h"

static gboolean handle_input(GwObex *ctx, gint *err) {
    gboolean ret = TRUE;
    int r;

    r = OBEX_HandleInput(ctx->handle, 10);

    if (r < 0) {
        debug("OBEX_HandleInput() failed\n");
        obex_link_error(ctx);
        if (err)
            *err = GW_OBEX_ERROR_INTERNAL;
        ret = FALSE;
    }
    else if (r == 0) { /* Timeout */
        debug("OBEX_HandleInput(): timeout\n");
        if (err)
            *err = GW_OBEX_ERROR_TIMEOUT;
        ret = FALSE;
    }

    return ret;
}

struct gw_obex_xfer *gw_obex_xfer_new(struct gw_obex *ctx, gboolean async, int stream_fd) {
    struct gw_obex_xfer *xfer;
    size_t buf_size = (ctx->obex_op == OBEX_CMD_GET) ? ctx->rx_max : ctx->tx_max;

    xfer = g_new0(struct gw_obex_xfer, 1);

    xfer->ctx         = ctx;
    xfer->async       = async;
    xfer->stream_fd   = stream_fd;
    xfer->target_size = GW_OBEX_UNKNOWN_LENGTH;
    xfer->modtime     = -1;

    if (async || (stream_fd >= 0 && ctx->obex_op == OBEX_CMD_PUT)) {
        xfer->buf = g_malloc(buf_size);
        xfer->buf_size = buf_size;
    }

    if (async && ctx->obex_op == OBEX_CMD_PUT)
        xfer->do_cb = TRUE;

    return xfer;
}

gboolean gw_obex_xfer_do_abort(struct gw_obex_xfer *xfer) {
    debug("gw_obex_xfer_do_abort()\n");

    if (xfer->ctx->conn_fd < 0 || xfer->ctx->xfer == NULL || xfer->ctx->done)
        return FALSE;

    if (xfer->abort)
        return TRUE;

    xfer->abort = TRUE;

#ifdef USE_NICE_ABORT
    debug("Performing nice abort\n");
    if (OBEX_CancelRequest(xfer->ctx->handle, TRUE) != 0)
        return FALSE;
    return TRUE;
#else
    debug("Performing abort through disconnection (without ABORT command)\n");
    xfer->ctx->done = TRUE;
    OBEX_CancelRequest(xfer->ctx->handle, FALSE);
    obex_link_error(xfer->ctx);
    return FALSE;
#endif
}

GwObexXfer *gw_obex_put_async(GwObex *ctx, const char *name, const char *type,
                              gint size, time_t time, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(NULL, error, ctx);
    ret = gw_obex_put(ctx, NULL, name, type, NULL, 0, NULL, size, time, -1, TRUE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret ? ctx->xfer : NULL;
}

GwObexXfer *gw_obex_get_async(GwObex *ctx, const char *name, const char *type, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(NULL, error, ctx);
    ret = gw_obex_get(ctx, NULL, name, type, NULL, 0, NULL, NULL, -1, TRUE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret ? ctx->xfer : NULL;
}

GwObexXfer *gw_obex_get_async_with_apparam(GwObex *ctx, const char *name, const char *type,
		const guint8  *apparam, gint apparam_size, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(NULL, error, ctx);
    ret = gw_obex_get(ctx, NULL, name, type, apparam, apparam_size, NULL, NULL, -1, TRUE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret ? ctx->xfer : NULL;
}

static gboolean gw_obex_put_idle(GwObexXfer *xfer) {
    struct gw_obex *ctx = xfer->ctx;

    g_source_destroy(xfer->idle_source);
    xfer->idle_source = NULL;

    if (!ctx)
        return FALSE;

    GW_OBEX_LOCK(ctx);

    if (xfer->cb && xfer->do_cb) {
        xfer->do_cb = FALSE;
        GW_OBEX_UNLOCK(ctx);
        xfer->cb(xfer, xfer->cb_data);
        GW_OBEX_LOCK(ctx);
    }

    GW_OBEX_UNLOCK(ctx);

    return FALSE;
}

void gw_obex_xfer_set_callback(GwObexXfer *xfer, gw_obex_xfer_cb_t cb, gpointer user_data) {
    GwObex *ctx = xfer->ctx;

    GW_OBEX_LOCK(ctx);

    xfer->cb = cb;
    xfer->cb_data = user_data;

    if (xfer->do_cb && xfer->idle_source == NULL) {
        xfer->idle_source = g_idle_source_new();
        g_source_set_callback(xfer->idle_source, (GSourceFunc)gw_obex_put_idle, xfer, NULL);
        (void) g_source_attach(xfer->idle_source, ctx->main_ctx);
        g_source_unref(xfer->idle_source);
    }

    GW_OBEX_UNLOCK(ctx);
}

time_t gw_obex_xfer_object_time(GwObexXfer *xfer) {
    return xfer->modtime;
}

gint gw_obex_xfer_object_size(GwObexXfer *xfer) {
    return xfer->target_size;
}

unsigned char *gw_obex_xfer_object_apparam(GwObexXfer *xfer, size_t *apparam_size) {
    if (apparam_size)
        *apparam_size = xfer->apparam_size;
    return xfer->apparam_buf;
}

gboolean gw_obex_xfer_object_done(GwObexXfer *xfer) {
    return xfer->ctx->done;
}

gboolean gw_obex_xfer_write(GwObexXfer *xfer, const char *buf, gint buf_size,
		            gint *bytes_written, gint *err) {
    GwObex *ctx = xfer->ctx;
    gboolean ret = TRUE;
    gint free_space;

    debug("gw_obex_xfer_write(buf_size=%d): entered\n", buf_size);

    if (!ctx) {
        if (err)
            *err = GW_OBEX_ERROR_INVALID_PARAMS;
	return FALSE;
    }

    GW_OBEX_LOCK(ctx);

    if (ctx->obex_op != OBEX_CMD_PUT) {
        ret = FALSE;
        if (err)
            *err = GW_OBEX_ERROR_INVALID_PARAMS;
        goto out;
    }

    if (gw_obex_set_error(ctx)) {
        gw_obex_get_error(ctx, err);
        ret = FALSE;
        goto out;
    }

    free_space = xfer->buf_size - (xfer->data_start + xfer->data_length);

    *bytes_written = buf_size > free_space ? free_space : buf_size;

    memcpy(&xfer->buf[xfer->data_start + xfer->data_length], buf, *bytes_written);

    xfer->data_length += *bytes_written;
    free_space -= *bytes_written;

    if (xfer->object) {
        if (OBEX_Request(ctx->handle, xfer->object) < 0) {
            debug("OBEX_Request() failed\n");
            xfer->data_length -= *bytes_written;
            ret = FALSE;
            goto out;
        }

        xfer->object = NULL;

        /* Recalculate free space */
        free_space = xfer->buf_size - (xfer->data_start + xfer->data_length);
    }

    if (xfer->data_length >= ctx->tx_max || !free_space) {
        guint old_length = xfer->data_length;

        debug("OBEX_ResumeRequest at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
        OBEX_ResumeRequest(ctx->handle);

        if (!xfer->block)
            goto out;

        /* Call OBEX_HandleInput if the xfer is blocking and no data could be sent */
        while (old_length == xfer->data_length) {
            if (gw_obex_set_error(ctx)) {
                gw_obex_get_error(ctx, err);
                ret = FALSE;
                goto out;
            }

            if (!handle_input(ctx, err)) {
                ret = FALSE;
                goto out;
            }
        }
    }

out:
    if (xfer->cb && xfer->do_cb && xfer->idle_source == NULL) {
        xfer->idle_source = g_idle_source_new();
        g_source_set_callback(xfer->idle_source, (GSourceFunc)gw_obex_put_idle, xfer, NULL);
        (void) g_source_attach(xfer->idle_source, ctx->main_ctx);
        g_source_unref(xfer->idle_source);
    }

    GW_OBEX_UNLOCK(ctx);
    if (ret)
        debug("gw_obex_xfer_write(): returning, %d bytes written\n", *bytes_written);
    else
        debug("gw_obex_xfer_write(): returning, failed (%d)\n", err ? *err : 0);
    return ret;
}

gboolean gw_obex_xfer_read(GwObexXfer *xfer, char *buf, gint buf_size,
		           gint *bytes_read, gint *err) {
    GwObex *ctx = xfer->ctx;
    gint data_length;
    gboolean ret = TRUE;

    debug("gw_obex_xfer_read(buf_size=%d): entered\n", buf_size);

    if (!ctx) {
        if (err)
            *err = GW_OBEX_ERROR_INVALID_PARAMS;
	return FALSE;
    }

    GW_OBEX_LOCK(ctx);

    if (ctx->obex_op != OBEX_CMD_GET) {
        ret = FALSE;
        if (err)
            *err = GW_OBEX_ERROR_INVALID_PARAMS;
        goto out;
    }

    while (TRUE) {
        if (gw_obex_set_error(ctx)) {
            gw_obex_get_error(ctx, err);
            ret = FALSE;
            goto out;
        }

        if (xfer->data_length)
            break;

        if (ctx->done) {
            *bytes_read = 0;
            goto out;
        }

        if (xfer->block) {
            if (!handle_input(ctx, err)) {
                ret = FALSE;
                goto out;
            }
        }
        else {
            ret = FALSE;
            if (err)
                *err = GW_OBEX_ERROR_NO_DATA;
            goto out;
        }
    }

    data_length = xfer->data_length;
    *bytes_read = buf_size < data_length ? buf_size : data_length;

    memcpy(buf, &xfer->buf[xfer->data_start], *bytes_read);

    xfer->data_length -= *bytes_read;

    if (xfer->data_length)
        xfer->data_start += *bytes_read;
    else {
        xfer->data_start = 0;
        debug("OBEX_ResumeRequest at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
        OBEX_ResumeRequest(ctx->handle);
    }

out:
    GW_OBEX_UNLOCK(ctx);
    if (ret)
        debug("gw_obex_xfer_read(): returning, %d bytes read\n", *bytes_read);
    else
        debug("gw_obex_xfer_read(): returning, failed (%d)\n", err ? *err : 0);
    return ret;
}

gboolean gw_obex_xfer_flush(GwObexXfer *xfer, gint *err) {
    gboolean ret = TRUE;
    struct gw_obex *ctx = xfer->ctx;

    if (!ctx) {
        if (err)
            *err = GW_OBEX_ERROR_INVALID_PARAMS;
	return FALSE;
    }

    GW_OBEX_LOCK(ctx);

    if (ctx->obex_op != OBEX_CMD_PUT)
        goto out;

    if (gw_obex_set_error(ctx)) {
        gw_obex_get_error(ctx, err);
        ret = FALSE;
        goto out;
    }

    while (xfer->data_length) {
        debug("OBEX_ResumeRequest at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
        OBEX_ResumeRequest(ctx->handle);

        if (gw_obex_set_error(ctx)) {
            gw_obex_get_error(ctx, err);
            ret = FALSE;
            goto out;
        }

        if (xfer->data_length) {
            if (!handle_input(ctx, err)) {
                ret = FALSE;
                goto out;
            }
        }
    }

out:
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

void _gw_obex_xfer_free(struct gw_obex_xfer *xfer) {
    g_free(xfer->buf);
    g_free(xfer->apparam_buf);
    g_free(xfer);
}

void gw_obex_xfer_free(struct gw_obex_xfer *xfer) {
    if (xfer->ctx)
        gw_obex_xfer_close(xfer, NULL);
    _gw_obex_xfer_free(xfer);
}

gboolean gw_obex_xfer_close(GwObexXfer *xfer, gint *err) {
    gboolean ret = TRUE;
    struct gw_obex *ctx = xfer->ctx;

    /* If previous close() failed, just signal success so caller can continue */
    if (!ctx)
        return TRUE;

    GW_OBEX_LOCK(ctx);

    xfer->close = TRUE;

    if (ctx->obex_op == OBEX_CMD_GET && !ctx->done)
        gw_obex_xfer_do_abort(xfer);

    if (ctx->obex_op == OBEX_CMD_PUT) {
        if (xfer->object) {
            if (OBEX_Request(ctx->handle, xfer->object) < 0) {
                debug("OBEX_Request() failed\n");
                ctx->done = TRUE;
            }
            xfer->object = NULL;
        }
        else {
            debug("OBEX_ResumeRequest at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
            OBEX_ResumeRequest(ctx->handle);
        }
    }

    while (!ctx->done) {
        if (!handle_input(ctx, err)) {
            ret = FALSE;
            break;
        }
    }

    /* Check for error but ignore ERROR_ABORT since we can still do a proper
     * xfer_close() in that case */
    if (gw_obex_set_error(ctx) && ctx->error != GW_OBEX_ERROR_ABORT) {
        gw_obex_get_error(ctx, err);
        ret = FALSE;
    }

    /* Remove the idle function related to this transfer (if there is one) */
    if (xfer->idle_source) {
        g_source_destroy(xfer->idle_source);
        xfer->idle_source = NULL;
    }

    /* Disassociate from the GwObex object */
    ctx->xfer = NULL;
    xfer->ctx = NULL;

    GW_OBEX_UNLOCK(ctx);

    return ret;
}

gboolean gw_obex_xfer_abort(GwObexXfer *xfer, gint *err) {
    GwObex *ctx = xfer->ctx;
    gboolean ret = TRUE;

    /* If previous call failed just signal success so caller can continue */
    if (!ctx)
        return TRUE;

    GW_OBEX_LOCK(ctx);

    /* Return if abort has already been sent */
    if (xfer->abort)
        goto out;

    /* Return if actual request hasn't been sent */
    if (xfer->object) {
        OBEX_ObjectDelete(ctx->handle, xfer->object);
        xfer->object = NULL;
        ctx->done = TRUE;
        goto out;
    }

    if (!gw_obex_xfer_do_abort(xfer)) {
        ret = FALSE;
        if (err)
            *err = GW_OBEX_ERROR_INTERNAL;
        goto out;
    }

out:
    GW_OBEX_UNLOCK(ctx);

    gw_obex_xfer_close(xfer, err);

    return ret;
}

void gw_obex_xfer_set_blocking(GwObexXfer *xfer, gboolean block) {
    GW_OBEX_LOCK(xfer->ctx);
    xfer->block = block;
    GW_OBEX_UNLOCK(xfer->ctx);
}
