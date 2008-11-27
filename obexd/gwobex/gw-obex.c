/**
  @file gw-obex.c

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
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <glib.h>

#include "log.h"
#include "gw-obex.h"
#include "utils.h"
#include "obex-xfer.h"
#include "obex-priv.h"


gboolean gw_obex_get_file(GwObex *ctx,
                          const gchar *local,
                          const gchar *remote,
                          const gchar *type,
                          gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_get(ctx, local, remote, type, NULL, 0, NULL, NULL, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_get_fd(GwObex      *ctx,
                        gint         fd,
                        const gchar *remote,
                        const gchar *type,
                        gint        *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_get(ctx, NULL, remote, type, NULL, 0, NULL, NULL, fd, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_put_fd(GwObex      *ctx,
                        gint         fd,
                        const gchar *remote,
                        const gchar *type,
                        gint        *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_put(ctx, NULL, remote, type, NULL, 0, NULL, 0, -1, fd, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_put_file(GwObex      *ctx,
                          const gchar *local,
                          const gchar *remote,
                          const gchar *type,
                          gint        *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_put(ctx, local, remote, type, NULL, 0, NULL, 0, -1, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_get_buf(GwObex       *ctx,
                         const gchar  *remote,
                         const gchar  *type,
                         gchar       **buf,
                         gint         *buf_size,
                         gint         *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_get(ctx, NULL, remote, type, NULL, 0, buf, buf_size, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_put_buf(GwObex      *ctx,
                         const gchar *remote,
                         const gchar *type,
                         const gchar *buf,
                         gint         buf_size,
                         gint         time,
                         gint        *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_put(ctx, NULL, remote, type, NULL, 0, buf, buf_size, time, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_get_buf_with_apparam(GwObex        *ctx,
                                      const gchar   *remote,
                                      const gchar   *type,
                                      const guint8  *apparam,
                                      gint           apparam_size,
                                      gchar        **buf,
                                      gint          *buf_size,
                                      gint          *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_get(ctx, NULL, remote, type, apparam, apparam_size, buf, buf_size, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_put_buf_with_apparam(GwObex       *ctx,
                                      const gchar  *remote,
                                      const gchar  *type,
                                      const guint8 *apparam,
                                      gint          apparam_size,
                                      const gchar  *buf,
                                      gint          buf_size,
                                      gint          time,
                                      gint         *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_put(ctx, NULL, remote, type, apparam, apparam_size, buf, buf_size, time, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_chdir(GwObex *ctx, const gchar *dir, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_setpath(ctx, dir ? dir : "", 0);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_mkdir(GwObex *ctx, const gchar *dir, gint *error) {
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    if (!gw_obex_setpath(ctx, dir ? dir : "", SETPATH_CREATE)) {
        gw_obex_get_error(ctx, error);
        GW_OBEX_UNLOCK(ctx);
        return FALSE;
    }
    (void) gw_obex_setpath(ctx, "..", 0);
    GW_OBEX_UNLOCK(ctx);
    return TRUE;
}

gboolean gw_obex_read_dir(GwObex *ctx, const gchar *dir,
                          gchar **buf, gint *buf_size, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_get(ctx, NULL, dir ? dir : "", LST_TYPE, NULL, 0, buf, buf_size, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    else if (*buf_size > 0) {
        /* Hack for some OBEX implementations which send nul's
         * at the end of the listing */
        int i;

        for (i = *buf_size - 1; i > 0; i--) {
            if ((*buf)[i] == '\0')
                (*buf_size)--;
            else
                break;
        }
    }
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_delete(GwObex *ctx, const gchar *name, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_put(ctx, NULL, name, NULL, NULL, 0, NULL, 0, -1, -1, FALSE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_move(GwObex *ctx, const gchar *src, const gchar *dst, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_action_op(ctx, src, dst, OBEX_ACTION_MOVE);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_copy(GwObex *ctx, const gchar *src, const gchar *dst, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_action_op(ctx, src, dst, OBEX_ACTION_COPY);
    if (ret == FALSE)
        gw_obex_get_error(ctx, error);
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

gboolean gw_obex_get_capability(GwObex *ctx, gchar **cap, gint *cap_len, gint *error) {
    gboolean ret;
    GW_OBEX_LOCK(ctx);
    CHECK_DISCONNECT(FALSE, error, ctx);
    ret = gw_obex_get(ctx, NULL, NULL, CAP_TYPE, NULL, 0, cap, cap_len, -1, FALSE);
    if (ret == FALSE) {
        *cap = NULL;
        *cap_len = 0;
        gw_obex_get_error(ctx, error);
    }
    GW_OBEX_UNLOCK(ctx);
    return ret;
}

void gw_obex_set_disconnect_callback(GwObex *ctx, gw_obex_disconnect_cb_t callback, gpointer data) {
    GW_OBEX_LOCK(ctx);
    ctx->dc_cb = callback;
    ctx->dc_data = data;
    GW_OBEX_UNLOCK(ctx);
}

void gw_obex_set_progress_callback(GwObex *ctx, gw_obex_progress_cb_t callback, gpointer data) {
    GW_OBEX_LOCK(ctx);
    ctx->pr_cb = callback;
    ctx->pr_data = data;
    GW_OBEX_UNLOCK(ctx);
}

void gw_obex_set_cancel_callback(GwObex *ctx, gw_obex_cancel_cb_t callback, gpointer data) {
    GW_OBEX_LOCK(ctx);
    ctx->cancel_cb = callback;
    ctx->cancel_data = data;
    GW_OBEX_UNLOCK(ctx);
}

void gw_obex_close(GwObex *ctx) {
    GW_OBEX_LOCK(ctx);
    if (ctx->xfer) {
        GwObexXfer *xfer = ctx->xfer;
        GW_OBEX_UNLOCK(ctx);
        gw_obex_xfer_close(ctx->xfer, NULL);
        GW_OBEX_LOCK(ctx);
        /* In the async case the caller of put/get_async owns the xfer object */
        if (!xfer->async)
            _gw_obex_xfer_free(xfer);
        ctx->xfer = NULL;
    }
    if (ctx->conn_fd >= 0) {
        if (!gw_obex_disconnect(ctx))
            debug("OBEX Disconnect command failed\n");
        OBEX_TransportDisconnect(ctx->handle);
        close(ctx->conn_fd);
        ctx->conn_fd = -1;
    }
    if (ctx->handle) {
        OBEX_Cleanup(ctx->handle);
        ctx->handle = NULL;
    }
    if (ctx->gio) {
        g_io_channel_unref(ctx->gio);
        ctx->gio = NULL;
    }
    if (ctx->gio_source) {
        g_source_destroy(ctx->gio_source);
        ctx->gio_source = NULL;
    }
    GW_OBEX_UNLOCK(ctx);
#ifdef GW_OBEX_THREADS_ENABLED
    g_mutex_free(ctx->mutex);
    ctx->mutex = NULL;
#endif
    g_free(ctx);
}

GwObex *gw_obex_setup_fd(int fd, const gchar *uuid, gint uuid_len,
                         GMainContext *context, gint *error) {
    obex_t *handle;
    GwObex *ctx;

    if (!gw_obex_transport_setup(fd, &handle)) {
        debug("gw_obex_open() failed\n");
        if (error)
            *error = GW_OBEX_ERROR_CONNECT_FAILED;
        return NULL;
    }

    debug("Transport connection opened.\n");

    ctx = make_context(handle);

#ifdef GW_OBEX_THREADS_ENABLED
    if (!g_thread_supported())
        g_thread_init(NULL);
    ctx->mutex = g_mutex_new();
#endif

    OBEX_SetCustomData(handle, ctx);

    debug("Connecting to OBEX service\n");
    if (!gw_obex_connect(ctx, uuid, uuid_len)) {
        debug("Unable to connect to OBEX service\n");
#ifdef GW_OBEX_THREADS_ENABLED
        g_mutex_free(ctx->mutex);
        ctx->mutex = NULL;
#endif
        g_free(ctx);
        OBEX_Cleanup(handle);
        if (error)
            *error = GW_OBEX_ERROR_NO_SERVICE;
        return NULL;
    }

    debug("Connected (Connection ID: %#x)\n", ctx->conid);

    ctx->gio = g_io_channel_unix_new(ctx->conn_fd);
    ctx->gio_source = g_io_create_watch (ctx->gio,
                                         G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL);
    g_source_set_callback(ctx->gio_source, (GSourceFunc)gw_obex_cb, ctx, NULL);
    (void) g_source_attach(ctx->gio_source, context);
    g_source_unref(ctx->gio_source);

    ctx->main_ctx = context;

    return ctx;
}

GwObex *gw_obex_setup_dev(const char *dev, const gchar *uuid, gint uuid_len,
                          GMainContext *context, gint *error) {
    GwObex *ctx;
    int fd;

    fd = open(dev, O_RDWR | O_NOCTTY | O_SYNC);
    if (fd < 0) {
        debug("open(\"%s\"): %s\n", dev, strerror(errno));
        if (error)
            *error = GW_OBEX_ERROR_CONNECT_FAILED;
        return NULL;
    }

    if (!fd_raw_mode(fd)) {
        debug("setting raw mode failed\n");
        close(fd);
        if (error)
            *error = GW_OBEX_ERROR_CONNECT_FAILED;
        return NULL;
    }

    ctx = gw_obex_setup_fd(fd, uuid, uuid_len, context, error);
    if (ctx == NULL) {
        close(fd);
    }

    return ctx;
}

