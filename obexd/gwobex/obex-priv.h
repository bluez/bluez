/**
  @file obex-priv.h

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
#ifndef _OBEX_PRIV_H_
#define _OBEX_PRIV_H_

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <glib.h>

#include <openobex/obex.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "gw-obex.h"
#include "obex-xfer.h"

#define CHECK_DISCONNECT(ret,err,ctx) do { \
                                          if ((ctx)->conn_fd < 0) { \
                                              if (err) \
                                                  *(err) = GW_OBEX_ERROR_DISCONNECT; \
                                              GW_OBEX_UNLOCK(ctx); \
                                              return (ret); \
                                          } \
                                      } while (0)

#ifndef OBEX_CMD_ACTION
# define OBEX_CMD_ACTION      0x06

# define OBEX_HDR_ACTION_ID   0x94
# define OBEX_HDR_DESTNAME    0x15
# define OBEX_HDR_PERMISSIONS 0xD6

# define OBEX_ACTION_COPY     0x00
# define OBEX_ACTION_MOVE     0x01
# define OBEX_ACTION_SETPERM  0x02

#endif /* OBEX_CMD_ACTION */

#define CONID_INVALID 0xFFFFFFFF

#define OBEX_CMD_NONE 0x10

#define GW_OBEX_RX_MTU 4096
#define GW_OBEX_TX_MTU 32767

#define SETPATH_CREATE  0x0001

#define CAP_TYPE "x-obex/capability"
#define OBP_TYPE "x-obex/object-profile"
#define LST_TYPE "x-obex/folder-listing"

#ifdef GW_OBEX_THREADS_ENABLED
# ifdef DEBUG
#  define GW_OBEX_LOCK(ctx) do { \
      debug("Attempting GW_OBEX_LOCK at %s:%d (%s)...", __FILE__, __LINE__, __PRETTY_FUNCTION__); \
      fflush(stdout); \
      g_mutex_lock((ctx)->mutex); \
      debug("got it!\n"); \
   } while (0)
#  define GW_OBEX_UNLOCK(ctx) do { \
      debug("Unlocking GW_OBEX_LOCK at %s:%d (%s)\n", __FILE__, __LINE__, __PRETTY_FUNCTION__); \
      g_mutex_unlock((ctx)->mutex); \
   } while (0)
# else
#  define GW_OBEX_LOCK(ctx)   g_mutex_lock((ctx)->mutex)
#  define GW_OBEX_UNLOCK(ctx) g_mutex_unlock((ctx)->mutex)
# endif
#else
# define GW_OBEX_LOCK(ctx)   ((void)(0))
# define GW_OBEX_UNLOCK(ctx) ((void)(0))
#endif

typedef struct obex_setpath_hdr {
    uint8_t  flags;
    uint8_t constants;
} __attribute__ ((packed)) obex_setpath_hdr_t;

typedef struct obex_connect_hdr {
    uint8_t  version;
    uint8_t  flags;
    uint16_t mtu;
} __attribute__ ((packed)) obex_connect_hdr_t;

struct gw_obex {
#ifdef GW_OBEX_THREADS_ENABLED
    /* To get rid of race conditions in multithreaded apps */
    GMutex                  *mutex;
#endif

    /* Main OpenOBEX handle */
    obex_t                  *handle;

    /* Exception callback and associated data */
    gw_obex_disconnect_cb_t  dc_cb;
    gpointer                 dc_data;

    /* Progress callback and associated data */
    gw_obex_progress_cb_t    pr_cb;
    gpointer                 pr_data;

    /* Whether calling pr_cb is necessary or not */
    gboolean                 report_progress;

    /* Cancel callback and associated data */
    gw_obex_cancel_cb_t      cancel_cb;
    gpointer                 cancel_data;

    /* For checking if the current operation is finished */
    gboolean                 done;

    /* TRUE if a link error has hapened */
    gboolean                 link_err;

    /* FD for the transport connection */
    int                      conn_fd;

    GMainContext            *main_ctx;

    /* The transport connection's GIOChannel */
    GIOChannel               *gio;

    /* The transport connection's GSource */
    GSource                  *gio_source;

    /* OBEX Connection ID */
    uint32_t                 conid;

    /* The last OBEX response code */
    uint8_t                  obex_rsp;

    /* The current OBEX operation */
    uint8_t                  obex_op;

    /* This is set if some operation fails */
    gint                     error;

    /* Bytes to read at a time when doing a put */
    uint16_t                 tx_max;

    /* How many bytes to allocate for incomming object data */
    uint16_t                 rx_max;

    /* Current object transfer handle */
    struct gw_obex_xfer     *xfer;
};

GwObex *make_context(obex_t *handle);

gboolean gw_obex_set_error(GwObex *ctx);

void gw_obex_get_error(GwObex *ctx, gint *error);

void obex_link_error(GwObex *ctx);

gboolean gw_obex_cb(GIOChannel *chan, GIOCondition cond, gpointer data);

gboolean gw_obex_connect(GwObex *ctx, const char *target, size_t target_len);

gboolean gw_obex_disconnect(GwObex *ctx);

gboolean gw_obex_transport_setup(int fd, obex_t **handle);

gboolean gw_obex_action_op(GwObex *ctx, const gchar *src, const gchar *dst,
                           uint8_t action);

gboolean gw_obex_setpath(GwObex *ctx, const gchar *path, int flags);

/** Get an object from the server
 * @param ctx Pointer returned by gw_obex_setup()
 * @param local Local filename which contains the object
 * @param remote Remote filename to store the object in
 * @param type MIME-type of the object (NULL if not known)
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_get(GwObex *ctx,
                     const gchar *local, const gchar *remote, const gchar *type,
                     const guint8 *apparam, gint apparam_size,
                     gchar **buf, gint *buf_size, int stream_fd,
                     gboolean async);

/** Send an object to the server
 * @param ctx Pointer returned by gw_obex_setup()
 * @param local Local filename to store the objec in
 * @param remote Remote filename which contains the object
 * @param type MIME-type of the object (NULL if not known)
 * @returns TRUE on success, FALSE on failure
 */
gboolean gw_obex_put(GwObex *ctx,
                     const gchar *local, const gchar *remote, const gchar *type,
                     const guint8 *apparam, gint apparam_size,
                     const gchar *buf, gint buf_size, time_t object_time,
                     int stream_fd, gboolean async);

#endif /* _OBEX_PRIV_H_ */
