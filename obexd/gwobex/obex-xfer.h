/**
  @file obex-xfer.h

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
#ifndef _OBEX_XFER_H_
#define _OBEX_XFER_H_

#include <stdint.h>
#include <time.h>
#include <glib.h>

#include <openobex/obex.h>

#include "gw-obex.h"
#include "obex-priv.h"

struct gw_obex_xfer {
    /* Pointer to parent gw_obex struct */
    struct gw_obex *ctx;

    /* Used only for async PUT transfers */
    obex_object_t           *object;

    /* Sync or async transfer */
    gboolean                 async;

    /* If read and write operations should block for an async transfer */
    gboolean                 block;

    /* When doing a get or put for a local file */
    int                      stream_fd;

    /* TRUE if the current operation was aborted */
    gboolean                 abort;

    /* Transfer should be closed when no more data to send */
    gboolean                 close;

    /* Temporary buffer when doing a put or get */
    unsigned char           *buf;
    size_t                   buf_size;

    /* Buffer and size for Application parameters */
    unsigned char           *apparam_buf;
    size_t                   apparam_size;

    /* These two elements are only used for async transfers */
    size_t                   data_start;
    size_t                   data_length;

    /* Bytes read or written for the current get/put operation */
    size_t                   counter;

    /* Target length of the current get/put operation */
    gint                     target_size;

    /* Modification time of last file transfered */
    time_t                   modtime;

    gboolean                 do_cb;
    gw_obex_xfer_cb_t        cb;
    gpointer                 cb_data;

    GSource                 *idle_source;
};

struct gw_obex_xfer *gw_obex_xfer_new(struct gw_obex *ctx, gboolean async, int stream_fd);

void _gw_obex_xfer_free(struct gw_obex_xfer *xfer);

gboolean gw_obex_xfer_do_abort(struct gw_obex_xfer *xfer);

#endif /* _OBEX_XFER_H_ */
