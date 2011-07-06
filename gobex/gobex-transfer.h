/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#ifndef __GOBEX_TRANSFER_H
#define __GOBEX_TRANSFER_H

#include <glib.h>

#include <gobex/gobex.h>
#include <gobex/gobex-defs.h>

guint g_obex_put_req(GObex *obex, const char *type, const char *name,
			GObexDataProducer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err);

guint g_obex_get_req(GObex *obex, const char *type, const char *name,
			GObexDataConsumer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err);

guint g_obex_put_rsp(GObex *obex, GObexPacket *req,
			GObexDataConsumer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err);

guint g_obex_get_rsp(GObex *obex, GObexPacket *req,
			GObexDataProducer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err);

#endif /* __GOBEX_TRANSFER_H_ */
