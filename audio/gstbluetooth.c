/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "gstsbcenc.h"
#include "gstsbcdec.h"
#include "gstsbcparse.h"
#include "gsta2dpsink.h"

static GstStaticCaps sbc_caps = GST_STATIC_CAPS("audio/x-sbc");

#define SBC_CAPS (gst_static_caps_get(&sbc_caps))

static void sbc_typefind(GstTypeFind *tf, gpointer ignore)
{
	guint8 *data = gst_type_find_peek(tf, 0, 1);

	if (data == NULL || *data != 0x9c)	/* SBC syncword */
		return;

	gst_type_find_suggest(tf, GST_TYPE_FIND_POSSIBLE, SBC_CAPS);
}

static gchar *sbc_exts[] = { "sbc", NULL };

static gboolean plugin_init(GstPlugin *plugin)
{
	GST_INFO("Bluetooth plugin %s", VERSION);

	if (gst_type_find_register(plugin, "sbc",
			GST_RANK_PRIMARY, sbc_typefind, sbc_exts,
					SBC_CAPS, NULL, NULL) == FALSE)
		return FALSE;

	if (gst_element_register(plugin, "sbcenc",
			GST_RANK_NONE, GST_TYPE_SBC_ENC) == FALSE)
		return FALSE;

	if (gst_element_register(plugin, "sbcdec",
			GST_RANK_PRIMARY, GST_TYPE_SBC_DEC) == FALSE)
		return FALSE;

	if (gst_element_register(plugin, "sbcparse",
			GST_RANK_PRIMARY, GST_TYPE_SBC_PARSE) == FALSE)
		return FALSE;

#if 0
	if (gst_element_register(plugin, "a2dpsink",
			GST_RANK_PRIMARY, GST_TYPE_A2DP_SINK) == FALSE)
		return FALSE;
#endif

	return TRUE;
}

GST_PLUGIN_DEFINE(GST_VERSION_MAJOR, GST_VERSION_MINOR,
	"bluetooth", "Bluetooth plugin library",
	plugin_init, VERSION, "LGPL", "BlueZ", "http://www.bluez.org/")
