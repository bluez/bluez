/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <string.h>

#include <gst/gst.h>

#include "gstsbcutil.h"
#include <sbc.h>

#include "gstsbcenc.h"
#include "gstsbcdec.h"
#include "gstsbcparse.h"
#include "gstavdtpsink.h"
#include "gsta2dpsink.h"
#include "gstrtpsbcpay.h"

static GstStaticCaps sbc_caps = GST_STATIC_CAPS("audio/x-sbc");

#define SBC_CAPS (gst_static_caps_get(&sbc_caps))

static void sbc_typefind(GstTypeFind *tf, gpointer ignore)
{
	GstCaps *caps;
	guint8 *aux;
	sbc_t sbc;
	guint8 *data = gst_type_find_peek(tf, 0, 32);

	if (data == NULL)
		return;

	if (sbc_init(&sbc, 0) < 0)
		return;

	aux = g_new(guint8, 32);
	memcpy(aux, data, 32);
	if (sbc_parse(&sbc, aux, 32) < 0)
		goto done;

	caps = gst_sbc_parse_caps_from_sbc(&sbc);
	gst_type_find_suggest(tf, GST_TYPE_FIND_POSSIBLE, caps);
	gst_caps_unref(caps);

done:
	g_free(aux);
	sbc_finish(&sbc);
}

static gchar *sbc_exts[] = { "sbc", NULL };

static gboolean plugin_init(GstPlugin *plugin)
{
	GST_INFO("Bluetooth plugin %s", VERSION);

	if (gst_type_find_register(plugin, "sbc",
			GST_RANK_PRIMARY, sbc_typefind, sbc_exts,
					SBC_CAPS, NULL, NULL) == FALSE)
		return FALSE;

	if (!gst_sbc_enc_plugin_init(plugin))
		return FALSE;

	if (!gst_sbc_dec_plugin_init(plugin))
		return FALSE;

	if (!gst_sbc_parse_plugin_init(plugin))
		return FALSE;

	if (!gst_avdtp_sink_plugin_init(plugin))
		return FALSE;

	if (!gst_a2dp_sink_plugin_init(plugin))
		return FALSE;

	if (!gst_rtp_sbc_pay_plugin_init(plugin))
		return FALSE;

	return TRUE;
}

extern GstPluginDesc gst_plugin_desc __attribute__ ((visibility("default")));

GST_PLUGIN_DEFINE(GST_VERSION_MAJOR, GST_VERSION_MINOR,
	"bluetooth", "Bluetooth plugin library",
	plugin_init, VERSION, "LGPL", "BlueZ", "http://www.bluez.org/")
