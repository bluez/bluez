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

#ifndef __GST_A2DP_SENDER_SINK_H
#define __GST_A2DP_SENDER_SINK_H

#include <gst/gst.h>
#include <gst/base/gstbasesink.h>

G_BEGIN_DECLS

#define GST_TYPE_A2DP_SENDER_SINK \
	(gst_a2dp_sender_sink_get_type())
#define GST_A2DP_SENDER_SINK(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj),GST_TYPE_A2DP_SENDER_SINK,\
		GstA2dpSenderSink))
#define GST_A2DP_SENDER_SINK_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass),GST_TYPE_A2DP_SENDER_SINK,\
		GstA2dpSenderSinkClass))
#define GST_IS_A2DP_SENDER_SINK(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj),GST_TYPE_A2DP_SENDER_SINK))
#define GST_IS_A2DP_SENDER_SINK_CLASS(obj) \
	(G_TYPE_CHECK_CLASS_TYPE((klass),GST_TYPE_A2DP_SENDER_SINK))

typedef struct _GstA2dpSenderSink GstA2dpSenderSink;
typedef struct _GstA2dpSenderSinkClass GstA2dpSenderSinkClass;

struct bluetooth_data;

struct _GstA2dpSenderSink {
	GstBaseSink sink;

	gchar *device;
	GIOChannel *stream;

	struct bluetooth_data *data;
	GIOChannel *server;

	/* mp3 stream data (outside caps data)*/
	gboolean mpeg_stream_changed;
	gint mp3_using_crc;
	gint channel_mode;

	/* stream connection data */
	GstCaps *stream_caps;

	GstCaps *dev_caps;

	GMutex *sink_lock;

	guint watch_id;
};

struct _GstA2dpSenderSinkClass {
	GstBaseSinkClass parent_class;
};

GType gst_a2dp_sender_sink_get_type(void);

GstCaps *gst_a2dp_sender_sink_get_device_caps(GstA2dpSenderSink *sink);
gboolean gst_a2dp_sender_sink_set_device_caps(GstA2dpSenderSink *sink,
			GstCaps *caps);

guint gst_a2dp_sender_sink_get_link_mtu(GstA2dpSenderSink *sink);

void gst_a2dp_sender_sink_set_device(GstA2dpSenderSink *sink,
		const gchar* device);

gchar *gst_a2dp_sender_sink_get_device(GstA2dpSenderSink *sink);

gboolean gst_a2dp_sender_sink_plugin_init(GstPlugin *plugin);

void gst_a2dp_sender_sink_set_crc(GstA2dpSenderSink *self, gboolean crc);

void gst_a2dp_sender_sink_set_channel_mode(GstA2dpSenderSink *self,
			const gchar *mode);


G_END_DECLS

#endif /* __GST_A2DP_SENDER_SINK_H */
