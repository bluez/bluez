/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
 *
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include <dbus/dbus.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "logging.h"
#include "manager.h"
#include "device.h"
#include "avdtp.h"
#include "sink.h"
#include "a2dp.h"

#ifndef MIN
# define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

struct a2dp_sep {
	struct avdtp_local_sep *sep;
	struct avdtp_stream *stream;
	struct device *used_by;
	uint32_t record_id;
	gboolean start_requested;
	gboolean suspending;
	gboolean starting;
};

struct a2dp_stream_cb {
	a2dp_stream_cb_t cb;
	void *user_data;
	int id;
};

struct a2dp_stream_setup {
	struct avdtp *session;
	struct device *dev;
	struct avdtp_stream *stream;
	gboolean start;
	gboolean canceled;
	GSList *cb;
};

static DBusConnection *connection = NULL;

static struct a2dp_sep sink = { NULL, NULL, 0 };
static struct a2dp_sep source = { NULL, NULL, 0 };

static struct a2dp_stream_setup *setup = NULL;

static void stream_setup_free(struct a2dp_stream_setup *s)
{
	if (s->session)
		avdtp_unref(s->session);
	g_slist_foreach(s->cb, (GFunc) g_free, NULL);
	g_slist_free(s->cb);
	g_free(s);
	setup = NULL;
}

static void setup_callback(struct a2dp_stream_cb *cb,
				struct a2dp_stream_setup *s)
{
	cb->cb(s->session, s->dev, s->stream, cb->user_data);
}

static void finalize_stream_setup(struct a2dp_stream_setup *s)
{
	g_slist_foreach(setup->cb, (GFunc) setup_callback, setup);
	stream_setup_free(setup);
}

static gboolean setconf_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				GSList *caps, uint8_t *err,
				uint8_t *category)
{
	struct device *dev;
	bdaddr_t addr;

	if (sep == sink.sep) {
		debug("SBC Sink: Set_Configuration_Ind");
		return TRUE;
	}

	debug("SBC Source: Set_Configuration_Ind");

	avdtp_get_peers(session, NULL, &addr);

	dev = manager_device_connected(&addr, A2DP_SOURCE_UUID);
	if (!dev) {
		*err = AVDTP_UNSUPPORTED_CONFIGURATION;
		*category = 0x00;
		return FALSE;
	}

	source.stream = stream;

	sink_new_stream(dev, session, stream);

	return TRUE;
}

static gboolean getcap_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				GSList **caps, uint8_t *err)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;

	if (sep == sink.sep)
		debug("SBC Sink: Get_Capability_Ind");
	else
		debug("SBC Source: Get_Capability_Ind");

	*caps = NULL;

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	*caps = g_slist_append(*caps, media_transport);

	memset(&sbc_cap, 0, sizeof(struct sbc_codec_cap));

	sbc_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
	sbc_cap.cap.media_codec_type = A2DP_CODEC_SBC;

	sbc_cap.frequency = ( A2DP_SAMPLING_FREQ_48000 |
				A2DP_SAMPLING_FREQ_44100 |
				A2DP_SAMPLING_FREQ_32000 |
				A2DP_SAMPLING_FREQ_16000 );

	sbc_cap.channel_mode = ( A2DP_CHANNEL_MODE_JOINT_STEREO |
					A2DP_CHANNEL_MODE_STEREO |
					A2DP_CHANNEL_MODE_DUAL_CHANNEL |
					A2DP_CHANNEL_MODE_MONO );

	sbc_cap.block_length = ( A2DP_BLOCK_LENGTH_16 |
					A2DP_BLOCK_LENGTH_12 |
					A2DP_BLOCK_LENGTH_8 |
					A2DP_BLOCK_LENGTH_4 );

	sbc_cap.subbands = ( A2DP_SUBBANDS_8 | A2DP_SUBBANDS_4 );

	sbc_cap.allocation_method = ( A2DP_ALLOCATION_LOUDNESS |
					A2DP_ALLOCATION_SNR );

	sbc_cap.min_bitpool = 2;
	sbc_cap.max_bitpool = 250;

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &sbc_cap,
						sizeof(sbc_cap));

	*caps = g_slist_append(*caps, media_codec);

	return TRUE;
}

static void setconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				struct avdtp_error *err)
{
	int ret;

	if (sep == sink.sep) {
		debug("SBC Sink: Set_Configuration_Cfm");
		return;
	}

	debug("SBC Source: Set_Configuration_Cfm");

	if (err) {
		source.stream = NULL;
		if (setup)
			finalize_stream_setup(setup);
		return;
	}

	source.stream = stream;

	if (!setup)
		return;

	ret = avdtp_open(session, stream);
	if (ret < 0) {
		error("Error on avdtp_open %s (%d)", strerror(-ret),
				-ret);
		setup->stream = FALSE;
		finalize_stream_setup(setup);
	}
}

static gboolean getconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Get_Configuration_Ind");
	else
		debug("SBC Source: Get_Configuration_Ind");
	return TRUE;
}

static void getconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Set_Configuration_Cfm");
	else
		debug("SBC Source: Set_Configuration_Cfm");
}

static gboolean open_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Open_Ind");
	else
		debug("SBC Source: Open_Ind");
	return TRUE;
}

static void open_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Open_Cfm");
	else
		debug("SBC Source: Open_Cfm");

	if (!setup)
		return;

	if (setup->canceled) {
		if (!err)
			avdtp_close(session, stream);
		stream_setup_free(setup);
		return;
	}

	if (err) {
		setup->stream = NULL;
		goto finalize;
	}

	if (setup->start) {
		if (avdtp_start(session, stream) == 0)
			return;

		error("avdtp_start failed");
		setup->stream = NULL;
	} 

finalize:
	finalize_stream_setup(setup);
}

static gboolean start_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Start_Ind");
	else
		debug("SBC Source: Start_Ind");

	/* Refuse to go into streaming state since this action should only be
	 * initiated by alsa */
	*err = AVDTP_NOT_SUPPORTED_COMMAND;
	return FALSE;
}

static void start_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Start_Cfm");
	else
		debug("SBC Source: Start_Cfm");

	if (!setup)
		return;

	if (setup->canceled) {
		if (!err)
			avdtp_close(session, stream);
		stream_setup_free(setup);
		return;
	}

	if (err)
		setup->stream = NULL;

	finalize_stream_setup(setup);
}

static gboolean suspend_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Suspend_Ind");
	else
		debug("SBC Source: Suspend_Ind");
	return TRUE;
}

static void suspend_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep) {
		debug("SBC Sink: Suspend_Cfm");
		return;
	}

	debug("SBC Source: Suspend_Cfm");

	source.suspending = FALSE;

	if (err) {
		source.start_requested = FALSE;
		if (setup)
			finalize_stream_setup(setup);
		return;
	}

	if (source.start_requested) {
		avdtp_start(session, stream);
		source.start_requested = FALSE;
	}
}

static gboolean close_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink.sep) {
		debug("SBC Sink: Close_Ind");
		return TRUE;
	}

	debug("SBC Source: Close_Ind");

	source.stream = NULL;

	return TRUE;
}

static void close_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep) {
		debug("SBC Sink: Close_Cfm");
		return;
	}

	debug("SBC Source: Close_Cfm");

	source.stream = NULL;
}

static gboolean abort_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink.sep) {
		debug("SBC Sink: Abort_Ind");
		return TRUE;
	}

	debug("SBC Source: Abort_Ind");

	source.stream = NULL;

	return TRUE;
}

static void abort_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: Abort_Cfm");
	else
		debug("SBC Source: Abort_Cfm");
}

static gboolean reconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: ReConfigure_Ind");
	else
		debug("SBC Source: ReConfigure_Ind");
	return TRUE;
}

static void reconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err)
{
	if (sep == sink.sep)
		debug("SBC Sink: ReConfigure_Cfm");
	else
		debug("SBC Source: ReConfigure_Cfm");
}

static struct avdtp_sep_cfm cfm = {
	.set_configuration	= setconf_cfm,
	.get_configuration	= getconf_cfm,
	.open			= open_cfm,
	.start			= start_cfm,
	.suspend		= suspend_cfm,
	.close			= close_cfm,
	.abort			= abort_cfm,
	.reconfigure		= reconf_cfm
};

static struct avdtp_sep_ind ind = {
	.get_capability		= getcap_ind,
	.set_configuration	= setconf_ind,
	.get_configuration	= getconf_ind,
	.open			= open_ind,
	.start			= start_ind,
	.suspend		= suspend_ind,
	.close			= close_ind,
	.abort			= abort_ind,
	.reconfigure		= reconf_ind
};

static int a2dp_source_record(sdp_buf_t *buf)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avdtp, a2src;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVDTP_UUID, ver = 0x0100, feat = 0x000F;
	int ret = 0;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&a2src, AUDIO_SOURCE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &a2src);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, ADVANCED_AUDIO_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avdtp, AVDTP_UUID);
	proto[1] = sdp_list_append(0, &avdtp);
	version = sdp_data_alloc(SDP_UINT16, &ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(&record, "Audio Source", 0, 0);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

static int a2dp_sink_record(sdp_buf_t *buf)
{
	return 0;
}

int a2dp_init(DBusConnection *conn, gboolean enable_sink, gboolean enable_source)
{
	sdp_buf_t buf;

	if (!enable_sink && !enable_source)
		return 0;

	connection = dbus_connection_ref(conn);

	avdtp_init();

	if (enable_sink) {
		source.sep = avdtp_register_sep(AVDTP_SEP_TYPE_SOURCE,
							AVDTP_MEDIA_TYPE_AUDIO,
							&ind, &cfm);
		if (source.sep == NULL)
			return -1;

		if (a2dp_source_record(&buf) < 0) {
			error("Unable to allocate new service record");
			return -1;
		}

		source.record_id = add_service_record(conn, &buf);
		free(buf.data);
		if (!source.record_id) {
			error("Unable to register A2DP Source service record");
			return -1;
		}
	}

	if (enable_source) {
		sink.sep = avdtp_register_sep(AVDTP_SEP_TYPE_SINK,
						AVDTP_MEDIA_TYPE_AUDIO,
						&ind, &cfm);
		if (sink.sep == NULL)
			return -1;

		if (a2dp_sink_record(&buf) < 0) {
			error("Unable to allocate new service record");
			return -1;
		}

		sink.record_id = add_service_record(conn, &buf);
		free(buf.data);
		if (!sink.record_id) {
			error("Unable to register A2DP Sink service record");
			return -1;
		}
	}

	return 0;
}

void a2dp_exit()
{
	if (sink.sep) {
		avdtp_unregister_sep(sink.sep);
		sink.sep = NULL;
	}

	if (source.sep) {
		avdtp_unregister_sep(source.sep);
		source.sep = NULL;
	}

	if (source.record_id) {
		remove_service_record(connection, source.record_id);
		source.record_id = 0;
	}

	if (sink.record_id) {
		remove_service_record(connection, sink.record_id);
		sink.record_id = 0;
	}

	dbus_connection_unref(connection);
}

static uint8_t default_bitpool(uint8_t freq, uint8_t mode) {
	switch (freq) {
	case A2DP_SAMPLING_FREQ_16000:
	case A2DP_SAMPLING_FREQ_32000:
		return 53;
	case A2DP_SAMPLING_FREQ_44100:
		switch (mode) {
		case A2DP_CHANNEL_MODE_MONO:
		case A2DP_CHANNEL_MODE_DUAL_CHANNEL:
			return 31;
		case A2DP_CHANNEL_MODE_STEREO:
		case A2DP_CHANNEL_MODE_JOINT_STEREO:
			return 53;
		default:
			error("Invalid channel mode %u", mode);
			return 53;
		}
	case A2DP_SAMPLING_FREQ_48000:
		switch (mode) {
		case A2DP_CHANNEL_MODE_MONO:
		case A2DP_CHANNEL_MODE_DUAL_CHANNEL:
			return 29;
		case A2DP_CHANNEL_MODE_STEREO:
		case A2DP_CHANNEL_MODE_JOINT_STEREO:
			return 51;
		default:
			error("Invalid channel mode %u", mode);
			return 51;
		}
	default:
		error("Invalid sampling freq %u", freq);
		return 53;
	}
}

static gboolean select_sbc_params(struct sbc_codec_cap *cap,
					struct sbc_codec_cap *supported)
{
	uint max_bitpool, min_bitpool;

	memset(cap, 0, sizeof(struct sbc_codec_cap));

	cap->cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
	cap->cap.media_codec_type = A2DP_CODEC_SBC;

	if (supported->frequency & A2DP_SAMPLING_FREQ_48000)
		cap->frequency = A2DP_SAMPLING_FREQ_48000;
	else if (supported->frequency & A2DP_SAMPLING_FREQ_44100)
		cap->frequency = A2DP_SAMPLING_FREQ_44100;
	else if (supported->frequency & A2DP_SAMPLING_FREQ_32000)
		cap->frequency = A2DP_SAMPLING_FREQ_32000;
	else if (supported->frequency & A2DP_SAMPLING_FREQ_16000)
		cap->frequency = A2DP_SAMPLING_FREQ_16000;
	else {
		error("No supported frequencies");
		return FALSE;
	}

	if (supported->channel_mode & A2DP_CHANNEL_MODE_JOINT_STEREO)
		cap->channel_mode = A2DP_CHANNEL_MODE_JOINT_STEREO;
	else if (supported->channel_mode & A2DP_CHANNEL_MODE_STEREO)
		cap->channel_mode = A2DP_CHANNEL_MODE_STEREO;
	else if (supported->channel_mode & A2DP_CHANNEL_MODE_DUAL_CHANNEL)
		cap->channel_mode = A2DP_CHANNEL_MODE_DUAL_CHANNEL;
	else if (supported->channel_mode & A2DP_CHANNEL_MODE_MONO)
		cap->channel_mode = A2DP_CHANNEL_MODE_MONO;
	else {
		error("No supported channel modes");
		return FALSE;
	}

	if (supported->block_length & A2DP_BLOCK_LENGTH_16)
		cap->block_length = A2DP_BLOCK_LENGTH_16;
	else if (supported->block_length & A2DP_BLOCK_LENGTH_12)
		cap->block_length = A2DP_BLOCK_LENGTH_12;
	else if (supported->block_length & A2DP_BLOCK_LENGTH_8)
		cap->block_length = A2DP_BLOCK_LENGTH_8;
	else if (supported->block_length & A2DP_BLOCK_LENGTH_4)
		cap->block_length = A2DP_BLOCK_LENGTH_4;
	else {
		error("No supported block lengths");
		return FALSE;
	}

	if (supported->subbands & A2DP_SUBBANDS_8)
		cap->subbands = A2DP_SUBBANDS_8;
	else if (supported->subbands & A2DP_SUBBANDS_4)
		cap->subbands = A2DP_SUBBANDS_4;
	else {
		error("No supported subbands");
		return FALSE;
	}

	if (supported->allocation_method & A2DP_ALLOCATION_LOUDNESS)
		cap->allocation_method = A2DP_ALLOCATION_LOUDNESS;
	else if (supported->allocation_method & A2DP_ALLOCATION_SNR)
		cap->allocation_method = A2DP_ALLOCATION_SNR;

	min_bitpool = MAX(2, supported->min_bitpool);
	max_bitpool = MIN(default_bitpool(cap->frequency, cap->channel_mode),
				supported->max_bitpool);

	cap->min_bitpool = min_bitpool;
	cap->max_bitpool = max_bitpool;

	return TRUE;
}

static gboolean a2dp_select_capabilities(struct avdtp_remote_sep *rsep, GSList **caps)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap, *acp_sbc;

	media_codec = avdtp_get_codec(rsep);
	if (!media_codec)
		return FALSE;

	acp_sbc = (void *) media_codec->data;

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	*caps = g_slist_append(*caps, media_transport);

	select_sbc_params(&sbc_cap, acp_sbc);

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &sbc_cap,
						sizeof(sbc_cap));

	*caps = g_slist_append(*caps, media_codec);

	return TRUE;
}

static void discovery_complete(struct avdtp *session, GSList *seps, int err,
				void *user_data)
{
	struct avdtp_local_sep *lsep;
	struct avdtp_remote_sep *rsep;
	GSList *caps = NULL;

	if (err < 0) {
		error("Discovery failed: %s (%d)", strerror(-err), -err);
		setup->stream = NULL;
		finalize_stream_setup(setup);
		return;
	}

	debug("Discovery complete");

	if (avdtp_get_seps(session, AVDTP_SEP_TYPE_SINK, AVDTP_MEDIA_TYPE_AUDIO,
				A2DP_CODEC_SBC, &lsep, &rsep) < 0) {
		error("No matching ACP and INT SEPs found");
		finalize_stream_setup(setup);
		return;
	}

	if (!a2dp_select_capabilities(rsep, &caps)) {
		error("Unable to select remote SEP capabilities");
		finalize_stream_setup(setup);
		return;
	}                       

	err = avdtp_set_configuration(session, rsep, lsep, caps,
					&setup->stream);
	if (err < 0) {
		error("avdtp_set_configuration: %s", strerror(-err));
		finalize_stream_setup(setup);
		return;
	}

	/* Notify sink.c of the new stream */
	sink_new_stream(setup->dev, session, setup->stream);
}

gboolean a2dp_source_cancel_stream(int id)
{
	struct a2dp_stream_cb *cb_data;
	GSList *l;

	if (!setup)
		return FALSE;

	for (cb_data = NULL, l = setup->cb; l != NULL; l = g_slist_next(l)) {
		struct a2dp_stream_cb *cb = l->data;

		if (cb->id == id) {
			cb_data = cb;
			break;
		}
	}

	if (!cb_data)
		return FALSE;

	setup->cb = g_slist_remove(setup->cb, cb_data);
	g_free(cb_data);

	if (!setup->cb)
		setup->canceled = TRUE;

	return TRUE;
}

unsigned int a2dp_source_request_stream(struct avdtp *session,
					struct device *dev,
					gboolean start, a2dp_stream_cb_t cb,
					void *user_data)
{
	struct a2dp_stream_cb *cb_data;
	static unsigned int cb_id = 0;

	cb_data = g_new(struct a2dp_stream_cb, 1);
	cb_data->cb = cb;
	cb_data->user_data = user_data;
	cb_data->id = ++cb_id;

	if (setup) {
		setup->canceled = FALSE;
		setup->cb = g_slist_append(setup->cb, cb_data);
		if (start)
			setup->start = TRUE;
		return cb_data->id;
	}

	setup = g_new0(struct a2dp_stream_setup, 1);
	setup->session = avdtp_ref(session);
	setup->dev = dev;
	setup->cb = g_slist_append(setup->cb, cb_data);
	setup->start = start;
	setup->stream = source.stream;

	switch (avdtp_sep_get_state(source.sep)) {
	case AVDTP_STATE_IDLE:
		if (avdtp_discover(session, discovery_complete, setup) < 0)
			goto failed;
		break;
	case AVDTP_STATE_OPEN:
		if (!start) {
			g_idle_add((GSourceFunc) finalize_stream_setup, setup);
			break;
		}
		if (source.starting)
			break;
		if (avdtp_start(session, source.stream) < 0)
			goto failed;
		break;
	case AVDTP_STATE_STREAMING:
		if (!start || !source.suspending) {
			g_idle_add((GSourceFunc) finalize_stream_setup, setup);
			return cb_data->id;
		}
		source.start_requested = TRUE;
		break;
	default:
		goto failed;
	}

	return cb_data->id;

failed:
	stream_setup_free(setup);
	cb_id--;
	return 0;
}

gboolean a2dp_source_lock(struct device *dev, struct avdtp *session)
{
	if (source.used_by)
		return FALSE;

	source.used_by = dev;

	return TRUE;
}

gboolean a2dp_source_unlock(struct device *dev, struct avdtp *session)
{
	avdtp_state_t state;

	if (!source.sep)
		return FALSE;

	if (source.used_by != dev)
		return FALSE;

	state = avdtp_sep_get_state(source.sep);

	source.used_by = NULL;

	if (!source.stream || state == AVDTP_STATE_IDLE)
		return TRUE;

	switch (state) {
	case AVDTP_STATE_OPEN:
		/* Set timer here */
		break;
	case AVDTP_STATE_STREAMING:
		if (avdtp_suspend(session, source.stream) == 0)
			source.suspending = TRUE;
		break;
	default:
		break;
	}

	return TRUE;
}

gboolean a2dp_source_suspend(struct device *dev, struct avdtp *session)
{
	avdtp_state_t state;

	if (!source.sep)
		return FALSE;

	if (source.used_by != dev)
		return FALSE;

	state = avdtp_sep_get_state(source.sep);

	if (!source.stream || state != AVDTP_STATE_STREAMING)
		return TRUE;

	if (avdtp_suspend(session, source.stream) == 0) {
		source.suspending = TRUE;
		return TRUE;
	}

	return FALSE;
}

gboolean a2dp_source_start_stream(struct device *dev, struct avdtp *session)
{
	avdtp_state_t state;

	if (!source.sep)
		return FALSE;

	if (source.used_by != dev)
		return FALSE;

	state = avdtp_sep_get_state(source.sep);

	if (state < AVDTP_STATE_OPEN) {
		error("a2dp_source_start_stream: no stream open");
		return FALSE;
	}

	if (state == AVDTP_STATE_STREAMING)
		return TRUE;

	if (avdtp_start(session, source.stream) < 0)
		return FALSE;

	return TRUE;
}
