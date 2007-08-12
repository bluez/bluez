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

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "logging.h"
#include "manager.h"
#include "avdtp.h"
#include "sink.h"
#include "a2dp.h"

static DBusConnection *connection = NULL;

static uint32_t sink_record_id = 0;
static uint32_t source_record_id = 0;

static struct avdtp_local_sep *sink_sep = NULL;
static struct avdtp_local_sep *source_sep = NULL;

static gboolean setconf_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				GSList *caps, uint8_t *err,
				uint8_t *category)
{
	struct device *dev;
	bdaddr_t addr;

	if (sep == sink_sep) {
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

	sink_new_stream(session, stream, dev);

	return TRUE;
}

static gboolean getcap_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				GSList **caps, uint8_t *err)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;

	if (sep == sink_sep)
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
				struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Set_Configuration_Cfm");
	else
		debug("SBC Source: Set_Configuration_Cfm");
}

static gboolean getconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: Get_Configuration_Ind");
	else
		debug("SBC Source: Get_Configuration_Ind");
	return TRUE;
}

static void getconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Set_Configuration_Cfm");
	else
		debug("SBC Source: Set_Configuration_Cfm");
}

static gboolean open_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: Open_Ind");
	else
		debug("SBC Source: Open_Ind");
	return TRUE;
}

static void open_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Open_Cfm");
	else
		debug("SBC Source: Open_Cfm");
}

static gboolean start_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: Start_Ind");
	else
		debug("SBC Source: Start_Ind");
	return TRUE;
}

static void start_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Start_Cfm");
	else
		debug("SBC Source: Start_Cfm");
}

static gboolean suspend_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: Suspend_Ind");
	else
		debug("SBC Source: Suspend_Ind");
	return TRUE;
}

static void suspend_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Suspend_Cfm");
	else
		debug("SBC Source: Suspend_Cfm");
}

static gboolean close_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: Close_Ind");
	else
		debug("SBC Source: Close_Ind");
	return TRUE;
}

static void close_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Close_Cfm");
	else
		debug("SBC Source: Close_Cfm");
}

static gboolean abort_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: Abort_Ind");
	else
		debug("SBC Source: Abort_Ind");
	return TRUE;
}

static void abort_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream)
{
	if (sep == sink_sep)
		debug("SBC Sink: Abort_Cfm");
	else
		debug("SBC Source: Abort_Cfm");
}

static gboolean reconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err)
{
	if (sep == sink_sep)
		debug("SBC Sink: ReConfigure_Ind");
	else
		debug("SBC Source: ReConfigure_Ind");
	return TRUE;
}

static void reconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep)
{
	if (sep == sink_sep)
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
		source_sep = avdtp_register_sep(AVDTP_SEP_TYPE_SOURCE,
						AVDTP_MEDIA_TYPE_AUDIO,
						&ind, &cfm);
		if (source_sep == NULL)
			return -1;

		if (a2dp_source_record(&buf) < 0) {
			error("Unable to allocate new service record");
			return -1;
		}

		source_record_id = add_service_record(conn, &buf);
		free(buf.data);
		if (!source_record_id) {
			error("Unable to register A2DP Source service record");
			return -1;
		}
	}

	if (enable_source) {
		sink_sep = avdtp_register_sep(AVDTP_SEP_TYPE_SINK,
						AVDTP_MEDIA_TYPE_AUDIO,
						&ind, &cfm);
		if (sink_sep == NULL)
			return -1;

		if (a2dp_sink_record(&buf) < 0) {
			error("Unable to allocate new service record");
			return -1;
		}

		sink_record_id = add_service_record(conn, &buf);
		free(buf.data);
		if (!sink_record_id) {
			error("Unable to register A2DP Sink service record");
			return -1;
		}
	}

	return 0;
}

void a2dp_exit()
{
	if (sink_sep)
		avdtp_unregister_sep(sink_sep);

	if (source_sep)
		avdtp_unregister_sep(source_sep);

	if (source_record_id) {
		remove_service_record(connection, source_record_id);
		source_record_id = 0;
	}

	if (sink_record_id) {
		remove_service_record(connection, sink_record_id);
		sink_record_id = 0;
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

	min_bitpool = MIN(default_bitpool(cap->frequency, cap->channel_mode),
				supported->min_bitpool);
	max_bitpool = MIN(default_bitpool(cap->frequency, cap->channel_mode),
				supported->max_bitpool);

	cap->min_bitpool = min_bitpool;
	cap->max_bitpool = max_bitpool;

	return TRUE;
}

gboolean a2dp_select_capabilities(struct avdtp_remote_sep *rsep, GSList **caps)
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

gboolean a2dp_get_config(struct avdtp_stream *stream,
				struct ipc_data_cfg **cfg, int *fd)
{
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap = NULL;
	struct sbc_codec_cap *sbc_cap;
	struct ipc_data_cfg *rsp;
	struct ipc_codec_sbc *sbc;
	GSList *caps;

	rsp = g_malloc0(sizeof(struct ipc_data_cfg) +
				sizeof(struct ipc_codec_sbc));
	*fd = -1;
	sbc = (void *) rsp->data;

	if (!avdtp_stream_get_transport(stream, fd, &rsp->pkt_len,
					&caps)) {
		g_free(rsp);
		return FALSE;
	}

	for (; caps; caps = g_slist_next(caps)) {
		cap = caps->data;
		if (cap->category == AVDTP_MEDIA_CODEC) {
			codec_cap = (void *) cap->data;
			break;
		}
	}

	if (codec_cap == NULL) {
		g_free(rsp);
		return FALSE;
	}

	rsp->fd_opt = CFG_FD_OPT_WRITE;

	*cfg = rsp;

	if (codec_cap->media_codec_type != A2DP_CODEC_SBC)
		return TRUE;

	sbc_cap = (struct sbc_codec_cap *) codec_cap;
	rsp->channels = sbc_cap->channel_mode ==
				A2DP_CHANNEL_MODE_MONO ? 1 : 2;
	rsp->channel_mode = sbc_cap->channel_mode;
	rsp->sample_size = 2;

	switch (sbc_cap->frequency) {
		case A2DP_SAMPLING_FREQ_16000:
			rsp->rate = 16000;
			break;
		case A2DP_SAMPLING_FREQ_32000:
			rsp->rate = 32000;
			break;
		case A2DP_SAMPLING_FREQ_44100:
			rsp->rate = 44100;
			break;
		case A2DP_SAMPLING_FREQ_48000:
			rsp->rate = 48000;
			break;
	}

	rsp->codec = CFG_CODEC_SBC;
	sbc->allocation = sbc_cap->allocation_method == A2DP_ALLOCATION_SNR ?
				0x01 : 0x00;
	sbc->subbands = sbc_cap->subbands == A2DP_SUBBANDS_4 ? 4 : 8;

	switch (sbc_cap->block_length) {
		case A2DP_BLOCK_LENGTH_4:
			sbc->blocks = 4;
			break;
		case A2DP_BLOCK_LENGTH_8:
			sbc->blocks = 8;
			break;
		case A2DP_BLOCK_LENGTH_12:
			sbc->blocks = 12;
			break;
		case A2DP_BLOCK_LENGTH_16:
			sbc->blocks = 16;
			break;
	}

	sbc->bitpool = sbc_cap->max_bitpool;

	return TRUE;
}
