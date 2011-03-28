/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>

#include <dbus/dbus.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "log.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "sink.h"
#include "source.h"
#include "unix.h"
#include "media.h"
#include "transport.h"
#include "a2dp.h"
#include "sdpd.h"

/* The duration that streams without users are allowed to stay in
 * STREAMING state. */
#define SUSPEND_TIMEOUT 5
#define RECONFIGURE_TIMEOUT 500

#ifndef MIN
# define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

struct a2dp_sep {
	struct a2dp_server *server;
	struct media_endpoint *endpoint;
	uint8_t type;
	uint8_t codec;
	struct avdtp_local_sep *lsep;
	struct avdtp *session;
	struct avdtp_stream *stream;
	guint suspend_timer;
	gboolean delay_reporting;
	gboolean locked;
	gboolean suspending;
	gboolean starting;
};

struct a2dp_setup_cb {
	struct a2dp_setup *setup;
	a2dp_select_cb_t select_cb;
	a2dp_config_cb_t config_cb;
	a2dp_stream_cb_t resume_cb;
	a2dp_stream_cb_t suspend_cb;
	void *user_data;
	unsigned int id;
};

struct a2dp_setup {
	struct audio_device *dev;
	struct avdtp *session;
	struct a2dp_sep *sep;
	struct avdtp_remote_sep *rsep;
	struct avdtp_stream *stream;
	struct avdtp_error *err;
	avdtp_set_configuration_cb setconf_cb;
	GSList *caps;
	gboolean reconfigure;
	gboolean start;
	GSList *cb;
	int ref;
};

static DBusConnection *connection = NULL;

struct a2dp_server {
	bdaddr_t src;
	GSList *sinks;
	GSList *sources;
	uint32_t source_record_id;
	uint32_t sink_record_id;
	uint16_t version;
	gboolean sink_enabled;
	gboolean source_enabled;
};

static GSList *servers = NULL;
static GSList *setups = NULL;
static unsigned int cb_id = 0;

static struct a2dp_setup *setup_ref(struct a2dp_setup *setup)
{
	setup->ref++;

	DBG("%p: ref=%d", setup, setup->ref);

	return setup;
}

static struct audio_device *a2dp_get_dev(struct avdtp *session)
{
	bdaddr_t src, dst;

	avdtp_get_peers(session, &src, &dst);

	return manager_find_device(NULL, &src, &dst, NULL, FALSE);
}

static struct a2dp_setup *setup_new(struct avdtp *session)
{
	struct audio_device *dev;
	struct a2dp_setup *setup;

	dev = a2dp_get_dev(session);
	if (!dev) {
		error("Unable to create setup");
		return NULL;
	}

	setup = g_new0(struct a2dp_setup, 1);
	setup->session = avdtp_ref(session);
	setup->dev = a2dp_get_dev(session);
	setups = g_slist_append(setups, setup);

	return setup;
}

static void setup_free(struct a2dp_setup *s)
{
	DBG("%p", s);

	setups = g_slist_remove(setups, s);
	if (s->session)
		avdtp_unref(s->session);
	g_slist_foreach(s->cb, (GFunc) g_free, NULL);
	g_slist_free(s->cb);
	g_slist_foreach(s->caps, (GFunc) g_free, NULL);
	g_slist_free(s->caps);
	g_free(s);
}

static void setup_unref(struct a2dp_setup *setup)
{
	setup->ref--;

	DBG("%p: ref=%d", setup, setup->ref);

	if (setup->ref > 0)
		return;

	setup_free(setup);
}

static struct a2dp_setup_cb *setup_cb_new(struct a2dp_setup *setup)
{
	struct a2dp_setup_cb *cb;

	cb = g_new0(struct a2dp_setup_cb, 1);
	cb->setup = setup;
	cb->id = ++cb_id;

	setup->cb = g_slist_append(setup->cb, cb);
	return cb;
}

static void setup_cb_free(struct a2dp_setup_cb *cb)
{
	struct a2dp_setup *setup = cb->setup;

	setup->cb = g_slist_remove(setup->cb, cb);
	setup_unref(cb->setup);
	g_free(cb);
}

static gboolean finalize_config(struct a2dp_setup *s)
{
	GSList *l;
	struct avdtp_stream *stream = s->err ? NULL : s->stream;

	for (l = s->cb; l != NULL; ) {
		struct a2dp_setup_cb *cb = l->data;

		l = l->next;

		if (!cb->config_cb)
			continue;

		cb->config_cb(s->session, s->sep, stream, s->err,
							cb->user_data);
		setup_cb_free(cb);
	}

	return FALSE;
}

static gboolean finalize_config_errno(struct a2dp_setup *s, int err)
{
	struct avdtp_error avdtp_err;

	avdtp_error_init(&avdtp_err, AVDTP_ERRNO, -err);
	s->err = err ? &avdtp_err : NULL;

	return finalize_config(s);
}

static gboolean finalize_resume(struct a2dp_setup *s)
{
	GSList *l;

	for (l = s->cb; l != NULL; ) {
		struct a2dp_setup_cb *cb = l->data;

		l = l->next;

		if (!cb->resume_cb)
			continue;

		cb->resume_cb(s->session, s->err, cb->user_data);
		setup_cb_free(cb);
	}

	return FALSE;
}

static gboolean finalize_resume_errno(struct a2dp_setup *s, int err)
{
	struct avdtp_error avdtp_err;

	avdtp_error_init(&avdtp_err, AVDTP_ERRNO, -err);
	s->err = err ? &avdtp_err : NULL;

	return finalize_resume(s);
}

static gboolean finalize_suspend(struct a2dp_setup *s)
{
	GSList *l;

	for (l = s->cb; l != NULL; ) {
		struct a2dp_setup_cb *cb = l->data;

		l = l->next;

		if (!cb->suspend_cb)
			continue;

		cb->suspend_cb(s->session, s->err, cb->user_data);
		setup_cb_free(cb);
	}

	return FALSE;
}

static gboolean finalize_suspend_errno(struct a2dp_setup *s, int err)
{
	struct avdtp_error avdtp_err;

	avdtp_error_init(&avdtp_err, AVDTP_ERRNO, -err);
	s->err = err ? &avdtp_err : NULL;

	return finalize_suspend(s);
}

static gboolean finalize_select(struct a2dp_setup *s)
{
	GSList *l;

	for (l = s->cb; l != NULL; ) {
		struct a2dp_setup_cb *cb = l->data;

		l = l->next;

		if (!cb->select_cb)
			continue;

		cb->select_cb(s->session, s->sep, s->caps, cb->user_data);
		setup_cb_free(cb);
	}

	return FALSE;
}

static struct a2dp_setup *find_setup_by_session(struct avdtp *session)
{
	GSList *l;

	for (l = setups; l != NULL; l = l->next) {
		struct a2dp_setup *setup = l->data;

		if (setup->session == session)
			return setup;
	}

	return NULL;
}

static struct a2dp_setup *a2dp_setup_get(struct avdtp *session)
{
	struct a2dp_setup *setup;

	setup = find_setup_by_session(session);
	if (!setup) {
		setup = setup_new(session);
		if (!setup)
			return NULL;
	}

	return setup_ref(setup);
}

static struct a2dp_setup *find_setup_by_dev(struct audio_device *dev)
{
	GSList *l;

	for (l = setups; l != NULL; l = l->next) {
		struct a2dp_setup *setup = l->data;

		if (setup->dev == dev)
			return setup;
	}

	return NULL;
}

static void stream_state_changed(struct avdtp_stream *stream,
					avdtp_state_t old_state,
					avdtp_state_t new_state,
					struct avdtp_error *err,
					void *user_data)
{
	struct a2dp_sep *sep = user_data;

	if (new_state != AVDTP_STATE_IDLE)
		return;

	if (sep->suspend_timer) {
		g_source_remove(sep->suspend_timer);
		sep->suspend_timer = 0;
	}

	if (sep->session) {
		avdtp_unref(sep->session);
		sep->session = NULL;
	}

	if (sep->endpoint)
		media_endpoint_clear_configuration(sep->endpoint);

	sep->stream = NULL;

}

static gboolean auto_config(gpointer data)
{
	struct a2dp_setup *setup = data;
	struct avdtp_error *err = NULL;

	/* Check if configuration was aborted */
	if (setup->sep->stream == NULL)
		return FALSE;

	if (setup->err != NULL) {
		err = setup->err;
		goto done;
	}

	avdtp_stream_add_cb(setup->session, setup->stream,
				stream_state_changed, setup->sep);

	if (setup->sep->type == AVDTP_SEP_TYPE_SOURCE)
		sink_new_stream(setup->dev, setup->session, setup->stream);
	else
		source_new_stream(setup->dev, setup->session, setup->stream);

done:
	if (setup->setconf_cb)
		setup->setconf_cb(setup->session, setup->stream, setup->err);

	finalize_config(setup);

	if (err)
		g_free(err);

	setup_unref(setup);

	return FALSE;
}

static gboolean sbc_setconf_ind(struct avdtp *session,
					struct avdtp_local_sep *sep,
					struct avdtp_stream *stream,
					GSList *caps,
					avdtp_set_configuration_cb cb,
					void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Set_Configuration_Ind", sep);
	else
		DBG("Source %p: Set_Configuration_Ind", sep);

	setup = a2dp_setup_get(session);
	if (!setup)
		return FALSE;

	a2dp_sep->stream = stream;
	setup->sep = a2dp_sep;
	setup->stream = stream;
	setup->setconf_cb = cb;

	/* Check valid settings */
	for (; caps != NULL; caps = g_slist_next(caps)) {
		struct avdtp_service_capability *cap = caps->data;
		struct avdtp_media_codec_capability *codec_cap;
		struct sbc_codec_cap *sbc_cap;

		if (cap->category == AVDTP_DELAY_REPORTING &&
					!a2dp_sep->delay_reporting) {
			setup->err = g_new(struct avdtp_error, 1);
			avdtp_error_init(setup->err, AVDTP_DELAY_REPORTING,
						AVDTP_UNSUPPORTED_CONFIGURATION);
			goto done;
		}

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		if (cap->length < sizeof(struct sbc_codec_cap))
			continue;

		codec_cap = (void *) cap->data;

		if (codec_cap->media_codec_type != A2DP_CODEC_SBC)
			continue;

		sbc_cap = (void *) codec_cap;

		if (sbc_cap->min_bitpool < MIN_BITPOOL ||
					sbc_cap->max_bitpool > MAX_BITPOOL) {
			setup->err = g_new(struct avdtp_error, 1);
			avdtp_error_init(setup->err, AVDTP_MEDIA_CODEC,
					AVDTP_UNSUPPORTED_CONFIGURATION);
			goto done;
		}
	}

done:
	g_idle_add(auto_config, setup);
	return TRUE;
}

static gboolean sbc_getcap_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				gboolean get_all, GSList **caps, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Get_Capability_Ind", sep);
	else
		DBG("Source %p: Get_Capability_Ind", sep);

	*caps = NULL;

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	*caps = g_slist_append(*caps, media_transport);

	memset(&sbc_cap, 0, sizeof(struct sbc_codec_cap));

	sbc_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
	sbc_cap.cap.media_codec_type = A2DP_CODEC_SBC;

	sbc_cap.frequency = ( SBC_SAMPLING_FREQ_48000 |
				SBC_SAMPLING_FREQ_44100 |
				SBC_SAMPLING_FREQ_32000 |
				SBC_SAMPLING_FREQ_16000 );

	sbc_cap.channel_mode = ( SBC_CHANNEL_MODE_JOINT_STEREO |
					SBC_CHANNEL_MODE_STEREO |
					SBC_CHANNEL_MODE_DUAL_CHANNEL |
					SBC_CHANNEL_MODE_MONO );

	sbc_cap.block_length = ( SBC_BLOCK_LENGTH_16 |
					SBC_BLOCK_LENGTH_12 |
					SBC_BLOCK_LENGTH_8 |
					SBC_BLOCK_LENGTH_4 );

	sbc_cap.subbands = ( SBC_SUBBANDS_8 | SBC_SUBBANDS_4 );

	sbc_cap.allocation_method = ( SBC_ALLOCATION_LOUDNESS |
					SBC_ALLOCATION_SNR );

	sbc_cap.min_bitpool = MIN_BITPOOL;
	sbc_cap.max_bitpool = MAX_BITPOOL;

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &sbc_cap,
						sizeof(sbc_cap));

	*caps = g_slist_append(*caps, media_codec);

	if (get_all) {
		struct avdtp_service_capability *delay_reporting;
		delay_reporting = avdtp_service_cap_new(AVDTP_DELAY_REPORTING,
								NULL, 0);
		*caps = g_slist_append(*caps, delay_reporting);
	}

	return TRUE;
}

static gboolean mpeg_setconf_ind(struct avdtp *session,
					struct avdtp_local_sep *sep,
					struct avdtp_stream *stream,
					GSList *caps,
					avdtp_set_configuration_cb cb,
					void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Set_Configuration_Ind", sep);
	else
		DBG("Source %p: Set_Configuration_Ind", sep);

	setup = a2dp_setup_get(session);
	if (!setup)
		return FALSE;

	a2dp_sep->stream = stream;
	setup->sep = a2dp_sep;
	setup->stream = stream;
	setup->setconf_cb = cb;

	for (; caps != NULL; caps = g_slist_next(caps)) {
		struct avdtp_service_capability *cap = caps->data;

		if (cap->category == AVDTP_DELAY_REPORTING &&
					!a2dp_sep->delay_reporting) {
			setup->err = g_new(struct avdtp_error, 1);
			avdtp_error_init(setup->err, AVDTP_DELAY_REPORTING,
					AVDTP_UNSUPPORTED_CONFIGURATION);
			goto done;
		}
	}

done:
	g_idle_add(auto_config, setup);
	return TRUE;
}

static gboolean mpeg_getcap_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				gboolean get_all,
				GSList **caps, uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct avdtp_service_capability *media_transport, *media_codec;
	struct mpeg_codec_cap mpeg_cap;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Get_Capability_Ind", sep);
	else
		DBG("Source %p: Get_Capability_Ind", sep);

	*caps = NULL;

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	*caps = g_slist_append(*caps, media_transport);

	memset(&mpeg_cap, 0, sizeof(struct mpeg_codec_cap));

	mpeg_cap.cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
	mpeg_cap.cap.media_codec_type = A2DP_CODEC_MPEG12;

	mpeg_cap.frequency = ( MPEG_SAMPLING_FREQ_48000 |
				MPEG_SAMPLING_FREQ_44100 |
				MPEG_SAMPLING_FREQ_32000 |
				MPEG_SAMPLING_FREQ_24000 |
				MPEG_SAMPLING_FREQ_22050 |
				MPEG_SAMPLING_FREQ_16000 );

	mpeg_cap.channel_mode = ( MPEG_CHANNEL_MODE_JOINT_STEREO |
					MPEG_CHANNEL_MODE_STEREO |
					MPEG_CHANNEL_MODE_DUAL_CHANNEL |
					MPEG_CHANNEL_MODE_MONO );

	mpeg_cap.layer = ( MPEG_LAYER_MP3 | MPEG_LAYER_MP2 | MPEG_LAYER_MP1 );

	mpeg_cap.bitrate = 0xFFFF;

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &mpeg_cap,
						sizeof(mpeg_cap));

	*caps = g_slist_append(*caps, media_codec);

	if (get_all) {
		struct avdtp_service_capability *delay_reporting;
		delay_reporting = avdtp_service_cap_new(AVDTP_DELAY_REPORTING,
								NULL, 0);
		*caps = g_slist_append(*caps, delay_reporting);
	}

	return TRUE;
}

static void endpoint_setconf_cb(struct media_endpoint *endpoint, void *ret,
						int size, void *user_data)
{
	struct a2dp_setup *setup = user_data;

	if (ret == NULL) {
		setup->err = g_new(struct avdtp_error, 1);
		avdtp_error_init(setup->err, AVDTP_MEDIA_CODEC,
					AVDTP_UNSUPPORTED_CONFIGURATION);
	}

	auto_config(setup);
}

static gboolean endpoint_setconf_ind(struct avdtp *session,
						struct avdtp_local_sep *sep,
						struct avdtp_stream *stream,
						GSList *caps,
						avdtp_set_configuration_cb cb,
						void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Set_Configuration_Ind", sep);
	else
		DBG("Source %p: Set_Configuration_Ind", sep);

	setup = a2dp_setup_get(session);
	if (!session)
		return FALSE;

	a2dp_sep->stream = stream;
	setup->sep = a2dp_sep;
	setup->stream = stream;
	setup->setconf_cb = cb;

	for (; caps != NULL; caps = g_slist_next(caps)) {
		struct avdtp_service_capability *cap = caps->data;
		struct avdtp_media_codec_capability *codec;
		gboolean ret;

		if (cap->category == AVDTP_DELAY_REPORTING &&
					!a2dp_sep->delay_reporting) {
			setup->err = g_new(struct avdtp_error, 1);
			avdtp_error_init(setup->err, AVDTP_DELAY_REPORTING,
					AVDTP_UNSUPPORTED_CONFIGURATION);
			goto done;
		}

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		codec = (struct avdtp_media_codec_capability *) cap->data;

		if (codec->media_codec_type != a2dp_sep->codec) {
			setup->err = g_new(struct avdtp_error, 1);
			avdtp_error_init(setup->err, AVDTP_MEDIA_CODEC,
					AVDTP_UNSUPPORTED_CONFIGURATION);
			goto done;
		}

		ret = media_endpoint_set_configuration(a2dp_sep->endpoint,
						setup->dev, codec->data,
						cap->length - sizeof(*codec),
						endpoint_setconf_cb, setup);
		if (ret)
			return TRUE;

		avdtp_error_init(setup->err, AVDTP_MEDIA_CODEC,
					AVDTP_UNSUPPORTED_CONFIGURATION);
		break;
	}

done:
	g_idle_add(auto_config, setup);
	return TRUE;
}

static gboolean endpoint_getcap_ind(struct avdtp *session,
					struct avdtp_local_sep *sep,
					gboolean get_all, GSList **caps,
					uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct avdtp_service_capability *media_transport, *media_codec;
	struct avdtp_media_codec_capability *codec_caps;
	uint8_t *capabilities;
	size_t length;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Get_Capability_Ind", sep);
	else
		DBG("Source %p: Get_Capability_Ind", sep);

	*caps = NULL;

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	*caps = g_slist_append(*caps, media_transport);

	length = media_endpoint_get_capabilities(a2dp_sep->endpoint,
						&capabilities);

	codec_caps = g_malloc0(sizeof(*codec_caps) + length);
	codec_caps->media_type = AVDTP_MEDIA_TYPE_AUDIO;
	codec_caps->media_codec_type = a2dp_sep->codec;
	memcpy(codec_caps->data, capabilities, length);

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, codec_caps,
						sizeof(*codec_caps) + length);

	*caps = g_slist_append(*caps, media_codec);
	g_free(codec_caps);

	if (get_all) {
		struct avdtp_service_capability *delay_reporting;
		delay_reporting = avdtp_service_cap_new(AVDTP_DELAY_REPORTING,
								NULL, 0);
		*caps = g_slist_append(*caps, delay_reporting);
	}

	return TRUE;
}

static void endpoint_open_cb(struct media_endpoint *endpoint, void *ret,
						int size, void *user_data)
{
	struct a2dp_setup *setup = user_data;
	int err;

	if (ret == NULL) {
		setup->stream = NULL;
		finalize_config_errno(setup, -EPERM);
		return;
	}

	err = avdtp_open(setup->session, setup->stream);
	if (err == 0)
		return;

	error("Error on avdtp_open %s (%d)", strerror(-err), -err);
	setup->stream = NULL;
	finalize_config_errno(setup, err);
}

static void setconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				struct avdtp_error *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;
	struct audio_device *dev;
	int ret;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Set_Configuration_Cfm", sep);
	else
		DBG("Source %p: Set_Configuration_Cfm", sep);

	setup = find_setup_by_session(session);

	if (err) {
		if (setup) {
			setup->err = err;
			finalize_config(setup);
		}
		return;
	}

	avdtp_stream_add_cb(session, stream, stream_state_changed, a2dp_sep);
	a2dp_sep->stream = stream;

	if (!setup)
		return;

	dev = a2dp_get_dev(session);

	/* Notify D-Bus interface of the new stream */
	if (a2dp_sep->type == AVDTP_SEP_TYPE_SOURCE)
		sink_new_stream(dev, session, setup->stream);
	else
		source_new_stream(dev, session, setup->stream);

	/* Notify Endpoint */
	if (a2dp_sep->endpoint) {
		struct avdtp_service_capability *service;
		struct avdtp_media_codec_capability *codec;

		service = avdtp_stream_get_codec(stream);
		codec = (struct avdtp_media_codec_capability *) service->data;

		if (media_endpoint_set_configuration(a2dp_sep->endpoint, dev,
						codec->data, service->length -
						sizeof(*codec),
						endpoint_open_cb, setup) ==
						TRUE)
			return;

		setup->stream = NULL;
		finalize_config_errno(setup, -EPERM);
		return;
	}

	ret = avdtp_open(session, stream);
	if (ret < 0) {
		error("Error on avdtp_open %s (%d)", strerror(-ret), -ret);
		setup->stream = NULL;
		finalize_config_errno(setup, ret);
	}
}

static gboolean getconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Get_Configuration_Ind", sep);
	else
		DBG("Source %p: Get_Configuration_Ind", sep);
	return TRUE;
}

static void getconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Set_Configuration_Cfm", sep);
	else
		DBG("Source %p: Set_Configuration_Cfm", sep);
}

static gboolean open_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Open_Ind", sep);
	else
		DBG("Source %p: Open_Ind", sep);
	return TRUE;
}

static void open_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Open_Cfm", sep);
	else
		DBG("Source %p: Open_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (setup->reconfigure)
		setup->reconfigure = FALSE;

	if (err) {
		setup->stream = NULL;
		setup->err = err;
	}

	finalize_config(setup);
}

static gboolean suspend_timeout(struct a2dp_sep *sep)
{
	if (avdtp_suspend(sep->session, sep->stream) == 0)
		sep->suspending = TRUE;

	sep->suspend_timer = 0;

	avdtp_unref(sep->session);
	sep->session = NULL;

	return FALSE;
}

static gboolean start_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Start_Ind", sep);
	else
		DBG("Source %p: Start_Ind", sep);

	setup = find_setup_by_session(session);
	if (setup)
		finalize_resume(setup);

	if (!a2dp_sep->locked) {
		a2dp_sep->session = avdtp_ref(session);
		a2dp_sep->suspend_timer = g_timeout_add_seconds(SUSPEND_TIMEOUT,
						(GSourceFunc) suspend_timeout,
						a2dp_sep);
	}

	return TRUE;
}

static void start_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Start_Cfm", sep);
	else
		DBG("Source %p: Start_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (err) {
		setup->stream = NULL;
		setup->err = err;
	}

	finalize_resume(setup);
}

static gboolean suspend_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Suspend_Ind", sep);
	else
		DBG("Source %p: Suspend_Ind", sep);

	if (a2dp_sep->suspend_timer) {
		g_source_remove(a2dp_sep->suspend_timer);
		a2dp_sep->suspend_timer = 0;
		avdtp_unref(a2dp_sep->session);
		a2dp_sep->session = NULL;
	}

	return TRUE;
}

static void suspend_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;
	gboolean start;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Suspend_Cfm", sep);
	else
		DBG("Source %p: Suspend_Cfm", sep);

	a2dp_sep->suspending = FALSE;

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	start = setup->start;
	setup->start = FALSE;

	if (err) {
		setup->stream = NULL;
		setup->err = err;
		finalize_suspend(setup);
	}
	else
		finalize_suspend_errno(setup, 0);

	if (!start)
		return;

	if (err) {
		setup->err = err;
		finalize_suspend(setup);
	} else if (avdtp_start(session, a2dp_sep->stream) < 0) {
		struct avdtp_error start_err;
		error("avdtp_start failed");
		avdtp_error_init(&start_err, AVDTP_ERRNO, EIO);
		setup->err = err;
		finalize_suspend(setup);
	}
}

static gboolean close_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Close_Ind", sep);
	else
		DBG("Source %p: Close_Ind", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return TRUE;

	finalize_suspend_errno(setup, -ECONNRESET);
	finalize_resume_errno(setup, -ECONNRESET);

	return TRUE;
}

static gboolean a2dp_reconfigure(gpointer data)
{
	struct a2dp_setup *setup = data;
	struct a2dp_sep *sep = setup->sep;
	int posix_err;
	struct avdtp_media_codec_capability *rsep_codec;
	struct avdtp_service_capability *cap;

	if (setup->rsep) {
		cap = avdtp_get_codec(setup->rsep);
		rsep_codec = (struct avdtp_media_codec_capability *) cap->data;
	}

	if (!setup->rsep || sep->codec != rsep_codec->media_codec_type)
		setup->rsep = avdtp_find_remote_sep(setup->session, sep->lsep);

	posix_err = avdtp_set_configuration(setup->session, setup->rsep,
						sep->lsep,
						setup->caps,
						&setup->stream);
	if (posix_err < 0) {
		error("avdtp_set_configuration: %s", strerror(-posix_err));
		goto failed;
	}

	return FALSE;

failed:
	finalize_config_errno(setup, posix_err);
	return FALSE;
}

static void close_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Close_Cfm", sep);
	else
		DBG("Source %p: Close_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (err) {
		setup->stream = NULL;
		setup->err = err;
		finalize_config(setup);
		return;
	}

	if (!setup->rsep)
		setup->rsep = avdtp_stream_get_remote_sep(stream);

	if (setup->reconfigure)
		g_timeout_add(RECONFIGURE_TIMEOUT, a2dp_reconfigure, setup);
}

static gboolean abort_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Abort_Ind", sep);
	else
		DBG("Source %p: Abort_Ind", sep);

	a2dp_sep->stream = NULL;

	return TRUE;
}

static void abort_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: Abort_Cfm", sep);
	else
		DBG("Source %p: Abort_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	setup_unref(setup);
}

static gboolean reconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: ReConfigure_Ind", sep);
	else
		DBG("Source %p: ReConfigure_Ind", sep);

	return TRUE;
}

static gboolean delayreport_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				uint8_t rseid, uint16_t delay,
				uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct audio_device *dev = a2dp_get_dev(session);

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: DelayReport_Ind", sep);
	else
		DBG("Source %p: DelayReport_Ind", sep);

	unix_delay_report(dev, rseid, delay);

	return TRUE;
}

static gboolean endpoint_delayreport_ind(struct avdtp *session,
						struct avdtp_local_sep *sep,
						uint8_t rseid, uint16_t delay,
						uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct media_transport *transport;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: DelayReport_Ind", sep);
	else
		DBG("Source %p: DelayReport_Ind", sep);

	transport = media_endpoint_get_transport(a2dp_sep->endpoint);
	if (transport == NULL)
		return FALSE;

	media_transport_update_delay(transport, delay);

	return TRUE;
}

static void reconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: ReConfigure_Cfm", sep);
	else
		DBG("Source %p: ReConfigure_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (err) {
		setup->stream = NULL;
		setup->err = err;
	}

	finalize_config(setup);
}

static void delay_report_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				struct avdtp_error *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		DBG("Sink %p: DelayReport_Cfm", sep);
	else
		DBG("Source %p: DelayReport_Cfm", sep);
}

static struct avdtp_sep_cfm cfm = {
	.set_configuration	= setconf_cfm,
	.get_configuration	= getconf_cfm,
	.open			= open_cfm,
	.start			= start_cfm,
	.suspend		= suspend_cfm,
	.close			= close_cfm,
	.abort			= abort_cfm,
	.reconfigure		= reconf_cfm,
	.delay_report		= delay_report_cfm,
};

static struct avdtp_sep_ind sbc_ind = {
	.get_capability		= sbc_getcap_ind,
	.set_configuration	= sbc_setconf_ind,
	.get_configuration	= getconf_ind,
	.open			= open_ind,
	.start			= start_ind,
	.suspend		= suspend_ind,
	.close			= close_ind,
	.abort			= abort_ind,
	.reconfigure		= reconf_ind,
	.delayreport		= delayreport_ind,
};

static struct avdtp_sep_ind mpeg_ind = {
	.get_capability		= mpeg_getcap_ind,
	.set_configuration	= mpeg_setconf_ind,
	.get_configuration	= getconf_ind,
	.open			= open_ind,
	.start			= start_ind,
	.suspend		= suspend_ind,
	.close			= close_ind,
	.abort			= abort_ind,
	.reconfigure		= reconf_ind,
	.delayreport		= delayreport_ind,
};

static struct avdtp_sep_ind endpoint_ind = {
	.get_capability		= endpoint_getcap_ind,
	.set_configuration	= endpoint_setconf_ind,
	.get_configuration	= getconf_ind,
	.open			= open_ind,
	.start			= start_ind,
	.suspend		= suspend_ind,
	.close			= close_ind,
	.abort			= abort_ind,
	.reconfigure		= reconf_ind,
	.delayreport		= endpoint_delayreport_ind,
};

static sdp_record_t *a2dp_record(uint8_t type, uint16_t avdtp_ver)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap_uuid, avdtp_uuid, a2dp_uuid;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVDTP_UUID;
	uint16_t a2dp_ver = 0x0102, feat = 0x000f;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	if (type == AVDTP_SEP_TYPE_SOURCE)
		sdp_uuid16_create(&a2dp_uuid, AUDIO_SOURCE_SVCLASS_ID);
	else
		sdp_uuid16_create(&a2dp_uuid, AUDIO_SINK_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &a2dp_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, ADVANCED_AUDIO_PROFILE_ID);
	profile[0].version = a2dp_ver;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&avdtp_uuid, AVDTP_UUID);
	proto[1] = sdp_list_append(0, &avdtp_uuid);
	version = sdp_data_alloc(SDP_UINT16, &avdtp_ver);
	proto[1] = sdp_list_append(proto[1], version);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	if (type == AVDTP_SEP_TYPE_SOURCE)
		sdp_set_info_attr(record, "Audio Source", 0, 0);
	else
		sdp_set_info_attr(record, "Audio Sink", 0, 0);

	free(psm);
	free(version);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

static struct a2dp_server *find_server(GSList *list, const bdaddr_t *src)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct a2dp_server *server = l->data;

		if (bacmp(&server->src, src) == 0)
			return server;
	}

	return NULL;
}

int a2dp_register(DBusConnection *conn, const bdaddr_t *src, GKeyFile *config)
{
	int sbc_srcs = 1, sbc_sinks = 1;
	int mpeg12_srcs = 0, mpeg12_sinks = 0;
	gboolean source = TRUE, sink = FALSE, socket = TRUE;
	gboolean delay_reporting = FALSE;
	char *str;
	GError *err = NULL;
	int i;
	struct a2dp_server *server;

	if (!config)
		goto proceed;

	str = g_key_file_get_string(config, "General", "Enable", &err);

	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		if (strstr(str, "Sink"))
			source = TRUE;
		if (strstr(str, "Source"))
			sink = TRUE;
		g_free(str);
	}

	str = g_key_file_get_string(config, "General", "Disable", &err);

	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		if (strstr(str, "Sink"))
			source = FALSE;
		if (strstr(str, "Source"))
			sink = FALSE;
		if (strstr(str, "Socket"))
			socket = FALSE;
		g_free(str);
	}

	/* Don't register any local sep if Socket is disabled */
	if (socket == FALSE) {
		sbc_srcs = 0;
		sbc_sinks = 0;
		mpeg12_srcs = 0;
		mpeg12_sinks = 0;
		goto proceed;
	}

	str = g_key_file_get_string(config, "A2DP", "SBCSources", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		sbc_srcs = atoi(str);
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "MPEG12Sources", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		mpeg12_srcs = atoi(str);
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "SBCSinks", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		sbc_sinks = atoi(str);
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "MPEG12Sinks", &err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		mpeg12_sinks = atoi(str);
		g_free(str);
	}

proceed:
	if (!connection)
		connection = dbus_connection_ref(conn);

	server = find_server(servers, src);
	if (!server) {
		int av_err;

		server = g_new0(struct a2dp_server, 1);
		if (!server)
			return -ENOMEM;

		av_err = avdtp_init(src, config, &server->version);
		if (av_err < 0) {
			g_free(server);
			return av_err;
		}

		bacpy(&server->src, src);
		servers = g_slist_append(servers, server);
	}

	if (config)
		delay_reporting = g_key_file_get_boolean(config, "A2DP",
						"DelayReporting", NULL);

	if (delay_reporting)
		server->version = 0x0103;
	else
		server->version = 0x0102;

	server->source_enabled = source;
	if (source) {
		for (i = 0; i < sbc_srcs; i++)
			a2dp_add_sep(src, AVDTP_SEP_TYPE_SOURCE,
				A2DP_CODEC_SBC, delay_reporting, NULL, NULL);

		for (i = 0; i < mpeg12_srcs; i++)
			a2dp_add_sep(src, AVDTP_SEP_TYPE_SOURCE,
					A2DP_CODEC_MPEG12, delay_reporting,
					NULL, NULL);
	}
	server->sink_enabled = sink;
	if (sink) {
		for (i = 0; i < sbc_sinks; i++)
			a2dp_add_sep(src, AVDTP_SEP_TYPE_SINK,
				A2DP_CODEC_SBC, delay_reporting, NULL, NULL);

		for (i = 0; i < mpeg12_sinks; i++)
			a2dp_add_sep(src, AVDTP_SEP_TYPE_SINK,
					A2DP_CODEC_MPEG12, delay_reporting,
					NULL, NULL);
	}

	return 0;
}

static void a2dp_unregister_sep(struct a2dp_sep *sep)
{
	if (sep->endpoint) {
		media_endpoint_release(sep->endpoint);
		sep->endpoint = NULL;
	}

	avdtp_unregister_sep(sep->lsep);
	g_free(sep);
}

void a2dp_unregister(const bdaddr_t *src)
{
	struct a2dp_server *server;

	server = find_server(servers, src);
	if (!server)
		return;

	g_slist_foreach(server->sinks, (GFunc) a2dp_remove_sep, NULL);
	g_slist_free(server->sinks);

	g_slist_foreach(server->sources, (GFunc) a2dp_remove_sep, NULL);
	g_slist_free(server->sources);

	avdtp_exit(src);

	servers = g_slist_remove(servers, server);
	g_free(server);

	if (servers)
		return;

	dbus_connection_unref(connection);
	connection = NULL;
}

struct a2dp_sep *a2dp_add_sep(const bdaddr_t *src, uint8_t type,
				uint8_t codec, gboolean delay_reporting,
				struct media_endpoint *endpoint, int *err)
{
	struct a2dp_server *server;
	struct a2dp_sep *sep;
	GSList **l;
	uint32_t *record_id;
	sdp_record_t *record;
	struct avdtp_sep_ind *ind;

	server = find_server(servers, src);
	if (server == NULL) {
		if (err)
			*err = -EINVAL;
		return NULL;
	}

	if (type == AVDTP_SEP_TYPE_SINK && !server->sink_enabled) {
		if (err)
			*err = -EPROTONOSUPPORT;
		return NULL;
	}

	if (type == AVDTP_SEP_TYPE_SOURCE && !server->source_enabled) {
		if (err)
			*err = -EPROTONOSUPPORT;
		return NULL;
	}

	sep = g_new0(struct a2dp_sep, 1);

	if (endpoint) {
		ind = &endpoint_ind;
		goto proceed;
	}

	ind = (codec == A2DP_CODEC_MPEG12) ? &mpeg_ind : &sbc_ind;

proceed:
	sep->lsep = avdtp_register_sep(&server->src, type,
					AVDTP_MEDIA_TYPE_AUDIO, codec,
					delay_reporting, ind, &cfm, sep);
	if (sep->lsep == NULL) {
		g_free(sep);
		if (err)
			*err = -EINVAL;
		return NULL;
	}

	sep->server = server;
	sep->endpoint = endpoint;
	sep->codec = codec;
	sep->type = type;
	sep->delay_reporting = delay_reporting;

	if (type == AVDTP_SEP_TYPE_SOURCE) {
		l = &server->sources;
		record_id = &server->source_record_id;
	} else {
		l = &server->sinks;
		record_id = &server->sink_record_id;
	}

	if (*record_id != 0)
		goto add;

	record = a2dp_record(type, server->version);
	if (!record) {
		error("Unable to allocate new service record");
		avdtp_unregister_sep(sep->lsep);
		g_free(sep);
		if (err)
			*err = -EINVAL;
		return NULL;
	}

	if (add_record_to_server(&server->src, record) < 0) {
		error("Unable to register A2DP service record");\
		sdp_record_free(record);
		avdtp_unregister_sep(sep->lsep);
		g_free(sep);
		if (err)
			*err = -EINVAL;
		return NULL;
	}
	*record_id = record->handle;

add:
	*l = g_slist_append(*l, sep);

	if (err)
		*err = 0;
	return sep;
}

void a2dp_remove_sep(struct a2dp_sep *sep)
{
	struct a2dp_server *server = sep->server;

	if (sep->type == AVDTP_SEP_TYPE_SOURCE) {
		if (g_slist_find(server->sources, sep) == NULL)
			return;
		server->sources = g_slist_remove(server->sources, sep);
		if (server->sources == NULL && server->source_record_id) {
			remove_record_from_server(server->source_record_id);
			server->source_record_id = 0;
		}
	} else {
		if (g_slist_find(server->sinks, sep) == NULL)
			return;
		server->sinks = g_slist_remove(server->sinks, sep);
		if (server->sinks == NULL && server->sink_record_id) {
			remove_record_from_server(server->sink_record_id);
			server->sink_record_id = 0;
		}
	}

	a2dp_unregister_sep(sep);
}

struct a2dp_sep *a2dp_get(struct avdtp *session,
				struct avdtp_remote_sep *rsep)
{
	GSList *l;
	struct a2dp_server *server;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap = NULL;
	bdaddr_t src;

	avdtp_get_peers(session, &src, NULL);
	server = find_server(servers, &src);
	if (!server)
		return NULL;

	cap = avdtp_get_codec(rsep);
	codec_cap = (void *) cap->data;

	if (avdtp_get_type(rsep) == AVDTP_SEP_TYPE_SINK)
		l = server->sources;
	else
		l = server->sinks;

	for (; l != NULL; l = l->next) {
		struct a2dp_sep *sep = l->data;

		if (sep->locked)
			continue;

		if (sep->codec != codec_cap->media_codec_type)
			continue;

		if (!sep->stream || avdtp_has_stream(session, sep->stream))
			return sep;
	}

	return NULL;
}

static uint8_t default_bitpool(uint8_t freq, uint8_t mode)
{
	switch (freq) {
	case SBC_SAMPLING_FREQ_16000:
	case SBC_SAMPLING_FREQ_32000:
		return 53;
	case SBC_SAMPLING_FREQ_44100:
		switch (mode) {
		case SBC_CHANNEL_MODE_MONO:
		case SBC_CHANNEL_MODE_DUAL_CHANNEL:
			return 31;
		case SBC_CHANNEL_MODE_STEREO:
		case SBC_CHANNEL_MODE_JOINT_STEREO:
			return 53;
		default:
			error("Invalid channel mode %u", mode);
			return 53;
		}
	case SBC_SAMPLING_FREQ_48000:
		switch (mode) {
		case SBC_CHANNEL_MODE_MONO:
		case SBC_CHANNEL_MODE_DUAL_CHANNEL:
			return 29;
		case SBC_CHANNEL_MODE_STEREO:
		case SBC_CHANNEL_MODE_JOINT_STEREO:
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
	unsigned int max_bitpool, min_bitpool;

	memset(cap, 0, sizeof(struct sbc_codec_cap));

	cap->cap.media_type = AVDTP_MEDIA_TYPE_AUDIO;
	cap->cap.media_codec_type = A2DP_CODEC_SBC;

	if (supported->frequency & SBC_SAMPLING_FREQ_44100)
		cap->frequency = SBC_SAMPLING_FREQ_44100;
	else if (supported->frequency & SBC_SAMPLING_FREQ_48000)
		cap->frequency = SBC_SAMPLING_FREQ_48000;
	else if (supported->frequency & SBC_SAMPLING_FREQ_32000)
		cap->frequency = SBC_SAMPLING_FREQ_32000;
	else if (supported->frequency & SBC_SAMPLING_FREQ_16000)
		cap->frequency = SBC_SAMPLING_FREQ_16000;
	else {
		error("No supported frequencies");
		return FALSE;
	}

	if (supported->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO)
		cap->channel_mode = SBC_CHANNEL_MODE_JOINT_STEREO;
	else if (supported->channel_mode & SBC_CHANNEL_MODE_STEREO)
		cap->channel_mode = SBC_CHANNEL_MODE_STEREO;
	else if (supported->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL)
		cap->channel_mode = SBC_CHANNEL_MODE_DUAL_CHANNEL;
	else if (supported->channel_mode & SBC_CHANNEL_MODE_MONO)
		cap->channel_mode = SBC_CHANNEL_MODE_MONO;
	else {
		error("No supported channel modes");
		return FALSE;
	}

	if (supported->block_length & SBC_BLOCK_LENGTH_16)
		cap->block_length = SBC_BLOCK_LENGTH_16;
	else if (supported->block_length & SBC_BLOCK_LENGTH_12)
		cap->block_length = SBC_BLOCK_LENGTH_12;
	else if (supported->block_length & SBC_BLOCK_LENGTH_8)
		cap->block_length = SBC_BLOCK_LENGTH_8;
	else if (supported->block_length & SBC_BLOCK_LENGTH_4)
		cap->block_length = SBC_BLOCK_LENGTH_4;
	else {
		error("No supported block lengths");
		return FALSE;
	}

	if (supported->subbands & SBC_SUBBANDS_8)
		cap->subbands = SBC_SUBBANDS_8;
	else if (supported->subbands & SBC_SUBBANDS_4)
		cap->subbands = SBC_SUBBANDS_4;
	else {
		error("No supported subbands");
		return FALSE;
	}

	if (supported->allocation_method & SBC_ALLOCATION_LOUDNESS)
		cap->allocation_method = SBC_ALLOCATION_LOUDNESS;
	else if (supported->allocation_method & SBC_ALLOCATION_SNR)
		cap->allocation_method = SBC_ALLOCATION_SNR;

	min_bitpool = MAX(MIN_BITPOOL, supported->min_bitpool);
	max_bitpool = MIN(default_bitpool(cap->frequency, cap->channel_mode),
							supported->max_bitpool);

	cap->min_bitpool = min_bitpool;
	cap->max_bitpool = max_bitpool;

	return TRUE;
}

static gboolean select_capabilities(struct avdtp *session,
					struct avdtp_remote_sep *rsep,
					GSList **caps)
{
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;

	media_codec = avdtp_get_codec(rsep);
	if (!media_codec)
		return FALSE;

	select_sbc_params(&sbc_cap, (struct sbc_codec_cap *) media_codec->data);

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	*caps = g_slist_append(*caps, media_transport);

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, &sbc_cap,
						sizeof(sbc_cap));

	*caps = g_slist_append(*caps, media_codec);

	if (avdtp_get_delay_reporting(rsep)) {
		struct avdtp_service_capability *delay_reporting;
		delay_reporting = avdtp_service_cap_new(AVDTP_DELAY_REPORTING,
								NULL, 0);
		*caps = g_slist_append(*caps, delay_reporting);
	}

	return TRUE;
}

static void select_cb(struct media_endpoint *endpoint, void *ret, int size,
			void *user_data)
{
	struct a2dp_setup *setup = user_data;
	struct avdtp_service_capability *media_transport, *media_codec;
	struct avdtp_media_codec_capability *cap;

	if (size < 0) {
		DBG("Endpoint replied an invalid configuration");
		goto done;
	}

	media_transport = avdtp_service_cap_new(AVDTP_MEDIA_TRANSPORT,
						NULL, 0);

	setup->caps = g_slist_append(setup->caps, media_transport);

	cap = g_malloc0(sizeof(*cap) + size);
	cap->media_type = AVDTP_MEDIA_TYPE_AUDIO;
	cap->media_codec_type = setup->sep->codec;
	memcpy(cap->data, ret, size);

	media_codec = avdtp_service_cap_new(AVDTP_MEDIA_CODEC, cap,
						sizeof(*cap) + size);

	setup->caps = g_slist_append(setup->caps, media_codec);
	g_free(cap);

done:
	finalize_select(setup);
}

static gboolean auto_select(gpointer data)
{
	struct a2dp_setup *setup = data;

	finalize_select(setup);

	return FALSE;
}

static struct a2dp_sep *a2dp_find_sep(struct avdtp *session, GSList *list,
					const char *sender)
{
	for (; list; list = list->next) {
		struct a2dp_sep *sep = list->data;

		/* Use sender's endpoint if available */
		if (sender) {
			const char *name;

			if (sep->endpoint == NULL)
				continue;

			name = media_endpoint_get_sender(sep->endpoint);
			if (g_strcmp0(sender, name) != 0)
				continue;
		}

		if (avdtp_find_remote_sep(session, sep->lsep) == NULL)
			continue;

		return sep;
	}

	return NULL;
}

static struct a2dp_sep *a2dp_select_sep(struct avdtp *session, uint8_t type,
					const char *sender)
{
	struct a2dp_server *server;
	struct a2dp_sep *sep;
	GSList *l;
	bdaddr_t src;

	avdtp_get_peers(session, &src, NULL);
	server = find_server(servers, &src);
	if (!server)
		return NULL;

	l = type == AVDTP_SEP_TYPE_SINK ? server->sources : server->sinks;

	/* Check sender's seps first */
	sep = a2dp_find_sep(session, l, sender);
	if (sep != NULL)
		return sep;

	return a2dp_find_sep(session, l, NULL);
}

unsigned int a2dp_select_capabilities(struct avdtp *session,
					uint8_t type, const char *sender,
					a2dp_select_cb_t cb,
					void *user_data)
{
	struct a2dp_setup *setup;
	struct a2dp_setup_cb *cb_data;
	struct a2dp_sep *sep;
	struct avdtp_service_capability *service;
	struct avdtp_media_codec_capability *codec;

	sep = a2dp_select_sep(session, type, sender);
	if (!sep) {
		error("Unable to select SEP");
		return 0;
	}

	setup = a2dp_setup_get(session);
	if (!setup)
		return 0;

	cb_data = setup_cb_new(setup);
	cb_data->select_cb = cb;
	cb_data->user_data = user_data;

	setup->sep = sep;
	setup->rsep = avdtp_find_remote_sep(session, sep->lsep);

	if (setup->rsep == NULL) {
		error("Could not find remote sep");
		goto fail;
	}

	/* FIXME: Remove auto select when it is not longer possible to register
	endpoint in the configuration file */
	if (sep->endpoint == NULL) {
		if (!select_capabilities(session, setup->rsep,
					&setup->caps)) {
			error("Unable to auto select remote SEP capabilities");
			goto fail;
		}

		g_idle_add(auto_select, setup);

		return cb_data->id;
	}

	service = avdtp_get_codec(setup->rsep);
	codec = (struct avdtp_media_codec_capability *) service->data;

	if (media_endpoint_select_configuration(sep->endpoint, codec->data,
						service->length - sizeof(*codec),
						select_cb, setup) ==
						TRUE)
		return cb_data->id;

fail:
	setup_cb_free(cb_data);
	return 0;

}

unsigned int a2dp_config(struct avdtp *session, struct a2dp_sep *sep,
				a2dp_config_cb_t cb, GSList *caps,
				void *user_data)
{
	struct a2dp_setup_cb *cb_data;
	GSList *l;
	struct a2dp_server *server;
	struct a2dp_setup *setup;
	struct a2dp_sep *tmp;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap = NULL;
	int posix_err;
	bdaddr_t src;
	uint8_t remote_type;

	avdtp_get_peers(session, &src, NULL);
	server = find_server(servers, &src);
	if (!server)
		return 0;

	for (l = caps; l != NULL; l = l->next) {
		cap = l->data;

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		codec_cap = (void *) cap->data;
		break;
	}

	if (!codec_cap)
		return 0;

	if (sep->codec != codec_cap->media_codec_type)
		return 0;

	DBG("a2dp_config: selected SEP %p", sep->lsep);

	setup = a2dp_setup_get(session);
	if (!setup)
		return 0;

	cb_data = setup_cb_new(setup);
	cb_data->config_cb = cb;
	cb_data->user_data = user_data;

	setup->sep = sep;
	setup->stream = sep->stream;

	/* Copy given caps if they are different than current caps */
	if (setup->caps != caps) {
		g_slist_foreach(setup->caps, (GFunc) g_free, NULL);
		g_slist_free(setup->caps);
		setup->caps = g_slist_copy(caps);
	}

	switch (avdtp_sep_get_state(sep->lsep)) {
	case AVDTP_STATE_IDLE:
		if (sep->type == AVDTP_SEP_TYPE_SOURCE) {
			l = server->sources;
			remote_type = AVDTP_SEP_TYPE_SINK;
		} else {
			remote_type = AVDTP_SEP_TYPE_SOURCE;
			l = server->sinks;
		}

		for (; l != NULL; l = l->next) {
			tmp = l->data;
			if (avdtp_has_stream(session, tmp->stream))
				break;
		}

		if (l != NULL) {
			if (a2dp_sep_get_lock(tmp))
				goto failed;
			setup->reconfigure = TRUE;
			if (avdtp_close(session, tmp->stream, FALSE) < 0) {
				error("avdtp_close failed");
				goto failed;
			}
			break;
		}

		setup->rsep = avdtp_find_remote_sep(session, sep->lsep);
		if (setup->rsep == NULL) {
			error("No matching ACP and INT SEPs found");
			goto failed;
		}

		posix_err = avdtp_set_configuration(session, setup->rsep,
							sep->lsep, caps,
							&setup->stream);
		if (posix_err < 0) {
			error("avdtp_set_configuration: %s",
				strerror(-posix_err));
			goto failed;
		}
		break;
	case AVDTP_STATE_OPEN:
	case AVDTP_STATE_STREAMING:
		if (avdtp_stream_has_capabilities(setup->stream, caps)) {
			DBG("Configuration match: resuming");
			g_idle_add((GSourceFunc) finalize_config, setup);
		} else if (!setup->reconfigure) {
			setup->reconfigure = TRUE;
			if (avdtp_close(session, sep->stream, FALSE) < 0) {
				error("avdtp_close failed");
				goto failed;
			}
		}
		break;
	default:
		error("SEP in bad state for requesting a new stream");
		goto failed;
	}

	return cb_data->id;

failed:
	setup_cb_free(cb_data);
	return 0;
}

unsigned int a2dp_resume(struct avdtp *session, struct a2dp_sep *sep,
				a2dp_stream_cb_t cb, void *user_data)
{
	struct a2dp_setup_cb *cb_data;
	struct a2dp_setup *setup;

	setup = a2dp_setup_get(session);
	if (!setup)
		return 0;

	cb_data = setup_cb_new(setup);
	cb_data->resume_cb = cb;
	cb_data->user_data = user_data;

	setup->sep = sep;
	setup->stream = sep->stream;

	switch (avdtp_sep_get_state(sep->lsep)) {
	case AVDTP_STATE_IDLE:
		goto failed;
		break;
	case AVDTP_STATE_OPEN:
		if (avdtp_start(session, sep->stream) < 0) {
			error("avdtp_start failed");
			goto failed;
		}
		break;
	case AVDTP_STATE_STREAMING:
		if (!sep->suspending && sep->suspend_timer) {
			g_source_remove(sep->suspend_timer);
			sep->suspend_timer = 0;
			avdtp_unref(sep->session);
			sep->session = NULL;
		}
		if (sep->suspending)
			setup->start = TRUE;
		else
			g_idle_add((GSourceFunc) finalize_resume, setup);
		break;
	default:
		error("SEP in bad state for resume");
		goto failed;
	}

	return cb_data->id;

failed:
	setup_cb_free(cb_data);
	return 0;
}

unsigned int a2dp_suspend(struct avdtp *session, struct a2dp_sep *sep,
				a2dp_stream_cb_t cb, void *user_data)
{
	struct a2dp_setup_cb *cb_data;
	struct a2dp_setup *setup;

	setup = a2dp_setup_get(session);
	if (!setup)
		return 0;

	cb_data = setup_cb_new(setup);
	cb_data->suspend_cb = cb;
	cb_data->user_data = user_data;

	setup->sep = sep;
	setup->stream = sep->stream;

	switch (avdtp_sep_get_state(sep->lsep)) {
	case AVDTP_STATE_IDLE:
		error("a2dp_suspend: no stream to suspend");
		goto failed;
		break;
	case AVDTP_STATE_OPEN:
		g_idle_add((GSourceFunc) finalize_suspend, setup);
		break;
	case AVDTP_STATE_STREAMING:
		if (avdtp_suspend(session, sep->stream) < 0) {
			error("avdtp_suspend failed");
			goto failed;
		}
		sep->suspending = TRUE;
		break;
	default:
		error("SEP in bad state for suspend");
		goto failed;
	}

	return cb_data->id;

failed:
	setup_cb_free(cb_data);
	return 0;
}

gboolean a2dp_cancel(struct audio_device *dev, unsigned int id)
{
	struct a2dp_setup *setup;
	GSList *l;

	setup = find_setup_by_dev(dev);
	if (!setup)
		return FALSE;

	for (l = setup->cb; l != NULL; l = g_slist_next(l)) {
		struct a2dp_setup_cb *cb = l->data;

		if (cb->id != id)
			continue;

		setup_ref(setup);
		setup_cb_free(cb);

		if (!setup->cb) {
			DBG("aborting setup %p", setup);
			avdtp_abort(setup->session, setup->stream);
			return TRUE;
		}

		setup_unref(setup);
		return TRUE;
	}

	return FALSE;
}

gboolean a2dp_sep_lock(struct a2dp_sep *sep, struct avdtp *session)
{
	if (sep->locked)
		return FALSE;

	DBG("SEP %p locked", sep->lsep);
	sep->locked = TRUE;

	return TRUE;
}

gboolean a2dp_sep_unlock(struct a2dp_sep *sep, struct avdtp *session)
{
	avdtp_state_t state;

	state = avdtp_sep_get_state(sep->lsep);

	sep->locked = FALSE;

	DBG("SEP %p unlocked", sep->lsep);

	if (!sep->stream || state == AVDTP_STATE_IDLE)
		return TRUE;

	switch (state) {
	case AVDTP_STATE_OPEN:
		/* Set timer here */
		break;
	case AVDTP_STATE_STREAMING:
		if (avdtp_suspend(session, sep->stream) == 0)
			sep->suspending = TRUE;
		break;
	default:
		break;
	}

	return TRUE;
}

gboolean a2dp_sep_get_lock(struct a2dp_sep *sep)
{
	return sep->locked;
}

static int stream_cmp(gconstpointer data, gconstpointer user_data)
{
	const struct a2dp_sep *sep = data;
	const struct avdtp_stream *stream = user_data;

	return (sep->stream != stream);
}

struct a2dp_sep *a2dp_get_sep(struct avdtp *session,
				struct avdtp_stream *stream)
{
	struct a2dp_server *server;
	bdaddr_t src, dst;
	GSList *l;

	avdtp_get_peers(session, &src, &dst);

	for (l = servers; l; l = l->next) {
		server = l->data;

		if (bacmp(&src, &server->src) == 0)
			break;
	}

	if (!l)
		return NULL;

	l = g_slist_find_custom(server->sources, stream, stream_cmp);
	if (l)
		return l->data;

	l = g_slist_find_custom(server->sinks, stream, stream_cmp);
	if (l)
		return l->data;

	return NULL;
}

struct avdtp_stream *a2dp_sep_get_stream(struct a2dp_sep *sep)
{
	return sep->stream;
}
