/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include "logging.h"
#include "device.h"
#include "manager.h"
#include "avdtp.h"
#include "sink.h"
#include "a2dp.h"
#include "sdpd.h"

/* The duration that streams without users are allowed to stay in
 * STREAMING state. */
#define SUSPEND_TIMEOUT 5000
#define RECONFIGURE_TIMEOUT 500

#ifndef MIN
# define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

struct a2dp_sep {
	uint8_t type;
	uint8_t codec;
	struct avdtp_local_sep *sep;
	struct avdtp *session;
	struct avdtp_stream *stream;
	guint suspend_timer;
	gboolean locked;
	gboolean suspending;
	gboolean starting;
};

struct a2dp_setup_cb {
	a2dp_config_cb_t config_cb;
	a2dp_stream_cb_t resume_cb;
	a2dp_stream_cb_t suspend_cb;
	void *user_data;
	int id;
};

struct a2dp_setup {
	struct avdtp *session;
	struct a2dp_sep *sep;
	struct avdtp_stream *stream;
	struct avdtp_error *err;
	GSList *client_caps;
	gboolean reconfigure;
	gboolean canceled;
	gboolean start;
	GSList *cb;
	int ref;
};

static DBusConnection *connection = NULL;

static GSList *sinks = NULL;
static GSList *sources = NULL;

static uint32_t source_record_id = 0;
static uint32_t sink_record_id = 0;

static GSList *setups = NULL;
static unsigned int cb_id = 0;

static struct a2dp_setup *setup_ref(struct a2dp_setup *setup)
{
	setup->ref++;

	debug("setup_ref(%p): ref=%d", setup, setup->ref);

	return setup;
}

static void setup_free(struct a2dp_setup *s)
{
	debug("setup_free(%p)", s);
	setups = g_slist_remove(setups, s);
	if (s->session)
		avdtp_unref(s->session);
	g_slist_foreach(s->cb, (GFunc) g_free, NULL);
	g_slist_free(s->cb);
	g_free(s);
}

static void setup_unref(struct a2dp_setup *setup)
{
	setup->ref--;

	debug("setup_unref(%p): ref=%d", setup, setup->ref);

	if (setup->ref <= 0)
		setup_free(setup);
}

static struct audio_device *a2dp_get_dev(struct avdtp *session)
{
	bdaddr_t addr;

	avdtp_get_peers(session, NULL, &addr);

	return manager_device_connected(&addr, A2DP_SOURCE_UUID);
}

static gboolean finalize_config(struct a2dp_setup *s)
{
	GSList *l;

	setup_ref(s);
	for (l = s->cb; l != NULL; l = l->next) {
		struct a2dp_setup_cb *cb = l->data;

		if (cb->config_cb) {
			cb->config_cb(s->session, s->sep, s->stream, s->err,
					cb->user_data);
			cb->config_cb = NULL;
			setup_unref(s);
		}
	}

	setup_unref(s);
	return FALSE;
}

static gboolean finalize_config_errno(struct a2dp_setup *s, int err)
{
	struct avdtp_error avdtp_err;

	avdtp_error_init(&avdtp_err, AVDTP_ERROR_ERRNO, -err);
	s->err = err ? &avdtp_err : NULL;

	return finalize_config(s);
}

static gboolean finalize_resume(struct a2dp_setup *s)
{
	GSList *l;

	setup_ref(s);
	for (l = s->cb; l != NULL; l = l->next) {
		struct a2dp_setup_cb *cb = l->data;

		if (cb->resume_cb) {
			cb->resume_cb(s->session, s->err, cb->user_data);
			cb->resume_cb = NULL;
			setup_unref(s);
		}
	}

	setup_unref(s);
	return FALSE;
}

static gboolean finalize_resume_errno(struct a2dp_setup *s, int err)
{
	struct avdtp_error avdtp_err;

	avdtp_error_init(&avdtp_err, AVDTP_ERROR_ERRNO, -err);
	s->err = err ? &avdtp_err : NULL;

	return finalize_resume(s);
}

static gboolean finalize_suspend(struct a2dp_setup *s)
{
	GSList *l;

	setup_ref(s);
	for (l = s->cb; l != NULL; l = l->next) {
		struct a2dp_setup_cb *cb = l->data;

		if (cb->suspend_cb) {
			cb->suspend_cb(s->session, s->err, cb->user_data);
			cb->suspend_cb = NULL;
			setup_unref(s);
		}
	}

	setup_unref(s);
	return FALSE;
}

static gboolean finalize_suspend_errno(struct a2dp_setup *s, int err)
{
	struct avdtp_error avdtp_err;

	avdtp_error_init(&avdtp_err, AVDTP_ERROR_ERRNO, -err);
	s->err = err ? &avdtp_err : NULL;

	return finalize_suspend(s);
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

static struct a2dp_setup *find_setup_by_dev(struct audio_device *dev)
{
	GSList *l;

	for (l = setups; l != NULL; l = l->next) {
		struct a2dp_setup *setup = l->data;
		struct audio_device *setup_dev = a2dp_get_dev(setup->session);

		if (setup_dev == dev)
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

	sep->stream = NULL;

}

static gboolean sbc_setconf_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				GSList *caps, uint8_t *err,
				uint8_t *category, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct audio_device *dev;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap;
	struct sbc_codec_cap *sbc_cap;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Set_Configuration_Ind", sep);
	else
		debug("Source %p: Set_Configuration_Ind", sep);

	dev = a2dp_get_dev(session);
	if (!dev) {
		*err = AVDTP_UNSUPPORTED_CONFIGURATION;
		*category = 0x00;
		return FALSE;
	}

	/* Check bipool range */
	for (codec_cap = NULL; caps; caps = g_slist_next(caps)) {
		cap = caps->data;
		if (cap->category == AVDTP_MEDIA_CODEC) {
			codec_cap = (void *) cap->data;
			if (codec_cap->media_codec_type == A2DP_CODEC_SBC) {
				sbc_cap = (void *) codec_cap;
				if (sbc_cap->min_bitpool < MIN_BITPOOL ||
					sbc_cap->max_bitpool > MAX_BITPOOL) {
					*err = AVDTP_UNSUPPORTED_CONFIGURATION;
					*category = AVDTP_MEDIA_CODEC;
					return FALSE;
				}
			}
			break;
		}
	}

	avdtp_stream_add_cb(session, stream, stream_state_changed, a2dp_sep);
	a2dp_sep->stream = stream;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SOURCE)
		sink_new_stream(dev, session, stream);

	return TRUE;
}

static gboolean sbc_getcap_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				GSList **caps, uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct avdtp_service_capability *media_transport, *media_codec;
	struct sbc_codec_cap sbc_cap;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Get_Capability_Ind", sep);
	else
		debug("Source %p: Get_Capability_Ind", sep);

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

	return TRUE;
}

static gboolean mpeg_setconf_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				struct avdtp_stream *stream,
				GSList *caps, uint8_t *err,
				uint8_t *category, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct audio_device *dev;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Set_Configuration_Ind", sep);
	else
		debug("Source %p: Set_Configuration_Ind", sep);

	dev = a2dp_get_dev(session);
	if (!dev) {
		*err = AVDTP_UNSUPPORTED_CONFIGURATION;
		*category = 0x00;
		return FALSE;
	}

	avdtp_stream_add_cb(session, stream, stream_state_changed, a2dp_sep);
	a2dp_sep->stream = stream;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SOURCE)
		sink_new_stream(dev, session, stream);

	return TRUE;
}

static gboolean mpeg_getcap_ind(struct avdtp *session,
				struct avdtp_local_sep *sep,
				GSList **caps, uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct avdtp_service_capability *media_transport, *media_codec;
	struct mpeg_codec_cap mpeg_cap;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Get_Capability_Ind", sep);
	else
		debug("Source %p: Get_Capability_Ind", sep);

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

	return TRUE;
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
		debug("Sink %p: Set_Configuration_Cfm", sep);
	else
		debug("Source %p: Set_Configuration_Cfm", sep);

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

	/* Notify sink.c of the new stream */
	sink_new_stream(dev, session, setup->stream);

	ret = avdtp_open(session, stream);
	if (ret < 0) {
		error("Error on avdtp_open %s (%d)", strerror(-ret),
				-ret);
		setup->stream = NULL;
		finalize_config_errno(setup, ret);
	}
}

static gboolean getconf_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				uint8_t *err, void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Get_Configuration_Ind");
	else
		debug("Source %p: Get_Configuration_Ind");
	return TRUE;
}

static void getconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Set_Configuration_Cfm", sep);
	else
		debug("Source %p: Set_Configuration_Cfm", sep);
}

static gboolean open_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Open_Ind", sep);
	else
		debug("Source %p: Open_Ind", sep);
	return TRUE;
}

static void open_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Open_Cfm", sep);
	else
		debug("Source %p: Open_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (setup->canceled) {
		if (!err)
			avdtp_close(session, stream);
		setup_unref(setup);
		return;
	}

	if (setup->reconfigure)
		setup->reconfigure = FALSE;

	if (err) {
		setup->stream = NULL;
		setup->err = err;
		finalize_config(setup);
	}
	else
		finalize_config_errno(setup, 0);
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

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Start_Ind", sep);
	else
		debug("Source %p: Start_Ind", sep);

	if (!a2dp_sep->locked) {
		a2dp_sep->session = avdtp_ref(session);
		a2dp_sep->suspend_timer = g_timeout_add(SUSPEND_TIMEOUT,
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
		debug("Sink %p: Start_Cfm", sep);
	else
		debug("Source %p: Start_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (setup->canceled) {
		if (!err)
			avdtp_close(session, stream);
		setup_unref(setup);
		return;
	}

	if (err) {
		setup->stream = NULL;
		setup->err = err;
		finalize_resume(setup);
	}
	else
		finalize_resume_errno(setup, 0);
}

static gboolean suspend_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Suspend_Ind", sep);
	else
		debug("Source %p: Suspend_Ind", sep);

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
		debug("Sink %p: Suspend_Cfm", sep);
	else
		debug("Source %p: Suspend_Cfm", sep);

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
		avdtp_error_init(&start_err, AVDTP_ERROR_ERRNO, EIO);
		setup->err = err;
		finalize_suspend(setup);
	}
}

static gboolean close_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Close_Ind", sep);
	else
		debug("Source %p: Close_Ind", sep);

	return TRUE;
}

static gboolean a2dp_reconfigure(gpointer data)
{
	struct a2dp_setup *setup = data;
	struct avdtp_local_sep *lsep;
	struct avdtp_remote_sep *rsep;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap = NULL;
	GSList *l;
	int posix_err;

	for (l = setup->client_caps; l != NULL; l = l->next) {
		cap = l->data;

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		codec_cap = (void *) cap->data;
		break;
	}

	posix_err = avdtp_get_seps(setup->session, AVDTP_SEP_TYPE_SINK,
					codec_cap->media_type,
					codec_cap->media_codec_type,
					&lsep, &rsep);
	if (posix_err < 0) {
		error("No matching ACP and INT SEPs found");
		finalize_config_errno(setup, posix_err);
	}

	posix_err = avdtp_set_configuration(setup->session, rsep, lsep,
						setup->client_caps,
						&setup->stream);
	if (posix_err < 0) {
		error("avdtp_set_configuration: %s",
			strerror(-posix_err));
		finalize_config_errno(setup, posix_err);
	}

	return FALSE;
}

static void close_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Close_Cfm", sep);
	else
		debug("Source %p: Close_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (setup->canceled) {
		setup_unref(setup);
		return;
	}

	if (err) {
		setup->stream = NULL;
		setup->err = err;
		finalize_config(setup);
		return;
	}

	if (setup->reconfigure)
		g_timeout_add(RECONFIGURE_TIMEOUT, a2dp_reconfigure, setup);
}

static gboolean abort_ind(struct avdtp *session, struct avdtp_local_sep *sep,
				struct avdtp_stream *stream, uint8_t *err,
				void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: Abort_Ind", sep);
	else
		debug("Source %p: Abort_Ind", sep);

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
		debug("Sink %p: Abort_Cfm", sep);
	else
		debug("Source %p: Abort_Cfm", sep);

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
		debug("Sink %p: ReConfigure_Ind", sep);
	else
		debug("Source %p: ReConfigure_Ind", sep);
	return TRUE;
}

static void reconf_cfm(struct avdtp *session, struct avdtp_local_sep *sep,
			struct avdtp_stream *stream, struct avdtp_error *err,
			void *user_data)
{
	struct a2dp_sep *a2dp_sep = user_data;
	struct a2dp_setup *setup;

	if (a2dp_sep->type == AVDTP_SEP_TYPE_SINK)
		debug("Sink %p: ReConfigure_Cfm", sep);
	else
		debug("Source %p: ReConfigure_Cfm", sep);

	setup = find_setup_by_session(session);
	if (!setup)
		return;

	if (setup->canceled) {
		if (!err)
			avdtp_close(session, stream);
		setup_unref(setup);
		return;
	}

	if (err) {
		setup->stream = NULL;
		setup->err = err;
		finalize_config(setup);
	}
	else
		finalize_config_errno(setup, 0);
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

static struct avdtp_sep_ind sbc_ind = {
	.get_capability		= sbc_getcap_ind,
	.set_configuration	= sbc_setconf_ind,
	.get_configuration	= getconf_ind,
	.open			= open_ind,
	.start			= start_ind,
	.suspend		= suspend_ind,
	.close			= close_ind,
	.abort			= abort_ind,
	.reconfigure		= reconf_ind
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
	.reconfigure		= reconf_ind
};

static sdp_record_t *a2dp_source_record()
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avdtp, a2src;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = AVDTP_UUID, ver = 0x0100, feat = 0x000F;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&a2src, AUDIO_SOURCE_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &a2src);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile[0].uuid, ADVANCED_AUDIO_PROFILE_ID);
	profile[0].version = 0x0100;
	pfseq = sdp_list_append(0, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

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
	sdp_set_access_protos(record, aproto);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "Audio Source", 0, 0);

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

static sdp_record_t *a2dp_sink_record()
{
	return NULL;
}

static struct a2dp_sep *a2dp_add_sep(DBusConnection *conn, uint8_t type,
					uint8_t codec)
{
	struct a2dp_sep *sep;
	GSList **l;
	sdp_record_t *(*create_record)(void);
	uint32_t *record_id;
	sdp_record_t *record;
	struct avdtp_sep_ind *ind;

	sep = g_new0(struct a2dp_sep, 1);

	ind = (codec == A2DP_CODEC_MPEG12) ? &mpeg_ind : &sbc_ind;
	sep->sep = avdtp_register_sep(type, AVDTP_MEDIA_TYPE_AUDIO, codec,
					ind, &cfm, sep);
	if (sep->sep == NULL) {
		g_free(sep);
		return NULL;
	}

	sep->codec = codec;
	sep->type = type;

	if (type == AVDTP_SEP_TYPE_SOURCE) {
		l = &sources;
		create_record = a2dp_source_record;
		record_id = &source_record_id;
	} else {
		l = &sinks;
		create_record = a2dp_sink_record;
		record_id = &sink_record_id;
	}

	if (*record_id != 0)
		goto add;

	record = create_record();
	if (!record) {
		error("Unable to allocate new service record");
		avdtp_unregister_sep(sep->sep);
		g_free(sep);
		return NULL;
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0) {
		error("Unable to register A2DP service record");\
		sdp_record_free(record);
		avdtp_unregister_sep(sep->sep);
		g_free(sep);
		return NULL;
	}
	*record_id = record->handle;

add:
	*l = g_slist_append(*l, sep);

	return sep;
}

int a2dp_init(DBusConnection *conn, GKeyFile *config)
{
	int sbc_srcs = 1, sbc_sinks = 0;
	int mpeg12_srcs = 0, mpeg12_sinks = 0;
	gboolean source = TRUE, sink = TRUE;
	char *str;
	GError *err = NULL;
	int i;

	if (!config)
		goto proceed;

	str = g_key_file_get_string(config, "General", "Disable", &err);

	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else {
		if (strstr(str, "Sink"))
			source = FALSE;
		if (strstr(str, "Source"))
			sink = FALSE;
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "SBCSources", &err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else {
		sbc_srcs = atoi(str);
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "MPEG12Sources", &err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else {
		mpeg12_srcs = atoi(str);
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "SBCSinks", &err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else {
		sbc_sinks = atoi(str);
		g_free(str);
	}

	str = g_key_file_get_string(config, "A2DP", "MPEG12Sinks", &err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else {
		mpeg12_sinks = atoi(str);
		g_free(str);
	}

proceed:
	connection = dbus_connection_ref(conn);

	avdtp_init(config);

	if (source) {
		for (i = 0; i < sbc_srcs; i++)
			a2dp_add_sep(conn, AVDTP_SEP_TYPE_SOURCE,
					A2DP_CODEC_SBC);

		for (i = 0; i < mpeg12_srcs; i++)
			a2dp_add_sep(conn, AVDTP_SEP_TYPE_SOURCE,
					A2DP_CODEC_MPEG12);
	}

	if (sink) {
		for (i = 0; i < sbc_sinks; i++)
			a2dp_add_sep(conn, AVDTP_SEP_TYPE_SINK,
					A2DP_CODEC_SBC);

		for (i = 0; i < mpeg12_sinks; i++)
			a2dp_add_sep(conn, AVDTP_SEP_TYPE_SINK,
					A2DP_CODEC_MPEG12);
	}

	return 0;
}

static void a2dp_unregister_sep(struct a2dp_sep *sep)
{
	avdtp_unregister_sep(sep->sep);
	g_free(sep);
}

void a2dp_exit()
{
	g_slist_foreach(sinks, (GFunc) a2dp_unregister_sep, NULL);
	g_slist_free(sinks);
	sinks = NULL;

	g_slist_foreach(sources, (GFunc) a2dp_unregister_sep, NULL);
	g_slist_free(sources);
	sources = NULL;

	if (source_record_id) {
		remove_record_from_server(source_record_id);
		source_record_id = 0;
	}

	if (sink_record_id) {
		remove_record_from_server(sink_record_id);
		sink_record_id = 0;
	}

	dbus_connection_unref(connection);
}

gboolean a2dp_source_cancel(struct audio_device *dev, unsigned int id)
{
	struct a2dp_setup_cb *cb_data;
	struct a2dp_setup *setup;
	GSList *l;

	setup = find_setup_by_dev(dev);
	if (!setup)
		return FALSE;

	for (cb_data = NULL, l = setup->cb; l != NULL; l = g_slist_next(l)) {
		struct a2dp_setup_cb *cb = l->data;

		if (cb->id == id) {
			cb_data = cb;
			break;
		}
	}

	if (!cb_data)
		return FALSE;

	setup->cb = g_slist_remove(setup->cb, cb_data);
	g_free(cb_data);

	if (!setup->cb) {
		setup->canceled = TRUE;
		setup->sep = NULL;
	}

	return TRUE;
}

unsigned int a2dp_source_config(struct avdtp *session, a2dp_config_cb_t cb,
				GSList *caps, void *user_data)
{
	struct a2dp_setup_cb *cb_data;
	GSList *l;
	struct a2dp_setup *setup;
	struct a2dp_sep *sep = NULL, *tmp;
	struct avdtp_local_sep *lsep;
	struct avdtp_remote_sep *rsep;
	struct avdtp_service_capability *cap;
	struct avdtp_media_codec_capability *codec_cap = NULL;
	int posix_err;

	for (l = caps; l != NULL; l = l->next) {
		cap = l->data;

		if (cap->category != AVDTP_MEDIA_CODEC)
			continue;

		codec_cap = (void *) cap->data;
		break;
	}

	if (!codec_cap)
		return 0;

	for (l = sources; l != NULL; l = l->next) {
		tmp = l->data;

		if (tmp->locked)
			continue;

		if (tmp->codec != codec_cap->media_codec_type)
			continue;

		if (!tmp->stream || avdtp_has_stream(session, tmp->stream)) {
			sep = tmp;
			break;
		}
	}

	if (!sep) {
		error("a2dp_source_cfg: no available SEP found");
		return 0;
	}

	debug("a2dp_source_config: selected SEP %p", sep->sep);

	cb_data = g_new0(struct a2dp_setup_cb, 1);
	cb_data->config_cb = cb;
	cb_data->user_data = user_data;
	cb_data->id = ++cb_id;

	setup = find_setup_by_session(session);
	if (!setup) {
		setup = g_new0(struct a2dp_setup, 1);
		setup->session = avdtp_ref(session);
		setups = g_slist_append(setups, setup);
	}

	setup_ref(setup);
	setup->cb = g_slist_append(setup->cb, cb_data);
	setup->sep = sep;
	setup->stream = sep->stream;
	setup->client_caps = caps;

	switch (avdtp_sep_get_state(sep->sep)) {
	case AVDTP_STATE_IDLE:
		for (l = sources; l != NULL; l = l->next) {
			tmp = l->data;

			if (avdtp_has_stream(session, tmp->stream))
				break;
		}

		if (l != NULL) {
			setup->reconfigure = TRUE;
			if (avdtp_close(session, tmp->stream) < 0) {
				error("avdtp_close failed");
				goto failed;
			}
			break;
		}

		if (avdtp_get_seps(session, AVDTP_SEP_TYPE_SINK,
				codec_cap->media_type,
				codec_cap->media_codec_type,
				&lsep, &rsep) < 0) {
			error("No matching ACP and INT SEPs found");
			goto failed;
		}

		posix_err = avdtp_set_configuration(session, rsep, lsep,
							caps, &setup->stream);
		if (posix_err < 0) {
			error("avdtp_set_configuration: %s",
				strerror(-posix_err));
			goto failed;
		}
		break;
	case AVDTP_STATE_OPEN:
	case AVDTP_STATE_STREAMING:
		if (avdtp_stream_has_capabilities(setup->stream, caps))
			g_idle_add((GSourceFunc) finalize_config, setup);
		else if (!setup->reconfigure) {
			setup->reconfigure = TRUE;
			if (avdtp_close(session, sep->stream) < 0) {
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
	setup_unref(setup);
	cb_id--;
	return 0;
}

unsigned int a2dp_source_resume(struct avdtp *session, struct a2dp_sep *sep,
				a2dp_stream_cb_t cb, void *user_data)
{
	struct a2dp_setup_cb *cb_data;
	struct a2dp_setup *setup;

	cb_data = g_new0(struct a2dp_setup_cb, 1);
	cb_data->resume_cb = cb;
	cb_data->user_data = user_data;
	cb_data->id = ++cb_id;

	setup = find_setup_by_session(session);
	if (!setup) {
		setup = g_new0(struct a2dp_setup, 1);
		setup->session = avdtp_ref(session);
		setups = g_slist_append(setups, setup);
	}

	setup_ref(setup);
	setup->cb = g_slist_append(setup->cb, cb_data);
	setup->sep = sep;
	setup->stream = sep->stream;

	switch (avdtp_sep_get_state(sep->sep)) {
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
		error("SEP in bad state");
		goto failed;
	}

	return cb_data->id;

failed:
	setup_unref(setup);
	cb_id--;
	return 0;
}

unsigned int a2dp_source_suspend(struct avdtp *session, struct a2dp_sep *sep,
				a2dp_stream_cb_t cb, void *user_data)
{
	struct a2dp_setup_cb *cb_data;
	struct a2dp_setup *setup;

	cb_data = g_new0(struct a2dp_setup_cb, 1);
	cb_data->suspend_cb = cb;
	cb_data->user_data = user_data;
	cb_data->id = ++cb_id;

	setup = find_setup_by_session(session);
	if (!setup) {
		setup = g_new0(struct a2dp_setup, 1);
		setup->session = avdtp_ref(session);
		setups = g_slist_append(setups, setup);
	}

	setup_ref(setup);
	setup->cb = g_slist_append(setup->cb, cb_data);
	setup->sep = sep;
	setup->stream = sep->stream;

	switch (avdtp_sep_get_state(sep->sep)) {
	case AVDTP_STATE_IDLE:
		error("a2dp_source_suspend: no stream to suspend");
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
		break;
	default:
		error("SEP in bad state for resume");
		goto failed;
	}

	return cb_data->id;

failed:
	setup_unref(setup);
	cb_id--;
	return 0;
}

gboolean a2dp_sep_lock(struct a2dp_sep *sep, struct avdtp *session)
{
	if (sep->locked)
		return FALSE;

	debug("SEP %p locked", sep->sep);
	sep->locked = TRUE;

	return TRUE;
}

gboolean a2dp_sep_unlock(struct a2dp_sep *sep, struct avdtp *session)
{
	avdtp_state_t state;

	state = avdtp_sep_get_state(sep->sep);

	sep->locked = FALSE;

	debug("SEP %p unlocked", sep->sep);

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

