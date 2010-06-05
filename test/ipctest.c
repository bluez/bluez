/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2009	Lennart Poettering
 *  Copyright (C) 2008	Joao Paulo Rechi Vita
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include <glib.h>

#include "ipc.h"
#include "sbc.h"

#define DBG(fmt, arg...)				\
	printf("debug %s: " fmt "\n" , __FUNCTION__ , ## arg)
#define ERR(fmt, arg...)				\
	fprintf(stderr, "ERROR %s: " fmt "\n" , __FUNCTION__ , ## arg)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef MIN
# define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#ifndef TRUE
# define TRUE (1)
#endif

#ifndef FALSE
# define FALSE (0)
#endif

#define YES_NO(t) ((t) ? "yes" : "no")

#define BUFFER_SIZE 2048
#define MAX_BITPOOL 64
#define MIN_BITPOOL 2

struct a2dp_info {
	sbc_capabilities_t sbc_capabilities;
	sbc_t sbc; /* Codec data */
	int sbc_initialized; /* Keep track if the encoder is initialized */
	size_t codesize; /* SBC codesize */

	void* buffer; /* Codec transfer buffer */
	size_t buffer_size; /* Size of the buffer */

	uint16_t seq_num; /* Cumulative packet sequence */
};

struct hsp_info {
	pcm_capabilities_t pcm_capabilities;
};

struct userdata {
	int service_fd;
	int stream_fd;
	GIOChannel *stream_channel;
	guint stream_watch;
	GIOChannel *gin; /* dude, I am thirsty now */
	guint gin_watch;
	int transport;
	uint32_t rate;
	int channels;
	char *address;
	struct a2dp_info a2dp;
	struct hsp_info hsp;
	size_t link_mtu;
	size_t block_size;
	gboolean debug_stream_read : 1;
	gboolean debug_stream_write : 1;
};

static struct userdata data = {
	.service_fd = -1,
	.stream_fd = -1,
	.transport = BT_CAPABILITIES_TRANSPORT_A2DP,
	.rate = 48000,
	.channels = 2,
	.address = NULL
};

static int start_stream(struct userdata *u);
static int stop_stream(struct userdata *u);
static gboolean input_cb(GIOChannel *gin, GIOCondition condition, gpointer data);

static GMainLoop *main_loop;

static int service_send(struct userdata *u, const bt_audio_msg_header_t *msg)
{
	int err;
	uint16_t length;

	assert(u);

	length = msg->length ? msg->length : BT_SUGGESTED_BUFFER_SIZE;

	DBG("sending %s:%s", bt_audio_strtype(msg->type),
		bt_audio_strname(msg->name));

	if (send(u->service_fd, msg, length, 0) > 0)
		err = 0;
	else {
		err = -errno;
		ERR("Error sending data to audio service: %s(%d)",
			strerror(errno), errno);
	}

	return err;
}

static int service_recv(struct userdata *u, bt_audio_msg_header_t *rsp)
{
	int err;
	const char *type, *name;
	uint16_t length;

	assert(u);

	length = rsp->length ? : BT_SUGGESTED_BUFFER_SIZE;

	DBG("trying to receive msg from audio service...");
	if (recv(u->service_fd, rsp, length, 0) > 0) {
		type = bt_audio_strtype(rsp->type);
		name = bt_audio_strname(rsp->name);
		if (type && name) {
			DBG("Received %s - %s", type, name);
			err = 0;
		} else {
			err = -EINVAL;
			ERR("Bogus message type %d - name %d"
				"received from audio service",
				rsp->type, rsp->name);
		}
	} else {
		err = -errno;
		ERR("Error receiving data from audio service: %s(%d)",
			strerror(errno), errno);
	}

	return err;
}

static ssize_t service_expect(struct userdata *u, bt_audio_msg_header_t *rsp,
				uint8_t expected_name)
{
	int r;

	assert(u);
	assert(u->service_fd >= 0);
	assert(rsp);

	if ((r = service_recv(u, rsp)) < 0)
		return r;

	if ((rsp->type != BT_INDICATION && rsp->type != BT_RESPONSE) ||
			(rsp->name != expected_name)) {
		if (rsp->type == BT_ERROR && rsp->length == sizeof(bt_audio_error_t))
			ERR("Received error condition: %s",
				strerror(((bt_audio_error_t*) rsp)->posix_errno));
		else
			ERR("Bogus message %s received while %s was expected",
				bt_audio_strname(rsp->name),
				bt_audio_strname(expected_name));
		return -1;
	}

	return 0;
}

static int init_bt(struct userdata *u)
{
	assert(u);

	if (u->service_fd != -1)
		return 0;

	DBG("bt_audio_service_open");

	u->service_fd = bt_audio_service_open();
	if (u->service_fd <= 0) {
		perror(strerror(errno));
		return errno;
	}

	return 0;
}

static int parse_caps(struct userdata *u, const struct bt_get_capabilities_rsp *rsp)
{
	unsigned char *ptr;
	uint16_t bytes_left;
	codec_capabilities_t codec;

	assert(u);
	assert(rsp);

	bytes_left = rsp->h.length - sizeof(*rsp);

	if (bytes_left < sizeof(codec_capabilities_t)) {
		ERR("Packet too small to store codec information.");
		return -1;
	}

	ptr = ((void *) rsp) + sizeof(*rsp);

	memcpy(&codec, ptr, sizeof(codec)); /** ALIGNMENT? **/

	DBG("Payload size is %lu %lu",
		(unsigned long) bytes_left, (unsigned long) sizeof(codec));

	if (u->transport != codec.transport) {
		ERR("Got capabilities for wrong codec.");
		return -1;
	}

	if (u->transport == BT_CAPABILITIES_TRANSPORT_SCO) {

		if (bytes_left <= 0 ||
				codec.length != sizeof(u->hsp.pcm_capabilities))
			return -1;

		assert(codec.type == BT_HFP_CODEC_PCM);

		memcpy(&u->hsp.pcm_capabilities,
				&codec, sizeof(u->hsp.pcm_capabilities));

		DBG("Has NREC: %s",
			YES_NO(u->hsp.pcm_capabilities.flags & BT_PCM_FLAG_NREC));

	} else if (u->transport == BT_CAPABILITIES_TRANSPORT_A2DP) {

		while (bytes_left > 0) {
			if (codec.type == BT_A2DP_SBC_SINK &&
					!(codec.lock & BT_WRITE_LOCK))
				break;

			bytes_left -= codec.length;
			ptr += codec.length;
			memcpy(&codec, ptr, sizeof(codec));
		}

		DBG("bytes_left = %d, codec.length = %d",
						bytes_left, codec.length);

		if (bytes_left <= 0 ||
				codec.length != sizeof(u->a2dp.sbc_capabilities))
			return -1;

		assert(codec.type == BT_A2DP_SBC_SINK);

		memcpy(&u->a2dp.sbc_capabilities, &codec,
					sizeof(u->a2dp.sbc_capabilities));
	} else {
		assert(0);
	}

	return 0;
}

static int get_caps(struct userdata *u)
{
	union {
		struct bt_get_capabilities_req getcaps_req;
		struct bt_get_capabilities_rsp getcaps_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	assert(u);

	memset(&msg, 0, sizeof(msg));
	msg.getcaps_req.h.type = BT_REQUEST;
	msg.getcaps_req.h.name = BT_GET_CAPABILITIES;
	msg.getcaps_req.h.length = sizeof(msg.getcaps_req);

	strncpy(msg.getcaps_req.destination, u->address,
			sizeof(msg.getcaps_req.destination));
	msg.getcaps_req.transport = u->transport;
	msg.getcaps_req.flags = BT_FLAG_AUTOCONNECT;

	if (service_send(u, &msg.getcaps_req.h) < 0)
		return -1;

	msg.getcaps_rsp.h.length = 0;
	if (service_expect(u, &msg.getcaps_rsp.h, BT_GET_CAPABILITIES) < 0)
		return -1;

	return parse_caps(u, &msg.getcaps_rsp);
}

static uint8_t a2dp_default_bitpool(uint8_t freq, uint8_t mode)
{
	switch (freq) {
	case BT_SBC_SAMPLING_FREQ_16000:
	case BT_SBC_SAMPLING_FREQ_32000:
		return 53;

	case BT_SBC_SAMPLING_FREQ_44100:

		switch (mode) {
		case BT_A2DP_CHANNEL_MODE_MONO:
		case BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL:
			return 31;

		case BT_A2DP_CHANNEL_MODE_STEREO:
		case BT_A2DP_CHANNEL_MODE_JOINT_STEREO:
			return 53;

		default:
			DBG("Invalid channel mode %u", mode);
			return 53;
		}

	case BT_SBC_SAMPLING_FREQ_48000:

		switch (mode) {
		case BT_A2DP_CHANNEL_MODE_MONO:
		case BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL:
			return 29;

		case BT_A2DP_CHANNEL_MODE_STEREO:
		case BT_A2DP_CHANNEL_MODE_JOINT_STEREO:
			return 51;

		default:
			DBG("Invalid channel mode %u", mode);
			return 51;
		}

	default:
		DBG("Invalid sampling freq %u", freq);
		return 53;
	}
}

static int setup_a2dp(struct userdata *u)
{
	sbc_capabilities_t *cap;
	int i;

	static const struct {
		uint32_t rate;
		uint8_t cap;
	} freq_table[] = {
		{ 16000U, BT_SBC_SAMPLING_FREQ_16000 },
		{ 32000U, BT_SBC_SAMPLING_FREQ_32000 },
		{ 44100U, BT_SBC_SAMPLING_FREQ_44100 },
		{ 48000U, BT_SBC_SAMPLING_FREQ_48000 }
	};

	assert(u);
	assert(u->transport == BT_CAPABILITIES_TRANSPORT_A2DP);

	cap = &u->a2dp.sbc_capabilities;

	/* Find the lowest freq that is at least as high as the requested
	 * sampling rate */
	for (i = 0; (unsigned) i < ARRAY_SIZE(freq_table); i++)
		if (freq_table[i].rate >= u->rate &&
			(cap->frequency & freq_table[i].cap)) {
			u->rate = freq_table[i].rate;
			cap->frequency = freq_table[i].cap;
			break;
		}

	if ((unsigned) i >= ARRAY_SIZE(freq_table)) {
		for (; i >= 0; i--) {
			if (cap->frequency & freq_table[i].cap) {
				u->rate = freq_table[i].rate;
				cap->frequency = freq_table[i].cap;
				break;
			}
		}

		if (i < 0) {
			DBG("Not suitable sample rate");
			return -1;
		}
	}

	if (u->channels <= 1) {
		if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_MONO) {
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_MONO;
			u->channels = 1;
		} else
			u->channels = 2;
	}

	if (u->channels >= 2) {
		u->channels = 2;

		if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_JOINT_STEREO)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_JOINT_STEREO;
		else if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_STEREO)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_STEREO;
		else if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL;
		else if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_MONO) {
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_MONO;
			u->channels = 1;
		} else {
			DBG("No supported channel modes");
			return -1;
		}
	}

	if (cap->block_length & BT_A2DP_BLOCK_LENGTH_16)
		cap->block_length = BT_A2DP_BLOCK_LENGTH_16;
	else if (cap->block_length & BT_A2DP_BLOCK_LENGTH_12)
		cap->block_length = BT_A2DP_BLOCK_LENGTH_12;
	else if (cap->block_length & BT_A2DP_BLOCK_LENGTH_8)
		cap->block_length = BT_A2DP_BLOCK_LENGTH_8;
	else if (cap->block_length & BT_A2DP_BLOCK_LENGTH_4)
		cap->block_length = BT_A2DP_BLOCK_LENGTH_4;
	else {
		DBG("No supported block lengths");
		return -1;
	}

	if (cap->subbands & BT_A2DP_SUBBANDS_8)
		cap->subbands = BT_A2DP_SUBBANDS_8;
	else if (cap->subbands & BT_A2DP_SUBBANDS_4)
		cap->subbands = BT_A2DP_SUBBANDS_4;
	else {
		DBG("No supported subbands");
		return -1;
	}

	if (cap->allocation_method & BT_A2DP_ALLOCATION_LOUDNESS)
		cap->allocation_method = BT_A2DP_ALLOCATION_LOUDNESS;
	else if (cap->allocation_method & BT_A2DP_ALLOCATION_SNR)
		cap->allocation_method = BT_A2DP_ALLOCATION_SNR;

	cap->min_bitpool = (uint8_t) MAX(MIN_BITPOOL, cap->min_bitpool);
	cap->max_bitpool = (uint8_t) MIN(
		a2dp_default_bitpool(cap->frequency, cap->channel_mode),
		cap->max_bitpool);

	return 0;
}

static void setup_sbc(struct a2dp_info *a2dp)
{
	sbc_capabilities_t *active_capabilities;

	assert(a2dp);

	active_capabilities = &a2dp->sbc_capabilities;

	if (a2dp->sbc_initialized)
		sbc_reinit(&a2dp->sbc, 0);
	else
		sbc_init(&a2dp->sbc, 0);
	a2dp->sbc_initialized = TRUE;

	switch (active_capabilities->frequency) {
	case BT_SBC_SAMPLING_FREQ_16000:
		a2dp->sbc.frequency = SBC_FREQ_16000;
		break;
	case BT_SBC_SAMPLING_FREQ_32000:
		a2dp->sbc.frequency = SBC_FREQ_32000;
		break;
	case BT_SBC_SAMPLING_FREQ_44100:
		a2dp->sbc.frequency = SBC_FREQ_44100;
		break;
	case BT_SBC_SAMPLING_FREQ_48000:
		a2dp->sbc.frequency = SBC_FREQ_48000;
		break;
	default:
		assert(0);
	}

	switch (active_capabilities->channel_mode) {
	case BT_A2DP_CHANNEL_MODE_MONO:
		a2dp->sbc.mode = SBC_MODE_MONO;
		break;
	case BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL:
		a2dp->sbc.mode = SBC_MODE_DUAL_CHANNEL;
		break;
	case BT_A2DP_CHANNEL_MODE_STEREO:
		a2dp->sbc.mode = SBC_MODE_STEREO;
		break;
	case BT_A2DP_CHANNEL_MODE_JOINT_STEREO:
		a2dp->sbc.mode = SBC_MODE_JOINT_STEREO;
		break;
	default:
		assert(0);
	}

	switch (active_capabilities->allocation_method) {
	case BT_A2DP_ALLOCATION_SNR:
		a2dp->sbc.allocation = SBC_AM_SNR;
		break;
	case BT_A2DP_ALLOCATION_LOUDNESS:
		a2dp->sbc.allocation = SBC_AM_LOUDNESS;
		break;
	default:
		assert(0);
	}

	switch (active_capabilities->subbands) {
	case BT_A2DP_SUBBANDS_4:
		a2dp->sbc.subbands = SBC_SB_4;
		break;
	case BT_A2DP_SUBBANDS_8:
		a2dp->sbc.subbands = SBC_SB_8;
		break;
	default:
		assert(0);
	}

	switch (active_capabilities->block_length) {
	case BT_A2DP_BLOCK_LENGTH_4:
		a2dp->sbc.blocks = SBC_BLK_4;
		break;
	case BT_A2DP_BLOCK_LENGTH_8:
		a2dp->sbc.blocks = SBC_BLK_8;
		break;
	case BT_A2DP_BLOCK_LENGTH_12:
		a2dp->sbc.blocks = SBC_BLK_12;
		break;
	case BT_A2DP_BLOCK_LENGTH_16:
		a2dp->sbc.blocks = SBC_BLK_16;
		break;
	default:
		assert(0);
	}

	a2dp->sbc.bitpool = active_capabilities->max_bitpool;
	a2dp->codesize = (uint16_t) sbc_get_codesize(&a2dp->sbc);
}

static int bt_open(struct userdata *u)
{
	union {
		struct bt_open_req open_req;
		struct bt_open_rsp open_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	memset(&msg, 0, sizeof(msg));
	msg.open_req.h.type = BT_REQUEST;
	msg.open_req.h.name = BT_OPEN;
	msg.open_req.h.length = sizeof(msg.open_req);

	strncpy(msg.open_req.destination, u->address,
			sizeof(msg.open_req.destination));
	msg.open_req.seid = u->transport == BT_CAPABILITIES_TRANSPORT_A2DP ?
				u->a2dp.sbc_capabilities.capability.seid :
				BT_A2DP_SEID_RANGE + 1;
	msg.open_req.lock = u->transport == BT_CAPABILITIES_TRANSPORT_A2DP ?
				BT_WRITE_LOCK : BT_READ_LOCK | BT_WRITE_LOCK;

	if (service_send(u, &msg.open_req.h) < 0)
		return -1;

	msg.open_rsp.h.length = sizeof(msg.open_rsp);
	if (service_expect(u, &msg.open_rsp.h, BT_OPEN) < 0)
		return -1;

	return 0;
}

static int set_conf(struct userdata *u)
{
	union {
		struct bt_set_configuration_req setconf_req;
		struct bt_set_configuration_rsp setconf_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	if (u->transport == BT_CAPABILITIES_TRANSPORT_A2DP) {
		if (setup_a2dp(u) < 0)
			return -1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.setconf_req.h.type = BT_REQUEST;
	msg.setconf_req.h.name = BT_SET_CONFIGURATION;
	msg.setconf_req.h.length = sizeof(msg.setconf_req);

	if (u->transport == BT_CAPABILITIES_TRANSPORT_A2DP) {
		memcpy(&msg.setconf_req.codec, &u->a2dp.sbc_capabilities,
			sizeof(u->a2dp.sbc_capabilities));
		msg.setconf_req.h.length += msg.setconf_req.codec.length -
			sizeof(msg.setconf_req.codec);
	} else {
		msg.setconf_req.codec.transport = BT_CAPABILITIES_TRANSPORT_SCO;
		msg.setconf_req.codec.seid = BT_A2DP_SEID_RANGE + 1;
		msg.setconf_req.codec.length = sizeof(pcm_capabilities_t);
	}

	if (service_send(u, &msg.setconf_req.h) < 0)
		return -1;

	msg.setconf_rsp.h.length = sizeof(msg.setconf_rsp);
	if (service_expect(u, &msg.setconf_rsp.h, BT_SET_CONFIGURATION) < 0)
		return -1;

	u->link_mtu = msg.setconf_rsp.link_mtu;

	/* setup SBC encoder now we agree on parameters */
	if (u->transport == BT_CAPABILITIES_TRANSPORT_A2DP) {
		setup_sbc(&u->a2dp);
		u->block_size = u->a2dp.codesize;
		DBG("SBC parameters:\n\tallocation=%u\n"
			"\tsubbands=%u\n\tblocks=%u\n\tbitpool=%u\n",
			u->a2dp.sbc.allocation, u->a2dp.sbc.subbands,
			u->a2dp.sbc.blocks, u->a2dp.sbc.bitpool);
	} else
		u->block_size = u->link_mtu;

	return 0;
}

static int setup_bt(struct userdata *u)
{
	assert(u);

	if (get_caps(u) < 0)
		return -1;

	DBG("Got device caps");

	if (bt_open(u) < 0)
		return -1;

	if (set_conf(u) < 0)
		return -1;

	return 0;
}

static int init_profile(struct userdata *u)
{
	assert(u);

	return setup_bt(u);
}

static void shutdown_bt(struct userdata *u)
{
	assert(u);

	if (u->stream_fd != -1) {
		stop_stream(u);
		DBG("close(stream_fd)");
		close(u->stream_fd);
		u->stream_fd = -1;
	}

	if (u->service_fd != -1) {
		DBG("bt_audio_service_close");
		bt_audio_service_close(u->service_fd);
		u->service_fd = -1;
	}
}

static void make_fd_nonblock(int fd)
{
	int v;

	assert(fd >= 0);
	assert((v = fcntl(fd, F_GETFL)) >= 0);

	if (!(v & O_NONBLOCK))
		assert(fcntl(fd, F_SETFL, v|O_NONBLOCK) >= 0);
}

static void make_socket_low_delay(int fd)
{
/* FIXME: is this widely supported? */
#ifdef SO_PRIORITY
	int priority;
	assert(fd >= 0);

	priority = 6;
	if (setsockopt(fd, SOL_SOCKET, SO_PRIORITY, (void*)&priority,
			sizeof(priority)) < 0)
		ERR("SO_PRIORITY failed: %s", strerror(errno));
#endif
}

static int read_stream(struct userdata *u)
{
	int ret = 0;
	ssize_t l;
	char *buf;

	assert(u);
	assert(u->stream_fd >= 0);

	buf = alloca(u->link_mtu);

	for (;;) {
		l = read(u->stream_fd, buf, u->link_mtu);
		if (u->debug_stream_read)
			DBG("read from socket: %lli bytes", (long long) l);
		if (l <= 0) {
			if (l < 0 && errno == EINTR)
				continue;
			else {
				ERR("Failed to read date from stream_fd: %s",
					ret < 0 ? strerror(errno) : "EOF");
				return -1;
			}
		} else {
			break;
		}
	}

	return ret;
}

/* It's what PulseAudio is doing, not sure it's necessary for this
 * test */
static ssize_t pa_write(int fd, const void *buf, size_t count)
{
	ssize_t r;

	if ((r = send(fd, buf, count, MSG_NOSIGNAL)) >= 0)
		return r;

	if (errno != ENOTSOCK)
		return r;

	return write(fd, buf, count);
}

static int write_stream(struct userdata *u)
{
	int ret = 0;
	ssize_t l;
	char *buf;

	assert(u);
	assert(u->stream_fd >= 0);
	buf = alloca(u->link_mtu);

	for (;;) {
		l = pa_write(u->stream_fd, buf, u->link_mtu);
		if (u->debug_stream_write)
			DBG("written to socket: %lli bytes", (long long) l);
		assert(l != 0);
		if (l < 0) {
			if (errno == EINTR)
				continue;
			else {
				ERR("Failed to write data: %s", strerror(errno));
				ret = -1;
				break;
			}
		} else {
			assert((size_t)l <= u->link_mtu);
			break;
		}
	}

	return ret;
}

static gboolean stream_cb(GIOChannel *gin, GIOCondition condition, gpointer data)
{
	struct userdata *u;

	assert(u = data);

	if (condition & G_IO_IN) {
		if (read_stream(u) < 0)
			goto fail;
	} else if (condition & G_IO_OUT) {
		if (write_stream(u) < 0)
			goto fail;
	} else {
		DBG("Got %d", condition);
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	return TRUE;

fail:
	stop_stream(u);
	return FALSE;
}

static int start_stream(struct userdata *u)
{
	union {
		bt_audio_msg_header_t rsp;
		struct bt_start_stream_req start_req;
		struct bt_start_stream_rsp start_rsp;
		struct bt_new_stream_ind streamfd_ind;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;

	assert(u);

	if (u->stream_fd >= 0)
		return 0;
	if (u->stream_watch != 0) {
		g_source_remove(u->stream_watch);
		u->stream_watch = 0;
	}
	if (u->stream_channel != 0) {
		g_io_channel_unref(u->stream_channel);
		u->stream_channel = NULL;
	}

	memset(msg.buf, 0, BT_SUGGESTED_BUFFER_SIZE);
	msg.start_req.h.type = BT_REQUEST;
	msg.start_req.h.name = BT_START_STREAM;
	msg.start_req.h.length = sizeof(msg.start_req);

	if (service_send(u, &msg.start_req.h) < 0)
		return -1;

	msg.rsp.length = sizeof(msg.start_rsp);
	if (service_expect(u, &msg.rsp, BT_START_STREAM) < 0)
		return -1;

	msg.rsp.length = sizeof(msg.streamfd_ind);
	if (service_expect(u, &msg.rsp, BT_NEW_STREAM) < 0)
		return -1;

	if ((u->stream_fd = bt_audio_service_get_data_fd(u->service_fd)) < 0) {
		DBG("Failed to get stream fd from audio service.");
		return -1;
	}

	make_fd_nonblock(u->stream_fd);
	make_socket_low_delay(u->stream_fd);

	assert(u->stream_channel = g_io_channel_unix_new(u->stream_fd));

	u->stream_watch = g_io_add_watch(u->stream_channel,
					G_IO_IN|G_IO_OUT|G_IO_ERR|G_IO_HUP|G_IO_NVAL,
					stream_cb, u);

	return 0;
}

static int stop_stream(struct userdata *u)
{
	union {
		bt_audio_msg_header_t rsp;
		struct bt_stop_stream_req stop_req;
		struct bt_stop_stream_rsp stop_rsp;
		bt_audio_error_t error;
		uint8_t buf[BT_SUGGESTED_BUFFER_SIZE];
	} msg;
	int r = 0;

	if (u->stream_fd < 0)
		return 0;

	assert(u);
	assert(u->stream_channel);

	g_source_remove(u->stream_watch);
	u->stream_watch = 0;
	g_io_channel_unref(u->stream_channel);
	u->stream_channel = NULL;

	memset(msg.buf, 0, BT_SUGGESTED_BUFFER_SIZE);
	msg.stop_req.h.type = BT_REQUEST;
	msg.stop_req.h.name = BT_STOP_STREAM;
	msg.stop_req.h.length = sizeof(msg.stop_req);

	if (service_send(u, &msg.stop_req.h) < 0) {
		r = -1;
		goto done;
	}

	msg.rsp.length = sizeof(msg.stop_rsp);
	if (service_expect(u, &msg.rsp, BT_STOP_STREAM) < 0)
		r = -1;

done:
	close(u->stream_fd);
	u->stream_fd = -1;

	return r;
}

static gboolean sleep_cb(gpointer data)
{
	struct userdata *u;

	assert(u = data);

	u->gin_watch = g_io_add_watch(u->gin,
		G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL, input_cb, data);

	printf(">>> ");
	fflush(stdout);

	return FALSE;
}

static gboolean input_cb(GIOChannel *gin, GIOCondition condition, gpointer data)
{
	char *line, *tmp;
	gsize term_pos;
	GError *error = NULL;
	struct userdata *u;
	int success;

	assert(u = data);
	if (!(condition & G_IO_IN)) {
		DBG("Got %d", condition);
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	if (g_io_channel_read_line(gin, &line, NULL, &term_pos, &error) !=
		G_IO_STATUS_NORMAL)
		return FALSE;

	line[term_pos] = '\0';
	g_strstrip(line);
	if ((tmp = strchr(line, '#')))
		*tmp = '\0';
	success = FALSE;

#define IF_CMD(cmd) \
	if (!success && (success = (strncmp(line, #cmd, strlen(#cmd)) == 0)))

	IF_CMD(quit) {
		g_main_loop_quit(main_loop);
		return FALSE;
	}

	IF_CMD(sleep) {
		unsigned int seconds;
		if (sscanf(line, "%*s %d", &seconds) != 1)
			DBG("sleep SECONDS");
		else {
			g_source_remove(u->gin_watch);
			g_timeout_add_seconds(seconds, sleep_cb, u);
			return FALSE;
		}
	}

	IF_CMD(debug) {
		char *what = NULL;
		int enable;

		if (sscanf(line, "%*s %as %d", &what, &enable) != 1)
			DBG("debug [stream_read|stream_write] [0|1]");
		if (strncmp(what, "stream_read", 12) == 0) {
			u->debug_stream_read = enable;
		} else if (strncmp(what, "stream_write", 13) == 0) {
			u->debug_stream_write = enable;
		} else {
			DBG("debug [stream_read|stream_write] [0|1]");
		}
	}

	IF_CMD(init_bt) {
		DBG("%d", init_bt(u));
	}

	IF_CMD(init_profile) {
		DBG("%d", init_profile(u));
	}

	IF_CMD(start_stream) {
		DBG("%d", start_stream(u));
	}

	IF_CMD(stop_stream) {
		DBG("%d", stop_stream(u));
	}

	IF_CMD(shutdown_bt) {
		shutdown_bt(u);
	}

	IF_CMD(rate) {
		if (sscanf(line, "%*s %d", &u->rate) != 1)
			DBG("set with rate RATE");
		DBG("rate %d", u->rate);
	}

	IF_CMD(bdaddr) {
		char *address;

		if (sscanf(line, "%*s %as", &address) != 1)
			DBG("set with bdaddr BDADDR");

		free(u->address);

		u->address = address;
		DBG("bdaddr %s", u->address);
	}

	IF_CMD(profile) {
		char *profile = NULL;

		if (sscanf(line, "%*s %as", &profile) != 1)
			DBG("set with profile [hsp|a2dp]");
		if (strncmp(profile, "hsp", 4) == 0) {
			u->transport = BT_CAPABILITIES_TRANSPORT_SCO;
		} else if (strncmp(profile, "a2dp", 5) == 0) {
			u->transport = BT_CAPABILITIES_TRANSPORT_A2DP;
		} else {
			DBG("set with profile [hsp|a2dp]");
		}

		free(profile);
		DBG("profile %s", u->transport == BT_CAPABILITIES_TRANSPORT_SCO ?
			"hsp" : "a2dp");
	}

	if (!success && strlen(line) != 0) {
		DBG("%s, unknown command", line);
	}

	printf(">>> ");
	fflush(stdout);
	return TRUE;
}


static void show_usage(char* prgname)
{
	printf("%s: ipctest [--interactive] BDADDR\n", basename(prgname));
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		show_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	assert(main_loop = g_main_loop_new(NULL, FALSE));

	if (strncmp("--interactive", argv[1], 14) == 0) {
		if (argc < 3) {
			show_usage(argv[0]);
			exit(EXIT_FAILURE);
		}

		data.address = strdup(argv[2]);

		signal(SIGTERM, sig_term);
		signal(SIGINT, sig_term);

		assert(data.gin = g_io_channel_unix_new(fileno(stdin)));

		data.gin_watch = g_io_add_watch(data.gin,
			G_IO_IN|G_IO_ERR|G_IO_HUP|G_IO_NVAL, input_cb, &data);

		printf(">>> ");
		fflush(stdout);

		g_main_loop_run(main_loop);

	} else {
		data.address = strdup(argv[1]);

		assert(init_bt(&data) == 0);

		assert(init_profile(&data) == 0);

		assert(start_stream(&data) == 0);

		g_main_loop_run(main_loop);

		assert(stop_stream(&data) == 0);

		shutdown_bt(&data);
	}

	g_main_loop_unref(main_loop);

	printf("\nExiting\n");

	exit(EXIT_SUCCESS);

	return 0;
}
