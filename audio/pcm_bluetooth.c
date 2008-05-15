/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>

#include <netinet/in.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#include "ipc.h"
#include "sbc.h"
#include "rtp.h"

//#define ENABLE_DEBUG

#define UINT_SECS_MAX (UINT_MAX / 1000000 - 1)

#define MIN_PERIOD_TIME 1

#define BUFFER_SIZE 2048

#ifdef ENABLE_DEBUG
#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
#else
#define DBG(fmt, arg...)
#endif

#ifndef SOL_SCO
#define SOL_SCO 17
#endif

#ifndef SCO_TXBUFS
#define SCO_TXBUFS 0x03
#endif

#ifndef SCO_RXBUFS
#define SCO_RXBUFS 0x04
#endif

#ifndef MIN
# define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
# define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define MAX_BITPOOL 64
#define MIN_BITPOOL 2

/* adapted from glibc sys/time.h timersub() macro */
#define priv_timespecsub(a, b, result)					\
	do {								\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
		(result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;	\
		if ((result)->tv_nsec < 0) {				\
			--(result)->tv_sec;				\
			(result)->tv_nsec += 1000000000;		\
		}							\
	} while (0)

struct bluetooth_a2dp {
	sbc_capabilities_t sbc_capabilities;
	sbc_t sbc;				/* Codec data */
	int sbc_initialized;			/* Keep track if the encoder is initialized */
	int codesize;				/* SBC codesize */
	int samples;				/* Number of encoded samples */
	uint8_t buffer[BUFFER_SIZE];		/* Codec transfer buffer */
	int count;				/* Codec transfer buffer counter */

	int nsamples;				/* Cumulative number of codec samples */
	uint16_t seq_num;			/* Cumulative packet sequence */
	int frame_count;			/* Current frames in buffer*/
};

struct bluetooth_alsa_config {
	char device[18];		/* Address of the remote Device */
	int has_device;
	uint8_t transport;		/* Requested transport */
	int has_transport;
	uint16_t rate;
	int has_rate;
	uint8_t channel_mode;		/* A2DP only */
	int has_channel_mode;
	uint8_t allocation_method;	/* A2DP only */
	int has_allocation_method;
	uint8_t subbands;		/* A2DP only */
	int has_subbands;
	uint8_t block_length;		/* A2DP only */
	int has_block_length;
	uint8_t bitpool;		/* A2DP only */
	int has_bitpool;
	int autoconnect;
};

struct bluetooth_data {
	snd_pcm_ioplug_t io;
	struct bluetooth_alsa_config alsa_config;	/* ALSA resource file parameters */
	volatile snd_pcm_sframes_t hw_ptr;
	int transport;					/* chosen transport SCO or AD2P */
	int link_mtu;					/* MTU for selected transport channel */
	volatile struct pollfd stream;			/* Audio stream filedescriptor */
	struct pollfd server;				/* Audio daemon filedescriptor */
	uint8_t buffer[BUFFER_SIZE];		/* Encoded transfer buffer */
	int count;					/* Transfer buffer counter */
	struct bluetooth_a2dp a2dp;			/* A2DP data */

	pthread_t hw_thread;				/* Makes virtual hw pointer move */
	int pipefd[2];					/* Inter thread communication */
	int stopped;
	sig_atomic_t reset;             /* Request XRUN handling */
};

static int audioservice_send(int sk, const bt_audio_msg_header_t *msg);
static int audioservice_expect(int sk, bt_audio_msg_header_t *outmsg,
				int expected_type);

static int bluetooth_start(snd_pcm_ioplug_t *io)
{
	DBG("bluetooth_start %p", io);

	return 0;
}

static int bluetooth_stop(snd_pcm_ioplug_t *io)
{
	DBG("bluetooth_stop %p", io);

	return 0;
}

static void *playback_hw_thread(void *param)
{
	struct bluetooth_data *data = param;
	unsigned int prev_periods;
	double period_time;
	struct timespec start;
	struct pollfd fds[2];
	int poll_timeout;

	data->server.events = POLLIN;
	/* note: only errors for data->stream.events */

	fds[0] = data->server;
	fds[1] = data->stream;

	prev_periods = 0;
	period_time = 1000000.0 * data->io.period_size / data->io.rate;
	if (period_time > (int) (MIN_PERIOD_TIME * 1000))
		poll_timeout = (int) (period_time / 1000.0f);
	else
		poll_timeout = MIN_PERIOD_TIME;

	clock_gettime(CLOCK_MONOTONIC, &start);

	while (1) {
		unsigned int dtime, periods;
		struct timespec cur, delta;
		int ret;

		if (data->stopped)
			goto iter_sleep;

		if (data->reset) {
			DBG("Handle XRUN in hw-thread.");
			data->reset = 0;
			clock_gettime(CLOCK_MONOTONIC, &start);
			prev_periods = 0;
		}

		clock_gettime(CLOCK_MONOTONIC, &cur);

		priv_timespecsub(&cur, &start, &delta);

		dtime = delta.tv_sec * 1000000 + delta.tv_nsec / 1000;
		periods = 1.0 * dtime / period_time;

		if (periods > prev_periods) {
			char c = 'w';
			int frags = periods - prev_periods, n;

			data->hw_ptr += frags *	data->io.period_size;
			data->hw_ptr %= data->io.buffer_size;

			for (n = 0; n < frags; n++) {
				/* Notify user that hardware pointer
				 * has moved * */
				if (write(data->pipefd[1], &c, 1) < 0)
					pthread_testcancel();
			}

			/* Reset point of reference to avoid too big values
			 * that wont fit an unsigned int */
			if (delta.tv_sec < UINT_SECS_MAX)
				prev_periods = periods;
			else {
				prev_periods = 0;
				clock_gettime(CLOCK_MONOTONIC, &start);
			}
		}

iter_sleep:
		/* sleep up to one period interval */
		ret = poll(fds, 2, poll_timeout);

		if (ret < 0) {
			SNDERR("poll error: %s (%d)", strerror(errno), errno);
			if (errno != EINTR)
				break;
		} else if (ret > 0) {
			ret = (fds[0].revents) ? 0 : 1;
			SNDERR("poll fd %d revents %d", ret, fds[ret].revents);
			if (fds[ret].revents & (POLLERR | POLLHUP | POLLNVAL))
				break;
		}

		/* Offer opportunity to be canceled by main thread */
		pthread_testcancel();
	}

	data->hw_thread = 0;
	pthread_exit(NULL);
}

static int bluetooth_playback_start(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;
	int err;

	DBG("%p", io);

	data->stopped = 0;

	if (data->hw_thread)
		return 0;

	err = pthread_create(&data->hw_thread, 0, playback_hw_thread, data);

	return -err;
}

static int bluetooth_playback_stop(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	DBG("%p", io);

	data->stopped = 1;

	return 0;
}

static snd_pcm_sframes_t bluetooth_pointer(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	return data->hw_ptr;
}

static void bluetooth_exit(struct bluetooth_data *data)
{
	struct bluetooth_a2dp *a2dp = &data->a2dp;

	if (data->server.fd >= 0)
		bt_audio_service_close(data->server.fd);

	if (data->stream.fd >= 0)
		close(data->stream.fd);

	if (data->hw_thread) {
		pthread_cancel(data->hw_thread);
		pthread_join(data->hw_thread, 0);
	}

	if (a2dp->sbc_initialized)
		sbc_finish(&a2dp->sbc);

	if (data->pipefd[0] > 0)
		close(data->pipefd[0]);

	if (data->pipefd[1] > 0)
		close(data->pipefd[1]);

	free(data);
}

static int bluetooth_close(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	DBG("%p", io);

	bluetooth_exit(data);

	return 0;
}

static int bluetooth_prepare(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;
	char c = 'w';
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	struct bt_streamstart_req *start_req = (void*) buf;
	bt_audio_rsp_msg_header_t *rsp_hdr = (void*) buf;
	struct bt_streamfd_ind *streamfd_ind = (void*) buf;
	uint32_t period_count = io->buffer_size / io->period_size;
	int opt_name, err;
	struct timeval t = { 0, period_count };

	DBG("Preparing with io->period_size=%lu io->buffer_size=%lu",
					io->period_size, io->buffer_size);

	data->reset = 0;

	/* As we're gonna receive messages on the server socket, we have to stop the
	   hw thread that is polling on it, if any */
	if (data->hw_thread) {
		pthread_cancel(data->hw_thread);
		pthread_join(data->hw_thread, 0);
		data->hw_thread = 0;
	}

	if (io->stream == SND_PCM_STREAM_PLAYBACK)
		/* If not null for playback, xmms doesn't display time
		 * correctly */
		data->hw_ptr = 0;
	else
		/* ALSA library is really picky on the fact hw_ptr is not null.
		 * If it is, capture won't start */
		data->hw_ptr = io->period_size;

	/* send start */
	memset(start_req, 0, BT_AUDIO_IPC_PACKET_SIZE);
	start_req->h.msg_type = BT_STREAMSTART_REQ;

	err = audioservice_send(data->server.fd, &start_req->h);
	if (err < 0)
		return err;

	err = audioservice_expect(data->server.fd, &rsp_hdr->msg_h,
					BT_STREAMSTART_RSP);
	if (err < 0)
		return err;

	if (rsp_hdr->posix_errno != 0) {
		SNDERR("BT_START failed : %s(%d)",
					strerror(rsp_hdr->posix_errno),
					rsp_hdr->posix_errno);
		return -rsp_hdr->posix_errno;
	}

	err = audioservice_expect(data->server.fd, &streamfd_ind->h,
					BT_STREAMFD_IND);
	if (err < 0)
		return err;

	if (data->stream.fd >= 0)
		close(data->stream.fd);

	data->stream.fd = bt_audio_service_get_data_fd(data->server.fd);
	if (data->stream.fd < 0) {
		return -errno;
	}

	if (data->transport == BT_CAPABILITIES_TRANSPORT_A2DP) {
		opt_name = (io->stream == SND_PCM_STREAM_PLAYBACK) ?
						SO_SNDTIMEO : SO_RCVTIMEO;

		if (setsockopt(data->stream.fd, SOL_SOCKET, opt_name, &t,
							sizeof(t)) < 0)
			return -errno;
	} else {
		opt_name = (io->stream == SND_PCM_STREAM_PLAYBACK) ?
						SCO_TXBUFS : SCO_RXBUFS;

		if (setsockopt(data->stream.fd, SOL_SCO, opt_name, &period_count,
						sizeof(period_count)) == 0)
			return 0;

		opt_name = (io->stream == SND_PCM_STREAM_PLAYBACK) ?
						SO_SNDBUF : SO_RCVBUF;

		if (setsockopt(data->stream.fd, SOL_SCO, opt_name, &period_count,
						sizeof(period_count)) == 0)
			return 0;

		/* FIXME : handle error codes */
	}

	/* wake up any client polling at us */
	err = write(data->pipefd[1], &c, 1);
	if (err < 0)
		return err;

	return 0;
}

static int bluetooth_hsp_hw_params(snd_pcm_ioplug_t *io,
					snd_pcm_hw_params_t *params)
{
	struct bluetooth_data *data = io->private_data;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	bt_audio_rsp_msg_header_t *rsp_hdr = (void*) buf;
	struct bt_setconfiguration_req *setconf_req = (void*) buf;
	struct bt_setconfiguration_rsp *setconf_rsp = (void*) buf;
	int err;

	DBG("Preparing with io->period_size=%lu io->buffer_size=%lu",
					io->period_size, io->buffer_size);

	memset(setconf_req, 0, BT_AUDIO_IPC_PACKET_SIZE);
	setconf_req->h.msg_type = BT_SETCONFIGURATION_REQ;
	strncpy(setconf_req->device, data->alsa_config.device, 18);
	setconf_req->transport = BT_CAPABILITIES_TRANSPORT_SCO;
	setconf_req->access_mode = (io->stream == SND_PCM_STREAM_PLAYBACK ?
			BT_CAPABILITIES_ACCESS_MODE_WRITE :
			BT_CAPABILITIES_ACCESS_MODE_READ);

	err = audioservice_send(data->server.fd, &setconf_req->h);
	if (err < 0)
		return err;

	err = audioservice_expect(data->server.fd, &rsp_hdr->msg_h,
					BT_SETCONFIGURATION_RSP);
	if (err < 0)
		return err;

	if (rsp_hdr->posix_errno != 0) {
		SNDERR("BT_SETCONFIGURATION failed : %s(%d)",
					strerror(rsp_hdr->posix_errno),
					rsp_hdr->posix_errno);
		return -rsp_hdr->posix_errno;
	}

	data->transport = setconf_rsp->transport;
	data->link_mtu = setconf_rsp->link_mtu;

	return 0;
}

static uint8_t default_bitpool(uint8_t freq, uint8_t mode)
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

static int bluetooth_a2dp_init(struct bluetooth_data *data,
				snd_pcm_hw_params_t *params)
{
	struct bluetooth_alsa_config *cfg = &data->alsa_config;
	sbc_capabilities_t *cap = &data->a2dp.sbc_capabilities;
	unsigned int max_bitpool, min_bitpool, rate, channels;
	int dir;

	snd_pcm_hw_params_get_rate(params, &rate, &dir);
	snd_pcm_hw_params_get_channels(params, &channels);

	switch (rate) {
	case 48000:
		cap->frequency = BT_SBC_SAMPLING_FREQ_48000;
		break;
	case 44100:
		cap->frequency = BT_SBC_SAMPLING_FREQ_44100;
		break;
	case 32000:
		cap->frequency = BT_SBC_SAMPLING_FREQ_32000;
		break;
	case 16000:
		cap->frequency = BT_SBC_SAMPLING_FREQ_16000;
		break;
	default:
		DBG("Rate %d not supported", rate);
		return -1;
	}

	if (cfg->has_channel_mode)
		cap->channel_mode = cfg->channel_mode;
	else if (channels == 2) {
		if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_JOINT_STEREO)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_JOINT_STEREO;
		else if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_STEREO)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_STEREO;
		else if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL;
	} else {
		if (cap->channel_mode & BT_A2DP_CHANNEL_MODE_MONO)
			cap->channel_mode = BT_A2DP_CHANNEL_MODE_MONO;
	}

	if (!cap->channel_mode) {
		DBG("No supported channel modes");
		return -1;
	}

	if (cfg->has_block_length)
		cap->block_length = cfg->block_length;
	else if (cap->block_length & BT_A2DP_BLOCK_LENGTH_16)
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

	if (cfg->has_subbands)
		cap->subbands = cfg->subbands;
	if (cap->subbands & BT_A2DP_SUBBANDS_8)
		cap->subbands = BT_A2DP_SUBBANDS_8;
	else if (cap->subbands & BT_A2DP_SUBBANDS_4)
		cap->subbands = BT_A2DP_SUBBANDS_4;
	else {
		DBG("No supported subbands");
		return -1;
	}

	if (cfg->has_allocation_method)
		cap->allocation_method = cfg->allocation_method;
	if (cap->allocation_method & BT_A2DP_ALLOCATION_LOUDNESS)
		cap->allocation_method = BT_A2DP_ALLOCATION_LOUDNESS;
	else if (cap->allocation_method & BT_A2DP_ALLOCATION_SNR)
		cap->allocation_method = BT_A2DP_ALLOCATION_SNR;

	if (cfg->has_bitpool)
		min_bitpool = max_bitpool = cfg->bitpool;
	else {
		min_bitpool = MAX(MIN_BITPOOL, cap->min_bitpool);
		max_bitpool = MIN(default_bitpool(cap->frequency,
					cap->channel_mode),
					cap->max_bitpool);
	}

	cap->min_bitpool = min_bitpool;
	cap->max_bitpool = max_bitpool;

	return 0;
}

static void bluetooth_a2dp_setup(struct bluetooth_a2dp *a2dp)
{
	sbc_capabilities_t active_capabilities = a2dp->sbc_capabilities;

	if (a2dp->sbc_initialized)
		sbc_reinit(&a2dp->sbc, 0);
	else
		sbc_init(&a2dp->sbc, 0);
	a2dp->sbc_initialized = 1;

	if (active_capabilities.frequency & BT_SBC_SAMPLING_FREQ_16000)
		a2dp->sbc.frequency = SBC_FREQ_16000;

	if (active_capabilities.frequency & BT_SBC_SAMPLING_FREQ_32000)
		a2dp->sbc.frequency = SBC_FREQ_32000;

	if (active_capabilities.frequency & BT_SBC_SAMPLING_FREQ_44100)
		a2dp->sbc.frequency = SBC_FREQ_44100;

	if (active_capabilities.frequency & BT_SBC_SAMPLING_FREQ_48000)
		a2dp->sbc.frequency = SBC_FREQ_48000;

	if (active_capabilities.channel_mode & BT_A2DP_CHANNEL_MODE_MONO)
		a2dp->sbc.mode = SBC_MODE_MONO;

	if (active_capabilities.channel_mode & BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL)
		a2dp->sbc.mode = SBC_MODE_DUAL_CHANNEL;

	if (active_capabilities.channel_mode & BT_A2DP_CHANNEL_MODE_STEREO)
		a2dp->sbc.mode = SBC_MODE_STEREO;

	if (active_capabilities.channel_mode & BT_A2DP_CHANNEL_MODE_JOINT_STEREO)
		a2dp->sbc.mode = SBC_MODE_JOINT_STEREO;

	a2dp->sbc.allocation = active_capabilities.allocation_method
				== BT_A2DP_ALLOCATION_SNR ? SBC_AM_SNR
				: SBC_AM_LOUDNESS;

	switch (active_capabilities.subbands) {
	case BT_A2DP_SUBBANDS_4:
		a2dp->sbc.subbands = SBC_SB_4;
		break;
	case BT_A2DP_SUBBANDS_8:
		a2dp->sbc.subbands = SBC_SB_8;
		break;
	}

	switch (active_capabilities.block_length) {
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
	}

	a2dp->sbc.bitpool = active_capabilities.max_bitpool;
	a2dp->codesize = sbc_get_codesize(&a2dp->sbc);
	a2dp->count = sizeof(struct rtp_header) + sizeof(struct rtp_payload);
}

static int bluetooth_a2dp_hw_params(snd_pcm_ioplug_t *io,
					snd_pcm_hw_params_t *params)
{
	struct bluetooth_data *data = io->private_data;
	struct bluetooth_a2dp *a2dp = &data->a2dp;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	bt_audio_rsp_msg_header_t *rsp_hdr = (void*) buf;
	struct bt_setconfiguration_req *setconf_req = (void*) buf;
	struct bt_setconfiguration_rsp *setconf_rsp = (void*) buf;
	int err;

	DBG("Preparing with io->period_size=%lu io->buffer_size=%lu",
					io->period_size, io->buffer_size);

	err = bluetooth_a2dp_init(data, params);
	if (err < 0)
		return err;

	memset(setconf_req, 0, BT_AUDIO_IPC_PACKET_SIZE);
	setconf_req->h.msg_type = BT_SETCONFIGURATION_REQ;
	strncpy(setconf_req->device, data->alsa_config.device, 18);
	setconf_req->transport = BT_CAPABILITIES_TRANSPORT_A2DP;
	setconf_req->sbc_capabilities = a2dp->sbc_capabilities;
	setconf_req->access_mode = (io->stream == SND_PCM_STREAM_PLAYBACK ?
			BT_CAPABILITIES_ACCESS_MODE_WRITE :
			BT_CAPABILITIES_ACCESS_MODE_READ);

	err = audioservice_send(data->server.fd, &setconf_req->h);
	if (err < 0)
		return err;

	err = audioservice_expect(data->server.fd, &rsp_hdr->msg_h,
					BT_SETCONFIGURATION_RSP);
	if (err < 0)
		return err;

	if (rsp_hdr->posix_errno != 0) {
		SNDERR("BT_SETCONFIGURATION failed : %s(%d)",
					strerror(rsp_hdr->posix_errno),
					rsp_hdr->posix_errno);
		return -rsp_hdr->posix_errno;
	}

	data->transport = setconf_rsp->transport;
	data->link_mtu = setconf_rsp->link_mtu;

	/* Setup SBC encoder now we agree on parameters */
	bluetooth_a2dp_setup(a2dp);

	DBG("\tallocation=%u\n\tsubbands=%u\n\tblocks=%u\n\tbitpool=%u\n",
		a2dp->sbc.allocation, a2dp->sbc.subbands, a2dp->sbc.blocks,
		a2dp->sbc.bitpool);

	return 0;
}

static int bluetooth_poll_descriptors(snd_pcm_ioplug_t *io,
					struct pollfd *pfd, unsigned int space)
{
	struct bluetooth_data *data = io->private_data;

	assert(io);

	if (space < 1)
		return 0;

	pfd[0].fd = data->stream.fd;
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;

	return 1;
}

static int bluetooth_poll_revents(snd_pcm_ioplug_t *io ATTRIBUTE_UNUSED,
					struct pollfd *pfds, unsigned int nfds,
					unsigned short *revents)
{
	assert(pfds && nfds == 1 && revents);

	*revents = pfds[0].revents;

	return 0;
}

static int bluetooth_playback_poll_descriptors_count(snd_pcm_ioplug_t *io)
{
	return 2;
}

static int bluetooth_playback_poll_descriptors(snd_pcm_ioplug_t *io,
					struct pollfd *pfd, unsigned int space)
{
	struct bluetooth_data *data = io->private_data;

	DBG("");

	assert(data->pipefd[0] >= 0);

	if (space < 2)
		return 0;

	pfd[0].fd = data->pipefd[0];
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;
	pfd[1].fd = data->stream.fd;
	pfd[1].events = POLLERR | POLLHUP | POLLNVAL;
	pfd[1].revents = 0;

	return 2;
}

static int bluetooth_playback_poll_revents(snd_pcm_ioplug_t *io,
					struct pollfd *pfds, unsigned int nfds,
					unsigned short *revents)
{
	static char buf[1];
	int ret;

	DBG("");

	assert(pfds);
	assert(nfds == 2);
	assert(revents);
	assert(pfds[0].fd >= 0);
	assert(pfds[1].fd >= 0);

	if (io->state != SND_PCM_STATE_PREPARED)
		ret = read(pfds[0].fd, buf, 1);

	if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL))
		io->state = SND_PCM_STATE_DISCONNECTED;

	revents[0] = (pfds[0].revents & ~POLLIN) | POLLOUT;
	revents[1] = (pfds[1].revents & ~POLLIN);

	return 0;
}


static snd_pcm_sframes_t bluetooth_hsp_read(snd_pcm_ioplug_t *io,
				const snd_pcm_channel_area_t *areas,
				snd_pcm_uframes_t offset,
				snd_pcm_uframes_t size)
{
	struct bluetooth_data *data = io->private_data;
	snd_pcm_uframes_t frames_to_write, ret;
	unsigned char *buff;
	int nrecv, frame_size = 0;

	DBG("areas->step=%u areas->first=%u offset=%lu size=%lu io->nonblock=%u",
			areas->step, areas->first, offset, size, io->nonblock);

	frame_size = areas->step / 8;

	if (data->count > 0)
		goto proceed;

	nrecv = recv(data->stream.fd, data->buffer, data->link_mtu,
			MSG_WAITALL | (io->nonblock ? MSG_DONTWAIT : 0));

	if (nrecv < 0) {
		ret = (errno == EPIPE) ? -EIO : -errno;
		goto done;
	}

	if (nrecv != data->link_mtu) {
		ret = -EIO;
		SNDERR(strerror(-ret));
		goto done;
	}

	/* Increment hardware transmition pointer */
	data->hw_ptr = (data->hw_ptr + data->link_mtu / frame_size) %
				io->buffer_size;

proceed:
	buff = (unsigned char *) areas->addr +
			(areas->first + areas->step * offset) / 8;

	if ((data->count + size * frame_size) <= data->link_mtu)
		frames_to_write = size;
	else
		frames_to_write = (data->link_mtu - data->count) / frame_size;

	memcpy(buff, data->buffer + data->count, frame_size * frames_to_write);
	data->count += (frame_size * frames_to_write);
	data->count %= data->link_mtu;

	/* Return written frames count */
	ret = frames_to_write;

done:
	DBG("returning %lu", ret);
	return ret;
}

static snd_pcm_sframes_t bluetooth_hsp_write(snd_pcm_ioplug_t *io,
				const snd_pcm_channel_area_t *areas,
				snd_pcm_uframes_t offset,
				snd_pcm_uframes_t size)
{
	struct bluetooth_data *data = io->private_data;
	snd_pcm_sframes_t ret = 0;
	snd_pcm_uframes_t frames_to_read;
	uint8_t *buff;
	int rsend, frame_size;

	DBG("areas->step=%u areas->first=%u offset=%lu, size=%lu io->nonblock=%u",
			areas->step, areas->first, offset, size, io->nonblock);

	if (io->hw_ptr > io->appl_ptr) {
		ret = bluetooth_playback_stop(io);
		if (ret == 0)
			ret = -EPIPE;
		goto done;
	}

	frame_size = areas->step / 8;
	if ((data->count + size * frame_size) <= data->link_mtu)
		frames_to_read = size;
	else
		frames_to_read = (data->link_mtu - data->count) / frame_size;

	DBG("count=%d frames_to_read=%lu", data->count, frames_to_read);

	/* Ready for more data */
	buff = (uint8_t *) areas->addr +
			(areas->first + areas->step * offset) / 8;
	memcpy(data->buffer + data->count, buff, frame_size * frames_to_read);

	/* Remember we have some frames in the pipe now */
	data->count += frames_to_read * frame_size;
	if (data->count != data->link_mtu) {
		ret = frames_to_read;
		goto done;
	}

	rsend = send(data->stream.fd, data->buffer, data->link_mtu,
			io->nonblock ? MSG_DONTWAIT : 0);
	if (rsend > 0) {
		/* Reset count pointer */
		data->count = 0;

		ret = frames_to_read;
	} else if (rsend < 0)
		ret = (errno == EPIPE) ? -EIO : -errno;
	else
		ret = -EIO;

done:
	DBG("returning %ld", ret);
	return ret;
}

static snd_pcm_sframes_t bluetooth_a2dp_read(snd_pcm_ioplug_t *io,
				const snd_pcm_channel_area_t *areas,
				snd_pcm_uframes_t offset,
				snd_pcm_uframes_t size)
{
	snd_pcm_uframes_t ret = 0;
	return ret;
}

static int avdtp_write(struct bluetooth_data *data)
{
	int ret = 0;
	struct rtp_header *header;
	struct rtp_payload *payload;
	struct bluetooth_a2dp *a2dp = &data->a2dp;

	header = (void *) a2dp->buffer;
	payload = (void *) (a2dp->buffer + sizeof(*header));

	memset(a2dp->buffer, 0, sizeof(*header) + sizeof(*payload));

	payload->frame_count = a2dp->frame_count;
	header->v = 2;
	header->pt = 1;
	header->sequence_number = htons(a2dp->seq_num);
	header->timestamp = htonl(a2dp->nsamples);
	header->ssrc = htonl(1);

        ret = send(data->stream.fd, a2dp->buffer, a2dp->count, MSG_DONTWAIT);
	if (ret < 0) {
		DBG("send returned %d errno %s.", ret, strerror(errno));
		ret = -errno;
	}

	/* Reset buffer of data to send */
	a2dp->count = sizeof(struct rtp_header) + sizeof(struct rtp_payload);
	a2dp->frame_count = 0;
	a2dp->samples = 0;
	a2dp->seq_num++;

	return ret;
}

static snd_pcm_sframes_t bluetooth_a2dp_write(snd_pcm_ioplug_t *io,
				const snd_pcm_channel_area_t *areas,
				snd_pcm_uframes_t offset, snd_pcm_uframes_t size)
{
	struct bluetooth_data *data = io->private_data;
	struct bluetooth_a2dp *a2dp = &data->a2dp;
	snd_pcm_sframes_t ret = 0;
	snd_pcm_uframes_t frames_to_read, frames_left = size;
	int frame_size, encoded, written;
	uint8_t *buff;

	DBG("areas->step=%u areas->first=%u offset=%lu size=%lu",
				areas->step, areas->first, offset, size);
	DBG("hw_ptr=%lu appl_ptr=%lu diff=%lu", io->hw_ptr, io->appl_ptr,
			io->appl_ptr - io->hw_ptr);

	if (io->hw_ptr > io->appl_ptr) {
		ret = bluetooth_playback_stop(io);
		if (ret == 0)
			ret = -EPIPE;
		data->reset = 1;
		goto done;
	}

	/* Check if we should autostart */
	if (io->state == SND_PCM_STATE_PREPARED) {
		snd_pcm_sw_params_t *swparams;
		snd_pcm_uframes_t threshold;

		snd_pcm_sw_params_malloc(&swparams);
		if (!snd_pcm_sw_params_current(io->pcm, swparams) &&
				!snd_pcm_sw_params_get_start_threshold(swparams,
								&threshold)) {
			if (io->appl_ptr >= threshold) {
				ret = snd_pcm_start(io->pcm);
				if (ret != 0)
					goto done;
			}
		}

		snd_pcm_sw_params_free(swparams);
	}

	while (frames_left > 0) {
		frame_size = areas->step / 8;

		if ((data->count + frames_left * frame_size) <= a2dp->codesize)
			frames_to_read = frames_left;
		else
			frames_to_read = (a2dp->codesize - data->count) / frame_size;

		DBG("count=%d frames_to_read=%lu", data->count, frames_to_read);
		DBG("a2dp.count=%d data.link_mtu=%d", a2dp->count, data->link_mtu);

		/* FIXME: If state is not streaming then return */

		/* Ready for more data */
		buff = (uint8_t *) areas->addr +
			(areas->first + areas->step * (offset + ret)) / 8;
		memcpy(data->buffer + data->count, buff,
				frame_size * frames_to_read);

		/* Remember we have some frames in the pipe now */
		data->count += frames_to_read * frame_size;
		if (data->count != a2dp->codesize) {
			ret = frames_to_read;
			goto done;
		}

		/* Enough data to encode (sbc wants 1k blocks) */
		encoded = sbc_encode(&(a2dp->sbc), data->buffer, a2dp->codesize,
					a2dp->buffer + a2dp->count,
					sizeof(a2dp->buffer) - a2dp->count,
					&written);
		if (encoded <= 0) {
			DBG("Encoding error %d", encoded);
			goto done;
		}

		data->count -= encoded;
		a2dp->count += written;
		a2dp->frame_count++;
		a2dp->samples += encoded / frame_size;
		a2dp->nsamples += encoded / frame_size;

		DBG("encoded=%d  written=%d count=%d", encoded,
				written, a2dp->count);

		/* No space left for another frame then send */
		if (a2dp->count + written >= data->link_mtu) {
			avdtp_write(data);
			DBG("sending packet %d, count %d, link_mtu %u",
					a2dp->seq_num, a2dp->count,
					data->link_mtu);
		}

		ret += frames_to_read;
		frames_left -= frames_to_read;
	}

	/* note: some ALSA apps will get confused otherwise */
	if (ret > size)
		ret = size;

done:
	DBG("returning %ld", ret);
	return ret;
}

static int bluetooth_playback_delay(snd_pcm_ioplug_t *io,
					snd_pcm_sframes_t *delayp)
{
	DBG("");

	/* This updates io->hw_ptr value using pointer() function */
	snd_pcm_hwsync(io->pcm);

	*delayp = io->appl_ptr - io->hw_ptr;
	if ((io->state == SND_PCM_STATE_RUNNING) && (*delayp < 0)) {
		io->callback->stop(io);
		io->state = SND_PCM_STATE_XRUN;
		*delayp = 0;
	}

	/* This should never fail, ALSA API is really not
	prepared to handle a non zero return value */
	return 0;
}

static snd_pcm_ioplug_callback_t bluetooth_hsp_playback = {
	.start			= bluetooth_playback_start,
	.stop			= bluetooth_playback_stop,
	.pointer		= bluetooth_pointer,
	.close			= bluetooth_close,
	.hw_params		= bluetooth_hsp_hw_params,
	.prepare		= bluetooth_prepare,
	.transfer		= bluetooth_hsp_write,
	.poll_descriptors_count	= bluetooth_playback_poll_descriptors_count,
	.poll_descriptors	= bluetooth_playback_poll_descriptors,
	.poll_revents		= bluetooth_playback_poll_revents,
	.delay			= bluetooth_playback_delay,
};

static snd_pcm_ioplug_callback_t bluetooth_hsp_capture = {
	.start			= bluetooth_start,
	.stop			= bluetooth_stop,
	.pointer		= bluetooth_pointer,
	.close			= bluetooth_close,
	.hw_params		= bluetooth_hsp_hw_params,
	.prepare		= bluetooth_prepare,
	.transfer		= bluetooth_hsp_read,
	.poll_descriptors	= bluetooth_poll_descriptors,
	.poll_revents		= bluetooth_poll_revents,
};

static snd_pcm_ioplug_callback_t bluetooth_a2dp_playback = {
	.start			= bluetooth_playback_start,
	.stop			= bluetooth_playback_stop,
	.pointer		= bluetooth_pointer,
	.close			= bluetooth_close,
	.hw_params		= bluetooth_a2dp_hw_params,
	.prepare		= bluetooth_prepare,
	.transfer		= bluetooth_a2dp_write,
	.poll_descriptors_count	= bluetooth_playback_poll_descriptors_count,
	.poll_descriptors	= bluetooth_playback_poll_descriptors,
	.poll_revents		= bluetooth_playback_poll_revents,
	.delay			= bluetooth_playback_delay,
};

static snd_pcm_ioplug_callback_t bluetooth_a2dp_capture = {
	.start			= bluetooth_start,
	.stop			= bluetooth_stop,
	.pointer		= bluetooth_pointer,
	.close			= bluetooth_close,
	.hw_params		= bluetooth_a2dp_hw_params,
	.prepare		= bluetooth_prepare,
	.transfer		= bluetooth_a2dp_read,
	.poll_descriptors	= bluetooth_poll_descriptors,
	.poll_revents		= bluetooth_poll_revents,
};

#define ARRAY_NELEMS(a) (sizeof((a)) / sizeof((a)[0]))

static int bluetooth_hsp_hw_constraint(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;
	snd_pcm_access_t access_list[] = {
		SND_PCM_ACCESS_RW_INTERLEAVED,
		/* Mmap access is really useless fo this driver, but we
		 * support it because some pieces of software out there
		 * insist on using it */
		SND_PCM_ACCESS_MMAP_INTERLEAVED
	};
	unsigned int format_list[] = {
		SND_PCM_FORMAT_S16_LE
	};
	int err;

	/* access type */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
					ARRAY_NELEMS(access_list), access_list);
	if (err < 0)
		return err;

	/* supported formats */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
					ARRAY_NELEMS(format_list), format_list);
	if (err < 0)
		return err;

	/* supported channels */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
							1, 1);
	if (err < 0)
		return err;

	/* supported rate */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE,
							8000, 8000);
	if (err < 0)
		return err;

	/* supported block size */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES,
						data->link_mtu, data->link_mtu);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS,
									2, 200);
	if (err < 0)
		return err;

	return 0;
}

static int bluetooth_a2dp_hw_constraint(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;
	struct bluetooth_a2dp *a2dp = &data->a2dp;
	struct bluetooth_alsa_config *cfg = &data->alsa_config;
	snd_pcm_access_t access_list[] = {
		SND_PCM_ACCESS_RW_INTERLEAVED,
		/* Mmap access is really useless fo this driver, but we
		 * support it because some pieces of software out there
		 * insist on using it */
		SND_PCM_ACCESS_MMAP_INTERLEAVED
	};
	unsigned int format_list[] = {
		SND_PCM_FORMAT_S16_LE
	};
	unsigned int rate_list[4];
	unsigned int rate_count;
	int err, min_channels, max_channels;
	unsigned int period_list[] = {
		2048,
		4096, /* e.g. 23.2msec/period (stereo 16bit at 44.1kHz) */
		8192
	};

	/* access type */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
					ARRAY_NELEMS(access_list), access_list);
	if (err < 0)
		return err;

	/* supported formats */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
					ARRAY_NELEMS(format_list), format_list);
	if (err < 0)
		return err;

	/* supported channels */
	if (cfg->has_channel_mode)
		a2dp->sbc_capabilities.channel_mode = cfg->channel_mode;

	if (a2dp->sbc_capabilities.channel_mode &
			BT_A2DP_CHANNEL_MODE_MONO)
		min_channels = 1;
	else
		min_channels = 2;

	if (a2dp->sbc_capabilities.channel_mode &
			(~BT_A2DP_CHANNEL_MODE_MONO))
		max_channels = 2;
	else
		max_channels = 1;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
							min_channels, max_channels);
	if (err < 0)
		return err;

	/* supported buffer sizes
	 * (can be used as 3*8192, 6*4096, 12*2048, ...) */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_BUFFER_BYTES,
					      8192*3, 8192*3);
	if (err < 0)
		return err;

	/* supported block sizes: */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES,
				ARRAY_NELEMS(period_list), period_list);
	if (err < 0)
		return err;

	/* supported rates */
	rate_count = 0;
	if (cfg->has_rate) {
		rate_list[rate_count] = cfg->rate;
		rate_count++;
	} else {
		if (a2dp->sbc_capabilities.frequency &
				BT_SBC_SAMPLING_FREQ_16000) {
			rate_list[rate_count] = 16000;
			rate_count++;
		}

		if (a2dp->sbc_capabilities.frequency &
				BT_SBC_SAMPLING_FREQ_32000) {
			rate_list[rate_count] = 32000;
			rate_count++;
		}

		if (a2dp->sbc_capabilities.frequency &
				BT_SBC_SAMPLING_FREQ_44100) {
			rate_list[rate_count] = 44100;
			rate_count++;
		}

		if (a2dp->sbc_capabilities.frequency &
				BT_SBC_SAMPLING_FREQ_48000) {
			rate_list[rate_count] = 48000;
			rate_count++;
		}
	}

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_RATE,
						rate_count, rate_list);
	if (err < 0)
		return err;

	return 0;
}

static int bluetooth_parse_config(snd_config_t *conf,
				struct bluetooth_alsa_config *bt_config)
{
	snd_config_iterator_t i, next;

	memset(bt_config, 0, sizeof(struct bluetooth_alsa_config));

	/* Set defaults */
	bt_config->autoconnect = 1;

	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id, *value;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0)
			continue;

		if (strcmp(id, "autoconnect") == 0) {
			int b;

			b = snd_config_get_bool(n);
			if (b < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			bt_config->autoconnect = b;
			continue;
		}

		if (strcmp(id, "device") == 0 || strcmp(id, "bdaddr") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			bt_config->has_device = 1;
			strncpy(bt_config->device, value, 18);
			continue;
		}

		if (strcmp(id, "profile") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			if (strcmp(value, "auto") == 0) {
				bt_config->transport = BT_CAPABILITIES_TRANSPORT_ANY;
				bt_config->has_transport = 1;
			} else if (strcmp(value, "voice") == 0 ||
						strcmp(value, "hfp") == 0) {
				bt_config->transport = BT_CAPABILITIES_TRANSPORT_SCO;
				bt_config->has_transport = 1;
			} else if (strcmp(value, "hifi") == 0 ||
						strcmp(value, "a2dp") == 0) {
				bt_config->transport = BT_CAPABILITIES_TRANSPORT_A2DP;
				bt_config->has_transport = 1;
			}
			continue;
		}

		if (strcmp(id, "rate") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			bt_config->rate = atoi(value);
			bt_config->has_rate = 1;
			continue;
		}

		if (strcmp(id, "mode") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			if (strcmp(value, "mono") == 0) {
				bt_config->channel_mode = BT_A2DP_CHANNEL_MODE_MONO;
				bt_config->has_channel_mode = 1;
			} else if (strcmp(value, "dual") == 0) {
				bt_config->channel_mode = BT_A2DP_CHANNEL_MODE_DUAL_CHANNEL;
				bt_config->has_channel_mode = 1;
			} else if (strcmp(value, "stereo") == 0) {
				bt_config->channel_mode = BT_A2DP_CHANNEL_MODE_STEREO;
				bt_config->has_channel_mode = 1;
			} else if (strcmp(value, "joint") == 0) {
				bt_config->channel_mode = BT_A2DP_CHANNEL_MODE_JOINT_STEREO;
				bt_config->has_channel_mode = 1;
			}
			continue;
		}

		if (strcmp(id, "allocation") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			if (strcmp(value, "loudness") == 0) {
				bt_config->allocation_method = BT_A2DP_ALLOCATION_LOUDNESS;
				bt_config->has_allocation_method = 1;
			} else if (strcmp(value, "snr") == 0) {
				bt_config->allocation_method = BT_A2DP_ALLOCATION_SNR;
				bt_config->has_allocation_method = 1;
			}
			continue;
		}

		if (strcmp(id, "subbands") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			bt_config->subbands = atoi(value);
			bt_config->has_subbands = 1;
			continue;
		}

		if (strcmp(id, "blocks") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			bt_config->block_length = atoi(value);
			bt_config->has_block_length = 1;
			continue;
		}

		if (strcmp(id, "bitpool") == 0) {
			if (snd_config_get_string(n, &value) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			bt_config->bitpool = atoi(value);
			bt_config->has_bitpool = 1;
			continue;
		}

		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	return 0;
}

static int audioservice_send(int sk, const bt_audio_msg_header_t *msg)
{
	int err;

	DBG("sending %s", bt_audio_strmsg(msg->msg_type));
	if (send(sk, msg, BT_AUDIO_IPC_PACKET_SIZE, 0) > 0)
		err = 0;
	else {
		err = -errno;
		SNDERR("Error sending data to audio service: %s(%d)",
			strerror(errno), errno);
	}

	return err;
}

static int audioservice_recv(int sk, bt_audio_msg_header_t *inmsg)
{
	int err;
	const char *type;

	DBG("trying to receive msg from audio service...");
	if (recv(sk, inmsg, BT_AUDIO_IPC_PACKET_SIZE, 0) > 0) {
		type = bt_audio_strmsg(inmsg->msg_type);
		if (type) {
			DBG("Received %s", type);
			err = 0;
		} else {
			err = -EINVAL;
			SNDERR("Bogus message type %d "
					"received from audio service",
					inmsg->msg_type);
		}
	} else {
		err = -errno;
		SNDERR("Error receiving data from audio service: %s(%d)",
					strerror(errno), errno);
	}

	return err;
}

static int audioservice_expect(int sk, bt_audio_msg_header_t *rsp_hdr,
				int expected_type)
{
	int err = audioservice_recv(sk, rsp_hdr);
	if (err == 0) {
		if (rsp_hdr->msg_type != expected_type) {
			err = -EINVAL;
			SNDERR("Bogus message %s received while "
					"%s was expected",
					bt_audio_strmsg(rsp_hdr->msg_type),
					bt_audio_strmsg(expected_type));
		}
	}
	return err;
}

static int bluetooth_init(struct bluetooth_data *data, snd_pcm_stream_t stream,
				snd_config_t *conf)
{
	int sk, err;
	struct bluetooth_alsa_config *alsa_conf = &data->alsa_config;
	char buf[BT_AUDIO_IPC_PACKET_SIZE];
	bt_audio_rsp_msg_header_t *rsp_hdr = (void*) buf;
	struct bt_getcapabilities_req *getcaps_req = (void*) buf;
	struct bt_getcapabilities_rsp *getcaps_rsp = (void*) buf;

	memset(data, 0, sizeof(struct bluetooth_data));

	err = bluetooth_parse_config(conf, alsa_conf);
	if (err < 0)
		return err;

	data->server.fd = -1;
	data->stream.fd = -1;

	sk = bt_audio_service_open();
	if (sk <= 0) {
		err = -errno;
		goto failed;
	}

	data->server.fd = sk;
	data->server.events = POLLIN;

	data->pipefd[0] = -1;
	data->pipefd[1] = -1;

	if (pipe(data->pipefd) < 0) {
		err = -errno;
		goto failed;
	}
	if (fcntl(data->pipefd[0], F_SETFL, O_NONBLOCK) < 0) {
		err = -errno;
		goto failed;
	}
	if (fcntl(data->pipefd[1], F_SETFL, O_NONBLOCK) < 0) {
		err = -errno;
		goto failed;
	}

	memset(getcaps_req, 0, BT_AUDIO_IPC_PACKET_SIZE);
	getcaps_req->h.msg_type = BT_GETCAPABILITIES_REQ;
	getcaps_req->flags = 0;
	if (alsa_conf->autoconnect)
		getcaps_req->flags |= BT_FLAG_AUTOCONNECT;
	strncpy(getcaps_req->device, alsa_conf->device, 18);
	if (alsa_conf->has_transport)
		getcaps_req->transport = alsa_conf->transport;
	else
		getcaps_req->transport = BT_CAPABILITIES_TRANSPORT_ANY;

	err = audioservice_send(data->server.fd, &getcaps_req->h);
	if (err < 0)
		goto failed;

	err = audioservice_expect(data->server.fd, &rsp_hdr->msg_h, BT_GETCAPABILITIES_RSP);
	if (err < 0)
		goto failed;

	if (rsp_hdr->posix_errno != 0) {
		SNDERR("BT_GETCAPABILITIES failed : %s(%d)",
					strerror(rsp_hdr->posix_errno),
					rsp_hdr->posix_errno);
		return -rsp_hdr->posix_errno;
	}

	data->transport = getcaps_rsp->transport;

	if (getcaps_rsp->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		data->a2dp.sbc_capabilities = getcaps_rsp->sbc_capabilities;

	return 0;

failed:
	bt_audio_service_close(sk);
	return err;
}

SND_PCM_PLUGIN_DEFINE_FUNC(bluetooth)
{
	struct bluetooth_data *data;
	int err;

	DBG("Bluetooth PCM plugin (%s)",
		stream == SND_PCM_STREAM_PLAYBACK ? "Playback" : "Capture");

	data = malloc(sizeof(struct bluetooth_data));
	if (!data) {
		err = -ENOMEM;
		goto error;
	}

	err = bluetooth_init(data, stream, conf);
	if (err < 0)
		goto error;

	data->io.version = SND_PCM_IOPLUG_VERSION;
	data->io.name = "Bluetooth Audio Device";
	data->io.mmap_rw = 0; /* No direct mmap communication */
	data->io.private_data = data;

	if (data->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		data->io.callback = stream == SND_PCM_STREAM_PLAYBACK ?
			&bluetooth_a2dp_playback :
			&bluetooth_a2dp_capture;
	else
		data->io.callback = stream == SND_PCM_STREAM_PLAYBACK ?
			&bluetooth_hsp_playback :
			&bluetooth_hsp_capture;

	err = snd_pcm_ioplug_create(&data->io, name, stream, mode);
	if (err < 0)
		goto error;

	if (data->transport == BT_CAPABILITIES_TRANSPORT_A2DP)
		err = bluetooth_a2dp_hw_constraint(&data->io);
	else
		err = bluetooth_hsp_hw_constraint(&data->io);

	if (err < 0) {
		snd_pcm_ioplug_delete(&data->io);
		goto error;
	}

	*pcmp = data->io.pcm;

	return 0;

error:
	bluetooth_exit(data);

	return err;
}

SND_PCM_PLUGIN_SYMBOL(bluetooth);
