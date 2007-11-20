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

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>

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

#ifndef TIMESPEC_TO_TIMEVAL
# define TIMESPEC_TO_TIMEVAL(tv, ts) {			\
		(tv)->tv_sec = (ts)->tv_sec;		\
		(tv)->tv_usec = (ts)->tv_nsec / 1000;	\
}
#endif

struct bluetooth_a2dp {
	sbc_t sbc;			/* Codec data */
	int codesize;			/* SBC codesize */
	int samples;			/* Number of encoded samples */
	uint8_t buffer[BUFFER_SIZE];	/* Codec transfer buffer */
	int count;			/* Codec transfer buffer counter */

	int nsamples;			/* Cumulative number of codec samples */
	uint16_t seq_num;		/* Cumulative packet sequence */
	int frame_count;		/* Current frames in buffer*/
};

struct bluetooth_data {
	snd_pcm_ioplug_t io;
	volatile snd_pcm_sframes_t hw_ptr;
	struct ipc_data_cfg cfg;	/* Bluetooth device config */
	struct pollfd stream;		/* Audio stream filedescriptor */
	struct pollfd server;		/* Audio daemon filedescriptor */
	uint8_t buffer[BUFFER_SIZE];	/* Encoded transfer buffer */
	int count;			/* Transfer buffer counter */
	struct bluetooth_a2dp a2dp;	/* A2DP data */

	pthread_t hw_thread;		/* Makes virtual hw pointer move */
	int pipefd[2];			/* Inter thread communication */
	int stopped;
	sig_atomic_t reset;             /* Request XRUN handling */
};

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
	struct timeval start;
	struct timespec start_monotonic;
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

	clock_gettime(CLOCK_MONOTONIC, &start_monotonic);
	TIMESPEC_TO_TIMEVAL(&start, &start_monotonic);

	while (1) {
		unsigned int dtime, periods;
		struct timeval cur, delta;
		struct timespec cur_monotonic;
		int ret;

		if (data->stopped)
			goto iter_sleep;

		if (data->reset) {
			DBG("Handle XRUN in hw-thread.");
			data->reset = 0;
			clock_gettime(CLOCK_MONOTONIC, &start_monotonic);
			TIMESPEC_TO_TIMEVAL(&start, &start_monotonic);
			prev_periods = 0;
		}

		clock_gettime(CLOCK_MONOTONIC, &cur_monotonic);
		TIMESPEC_TO_TIMEVAL(&cur, &cur_monotonic);

		timersub(&cur, &start, &delta);

		dtime = delta.tv_sec * 1000000 + delta.tv_usec;
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
				gettimeofday(&start, 0);
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

#if 0
static int bluetooth_state_init(struct ipc_packet *pkt, int newstate)
{
	struct ipc_data_state *state = (void *) pkt->data;

	pkt->length = sizeof(*state);
	pkt->type = PKT_TYPE_STATE_REQ;
	pkt->error = PKT_ERROR_NONE;
	state->state = newstate;

	return 0;
}

static int bluetooth_state(struct bluetooth_data *data, int newstate)
{
	char buf[IPC_MTU];
	struct ipc_packet *pkt = (void *) buf;
	struct ipc_data_state *state = (void *) pkt->data;
	int ret;

	memset(buf, 0, sizeof(buf));

	ret = bluetooth_state_init(pkt, newstate);
	if (ret < 0)
		return -ret;

	ret = send(data->server.fd, pkt, sizeof(*pkt) + pkt->length, 0);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -EIO;

	DBG("OK - %d bytes sent. Waiting for response...", ret);

	memset(buf, 0, sizeof(buf));

	ret = recv(data->server.fd, buf, sizeof(*pkt) + sizeof(*state), 0);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -EIO;

	if (pkt->type != PKT_TYPE_STATE_RSP) {
		SNDERR("Unexpected packet type %d received", pkt->type);
		return -EINVAL;
	}

	if (pkt->error != PKT_ERROR_NONE) {
		SNDERR("Error %d while configuring device", pkt->error);
		return -pkt->error;
	}

	return 0;
}
#endif

static int bluetooth_playback_start(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;
	int err;

	DBG("%p", io);

#if 0
	bluetooth_state(data, STATE_STREAMING);
#endif
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

#if 0
	bluetooth_state(data, STATE_CONNECTED);
#endif
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
		close(data->server.fd);

	if (data->stream.fd >= 0)
		close(data->stream.fd);

	if (data->hw_thread) {
		pthread_cancel(data->hw_thread);
		pthread_join(data->hw_thread, 0);
	}

	if (data->cfg.codec == CFG_CODEC_SBC)
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

	DBG("Preparing with io->period_size=%lu io->buffer_size=%lu",
					io->period_size, io->buffer_size);

	data->reset = 0;

	if (io->stream == SND_PCM_STREAM_PLAYBACK)
		/* If not null for playback, xmms doesn't display time
		 * correctly */
		data->hw_ptr = 0;
	else
		/* ALSA library is really picky on the fact hw_ptr is not null.
		 * If it is, capture won't start */
		data->hw_ptr = io->period_size;

	/* wake up any client polling at us */
	return write(data->pipefd[1], &c, 1);
}

static int bluetooth_hsp_hw_params(snd_pcm_ioplug_t *io,
					snd_pcm_hw_params_t *params)
{
	struct bluetooth_data *data = io->private_data;
	uint32_t period_count = io->buffer_size / io->period_size;
	int opt_name, err;

	DBG("fd=%d period_count=%d", data->stream.fd, period_count);

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

	err = errno;

	SNDERR("%s (%d)", strerror(err), err);

	/* FIXME: We should not ignores errors in the future. */
	return 0;
}

static int bluetooth_a2dp_hw_params(snd_pcm_ioplug_t *io,
					snd_pcm_hw_params_t *params)
{
	struct bluetooth_data *data = io->private_data;
	uint32_t period_count = io->buffer_size / io->period_size;
	int opt_name, err;
	struct timeval t = { 0, period_count };

	DBG("fd=%d period_count=%d", data->stream.fd, period_count);

	opt_name = (io->stream == SND_PCM_STREAM_PLAYBACK) ?
						SO_SNDTIMEO : SO_RCVTIMEO;

	if (setsockopt(data->stream.fd, SOL_SOCKET, opt_name, &t,
							sizeof(t)) == 0)
		return 0;

	err = errno;

	SNDERR("%s (%d)", strerror(err), err);

	return -err;
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

static int bluetooth_playback_poll_descriptors(snd_pcm_ioplug_t *io,
					struct pollfd *pfd, unsigned int space)
{
	struct bluetooth_data *data = io->private_data;

	DBG("");

	assert(data->pipefd[0] >= 0);

	if (space < 1)
		return 0;

	pfd[0].fd = data->pipefd[0];
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;

	return 1;
}

static int bluetooth_playback_poll_revents(snd_pcm_ioplug_t *io,
					struct pollfd *pfds, unsigned int nfds,
					unsigned short *revents)
{
	static char buf[1];
	int ret;

	DBG("");

	assert(pfds);
	assert(nfds == 1);
	assert(revents);
	assert(pfds[0].fd >= 0);

	if (io->state != SND_PCM_STATE_PREPARED)
		ret = read(pfds[0].fd, buf, 1);

	*revents = (pfds[0].revents & ~POLLIN) | POLLOUT;

	return 0;
}


static snd_pcm_sframes_t bluetooth_hsp_read(snd_pcm_ioplug_t *io,
				const snd_pcm_channel_area_t *areas,
				snd_pcm_uframes_t offset,
				snd_pcm_uframes_t size)
{
	struct bluetooth_data *data = io->private_data;
	struct ipc_data_cfg cfg = data->cfg;
	snd_pcm_uframes_t frames_to_write, ret;
	unsigned char *buff;
	int nrecv, frame_size = 0;

	DBG("areas->step=%u areas->first=%u offset=%lu size=%lu io->nonblock=%u",
			areas->step, areas->first, offset, size, io->nonblock);

	if (data->count > 0)
		goto proceed;

	frame_size = areas->step / 8;

	nrecv = recv(data->stream.fd, data->buffer, cfg.pkt_len,
			MSG_WAITALL | (io->nonblock ? MSG_DONTWAIT : 0));

	if (nrecv < 0) {
		ret = (errno == EPIPE) ? -EIO : -errno;
		goto done;
	}

	if (nrecv != cfg.pkt_len) {
		ret = -EIO;
		SNDERR(strerror(-ret));
		goto done;
	}

	/* Increment hardware transmition pointer */
	data->hw_ptr = (data->hw_ptr + cfg.pkt_len / cfg.sample_size) %
								io->buffer_size;

proceed:
	buff = (unsigned char *) areas->addr +
			(areas->first + areas->step * offset) / 8;

	if ((data->count + size * frame_size) <= cfg.pkt_len)
		frames_to_write = size;
	else
		frames_to_write = (cfg.pkt_len - data->count) / frame_size;

	memcpy(buff, data->buffer + data->count, frame_size * frames_to_write);
	data->count += (frame_size * frames_to_write);
	data->count %= cfg.pkt_len;

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
	struct ipc_data_cfg cfg = data->cfg;
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
	if ((data->count + size * frame_size) <= cfg.pkt_len)
		frames_to_read = size;
	else
		frames_to_read = (cfg.pkt_len - data->count) / frame_size;

	DBG("count=%d frames_to_read=%lu", data->count, frames_to_read);

	/* Ready for more data */
	buff = (uint8_t *) areas->addr +
			(areas->first + areas->step * offset) / 8;
	memcpy(data->buffer + data->count, buff, frame_size * frames_to_read);

	/* Remember we have some frames in the pipe now */
	data->count += frames_to_read * frame_size;
	if (data->count != cfg.pkt_len) {
		ret = frames_to_read;
		goto done;
	}

	rsend = send(data->stream.fd, data->buffer, cfg.pkt_len,
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
		DBG("a2dp.count=%d cfg.pkt_len=%d", a2dp->count, data->cfg.pkt_len);

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
		if (a2dp->count + written >= data->cfg.pkt_len) {
			avdtp_write(data);
			DBG("sending packet %d, count %d, pkt_len %u", c,
					old_count, data->cfg.pkt_len);
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
	struct ipc_data_cfg cfg = data->cfg;
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
	int err, channels;

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
	channels = cfg.mode == CFG_MODE_MONO ? 1 : 2;
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
							channels, channels);
	if (err < 0)
		return err;

	/* supported rate */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE,
							cfg.rate, cfg.rate);
	if (err < 0)
		return err;

	/* supported block size */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES,
						cfg.pkt_len, cfg.pkt_len);
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
	struct ipc_data_cfg cfg = data->cfg;
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
	unsigned int period_list[] = {
		4096, /* 23/46ms (stereo/mono 16bit at 44.1kHz) */
	};
	int err, channels;

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
	channels = cfg.mode == CFG_MODE_MONO ? 1 : 2;
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS,
							channels, channels);
	if (err < 0)
		return err;

	/* supported rate */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE,
							cfg.rate, cfg.rate);
	if (err < 0)
		return err;

	/* supported block sizes: */
	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES,
			ARRAY_NELEMS(period_list), period_list);
	if (err < 0)
		return err;

	/* period count fixed to 3 as we don't support prefilling */
	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS,
					      3, 3);
	if (err < 0)
		return err;

	return 0;
}

static int bluetooth_recvmsg_fd(struct bluetooth_data *data)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))], m;
	int err, ret;
	struct iovec iov = { &m, sizeof(m) };
	struct msghdr msgh;
	struct cmsghdr *cmsg;

	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = &cmsg_b;
	msgh.msg_controllen = CMSG_LEN(sizeof(int));

	ret = recvmsg(data->server.fd, &msgh, 0);
	if (ret < 0) {
		err = errno;
		SNDERR("Unable to receive fd: %s (%d)", strerror(err), err);
		return -err;
	}

	/* Receive auxiliary data in msgh */
	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
			cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
				&& cmsg->cmsg_type == SCM_RIGHTS) {
			data->stream.fd = (*(int *) CMSG_DATA(cmsg));
			DBG("stream_fd=%d", data->stream.fd);
			return 0;
		}
	}

	return -EINVAL;
}

static int bluetooth_a2dp_init(struct bluetooth_data *data,
				struct ipc_codec_sbc *sbc)
{
	struct bluetooth_a2dp *a2dp = &data->a2dp;
	struct ipc_data_cfg *cfg = &data->cfg;

	if (cfg == NULL) {
		SNDERR("Error getting codec parameters");
		return -1;
	}

	if (cfg->codec != CFG_CODEC_SBC)
		return -1;

	/* FIXME: init using flags? */
	sbc_init(&a2dp->sbc, 0);
	a2dp->sbc.rate = cfg->rate;
	a2dp->sbc.channels = cfg->mode == CFG_MODE_MONO ? 1 : 2;
	if (cfg->mode == CFG_MODE_MONO || cfg->mode == CFG_MODE_JOINT_STEREO)
		a2dp->sbc.joint = 1;
	a2dp->sbc.allocation = sbc->allocation;
	a2dp->sbc.subbands = sbc->subbands;
	a2dp->sbc.blocks = sbc->blocks;
	a2dp->sbc.bitpool = sbc->bitpool;
	a2dp->codesize = a2dp->sbc.subbands * a2dp->sbc.blocks *
						a2dp->sbc.channels * 2;
	a2dp->count = sizeof(struct rtp_header) + sizeof(struct rtp_payload);

	DBG("\tallocation=%u\n\tsubbands=%u\n\tblocks=%u\n\tbitpool=%u\n",
		a2dp->sbc.allocation, a2dp->sbc.subbands, a2dp->sbc.blocks,
		a2dp->sbc.bitpool);

	return 0;
}

static int bluetooth_cfg_init(struct ipc_packet *pkt, snd_pcm_stream_t stream,
				snd_config_t *conf)
{
	struct ipc_data_cfg *cfg = (void *) pkt->data;
	struct ipc_codec_sbc *sbc = (void *) cfg->data;
	snd_config_iterator_t i, next;
	const char *addr, *pref;
	const char *mode, *allocation, *rate, *subbands, *blocks, *bitpool;

	switch (stream) {
	case SND_PCM_STREAM_PLAYBACK:
		cfg->fd_opt = CFG_FD_OPT_WRITE;
		break;
	case SND_PCM_STREAM_CAPTURE:
		cfg->fd_opt = CFG_FD_OPT_READ;
		break;
	}

	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0)
			continue;

		if (strcmp(id, "device") == 0 || strcmp(id, "bdaddr") == 0) {
			if (snd_config_get_string(n, &addr) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			strncpy(pkt->device, addr, 18);
			continue;
		}

		if (strcmp(id, "profile") == 0) {
			if (snd_config_get_string(n, &pref) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			if (strcmp(pref, "auto") == 0)
				pkt->role = PKT_ROLE_AUTO;
			else if (strcmp(pref, "voice") == 0 ||
						strcmp(pref, "hfp") == 0) {
				pkt->role = PKT_ROLE_VOICE;
			} else if (strcmp(pref, "hifi") == 0 ||
						strcmp(pref, "a2dp") == 0)
				pkt->role = PKT_ROLE_HIFI;
			continue;
		}

		if (strcmp(id, "rate") == 0) {
			if (snd_config_get_string(n, &rate) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			cfg->rate = atoi(rate);
			continue;
		}

		if (strcmp(id, "mode") == 0) {
			if (snd_config_get_string(n, &mode) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			if (strcmp(pref, "auto") == 0)
				cfg->mode = CFG_MODE_AUTO;
			else if (strcmp(pref, "mono") == 0)
				cfg->mode = CFG_MODE_MONO;
			else if (strcmp(pref, "dual") == 0)
				cfg->mode = CFG_MODE_DUAL_CHANNEL;
			else if (strcmp(pref, "stereo") == 0)
				cfg->mode = CFG_MODE_STEREO;
			else if (strcmp(pref, "joint") == 0)
				cfg->mode = CFG_MODE_JOINT_STEREO;
			continue;
		}

		if (strcmp(id, "allocation") == 0) {
			if (snd_config_get_string(n, &allocation) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			if (strcmp(pref, "auto") == 0)
				sbc->allocation = CFG_ALLOCATION_AUTO;
			else if (strcmp(pref, "loudness") == 0)
				sbc->allocation = CFG_ALLOCATION_LOUDNESS;
			else if (strcmp(pref, "snr") == 0)
				sbc->allocation = CFG_ALLOCATION_SNR;
			continue;
		}

		if (strcmp(id, "subbands") == 0) {
			if (snd_config_get_string(n, &subbands) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			sbc->subbands = atoi(subbands);
			continue;
		}

		if (strcmp(id, "blocks") == 0) {
			if (snd_config_get_string(n, &blocks) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			sbc->blocks = atoi(blocks);
			continue;
		}

		if (strcmp(id, "bitpool") == 0) {
			if (snd_config_get_string(n, &bitpool) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}

			sbc->bitpool = atoi(bitpool);
			continue;
		}

		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	pkt->length = sizeof(*cfg) + sizeof(*sbc);
	pkt->type = PKT_TYPE_CFG_REQ;
	pkt->error = PKT_ERROR_NONE;

	return 0;
}

static int bluetooth_cfg(struct bluetooth_data *data, snd_pcm_stream_t stream,
				snd_config_t *conf)
{
	int ret, total;
	char buf[IPC_MTU];
	struct ipc_packet *pkt = (void *) buf;
	struct ipc_data_cfg *cfg = (void *) pkt->data;
	struct ipc_codec_sbc *sbc = (void *) cfg->data;

	DBG("Sending PKT_TYPE_CFG_REQ...");

	memset(buf, 0, sizeof(buf));

	ret = bluetooth_cfg_init(pkt, stream, conf);
	if (ret < 0)
		return -ret;

	ret = send(data->server.fd, pkt, sizeof(*pkt) + pkt->length, 0);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -EIO;

	DBG("OK - %d bytes sent. Waiting for response...", ret);

	memset(buf, 0, sizeof(buf));

	ret = recv(data->server.fd, buf, sizeof(*pkt) + sizeof(*cfg), 0);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -EIO;

	total = ret;

	if (pkt->type != PKT_TYPE_CFG_RSP) {
		SNDERR("Unexpected packet type %d received", pkt->type);
		return -EINVAL;
	}

	if (pkt->error != PKT_ERROR_NONE) {
		SNDERR("Error %d while configuring device", pkt->error);
		return -pkt->error;
	}

	if (cfg->codec != CFG_CODEC_SBC)
		goto done;

	ret = recv(data->server.fd, sbc, sizeof(*sbc), 0);
	if (ret < 0)
		return -errno;
	else if (ret == 0)
		return -EIO;

	total += ret;

done:
	DBG("OK - %d bytes received", total);

	if (pkt->length != (total - sizeof(struct ipc_packet))) {
		SNDERR("Error while configuring device: packet size doesn't match");
		return -EINVAL;
	}

	memcpy(&data->cfg, cfg, sizeof(*cfg));

	DBG("Device configuration:");

	DBG("\n\tfd=%d\n\tfd_opt=%u\n\tpkt_len=%u\n\tsample_size=%u\n\trate=%u",
			data->stream.fd, data->cfg.fd_opt, data->cfg.pkt_len,
			data->cfg.sample_size, data->cfg.rate);

	if (data->cfg.codec == CFG_CODEC_SBC) {
		ret = bluetooth_a2dp_init(data, sbc);
		if (ret < 0)
			return ret;
	}

	ret = bluetooth_recvmsg_fd(data);
	if (ret < 0)
		return ret;

	if (data->stream.fd == -1) {
		SNDERR("Error while configuring device: could not acquire audio socket");
		return -EINVAL;
	}

	/* It is possible there is some outstanding
	data in the pipe - we have to empty it */
	while (recv(data->stream.fd, data->buffer, data->cfg.pkt_len,
				MSG_DONTWAIT) > 0);

	memset(data->buffer, 0, sizeof(data->buffer));

	return 0;
}

static int bluetooth_init(struct bluetooth_data *data, snd_pcm_stream_t stream,
				snd_config_t *conf)
{
	int sk, err;
	struct sockaddr_un addr = {
		AF_UNIX, IPC_SOCKET_NAME
	};

	if (!data)
		return -EINVAL;

	memset(data, 0, sizeof(struct bluetooth_data));

	data->server.fd = -1;
	data->stream.fd = -1;

	sk = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		SNDERR("Cannot open socket: %s (%d)", strerror(err), err);
		return -err;
	}

	DBG("Connecting to address: %s", addr.sun_path + 1);
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		SNDERR("Connection fail", strerror(err), err);
		close(sk);
		return -err;
	}

	data->server.fd = sk;
	data->server.events = POLLIN;

	data->pipefd[0] = -1;
	data->pipefd[1] = -1;

	if (pipe(data->pipefd) < 0)
		return -errno;
	if (fcntl(data->pipefd[0], F_SETFL, O_NONBLOCK) < 0)
		return -errno;
	if (fcntl(data->pipefd[1], F_SETFL, O_NONBLOCK) < 0)
		return -errno;

	return bluetooth_cfg(data, stream, conf);
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

	if (data->cfg.codec == CFG_CODEC_SBC)
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

	if (data->cfg.codec == CFG_CODEC_SBC)
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
