/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <malloc.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#include "sbc.h"

//#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
#define DBG(D...)

typedef struct snd_pcm_a2dp {
	snd_pcm_ioplug_t io;
	int refcnt;
	bdaddr_t src;
	bdaddr_t dst;
	int sk;
	sbc_t sbc;
	snd_pcm_sframes_t num;
	unsigned char buf[1024];
	unsigned int len;
	unsigned int frame_bytes;
} snd_pcm_a2dp_t;

#define MAX_CONNECTIONS 10

static snd_pcm_a2dp_t *connections[MAX_CONNECTIONS];

static void sig_alarm(int sig)
{
	int i;

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		snd_pcm_a2dp_t *a2dp = connections[i];

		if (!a2dp || a2dp->refcnt > 0)
			continue;

		connections[i] = NULL;

		if (a2dp->sk >= 0)
			close(a2dp->sk);

		sbc_finish(&a2dp->sbc);

		free(a2dp);
	}
}

static int a2dp_start(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	return 0;
}

static int a2dp_stop(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	return 0;
}

static snd_pcm_sframes_t a2dp_pointer(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	return a2dp->num;
}

static snd_pcm_sframes_t a2dp_transfer(snd_pcm_ioplug_t *io,
			const snd_pcm_channel_area_t *areas,
			snd_pcm_uframes_t offset, snd_pcm_uframes_t size)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	unsigned char *buf;
	int len;

	buf = (unsigned char *) areas->addr + (areas->first + areas->step * offset) / 8;

	size *= a2dp->frame_bytes;

	len = sbc_encode(&a2dp->sbc, buf, size);
	if (len <= 0)
		return len;

	memcpy(a2dp->buf + a2dp->len, a2dp->sbc.data, a2dp->sbc.len);
	a2dp->len += a2dp->sbc.len;

	if (a2dp->len > 700) {
		write(a2dp->sk, a2dp->buf, a2dp->len);
		a2dp->len = 0;
	}

	a2dp->num += len / a2dp->frame_bytes;

	return len / a2dp->frame_bytes;
}

static int a2dp_close(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	a2dp->refcnt--;

	if (!a2dp->refcnt)
		alarm(2);

	return 0;
}

static int a2dp_params(snd_pcm_ioplug_t *io, snd_pcm_hw_params_t *params)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;
	unsigned int period_bytes;

	DBG("a2dp %p", a2dp);

	a2dp->frame_bytes = (snd_pcm_format_physical_width(io->format) * io->channels) / 8;

	period_bytes = io->period_size * a2dp->frame_bytes;

	DBG("format %s rate %d channels %d", snd_pcm_format_name(io->format),
					io->rate, io->channels);

	DBG("frame_bytes %d period_byts %d period_size %ld buffer_size %ld",
		a2dp->frame_bytes, period_bytes, io->period_size, io->buffer_size);

	return 0;
}

static int a2dp_prepare(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	a2dp->num = 0;

	a2dp->sbc.rate = io->rate;
	a2dp->sbc.channels = io->channels;

	return 0;
}

static int a2dp_drain(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	return 0;
}

static int a2dp_poll(snd_pcm_ioplug_t *io, struct pollfd *ufds,
				unsigned int nfds, unsigned short *revents)
{
	*revents = ufds[0].revents;

	return 0;
}

static snd_pcm_ioplug_callback_t a2dp_callback = {
	.start		= a2dp_start,
	.stop		= a2dp_stop,
	.pointer	= a2dp_pointer,
	.transfer	= a2dp_transfer,
	.close		= a2dp_close,
	.hw_params	= a2dp_params,
	.prepare	= a2dp_prepare,
	.drain		= a2dp_drain,
	.poll_revents	= a2dp_poll,
};

static int a2dp_connect(snd_pcm_a2dp_t *a2dp)
{
	struct sockaddr_rc addr;
	socklen_t len;
	int sk;

	DBG("a2dp %p", a2dp);

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &a2dp->src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &a2dp->dst);
	addr.rc_channel = 1;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);

	if (getsockname(sk, (struct sockaddr *) &addr, &len) < 0) {
		close(sk);
		return -errno;
	}

	bacpy(&a2dp->src, &addr.rc_bdaddr);

	a2dp->sk = sk;

	return 0;
}

static int a2dp_constraint(snd_pcm_a2dp_t *a2dp)
{
	snd_pcm_ioplug_t *io = &a2dp->io;
	snd_pcm_access_t access_list[] = {
		SND_PCM_ACCESS_RW_INTERLEAVED,
		SND_PCM_ACCESS_MMAP_INTERLEAVED,
	};
	unsigned int format[2], channel[2], rate[2];
	int err;

	DBG("a2dp %p", a2dp);

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS, 2, access_list);
	if (err < 0)
		return err;

	format[0] = SND_PCM_FORMAT_S16_LE;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT, 1, format);
	if (err < 0)
		return err;

	channel[0] = 1;
	channel[1] = 2;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_CHANNELS, 2, channel);
	if (err < 0)
		return err;

	rate[0] = 44100;
	rate[1] = 48000;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_RATE, 2, rate);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 2048, 2048);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS, 2, 2);
	if (err < 0)
		return err;

	sbc_init(&a2dp->sbc, SBC_NULL);

	return 0;
}

SND_PCM_PLUGIN_DEFINE_FUNC(a2dp)
{
	snd_pcm_a2dp_t *a2dp = NULL;
	snd_config_iterator_t i, next;
	bdaddr_t src, dst;
	int err, n, pos = -1;

	DBG("name %s mode %d", name, mode);

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	snd_config_for_each(i, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(i);
		const char *id, *addr;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (!strcmp(id, "comment") || !strcmp(id, "type"))
			continue;

		if (!strcmp(id, "bdaddr") || !strcmp(id, "dst")) {
			if (snd_config_get_string(n, &addr) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			str2ba(addr, &dst);
			continue;
		}

		if (!strcmp(id, "local") || !strcmp(id, "src")) {
			if (snd_config_get_string(n, &addr) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			str2ba(addr, &src);
			continue;
		}

		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	for (n = 0; n < MAX_CONNECTIONS; n++) {
		if (connections[n]) {
			if (!bacmp(&connections[n]->dst, &dst) &&
					(!bacmp(&connections[n]->src, &src) ||
						!bacmp(&src, BDADDR_ANY))) {
				a2dp = connections[n];
				a2dp->refcnt++;
				break;
			}
		} else if (pos < 0)
			pos = n;
	}

	if (!a2dp) {
		struct sigaction sa;

		if (pos < 0) {
			SNDERR("Too many connections");
			return -ENOMEM;
		}

		a2dp = malloc(sizeof(*a2dp));
		if (!a2dp) {
			SNDERR("Cannot allocate");
			return -ENOMEM;
		}

		memset(a2dp, 0, sizeof(*a2dp));

		a2dp->refcnt = 1;

		bacpy(&a2dp->src, &src);
		bacpy(&a2dp->dst, &dst);

		err = a2dp_connect(a2dp);
		if (err < 0) {
			SNDERR("Cannot connect");
			goto error;
		}

		memset(&sa, 0, sizeof(sa));
		sa.sa_flags   = SA_NOCLDSTOP;
		sa.sa_handler = sig_alarm;
		sigaction(SIGALRM, &sa, NULL);

		alarm(0);

		connections[pos] = a2dp;
	}

	a2dp->io.name = "Bluetooth Advanced Audio Distribution";
	a2dp->io.poll_fd = a2dp->sk;
	a2dp->io.poll_events = POLLOUT;
	a2dp->io.mmap_rw = 0;
	a2dp->io.callback = &a2dp_callback;
	a2dp->io.private_data = a2dp;

	err = snd_pcm_ioplug_create(&a2dp->io, name, stream, mode);
	if (err < 0)
		goto error;

	err = a2dp_constraint(a2dp);
	if (err < 0) {
		snd_pcm_ioplug_delete(&a2dp->io);
		goto error;
	}

	*pcmp = a2dp->io.pcm;
	return 0;

error:
	a2dp->refcnt--;

	if (!a2dp->refcnt)
		alarm(2);

	return err;
}

SND_PCM_PLUGIN_SYMBOL(a2dp);
