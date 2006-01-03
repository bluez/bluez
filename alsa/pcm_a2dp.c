/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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

static void a2dp_init(void) __attribute__ ((constructor));
static void a2dp_exit(void) __attribute__ ((destructor));

typedef struct snd_pcm_a2dp {
	snd_pcm_ioplug_t io;
	int refcnt;
	int timeout;
	unsigned long state;
	bdaddr_t src;
	bdaddr_t dst;
	int sk;
	sbc_t sbc;
	snd_pcm_sframes_t num;
	unsigned char buf[1024];
	unsigned int len;
	unsigned int frame_bytes;
} snd_pcm_a2dp_t;

static void inline a2dp_get(snd_pcm_a2dp_t *a2dp)
{
	a2dp->refcnt++;
	a2dp->timeout = 0;
}

static void inline a2dp_put(snd_pcm_a2dp_t *a2dp)
{
	a2dp->refcnt--;

	if (a2dp->refcnt <= 0)
		a2dp->timeout = 2;
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

	len = sbc_encode(&a2dp->sbc, buf, size * a2dp->frame_bytes);
	if (len <= 0)
		return len;

	if (a2dp->len + a2dp->sbc.len > sizeof(a2dp->buf)) {
		write(a2dp->sk, a2dp->buf, a2dp->len);
		a2dp->len = 0;
	}

	memcpy(a2dp->buf + a2dp->len, a2dp->sbc.data, a2dp->sbc.len);
	a2dp->len += a2dp->sbc.len;

	if (a2dp->state == BT_CONNECTED)
		a2dp->num += len / a2dp->frame_bytes;

	return len / a2dp->frame_bytes;
}

static int a2dp_close(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	DBG("a2dp %p", a2dp);

	a2dp->len = 0;

	a2dp_put(a2dp);

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

	DBG("frame_bytes %d period_bytes %d period_size %ld buffer_size %ld",
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

static int a2dp_descriptors_count(snd_pcm_ioplug_t *io)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	if (a2dp->state == BT_CLOSED)
		return 0;

	return 1;
}

static int a2dp_descriptors(snd_pcm_ioplug_t *io, struct pollfd *pfds, unsigned int space)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	if (a2dp->state == BT_CLOSED)
		return 0;

	if (space < 1) {
		SNDERR("Can't fill in descriptors");
		return 0;
	}

	pfds[0].fd = a2dp->sk;
	pfds[0].events = POLLOUT;

	return 1;
}

static int a2dp_poll(snd_pcm_ioplug_t *io, struct pollfd *pfds,
			unsigned int nfds, unsigned short *revents)
{
	snd_pcm_a2dp_t *a2dp = io->private_data;

	*revents = pfds[0].revents;

	if (a2dp->state == BT_CLOSED)
		return 0;

	if (pfds[0].revents & POLLHUP) {
		a2dp->state = BT_CLOSED;
		snd_pcm_ioplug_reinit_status(&a2dp->io);
	}

	return 0;
}

static snd_pcm_ioplug_callback_t a2dp_callback = {
	.start			= a2dp_start,
	.stop			= a2dp_stop,
	.pointer		= a2dp_pointer,
	.transfer		= a2dp_transfer,
	.close			= a2dp_close,
	.hw_params		= a2dp_params,
	.prepare		= a2dp_prepare,
	.drain			= a2dp_drain,
	.poll_descriptors_count	= a2dp_descriptors_count,
	.poll_descriptors	= a2dp_descriptors,
	.poll_revents		= a2dp_poll,
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

	fcntl(sk, F_SETFL, fcntl(sk, F_GETFL) | O_NONBLOCK);

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

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 8192, 8192);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS, 2, 2);
	if (err < 0)
		return err;

	return 0;
}

#define MAX_CONNECTIONS 10

static snd_pcm_a2dp_t *connections[MAX_CONNECTIONS];

static snd_timer_t *timer = NULL;

static volatile sig_atomic_t __locked = 0;

static inline void a2dp_lock(void)
{
	while (__locked)
		usleep(100);

	__locked = 1;
}

static inline void a2dp_unlock(void)
{
	__locked = 0;
}

static inline snd_pcm_a2dp_t *a2dp_alloc(void)
{
	snd_pcm_a2dp_t *a2dp;

	a2dp = malloc(sizeof(*a2dp));
	if (!a2dp)
		return NULL;

	memset(a2dp, 0, sizeof(*a2dp));

	a2dp->refcnt = 1;

	a2dp->state = BT_OPEN;

	sbc_init(&a2dp->sbc, SBC_NULL);

	return a2dp;
}

static inline void a2dp_free(snd_pcm_a2dp_t *a2dp)
{
	if (a2dp->sk > fileno(stderr))
		close(a2dp->sk);

	sbc_finish(&a2dp->sbc);

	free(a2dp);
}

static void a2dp_timer(snd_async_handler_t *async)
{
	snd_timer_t *handle = snd_async_handler_get_timer(async);
	snd_timer_read_t tr;
	int i, ticks = 0;

	while (snd_timer_read(handle, &tr, sizeof(tr)) == sizeof(tr))
		ticks += tr.ticks;

	a2dp_lock();

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		snd_pcm_a2dp_t *a2dp = connections[i];

		if (a2dp && a2dp->refcnt <= 0) {
			a2dp->timeout = ((a2dp->timeout * 1000) - ticks) / 1000;
			if (a2dp->timeout <= 0) {
				connections[i] = NULL;
				a2dp_free(a2dp);
			}
		}
	}

	a2dp_unlock();
}

static void a2dp_init(void)
{
	snd_async_handler_t *async;
	snd_timer_info_t *info;
	snd_timer_params_t *params;
	long resolution;
	char timername[64];
	int err, i;

	a2dp_lock();

	for (i = 0; i < MAX_CONNECTIONS; i++)
		connections[i] = NULL;

	a2dp_unlock();

	snd_timer_info_alloca(&info);
	snd_timer_params_alloca(&params);

	sprintf(timername, "hw:CLASS=%i,SCLASS=%i,CARD=%i,DEV=%i,SUBDEV=%i",
		SND_TIMER_CLASS_GLOBAL, SND_TIMER_CLASS_NONE, 0,
					SND_TIMER_GLOBAL_SYSTEM, 0);

	err = snd_timer_open(&timer, timername, SND_TIMER_OPEN_NONBLOCK);
	if (err < 0) {
		SNDERR("Can't open global timer");
		return;
	}

	err = snd_timer_info(timer, info);
	if (err < 0) {
		SNDERR("Can't get global timer info");
		return;
	}

	snd_timer_params_set_auto_start(params, 1);

	resolution = snd_timer_info_get_resolution(info);
	snd_timer_params_set_ticks(params, 1000000000 / resolution);
	if (snd_timer_params_get_ticks(params) < 1)
		snd_timer_params_set_ticks(params, 1);

	err = snd_timer_params(timer, params);
	if (err < 0) {
		SNDERR("Can't set global timer parameters");
		snd_timer_close(timer);
		return;
	}

	err = snd_async_add_timer_handler(&async, timer, a2dp_timer, NULL);
	if (err < 0) {
		SNDERR("Can't create global async callback");
		snd_timer_close(timer);
		return;
	}

	err = snd_timer_start(timer);
}

static void a2dp_exit(void)
{
	int err, i;

	err = snd_timer_stop(timer);

	err = snd_timer_close(timer);

	a2dp_lock();

	for (i = 0; i < MAX_CONNECTIONS; i++) {
		snd_pcm_a2dp_t *a2dp = connections[i];

		if (a2dp) {
			connections[i] = NULL;
			a2dp_free(a2dp);
		}
	}

	a2dp_unlock();
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

	a2dp_lock();

	for (n = 0; n < MAX_CONNECTIONS; n++) {
		if (connections[n]) {
			if (!bacmp(&connections[n]->dst, &dst) &&
					(!bacmp(&connections[n]->src, &src) ||
						!bacmp(&src, BDADDR_ANY))) {
				a2dp = connections[n];
				a2dp_get(a2dp);
				break;
			}
		} else if (pos < 0)
			pos = n;
	}

	if (!a2dp) {
		if (pos < 0) {
			SNDERR("Too many connections");
			return -ENOMEM;
		}

		a2dp = a2dp_alloc();
		if (!a2dp) {
			SNDERR("Can't allocate");
			return -ENOMEM;
		}

		connections[pos] = a2dp;

		a2dp->state  = BT_CONNECT;

		bacpy(&a2dp->src, &src);
		bacpy(&a2dp->dst, &dst);
	}

	a2dp_unlock();

	if (a2dp->state != BT_CONNECTED) {
		err = a2dp_connect(a2dp);
		if (err < 0) {
			SNDERR("Can't connect");
			goto error;
		}

		a2dp->state = BT_CONNECTED;
	}

	a2dp->io.version      = SND_PCM_IOPLUG_VERSION;
	a2dp->io.name         = "Bluetooth Advanced Audio Distribution";
	a2dp->io.mmap_rw      = 0;
	a2dp->io.callback     = &a2dp_callback;
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
	a2dp_put(a2dp);

	return err;
}

SND_PCM_PLUGIN_SYMBOL(a2dp);
