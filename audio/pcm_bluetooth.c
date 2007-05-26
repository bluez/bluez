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

#include <sys/socket.h>
#include <sys/un.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#include "ipc.h"

#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)

struct bluetooth_data {
	snd_pcm_ioplug_t io;
	snd_pcm_sframes_t hw_ptr;
	int sock;
};

static int bluetooth_start(snd_pcm_ioplug_t *io)
{
	DBG("io %p", io);

	return 0;
}

static int bluetooth_stop(snd_pcm_ioplug_t *io)
{
	DBG("io %p", io);

	return 0;
}

static snd_pcm_sframes_t bluetooth_pointer(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	//DBG("io %p", io);

	//DBG("hw_ptr=%lu", data->hw_ptr);

	return data->hw_ptr;
}

static int bluetooth_close(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	DBG("io %p", io);

	free(data);

	return 0;
}

static snd_pcm_ioplug_callback_t bluetooth_playback_callback = {
	.start		= bluetooth_start,
	.stop		= bluetooth_stop,
	.pointer	= bluetooth_pointer,
	.close		= bluetooth_close,
#if 0
	.hw_params	= bluetooth_hw_params,
	.prepare	= bluetooth_prepare,
	.transfer	= bluetooth_write,
#endif
};

static snd_pcm_ioplug_callback_t bluetooth_capture_callback = {
	.start		= bluetooth_start,
	.stop		= bluetooth_stop,
	.pointer	= bluetooth_pointer,
	.close		= bluetooth_close,
#if 0
	.hw_params	= bluetooth_hw_params,
	.prepare	= bluetooth_prepare,
	.transfer	= bluetooth_read,
#endif
};

#define ARRAY_NELEMS(a) (sizeof((a)) / sizeof((a)[0]))

static int bluetooth_hw_constraint(snd_pcm_ioplug_t *io)
{
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

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
					ARRAY_NELEMS(access_list), access_list);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
					ARRAY_NELEMS(format_list), format_list);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_CHANNELS, 1, 1);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE, 8000, 8000);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIOD_BYTES, 48, 48);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS, 2, 200);
	if (err < 0)
		return err;

	return 0;
}

SND_PCM_PLUGIN_DEFINE_FUNC(bluetooth)
{
	snd_config_iterator_t iter, next;
	struct bluetooth_data *data;
	struct sockaddr_un addr;
	unsigned int id;
	int sk, err;

	DBG("Bluetooth PCM plugin (%s)",
		stream == SND_PCM_STREAM_PLAYBACK ? "Playback" : "Capture");

	snd_config_for_each(iter, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(iter);
		const char *id;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0)
			continue;

		if (strcmp(id, "bdaddr") == 0) {
			const char *str;
			if (snd_config_get_string(n, &str) < 0) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			printf("bdaddr %s\n", str);
			continue;
		}

		SNDERR("Unknown field %s", id);

		return -EINVAL;
	}

	id = abs(getpid() * rand());

	sk = socket(PF_LOCAL, SOCK_DGRAM, 0);
	if (sk < 0) {
		SNDERR("Can't open socket");
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, UNIX_PATH_MAX - 2, "%s/%d",
			IPC_SOCKET_NAME, id);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		SNDERR("Can't bind socket");
		close(sk);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, UNIX_PATH_MAX - 2, "%s", IPC_SOCKET_NAME);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		SNDERR("Can't connect socket");
		close(sk);
		return -errno;
	}

	data = malloc(sizeof(*data));
	if (!data) {
		close(sk);
		return -ENOMEM;
	}

	memset(data, 0, sizeof(*data));

	data->sock = sk;

	data->io.version = SND_PCM_IOPLUG_VERSION;
	data->io.name = "Bluetooth Audio";
	data->io.mmap_rw =  0;		/* No direct mmap communication */

	data->io.callback = stream == SND_PCM_STREAM_PLAYBACK ?
		&bluetooth_playback_callback : &bluetooth_capture_callback;
	data->io.poll_fd = sk;
	data->io.poll_events = POLLIN;
	data->io.private_data = data;

	err = snd_pcm_ioplug_create(&data->io, name, stream, mode);
	if (err < 0)
		goto error;

	err = bluetooth_hw_constraint(&data->io);
	if (err < 0) {
		snd_pcm_ioplug_delete(&data->io);
		goto error; 
	}

	*pcmp = data->io.pcm;

	return 0;

error:
	close(sk);

	free(data);

	return err;
}

SND_PCM_PLUGIN_SYMBOL(bluetooth);
