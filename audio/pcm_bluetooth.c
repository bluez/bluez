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

#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>

#include "ipc.h"

#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)

#ifndef SCO_TXBUFS
#define SCO_TXBUFS 0x03
#endif

#ifndef SCO_RXBUFS
#define SCO_RXBUFS 0x04
#endif

struct bluetooth_data {
	snd_pcm_ioplug_t io;
	snd_pcm_sframes_t hw_ptr;
	struct ipc_data_cfg cfg;	/* Bluetooth device config */
	int sock;			/* Daemon unix socket */
	uint8_t *buffer;		/* Transfer buffer */
	uint8_t count;			/* Transfer buffer counter */
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

static snd_pcm_sframes_t bluetooth_pointer(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	DBG("bluetooth_pointer %p", io);

	DBG("hw_ptr=%lu", data->hw_ptr);

	return data->hw_ptr;
}

static int bluetooth_close(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	DBG("bluetooth_close %p", io);

	free(data->buffer);
	free(data);

	return 0;
}

static int bluetooth_prepare(snd_pcm_ioplug_t *io)
{
	struct bluetooth_data *data = io->private_data;

	DBG("Preparing with io->period_size = %lu, io->buffer_size = %lu",
			io->period_size, io->buffer_size);

	if (io->stream == SND_PCM_STREAM_PLAYBACK)
		/* If not null for playback, xmms doesn't display time
		 * correctly */
		data->hw_ptr = 0;
	else
		/* ALSA library is really picky on the fact hw_ptr is not null.
		 * If it is, capture won't start */
		data->hw_ptr = io->period_size;

	return 0;
}

static int bluetooth_hw_params(snd_pcm_ioplug_t *io, snd_pcm_hw_params_t *params)
{
	struct bluetooth_data *data = io->private_data;
	struct ipc_data_cfg cfg = data->cfg;
	uint32_t period_count = io->buffer_size / io->period_size;
	int opt_name, err;

	DBG("fd = %d, period_count = %d", cfg.fd, period_count);

	opt_name = (io->stream == SND_PCM_STREAM_PLAYBACK) ?
			SCO_TXBUFS : SCO_RXBUFS;

	if (setsockopt(cfg.fd, SOL_SCO, opt_name, &period_count,
			sizeof(period_count)) == 0)
		return 0;

	opt_name = (io->stream == SND_PCM_STREAM_PLAYBACK) ?
		SO_SNDBUF : SO_RCVBUF;

	if (setsockopt(cfg.fd, SOL_SCO, opt_name, &period_count,
			sizeof(period_count)) == 0)
		return 0;

	err = errno;
	SNDERR("%s (%d)", strerror(err), err);

	return -err;
}

static snd_pcm_sframes_t bluetooth_read(snd_pcm_ioplug_t *io,
					const snd_pcm_channel_area_t *areas,
					snd_pcm_uframes_t offset,
					snd_pcm_uframes_t size)
{
	struct bluetooth_data *data = io->private_data;
	struct ipc_data_cfg cfg = data->cfg;
	snd_pcm_uframes_t frames_to_write, ret;
	unsigned char *buff;
	int nrecv;

	DBG("areas->step=%u, areas->first=%u, offset=%lu, size=%lu, io->nonblock=%u",
		areas->step, areas->first, offset, size, io->nonblock);

	if (data->count > 0)
		goto proceed;

	nrecv = recv(cfg.fd, data->buffer, cfg.pkt_len,
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
	data->hw_ptr = (data->hw_ptr + cfg.pkt_len / cfg.sample_size) % io->buffer_size;

proceed:
	buff = (unsigned char *) areas->addr + (areas->first + areas->step * offset) / 8;

	if ((data->count + cfg.sample_size * size) <= cfg.pkt_len)
		frames_to_write = size;
	else
		frames_to_write = (cfg.pkt_len - data->count) / cfg.sample_size;

	memcpy(buff, data->buffer + data->count, areas->step / 8 * frames_to_write);
	data->count += (areas->step / 8 * frames_to_write);
	data->count %= cfg.pkt_len;

	/* Return written frames count */
	ret = frames_to_write;

done:
	DBG("returning %lu", ret);
	return ret;
}

static snd_pcm_sframes_t bluetooth_write(snd_pcm_ioplug_t *io,
					const snd_pcm_channel_area_t *areas,
					snd_pcm_uframes_t offset,
					snd_pcm_uframes_t size)
{
	struct bluetooth_data *data = io->private_data;
	struct ipc_data_cfg cfg = data->cfg;
	snd_pcm_sframes_t ret = 0;
	snd_pcm_uframes_t frames_to_read;
	uint8_t *buff;
	int rsend;

	DBG("areas->step=%u, areas->first=%u, offset=%lu, size=%lu,"
			"io->nonblock=%u", areas->step, areas->first,
			offset, size, io->nonblock);

	if ((data->count + cfg.sample_size * size) <= cfg.pkt_len)
		frames_to_read = size;
	else
		frames_to_read = (cfg.pkt_len - data->count) / cfg.sample_size;

	DBG("count = %d, frames_to_read = %lu", data->count, frames_to_read);

	/* Ready for more data */
	buff = (uint8_t *) areas->addr + (areas->first + areas->step * offset) / 8;
	memcpy(data->buffer + data->count, buff, areas->step / 8 * frames_to_read);

	if ((data->count + areas->step / 8 * frames_to_read) != cfg.pkt_len) {
		/* Remember we have some frame in the pipe now */
		data->count += areas->step / 8 * frames_to_read;
		ret = frames_to_read;
		goto done;
	}

	rsend = send(cfg.fd, data->buffer, cfg.pkt_len,
			io->nonblock ? MSG_DONTWAIT : 0);
	if (rsend > 0) {
		/* Reset count pointer */
		data->count = 0;

		/* Increment hardware transmition pointer */
		data->hw_ptr = (data->hw_ptr + frames_to_read / cfg.sample_size)
				% io->buffer_size;

		ret = frames_to_read;
	} else if (rsend < 0)
		ret = (errno == EPIPE) ? -EIO : -errno;
	else
		ret = -EIO;

done:
	DBG("returning %d", (int)ret);
	return ret;
}

static snd_pcm_ioplug_callback_t bluetooth_playback_callback = {
	.start		= bluetooth_start,
	.stop		= bluetooth_stop,
	.pointer	= bluetooth_pointer,
	.close		= bluetooth_close,
	.hw_params	= bluetooth_hw_params,
	.prepare	= bluetooth_prepare,
	.transfer	= bluetooth_write,
};

static snd_pcm_ioplug_callback_t bluetooth_capture_callback = {
	.start		= bluetooth_start,
	.stop		= bluetooth_stop,
	.pointer	= bluetooth_pointer,
	.close		= bluetooth_close,
	.hw_params	= bluetooth_hw_params,
	.prepare	= bluetooth_prepare,
	.transfer	= bluetooth_read,
};

#define ARRAY_NELEMS(a) (sizeof((a)) / sizeof((a)[0]))

static int bluetooth_hw_constraint(snd_pcm_ioplug_t *io)
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
					cfg.channels, cfg.channels);
	if (err < 0)
		return err;

	err = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_RATE,
					cfg.rate, cfg.rate);
	if (err < 0)
		return err;

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

static int bluetooth_recvmsg_fd(struct bluetooth_data *data)
{
	char cmsg_b[CMSG_SPACE(sizeof(int))];
	struct ipc_packet pkt;
	int err, ret;
	struct iovec iov = {
		.iov_base = &pkt,
		.iov_len  = sizeof(pkt)
        };
	struct msghdr msgh = {
		.msg_name       = 0,
		.msg_namelen    = 0,
		.msg_iov        = &iov,
		.msg_iovlen     = 1,
		.msg_control    = &cmsg_b,
		.msg_controllen = CMSG_LEN(sizeof(int)),
		.msg_flags      = 0
	};

	ret = recvmsg(data->sock, &msgh, 0);

	if (ret < 0) {
		err = errno;
		SNDERR("Unable to receive fd: %s (%d)", strerror(err), err);
		return -err;
	}

	if (pkt.type == PKT_TYPE_CFG_RSP) {
		struct cmsghdr *cmsg;
		/* Receive auxiliary data in msgh */
		for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
				cmsg = CMSG_NXTHDR(&msgh,cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET
				&& cmsg->cmsg_type == SCM_RIGHTS)
				data->cfg.fd = (*(int *) CMSG_DATA(cmsg));
				DBG("fd = %d", data->cfg.fd);
				return 0;
		}
	}
	else
		SNDERR("Unexpected packet type received: type = %d", pkt.type);

	return -EINVAL;
}

static int bluetooth_cfg(struct bluetooth_data *data)
{
	int ret, len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_cfg);
	struct ipc_packet *pkt;

	DBG("Sending PKT_TYPE_CFG_REQ...");

	if ((pkt = malloc(len)) == 0)
		return -ENOMEM;

	memset(pkt, 0, len);
	pkt->type = PKT_TYPE_CFG_REQ;
	pkt->role = PKT_ROLE_NONE;
	pkt->error = PKT_ERROR_NONE;

	if ((ret = send(data->sock, pkt, len, 0)) < 0) {
		ret = -errno;
		goto done;
	} else if (ret == 0) {
		ret = -EIO;
		goto done;
	}

	DBG("OK - %d bytes sent", ret);

	DBG("Waiting for response...");

	memset(pkt, 0, len);
	if ((ret = recv(data->sock, pkt, len, 0)) < 0) {
		ret = -errno;
		goto done;
	} else if (ret == 0) {
		ret = -EIO;
		goto done;
	}

	DBG("OK - %d bytes received", ret);

	if (pkt->type != PKT_TYPE_CFG_RSP) {
		SNDERR("Unexpected packet type received: type = %d",
				pkt->type);
		ret = -EINVAL;
		goto done;
	}

	if (pkt->error != PKT_ERROR_NONE) {
		SNDERR("Error while configuring device: error = %d",
				pkt->error);
		ret = pkt->error;
		goto done;
	}

	if (pkt->length != sizeof(struct ipc_data_cfg)) {
		SNDERR("Error while configuring device: packet size doesn't "
				"match");
		ret = -EINVAL;
		goto done;
	}

	memcpy(&data->cfg, pkt->data, sizeof(struct ipc_data_cfg));

	DBG("Device configuration:");

	DBG("fd=%d, fd_opt=%u, channels=%u, pkt_len=%u, sample_size=%u,"
			"rate=%u", data->cfg.fd, data->cfg.fd_opt,
			data->cfg.channels, data->cfg.pkt_len,
			data->cfg.sample_size, data->cfg.rate);

	if (data->cfg.fd == -1) {
		SNDERR("Error while configuring device: could not acquire "
				"audio socket");
		ret = -EINVAL;
		goto done;
	}

	if ((ret = bluetooth_recvmsg_fd(data)) < 0)
		goto done;

	if ((data->buffer = malloc(data->cfg.pkt_len)) == 0)
		return -ENOMEM;

	/* It is possible there is some outstanding
	data in the pipe - we have to empty it */
	while(recv(data->cfg.fd, data->buffer, data->cfg.pkt_len,
		MSG_DONTWAIT) > 0);

	memset(data->buffer, 0, data->cfg.pkt_len);

done:
	free(pkt);
	return ret;
}

static int bluetooth_init(struct bluetooth_data *data)
{
	int sk, err, id;
	struct sockaddr_un addr = {
		AF_UNIX, IPC_SOCKET_NAME
	};

	if (!data)
		return -EINVAL;

	memset(data, 0, sizeof(struct bluetooth_data));

	data->sock = -1;

	id = abs(getpid() * rand());

	if ((sk = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		err = -errno;
		SNDERR("Can't open socket");
		return -errno;
	}

	DBG("Connecting to address: %s", addr.sun_path + 1);
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		SNDERR("Can't connect socket");
		close(sk);
		return err;
	}

	data->sock = sk;

	if ((err = bluetooth_cfg(data)) < 0)
		return err;

	return 0;
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

	err = bluetooth_init(data);
	if (err < 0)
		goto error;

	data->io.version = SND_PCM_IOPLUG_VERSION;
	data->io.name = "Bluetooth Audio Device";
	data->io.mmap_rw = 0; /* No direct mmap communication */

	data->io.callback = stream == SND_PCM_STREAM_PLAYBACK ?
		&bluetooth_playback_callback : &bluetooth_capture_callback;
	data->io.poll_fd = data->cfg.fd;
	data->io.poll_events = stream == SND_PCM_STREAM_PLAYBACK ?
					POLLOUT : POLLIN;
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
	if (data) {
		if (data->sock >= 0)
			close(data->sock);
		free(data);
	}

	return err;
}

SND_PCM_PLUGIN_SYMBOL(bluetooth);
