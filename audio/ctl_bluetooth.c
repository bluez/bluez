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
#include <alsa/control_external.h>

#include "ipc.h"

#ifdef ENABLE_DEBUG
#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)
#else
#define DBG(fmt, arg...)
#endif

#define BLUETOOTH_MINVOL 0
#define BLUETOOTH_MAXVOL 15

struct bluetooth_data {
	snd_ctl_ext_t ext;
	int sock;
};

enum {
	BLUETOOTH_PLAYBACK,
	BLUETOOTH_CAPTURE,
};

static const char *vol_devices[2] = {
	[BLUETOOTH_PLAYBACK]	= "Playback volume",
	[BLUETOOTH_CAPTURE]	= "Capture volume",
};

static void bluetooth_exit(struct bluetooth_data *data)
{
	if (data == NULL)
		return;

	if (data->sock >= 0)
		close(data->sock);

	free(data);
}

static void bluetooth_close(snd_ctl_ext_t *ext)
{
	struct bluetooth_data *data = ext->private_data;

	DBG("ext %p", ext);

	bluetooth_exit(data);
}

static int bluetooth_elem_count(snd_ctl_ext_t *ext)
{
	DBG("ext %p", ext);

	return 2;
}

static int bluetooth_elem_list(snd_ctl_ext_t *ext,
				unsigned int offset, snd_ctl_elem_id_t *id)
{
	DBG("ext %p offset %d id %p", ext, offset, id);

	snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);

	if (offset > 1)
		return -EINVAL;

	snd_ctl_elem_id_set_name(id, vol_devices[offset]);

	return 0;
}

static snd_ctl_ext_key_t bluetooth_find_elem(snd_ctl_ext_t *ext,
						const snd_ctl_elem_id_t *id)
{
	const char *name = snd_ctl_elem_id_get_name(id);
	int i;

	DBG("ext %p id %p name '%s'", ext, id, name);

	for (i = 0; i < 2; i++)
		if (strcmp(name, vol_devices[i]) == 0)
			return i;

	return SND_CTL_EXT_KEY_NOT_FOUND;
}

static int bluetooth_get_attribute(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
			int *type, unsigned int *acc, unsigned int *count)
{
	DBG("ext %p key %ld", ext, key);

	*type  = SND_CTL_ELEM_TYPE_INTEGER;
	*acc   = SND_CTL_EXT_ACCESS_READWRITE;
	*count = 1;

	return 0;
}

static int bluetooth_get_integer_info(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
					long *imin, long *imax, long *istep)
{
	DBG("ext %p key %ld", ext, key);

	*istep = 1;
	*imin  = BLUETOOTH_MINVOL;
	*imax  = BLUETOOTH_MAXVOL;

	return 0;
}

static int bluetooth_send_ctl(struct bluetooth_data *data,
				struct ipc_packet *pkt, int len)
{
	int ret;

	ret = send(data->sock, pkt, len, MSG_NOSIGNAL);
	if (ret <= 0) {
		SYSERR("Unable to request new volume value to server");
		return  -errno;
	}

	ret = recv(data->sock, pkt, len, 0);
	if (ret <= 0) {
		SYSERR("Unable to receive new volume value from server");
		return  -errno;
	}

	if(pkt->type != PKT_TYPE_CTL_RSP) {
		SNDERR("Unexpected packet type %d received", pkt->type);
		return -EINVAL;
	}

	if(pkt->length != sizeof(struct ipc_data_ctl)) {
		SNDERR("Unexpected packet length %d received", pkt->length);
		return -EINVAL;
	}

	return 0;
}

static int bluetooth_read_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
								long *value)
{
	struct bluetooth_data *data = ext->private_data;
	struct ipc_packet *pkt;
	struct ipc_data_ctl *ctl;
	int len, ret;

	DBG("ext %p key %ld", ext, key);

	len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_ctl);
	pkt = malloc(len);
	memset(pkt, 0, len);
	*value = 0;

	pkt->type = PKT_TYPE_CTL_REQ;
	pkt->length = sizeof(struct ipc_data_ctl);
	ctl = (struct ipc_data_ctl *) pkt->data;
	ctl->mode = key;

	if ((ret = bluetooth_send_ctl(data, pkt, len)) < 0)
		goto done;

	*value = ctl->key;
done:
	free(pkt);
	return ret;
}

static int bluetooth_write_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
								long *value)
{
	struct bluetooth_data *data = ext->private_data;
	struct ipc_packet *pkt;
	struct ipc_data_ctl *ctl;
	long current;
	int len, ret;

	DBG("ext %p key %ld", ext, key);

	if ((ret = bluetooth_read_integer(ext, key, &current)) < 0)
		return ret;

	if (*value == current)
		return 0;

	len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_ctl);
	pkt = malloc(len);
	memset(pkt, 0, len);

	pkt->length = sizeof(struct ipc_data_ctl);
	ctl = (struct ipc_data_ctl *) pkt->data;
	ctl->mode = key;

	while (*value != current) {
		pkt->type = PKT_TYPE_CTL_REQ;
		ctl->key = (*value > current) ? CTL_KEY_VOL_UP : CTL_KEY_VOL_DOWN;

		if ((ret = bluetooth_send_ctl(data, pkt, len)) < 0)
			break;

		current = ctl->key;
	}

	free(pkt);
	return ret;
}

static int bluetooth_read_event(snd_ctl_ext_t *ext, snd_ctl_elem_id_t *id,
						unsigned int *event_mask)
{
	struct bluetooth_data *data = ext->private_data;
	struct ipc_packet *pkt;
	struct ipc_data_ctl *ctl;
	int len, ret;

	DBG("ext %p id %p", ext, id);

	len = sizeof(struct ipc_packet) + sizeof(struct ipc_data_ctl);
	pkt = malloc(len);
	memset(pkt, 0, len);

	ret = recv(data->sock, pkt, len, MSG_DONTWAIT);
	if (ret <= 0)
		return  -errno;

	if(pkt->type != PKT_TYPE_CTL_NTFY) {
		SNDERR("Unexpected packet type %d received!", pkt->type);
		return -EAGAIN;
	}

	if(pkt->length != sizeof(struct ipc_data_ctl)) {
		SNDERR("Unexpected packet length %d received", pkt->length);
		return -EAGAIN;
	}

	ctl = (struct ipc_data_ctl *) pkt->data;
	snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
	snd_ctl_elem_id_set_name(id, ctl->mode == BLUETOOTH_PLAYBACK ?
				vol_devices[BLUETOOTH_PLAYBACK] :
				vol_devices[BLUETOOTH_CAPTURE]);
	*event_mask = SND_CTL_EVENT_MASK_VALUE;

	return 1;
}

static snd_ctl_ext_callback_t bluetooth_callback = {
	.close			= bluetooth_close,
	.elem_count		= bluetooth_elem_count,
	.elem_list		= bluetooth_elem_list,
	.find_elem		= bluetooth_find_elem,
	.get_attribute		= bluetooth_get_attribute,
	.get_integer_info	= bluetooth_get_integer_info,
	.read_integer		= bluetooth_read_integer,
	.write_integer		= bluetooth_write_integer,
	.read_event		= bluetooth_read_event,
};

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

	return 0;
}

SND_CTL_PLUGIN_DEFINE_FUNC(bluetooth)
{
	struct bluetooth_data *data;
	int err;

	DBG("Bluetooth Control plugin");

	data = malloc(sizeof(struct bluetooth_data));
	memset(data, 0, sizeof(struct bluetooth_data));
	if (!data) {
		err = -ENOMEM;
		goto error;
	}

	err = bluetooth_init(data);
	if (err < 0)
		goto error;

	memset(data, 0, sizeof(*data));

	data->ext.version = SND_CTL_EXT_VERSION;
	data->ext.card_idx = -1;

	strncpy(data->ext.id, "bluetooth", sizeof(data->ext.id) - 1);
	strncpy(data->ext.driver, "Bluetooth-Audio", sizeof(data->ext.driver) - 1);
	strncpy(data->ext.name, "Bluetooth Audio", sizeof(data->ext.name) - 1);
	strncpy(data->ext.longname, "Bluetooth Audio", sizeof(data->ext.longname) - 1);
	strncpy(data->ext.mixername, "Bluetooth Audio", sizeof(data->ext.mixername) - 1);

	data->ext.callback = &bluetooth_callback;
	data->ext.poll_fd = data->sock;
	data->ext.private_data = data;

	err = snd_ctl_ext_create(&data->ext, name, mode);
	if (err < 0)
		goto error;

	*handlep = data->ext.handle;

	return 0;

error:
	bluetooth_exit(data);

	return err;
}

SND_CTL_PLUGIN_SYMBOL(bluetooth);
