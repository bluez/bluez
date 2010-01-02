/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>

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
		bt_audio_service_close(data->sock);

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

	*type = SND_CTL_ELEM_TYPE_INTEGER;
	*acc = SND_CTL_EXT_ACCESS_READWRITE;
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
			uint8_t mode, uint8_t key, struct bt_control_rsp *rsp)
{
	int ret;
	struct bt_control_req *req = (void *) rsp;
	bt_audio_error_t *err = (void *) rsp;
	const char *type, *name;

	memset(req, 0, BT_SUGGESTED_BUFFER_SIZE);
	req->h.type = BT_REQUEST;
	req->h.name = BT_CONTROL;
	req->h.length = sizeof(*req);

	req->mode = mode;
	req->key = key;

	ret = send(data->sock, req, BT_SUGGESTED_BUFFER_SIZE, MSG_NOSIGNAL);
	if (ret <= 0) {
		SYSERR("Unable to request new volume value to server");
		return  -errno;
	}

	ret = recv(data->sock, rsp, BT_SUGGESTED_BUFFER_SIZE, 0);
	if (ret <= 0) {
		SNDERR("Unable to receive new volume value from server");
		return  -errno;
	}

	if (rsp->h.type == BT_ERROR) {
		SNDERR("BT_CONTROL failed : %s (%d)",
					strerror(err->posix_errno),
					err->posix_errno);
		return -err->posix_errno;
	}

	type = bt_audio_strtype(rsp->h.type);
	if (!type) {
		SNDERR("Bogus message type %d "
				"received from audio service",
				rsp->h.type);
		return -EINVAL;
	}

	name = bt_audio_strname(rsp->h.name);
	if (!name) {
		SNDERR("Bogus message name %d "
				"received from audio service",
				rsp->h.name);
		return -EINVAL;
	}

	if (rsp->h.name != BT_CONTROL) {
		SNDERR("Unexpected message %s received", type);
		return -EINVAL;
	}

	return 0;
}

static int bluetooth_read_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
								long *value)
{
	struct bluetooth_data *data = ext->private_data;
	int ret;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_control_rsp *rsp = (void *) buf;

	DBG("ext %p key %ld", ext, key);

	memset(buf, 0, sizeof(buf));
	*value = 0;

	ret = bluetooth_send_ctl(data, key, 0, rsp);
	if (ret < 0)
		goto done;

	*value = rsp->key;
done:
	return ret;
}

static int bluetooth_write_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
								long *value)
{
	struct bluetooth_data *data = ext->private_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_control_rsp *rsp = (void *) buf;
	long current;
	int ret, keyvalue;

	DBG("ext %p key %ld", ext, key);

	ret = bluetooth_read_integer(ext, key, &current);
	if (ret < 0)
		return ret;

	if (*value == current)
		return 0;

	while (*value != current) {
		keyvalue = (*value > current) ? BT_CONTROL_KEY_VOL_UP :
				BT_CONTROL_KEY_VOL_DOWN;

		ret = bluetooth_send_ctl(data, key, keyvalue, rsp);
		if (ret < 0)
			break;

		current = keyvalue;
	}

	return ret;
}

static int bluetooth_read_event(snd_ctl_ext_t *ext, snd_ctl_elem_id_t *id,
						unsigned int *event_mask)
{
	struct bluetooth_data *data = ext->private_data;
	char buf[BT_SUGGESTED_BUFFER_SIZE];
	struct bt_control_ind *ind = (void *) buf;
	int ret;
	const char *type, *name;

	DBG("ext %p id %p", ext, id);

	memset(buf, 0, sizeof(buf));

	ret = recv(data->sock, ind, BT_SUGGESTED_BUFFER_SIZE, MSG_DONTWAIT);
	if (ret < 0) {
		SNDERR("Failed while receiving data: %s (%d)",
				strerror(errno), errno);
		return -errno;
	}

	type = bt_audio_strtype(ind->h.type);
	if (!type) {
		SNDERR("Bogus message type %d "
				"received from audio service",
				ind->h.type);
		return -EAGAIN;
	}

	name = bt_audio_strname(ind->h.name);
	if (!name) {
		SNDERR("Bogus message name %d "
				"received from audio service",
				ind->h.name);
		return -EAGAIN;
	}

	if (ind->h.name != BT_CONTROL) {
		SNDERR("Unexpected message %s received", name);
		return -EAGAIN;
	}

	snd_ctl_elem_id_set_interface(id, SND_CTL_ELEM_IFACE_MIXER);
	snd_ctl_elem_id_set_name(id, ind->mode == BLUETOOTH_PLAYBACK ?
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
	int sk;

	if (!data)
		return -EINVAL;

	memset(data, 0, sizeof(struct bluetooth_data));

	data->sock = -1;

	sk = bt_audio_service_open();
	if (sk < 0)
		return -errno;

	data->sock = sk;

	return 0;
}

SND_CTL_PLUGIN_DEFINE_FUNC(bluetooth);

SND_CTL_PLUGIN_DEFINE_FUNC(bluetooth)
{
	struct bluetooth_data *data;
	int err;

	DBG("Bluetooth Control plugin");

	data = malloc(sizeof(struct bluetooth_data));
	if (!data) {
		err = -ENOMEM;
		goto error;
	}

	err = bluetooth_init(data);
	if (err < 0)
		goto error;

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
