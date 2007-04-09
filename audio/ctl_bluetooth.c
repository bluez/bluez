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

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define DBG(fmt, arg...)  printf("DEBUG: %s: " fmt "\n" , __FUNCTION__ , ## arg)

#define SOCKET_NAME "/org/bluez/audio"

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

static void bluetooth_close(snd_ctl_ext_t *ext)
{
	struct bluetooth_data *data = ext->private_data;

	DBG("ext %p", ext);

	close(data->sock);

	free(data);
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
	DBG("ext %p key %td", ext, key);

	*type  = SND_CTL_ELEM_TYPE_INTEGER;
	*acc   = SND_CTL_EXT_ACCESS_READWRITE;
	*count = 1;

	return 0;
}

static int bluetooth_get_integer_info(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
					long *imin, long *imax, long *istep)
{
	DBG("ext %p key %td", ext, key);

	*istep = 1;
	*imin  = BLUETOOTH_MINVOL;
	*imax  = BLUETOOTH_MAXVOL;

	return 0;
}

static int bluetooth_read_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
								long *value)
{
	struct bluetooth_data *data = ext->private_data;
	unsigned char buf[] = { 0x00, 0x00 };
	int len;

	DBG("ext %p key %td", ext, key);

	len = write(data->sock, buf, sizeof(buf));

	*value = 0;

	return 0;
}

static int bluetooth_write_integer(snd_ctl_ext_t *ext, snd_ctl_ext_key_t key,
								long *value)
{
	struct bluetooth_data *data = ext->private_data;
	unsigned char buf[] = { 0xff, 0xff };
	int len;

	DBG("ext %p key %td", ext, key);

	len = write(data->sock, buf, sizeof(buf));

	return 0;
}

static int bluetooth_read_event(snd_ctl_ext_t *ext, snd_ctl_elem_id_t *id,
						unsigned int *event_mask)
{
	struct bluetooth_data *data = ext->private_data;
	unsigned char buf[128];
	int len;

	//DBG("ext %p id %p", ext, id);

	len = recv(data->sock, buf, sizeof(buf), MSG_DONTWAIT);

	return 0;
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

SND_CTL_PLUGIN_DEFINE_FUNC(bluetooth)
{
	snd_config_iterator_t iter, next;
	struct bluetooth_data *data;
	struct sockaddr_un addr;
	unsigned int id;
	int sk, err;

	DBG("");

	snd_config_for_each(iter, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(iter);
		const char *id;

		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "comment") == 0 || strcmp(id, "type") == 0)
			continue;

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
	snprintf(addr.sun_path + 1, UNIX_PATH_MAX - 2, "%s/%d", SOCKET_NAME, id);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		SNDERR("Can't bind socket");
		close(sk);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, UNIX_PATH_MAX - 2, "%s", SOCKET_NAME);

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

	data->ext.version = SND_CTL_EXT_VERSION;
	data->ext.card_idx = -1;

	strncpy(data->ext.id, "bluetooth", sizeof(data->ext.id) - 1);
	strncpy(data->ext.driver, "Bluetooth-Audio", sizeof(data->ext.driver) - 1);
	strncpy(data->ext.name, "Bluetooth Audio", sizeof(data->ext.name) - 1);
	strncpy(data->ext.longname, "Bluetooth Audio", sizeof(data->ext.longname) - 1);
	strncpy(data->ext.mixername, "Bluetooth Audio", sizeof(data->ext.mixername) - 1);

	data->ext.callback = &bluetooth_callback;
	data->ext.poll_fd = sk;
	data->ext.private_data = data;

	err = snd_ctl_ext_create(&data->ext, name, mode);
	if (err < 0)
		goto error;

	*handlep = data->ext.handle;

	return 0;

error:
	free(data);

	return err;
}

SND_CTL_PLUGIN_SYMBOL(bluetooth);
