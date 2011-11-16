/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <gdbus.h>

#include "../src/dbus-common.h"
#include "../src/adapter.h"

#include "log.h"

#include "error.h"
#include "sdpd.h"
#include "glib-helper.h"
#include "btio.h"
#include "proxy.h"

#define SERIAL_PROXY_INTERFACE	"org.bluez.SerialProxy"
#define SERIAL_MANAGER_INTERFACE "org.bluez.SerialProxyManager"
#define BUF_SIZE		1024

typedef enum {
	TTY_PROXY,
	UNIX_SOCKET_PROXY,
	TCP_SOCKET_PROXY,
	UNKNOWN_PROXY_TYPE = 0xFF
} proxy_type_t;

struct serial_adapter {
	struct btd_adapter	*btd_adapter;	/* Adapter pointer */
	DBusConnection		*conn;		/* Adapter connection */
	GSList			*proxies;	/* Proxies list */
};

struct serial_proxy {
	bdaddr_t	src;		/* Local address */
	bdaddr_t	dst;		/* Remote address */
	char		*path;		/* Proxy path */
	char		*uuid128;	/* UUID 128 */
	char		*address;	/* TTY or Unix socket name */
	char		*owner;		/* Application bus name */
	guint		watch;		/* Application watch */
	short int	port;		/* TCP port */
	proxy_type_t	type;		/* TTY or Unix socket */
	struct termios  sys_ti;		/* Default TTY setting */
	struct termios  proxy_ti;	/* Proxy TTY settings */
	uint8_t		channel;	/* RFCOMM channel */
	uint32_t	record_id;	/* Service record id */
	GIOChannel	*io;		/* Server listen */
	GIOChannel	*rfcomm;	/* Remote RFCOMM channel*/
	GIOChannel	*local;		/* Local channel: TTY or Unix socket */
	struct serial_adapter *adapter;	/* Adapter pointer */
};

static GSList *adapters = NULL;
static int sk_counter = 0;

static void disable_proxy(struct serial_proxy *prx)
{
	if (prx->rfcomm) {
		g_io_channel_shutdown(prx->rfcomm, TRUE, NULL);
		g_io_channel_unref(prx->rfcomm);
		prx->rfcomm = NULL;
	}

	if (prx->local) {
		g_io_channel_shutdown(prx->local, TRUE, NULL);
		g_io_channel_unref(prx->local);
		prx->local = NULL;
	}

	remove_record_from_server(prx->record_id);
	prx->record_id = 0;

	g_io_channel_unref(prx->io);
	prx->io = NULL;
}

static void proxy_free(struct serial_proxy *prx)
{
	g_free(prx->owner);
	g_free(prx->path);
	g_free(prx->address);
	g_free(prx->uuid128);
	g_free(prx);
}

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	/* UTF-8 MIBenum (http://www.iana.org/assignments/character-sets) */
	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

static sdp_record_t *proxy_record_new(const char *uuid128, uint8_t channel)
{
	sdp_list_t *apseq, *aproto, *profiles, *proto[2], *root, *svclass_id;
	uuid_t uuid, root_uuid, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_record_t *record;
	sdp_data_t *ch;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);
	sdp_list_free(root, NULL);

	bt_string2uuid(&uuid, uuid128);
	sdp_uuid128_to_uuid(&uuid);
	svclass_id = sdp_list_append(NULL, &uuid);
	sdp_set_service_classes(record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, profiles);
	sdp_list_free(profiles, NULL);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	ch = sdp_data_alloc(SDP_UINT8, &channel);
	proto[1] = sdp_list_append(proto[1], ch);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	add_lang_attr(record);

	sdp_set_info_attr(record, "Serial Proxy", NULL, "Serial Proxy");

	sdp_data_free(ch);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	return record;
}

static int channel_write(GIOChannel *chan, char *buf, size_t size)
{
	size_t wbytes;
	ssize_t written;
	int fd;

	fd = g_io_channel_unix_get_fd(chan);

	wbytes = 0;
	while (wbytes < size) {
		written = write(fd, buf + wbytes, size - wbytes);
		if (written < 0)
			return -errno;

		wbytes += written;
	}

	return 0;
}

static gboolean forward_data(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[BUF_SIZE];
	struct serial_proxy *prx = data;
	GIOChannel *dest;
	ssize_t rbytes;
	int fd, err;

	if (cond & G_IO_NVAL)
		return FALSE;

	dest = (chan == prx->rfcomm) ? prx->local : prx->rfcomm;

	fd = g_io_channel_unix_get_fd(chan);

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		/* Try forward remaining data */
		do {
			rbytes = read(fd, buf, sizeof(buf));
			if (rbytes <= 0)
				break;

			err = channel_write(dest, buf, rbytes);
		} while (err == 0);

		g_io_channel_shutdown(prx->local, TRUE, NULL);
		g_io_channel_unref(prx->local);
		prx->local = NULL;

		g_io_channel_shutdown(prx->rfcomm, TRUE, NULL);
		g_io_channel_unref(prx->rfcomm);
		prx->rfcomm = NULL;

		return FALSE;
	}

	rbytes = read(fd, buf, sizeof(buf));
	if (rbytes < 0)
		return FALSE;

	err = channel_write(dest, buf, rbytes);
	if (err != 0)
		return FALSE;

	return TRUE;
}

static inline int unix_socket_connect(const char *address)
{
	struct sockaddr_un addr;
	int err, sk;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	if (strncmp("x00", address, 3) == 0) {
		/*
		 * Abstract namespace: first byte NULL, x00
		 * must be removed from the original address.
		 */
		strncpy(addr.sun_path + 1, address + 3,
						sizeof(addr.sun_path) - 2);
	} else {
		/* Filesystem address */
		strncpy(addr.sun_path, address, sizeof(addr.sun_path) - 1);
	}

	/* Unix socket */
	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		err = -errno;
		error("Unix socket(%s) create failed: %s(%d)",
				address, strerror(-err), -err);
		return err;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		error("Unix socket(%s) connect failed: %s(%d)",
				address, strerror(-err), -err);
		close(sk);
		return err;
	}

	return sk;
}

static int tcp_socket_connect(const char *address)
{
	struct sockaddr_in addr;
	int err, sk, port;

	memset(&addr, 0, sizeof(addr));

	if (strncmp(address, "localhost", 9) != 0) {
		error("Address should have the form localhost:port.");
		return -1;
	}
	port = atoi(strchr(address, ':') + 1);
	if (port <= 0) {
		error("Invalid port '%d'.", port);
		return -1;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(port);

	sk = socket(PF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		err = -errno;
		error("TCP socket(%s) create failed %s(%d)", address,
							strerror(-err), -err);
		return err;
	}
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		error("TCP socket(%s) connect failed: %s(%d)",
						address, strerror(-err), -err);
		close(sk);
		return err;
	}
	return sk;
}

static inline int tty_open(const char *tty, struct termios *ti)
{
	int err, sk;

	sk = open(tty, O_RDWR | O_NOCTTY);
	if (sk < 0) {
		err = -errno;
		error("Can't open TTY %s: %s(%d)", tty, strerror(-err), -err);
		return err;
	}

	if (ti && tcsetattr(sk, TCSANOW, ti) < 0) {
		err = -errno;
		error("Can't change serial settings: %s(%d)",
				strerror(-err), -err);
		close(sk);
		return err;
	}

	return sk;
}

static void connect_event_cb(GIOChannel *chan, GError *conn_err, gpointer data)
{
	struct serial_proxy *prx = data;
	int sk;

	if (conn_err) {
		error("%s", conn_err->message);
		goto drop;
	}

	/* Connect local */
	switch (prx->type) {
	case UNIX_SOCKET_PROXY:
		sk = unix_socket_connect(prx->address);
		break;
	case TTY_PROXY:
		sk = tty_open(prx->address, &prx->proxy_ti);
		break;
	case TCP_SOCKET_PROXY:
		sk = tcp_socket_connect(prx->address);
		break;
	default:
		sk = -1;
	}

	if (sk < 0)
		goto drop;

	prx->local = g_io_channel_unix_new(sk);

	g_io_add_watch(prx->rfcomm,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			forward_data, prx);

	g_io_add_watch(prx->local,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			forward_data, prx);

	return;

drop:
	g_io_channel_shutdown(prx->rfcomm, TRUE, NULL);
	g_io_channel_unref(prx->rfcomm);
	prx->rfcomm = NULL;
}

static void auth_cb(DBusError *derr, void *user_data)
{
	struct serial_proxy *prx = user_data;
	GError *err = NULL;

	if (derr) {
		error("Access denied: %s", derr->message);
		goto reject;
	}

	if (!bt_io_accept(prx->rfcomm, connect_event_cb, prx, NULL,
							&err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		goto reject;
	}

	return;

reject:
	g_io_channel_shutdown(prx->rfcomm, TRUE, NULL);
	g_io_channel_unref(prx->rfcomm);
	prx->rfcomm = NULL;
}

static void confirm_event_cb(GIOChannel *chan, gpointer user_data)
{
	struct serial_proxy *prx = user_data;
	int perr;
	char address[18];
	GError *err = NULL;

	bt_io_get(chan, BT_IO_RFCOMM, &err,
			BT_IO_OPT_DEST_BDADDR, &prx->dst,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	if (prx->rfcomm) {
		error("Refusing connect from %s: Proxy already in use",
				address);
		goto drop;
	}

	DBG("Serial Proxy: incoming connect from %s", address);

	prx->rfcomm = g_io_channel_ref(chan);

	perr = btd_request_authorization(&prx->src, &prx->dst,
					prx->uuid128, auth_cb, prx);
	if (perr < 0) {
		error("Refusing connect from %s: %s (%d)", address,
				strerror(-perr), -perr);
		g_io_channel_unref(prx->rfcomm);
		prx->rfcomm = NULL;
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(chan, TRUE, NULL);
}

static int enable_proxy(struct serial_proxy *prx)
{
	sdp_record_t *record;
	GError *gerr = NULL;
	int err;

	if (prx->io)
		return -EALREADY;

	/* Listen */
	prx->io = bt_io_listen(BT_IO_RFCOMM, NULL, confirm_event_cb, prx,
				NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &prx->src,
				BT_IO_OPT_INVALID);
	if (!prx->io)
		goto failed;

	bt_io_get(prx->io, BT_IO_RFCOMM, &gerr,
			BT_IO_OPT_CHANNEL, &prx->channel,
			BT_IO_OPT_INVALID);
	if (gerr) {
		g_io_channel_unref(prx->io);
		prx->io = NULL;
		goto failed;
	}

	DBG("Allocated channel %d", prx->channel);

	g_io_channel_set_close_on_unref(prx->io, TRUE);

	record = proxy_record_new(prx->uuid128, prx->channel);
	if (!record) {
		g_io_channel_unref(prx->io);
		return -ENOMEM;
	}

	err = add_record_to_server(&prx->src, record);
	if (err < 0) {
		sdp_record_free(record);
		g_io_channel_unref(prx->io);
		return err;
	}

	prx->record_id = record->handle;

	return 0;

failed:
	error("%s", gerr->message);
	g_error_free(gerr);
	return -EIO;

}
static DBusMessage *proxy_enable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct serial_proxy *prx = data;
	int err;

	err = enable_proxy(prx);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return dbus_message_new_method_return(msg);
}

static DBusMessage *proxy_disable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct serial_proxy *prx = data;

	if (!prx->io)
		return btd_error_failed(msg, "Not enabled");

	/* Remove the watches and unregister the record */
	disable_proxy(prx);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *proxy_get_info(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct serial_proxy *prx = data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	dbus_bool_t boolean;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "uuid", DBUS_TYPE_STRING, &prx->uuid128);

	dict_append_entry(&dict, "address", DBUS_TYPE_STRING, &prx->address);

	if (prx->channel)
		dict_append_entry(&dict, "channel",
					DBUS_TYPE_BYTE, &prx->channel);

	boolean = (prx->io ? TRUE : FALSE);
	dict_append_entry(&dict, "enabled", DBUS_TYPE_BOOLEAN, &boolean);

	boolean = (prx->rfcomm ? TRUE : FALSE);
	dict_append_entry(&dict, "connected", DBUS_TYPE_BOOLEAN, &boolean);

	/* If connected: append the remote address */
	if (boolean) {
		char bda[18];
		const char *pstr = bda;

		ba2str(&prx->dst, bda);
		dict_append_entry(&dict, "address", DBUS_TYPE_STRING, &pstr);
	}

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static struct {
	const char	*str;
	speed_t		speed;
} supported_speed[]  = {
	{"50",		B50	},
	{"300",		B300	},
	{"600",		B600	},
	{"1200",	B1200	},
	{"1800",	B1800	},
	{"2400",	B2400	},
	{"4800",	B4800	},
	{"9600",	B9600	},
	{"19200",	B19200	},
	{"38400",	B38400	},
	{"57600",	B57600	},
	{"115200",	B115200	},
	{ NULL,		B0	}
};

static speed_t str2speed(const char *str, speed_t *speed)
{
	int i;

	for (i = 0; supported_speed[i].str; i++) {
		if (strcmp(supported_speed[i].str, str) != 0)
			continue;

		if (speed)
			*speed = supported_speed[i].speed;

		return supported_speed[i].speed;
	}

	return B0;
}

static int set_parity(const char *str, tcflag_t *ctrl)
{
	if (strcasecmp("even", str) == 0) {
		*ctrl |= PARENB;
		*ctrl &= ~PARODD;
	} else if (strcasecmp("odd", str) == 0) {
		*ctrl |= PARENB;
		*ctrl |= PARODD;
	} else if (strcasecmp("mark", str) == 0)
		*ctrl |= PARENB;
	else if ((strcasecmp("none", str) == 0) ||
			(strcasecmp("space", str) == 0))
		*ctrl &= ~PARENB;
	else
		return -1;

	return 0;
}

static int set_databits(uint8_t databits, tcflag_t *ctrl)
{
	if (databits < 5 || databits > 8)
		return -EINVAL;

	*ctrl &= ~CSIZE;
	switch (databits) {
	case 5:
		*ctrl |= CS5;
		break;
	case 6:
		*ctrl |= CS6;
		break;
	case 7:
		*ctrl |= CS7;
		break;
	case 8:
		*ctrl |= CS8;
		break;
	}

	return 0;
}

static int set_stopbits(uint8_t stopbits, tcflag_t *ctrl)
{
	/* 1.5 will not be allowed */
	switch (stopbits) {
	case 1:
		*ctrl &= ~CSTOPB;
		return 0;
	case 2:
		*ctrl |= CSTOPB;
		return 0;
	}

	return -EINVAL;
}

static DBusMessage *proxy_set_serial_params(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct serial_proxy *prx = data;
	const char *ratestr, *paritystr;
	uint8_t databits, stopbits;
	tcflag_t ctrl;		/* Control mode flags */
	speed_t speed = B0;	/* In/Out speed */

	/* Don't allow change TTY settings if it is open */
	if (prx->local)
		return btd_error_not_authorized(msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &ratestr,
				DBUS_TYPE_BYTE, &databits,
				DBUS_TYPE_BYTE, &stopbits,
				DBUS_TYPE_STRING, &paritystr,
				DBUS_TYPE_INVALID))
		return NULL;

	if (str2speed(ratestr, &speed)  == B0)
		return btd_error_invalid_args(msg);

	ctrl = prx->proxy_ti.c_cflag;
	if (set_databits(databits, &ctrl) < 0)
		return btd_error_invalid_args(msg);

	if (set_stopbits(stopbits, &ctrl) < 0)
		return btd_error_invalid_args(msg);

	if (set_parity(paritystr, &ctrl) < 0)
		return btd_error_invalid_args(msg);

	prx->proxy_ti.c_cflag = ctrl;
	prx->proxy_ti.c_cflag |= (CLOCAL | CREAD);
	cfsetispeed(&prx->proxy_ti, speed);
	cfsetospeed(&prx->proxy_ti, speed);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable proxy_methods[] = {
	{ "Enable",			"",	"",	proxy_enable },
	{ "Disable",			"",	"",	proxy_disable },
	{ "GetInfo",			"",	"a{sv}",proxy_get_info },
	{ "SetSerialParameters",	"syys",	"",	proxy_set_serial_params },
	{ },
};

static void proxy_path_unregister(gpointer data)
{
	struct serial_proxy *prx = data;
	int sk;

	DBG("Unregistered proxy: %s", prx->address);

	if (prx->type != TTY_PROXY)
		goto done;

	/* Restore the initial TTY configuration */
	sk = open(prx->address, O_RDWR | O_NOCTTY);
	if (sk >= 0) {
		tcsetattr(sk, TCSAFLUSH, &prx->sys_ti);
		close(sk);
	}
done:

	proxy_free(prx);
}

static int register_proxy_object(struct serial_proxy *prx)
{
	struct serial_adapter *adapter = prx->adapter;
	char path[MAX_PATH_LENGTH + 1];

	snprintf(path, MAX_PATH_LENGTH, "%s/proxy%d",
			adapter_get_path(adapter->btd_adapter), sk_counter++);

	if (!g_dbus_register_interface(adapter->conn, path,
					SERIAL_PROXY_INTERFACE,
					proxy_methods, NULL, NULL,
					prx, proxy_path_unregister)) {
		error("D-Bus failed to register %s path", path);
		return -1;
	}

	prx->path = g_strdup(path);
	adapter->proxies = g_slist_append(adapter->proxies, prx);

	DBG("Registered proxy: %s", path);

	return 0;
}

static int proxy_tty_register(struct serial_adapter *adapter,
				const char *uuid128, const char *address,
				struct termios *ti,
				struct serial_proxy **proxy)
{
	struct termios sys_ti;
	struct serial_proxy *prx;
	int sk, ret;

	sk = open(address, O_RDONLY | O_NOCTTY);
	if (sk < 0) {
		error("Can't open TTY: %s(%d)", strerror(errno), errno);
		return -EINVAL;
	}

	prx = g_new0(struct serial_proxy, 1);
	prx->address = g_strdup(address);
	prx->uuid128 = g_strdup(uuid128);
	prx->type = TTY_PROXY;
	adapter_get_address(adapter->btd_adapter, &prx->src);
	prx->adapter = adapter;

	/* Current TTY settings */
	memset(&sys_ti, 0, sizeof(sys_ti));
	tcgetattr(sk, &sys_ti);
	memcpy(&prx->sys_ti, &sys_ti, sizeof(sys_ti));
	close(sk);

	if (!ti) {
		/* Use current settings */
		memcpy(&prx->proxy_ti, &sys_ti, sizeof(sys_ti));
	} else {
		/* New TTY settings: user provided */
		memcpy(&prx->proxy_ti, ti, sizeof(*ti));
	}

	ret = register_proxy_object(prx);
	if (ret < 0) {
		proxy_free(prx);
		return ret;
	}

	*proxy = prx;

	return ret;
}

static int proxy_socket_register(struct serial_adapter *adapter,
				const char *uuid128, const char *address,
				struct serial_proxy **proxy)
{
	struct serial_proxy *prx;
	int ret;

	prx = g_new0(struct serial_proxy, 1);
	prx->address = g_strdup(address);
	prx->uuid128 = g_strdup(uuid128);
	prx->type = UNIX_SOCKET_PROXY;
	adapter_get_address(adapter->btd_adapter, &prx->src);
	prx->adapter = adapter;

	ret = register_proxy_object(prx);
	if (ret < 0) {
		proxy_free(prx);
		return ret;
	}

	*proxy = prx;

	return ret;
}

static int proxy_tcp_register(struct serial_adapter *adapter,
				const char *uuid128, const char *address,
				struct serial_proxy **proxy)
{
	struct serial_proxy *prx;
	int ret;

	prx = g_new0(struct serial_proxy, 1);
	prx->address = g_strdup(address);
	prx->uuid128 = g_strdup(uuid128);
	prx->type = TCP_SOCKET_PROXY;
	adapter_get_address(adapter->btd_adapter, &prx->src);
	prx->adapter = adapter;

	ret = register_proxy_object(prx);
	if (ret < 0) {
		proxy_free(prx);
		return ret;
	}

	*proxy = prx;

	return ret;
}

static proxy_type_t addr2type(const char *address)
{
	struct stat st;

	if (stat(address, &st) < 0) {
		/*
		 * Unix socket: if the sun_path starts with null byte
		 * it refers to abstract namespace. 'x00' will be used
		 * to represent the null byte.
		 */
		if (strncmp("localhost:", address, 10) == 0)
			return TCP_SOCKET_PROXY;
		if (strncmp("x00", address, 3) != 0)
			return UNKNOWN_PROXY_TYPE;
		else
			return UNIX_SOCKET_PROXY;
	} else {
		/* Filesystem: char device or unix socket */
		if (S_ISCHR(st.st_mode) && strncmp("/dev/", address, 4) == 0)
			return TTY_PROXY;
		else if (S_ISSOCK(st.st_mode))
			return UNIX_SOCKET_PROXY;
		else
			return UNKNOWN_PROXY_TYPE;
	}
}

static int proxy_addrcmp(gconstpointer proxy, gconstpointer addr)
{
	const struct serial_proxy *prx = proxy;
	const char *address = addr;

	return strcmp(prx->address, address);
}

static int proxy_pathcmp(gconstpointer proxy, gconstpointer p)
{
	const struct serial_proxy *prx = proxy;
	const char *path = p;

	return strcmp(prx->path, path);
}

static int register_proxy(struct serial_adapter *adapter,
				const char *uuid_str, const char *address,
				struct serial_proxy **proxy)
{
	proxy_type_t type;
	int err;

	type = addr2type(address);
	if (type == UNKNOWN_PROXY_TYPE)
		return -EINVAL;

	/* Only one proxy per address(TTY or unix socket) is allowed */
	if (g_slist_find_custom(adapter->proxies, address, proxy_addrcmp))
		return -EALREADY;

	switch (type) {
	case UNIX_SOCKET_PROXY:
		err = proxy_socket_register(adapter, uuid_str, address, proxy);
		break;
	case TTY_PROXY:
		err = proxy_tty_register(adapter, uuid_str, address, NULL,
					proxy);
		break;
	case TCP_SOCKET_PROXY:
		err = proxy_tcp_register(adapter, uuid_str, address, proxy);
		break;
	default:
		err = -EINVAL;
	}

	if (err < 0)
		return err;

	g_dbus_emit_signal(adapter->conn,
				adapter_get_path(adapter->btd_adapter),
				SERIAL_MANAGER_INTERFACE, "ProxyCreated",
				DBUS_TYPE_STRING, &(*proxy)->path,
				DBUS_TYPE_INVALID);

	return 0;
}

static void unregister_proxy(struct serial_proxy *proxy)
{
	struct serial_adapter *adapter = proxy->adapter;
	char *path = g_strdup(proxy->path);

	if (proxy->watch > 0)
		g_dbus_remove_watch(adapter->conn, proxy->watch);

	g_dbus_emit_signal(adapter->conn,
			adapter_get_path(adapter->btd_adapter),
			SERIAL_MANAGER_INTERFACE, "ProxyRemoved",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	adapter->proxies = g_slist_remove(adapter->proxies, proxy);

	g_dbus_unregister_interface(adapter->conn, path,
					SERIAL_PROXY_INTERFACE);

	g_free(path);
}

static void watch_proxy(DBusConnection *connection, void *user_data)
{
	struct serial_proxy *proxy = user_data;

	proxy->watch = 0;
	unregister_proxy(proxy);
}

static DBusMessage *create_proxy(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct serial_adapter *adapter = data;
	struct serial_proxy *proxy;
	const char *pattern, *address;
	char *uuid_str;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID))
		return NULL;

	uuid_str = bt_name2string(pattern);
	if (!uuid_str)
		return btd_error_invalid_args(msg);

	err = register_proxy(adapter, uuid_str, address, &proxy);
	g_free(uuid_str);

	if (err == -EINVAL)
		return btd_error_invalid_args(msg);
	else if (err == -EALREADY)
		return btd_error_already_exists(msg);
	else if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	proxy->owner = g_strdup(dbus_message_get_sender(msg));
	proxy->watch = g_dbus_add_disconnect_watch(conn, proxy->owner,
						watch_proxy,
						proxy, NULL);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &proxy->path,
					DBUS_TYPE_INVALID);
}

static DBusMessage *list_proxies(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct serial_adapter *adapter = data;
	const GSList *l;
	DBusMessage *reply;
	DBusMessageIter iter, iter_array;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (l = adapter->proxies; l; l = l->next) {
		struct serial_proxy *prx = l->data;

		dbus_message_iter_append_basic(&iter_array,
				DBUS_TYPE_STRING, &prx->path);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return reply;
}

static DBusMessage *remove_proxy(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct serial_adapter *adapter = data;
	struct serial_proxy *prx;
	const char *path, *sender;
	GSList *l;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return NULL;

	l = g_slist_find_custom(adapter->proxies, path, proxy_pathcmp);
	if (!l)
		return btd_error_does_not_exist(msg);

	prx = l->data;

	sender = dbus_message_get_sender(msg);
	if (g_strcmp0(prx->owner, sender) != 0)
		return btd_error_not_authorized(msg);

	unregister_proxy(prx);

	return dbus_message_new_method_return(msg);
}

static void manager_path_unregister(void *data)
{
	struct serial_adapter *adapter = data;
	GSList *l;

	/* Remove proxy objects */
	for (l = adapter->proxies; l; l = l->next) {
		struct serial_proxy *prx = l->data;
		char *path = g_strdup(prx->path);

		g_dbus_unregister_interface(adapter->conn, path,
					SERIAL_PROXY_INTERFACE);
		g_free(path);
	}

	if (adapter->conn)
		dbus_connection_unref(adapter->conn);

	adapters = g_slist_remove(adapters, adapter);
	g_slist_free(adapter->proxies);
	btd_adapter_unref(adapter->btd_adapter);
	g_free(adapter);
}

static GDBusMethodTable manager_methods[] = {
	{ "CreateProxy",		"ss",	"s",	create_proxy },
	{ "ListProxies",		"",	"as",	list_proxies },
	{ "RemoveProxy",		"s",	"",	remove_proxy },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "ProxyCreated",		"s"	},
	{ "ProxyRemoved",		"s"	},
	{ }
};

static struct serial_adapter *find_adapter(GSList *list,
					struct btd_adapter *btd_adapter)
{
	for (; list; list = list->next) {
		struct serial_adapter *adapter = list->data;

		if (adapter->btd_adapter == btd_adapter)
			return adapter;
	}

	return NULL;
}

static void serial_proxy_init(struct serial_adapter *adapter)
{
	GKeyFile *config;
	GError *gerr = NULL;
	const char *file = CONFIGDIR "/serial.conf";
	char **group_list;
	int i;

	config = g_key_file_new();

	if (!g_key_file_load_from_file(config, file, 0, &gerr)) {
		error("Parsing %s failed: %s", file, gerr->message);
		g_error_free(gerr);
		g_key_file_free(config);
		return;
	}

	group_list = g_key_file_get_groups(config, NULL);

	for (i = 0; group_list[i] != NULL; i++) {
		char *group_str = group_list[i], *uuid_str, *address;
		int err;
		struct serial_proxy *prx;

		/* string length of "Proxy" is 5 */
		if (strlen(group_str) < 5 || strncmp(group_str, "Proxy", 5))
			continue;

		uuid_str = g_key_file_get_string(config, group_str, "UUID",
									&gerr);
		if (gerr) {
			DBG("%s: %s", file, gerr->message);
			g_error_free(gerr);
			g_key_file_free(config);
			g_strfreev(group_list);
			return;
		}

		address = g_key_file_get_string(config, group_str, "Address",
									&gerr);
		if (gerr) {
			DBG("%s: %s", file, gerr->message);
			g_error_free(gerr);
			g_key_file_free(config);
			g_free(uuid_str);
			g_strfreev(group_list);
			return;
		}

		err = register_proxy(adapter, uuid_str, address, &prx);
		if (err == -EINVAL)
			error("Invalid address.");
		else if (err == -EALREADY)
			DBG("Proxy already exists.");
		else if (err < 0)
			error("Proxy creation failed (%s)", strerror(-err));
		else {
			err = enable_proxy(prx);
			if (err < 0)
				error("Proxy enable failed (%s)",
						strerror(-err));
		}

		g_free(uuid_str);
		g_free(address);
	}

	g_strfreev(group_list);
	g_key_file_free(config);
}

int proxy_register(DBusConnection *conn, struct btd_adapter *btd_adapter)
{
	struct serial_adapter *adapter;
	const char *path;

	adapter = find_adapter(adapters, btd_adapter);
	if (adapter)
		return -EINVAL;

	adapter = g_new0(struct serial_adapter, 1);
	adapter->conn = dbus_connection_ref(conn);
	adapter->btd_adapter = btd_adapter_ref(btd_adapter);

	path = adapter_get_path(btd_adapter);

	if (!g_dbus_register_interface(conn, path,
					SERIAL_MANAGER_INTERFACE,
					manager_methods, manager_signals, NULL,
					adapter, manager_path_unregister)) {
		error("Failed to register %s interface to %s",
				SERIAL_MANAGER_INTERFACE, path);
		return -1;
	}

	adapters = g_slist_append(adapters, adapter);

	DBG("Registered interface %s on path %s",
		SERIAL_MANAGER_INTERFACE, path);

	serial_proxy_init(adapter);

	return 0;
}

void proxy_unregister(struct btd_adapter *btd_adapter)
{
	struct serial_adapter *adapter;

	adapter = find_adapter(adapters, btd_adapter);
	if (!adapter)
		return;

	g_dbus_unregister_interface(adapter->conn,
			adapter_get_path(btd_adapter),
			SERIAL_MANAGER_INTERFACE);
}
