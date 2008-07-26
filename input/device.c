/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hidp.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"
#include "uinput.h"

#include "device.h"
#include "error.h"
#include "manager.h"
#include "storage.h"
#include "fakehid.h"
#include "glib-helper.h"

#define INPUT_DEVICE_INTERFACE	"org.bluez.input.Device"

#define BUF_SIZE	16

#define UPDOWN_ENABLED		1

#define FI_FLAG_CONNECTED	1

struct device;

struct device {
	bdaddr_t		src;
	bdaddr_t		dst;
	int			timeout;
	char			*name;
	uint8_t			major;
	uint8_t			minor;
	uint16_t		product;
	uint16_t		vendor;
	struct fake_input	*fake;
	DBusMessage		*pending_connect;
	DBusConnection		*conn;
	char			*path;
	int			ctrl_sk;
	int			intr_sk;
	guint			ctrl_watch;
	guint			intr_watch;
};

GSList *devices = NULL;

static struct device *device_new(bdaddr_t *src, bdaddr_t *dst,
					uint8_t subclass, int timeout)
{
	struct device *idev;
	uint32_t cls;
	uint8_t major, minor;

	if (!subclass) {
		if (read_device_class(src, dst, &cls) < 0)
			return NULL;

		major = (cls >> 8) & 0x1f;
		minor = (cls >> 2) & 0x3f;
	} else {
		major = 0x05; /* Peripheral */
		minor = (subclass >> 2) & 0x3f;
	}

	idev = g_new0(struct device, 1);

	bacpy(&idev->src, src);
	bacpy(&idev->dst, dst);
	idev->timeout = timeout;

	read_device_name(src, dst, &idev->name);

	idev->major	= major;
	idev->minor	= minor;
	idev->ctrl_sk	= -1;
	idev->intr_sk	= -1;

	return idev;
}

static void device_free(struct device *idev)
{
	if (!idev)
		return;
	if (idev->name)
		g_free(idev->name);
	if (idev->fake)
		g_free(idev->fake);
	if (idev->path)
		g_free(idev->path);
	if (idev->pending_connect)
		dbus_message_unref(idev->pending_connect);
	dbus_connection_unref(idev->conn);
	g_free(idev);
}

static int uinput_create(char *name)
{
	struct uinput_dev dev;
	int fd, err;

	fd = open("/dev/uinput", O_RDWR);
	if (fd < 0) {
		fd = open("/dev/input/uinput", O_RDWR);
		if (fd < 0) {
			fd = open("/dev/misc/uinput", O_RDWR);
			if (fd < 0) {
				err = errno;
				error("Can't open input device: %s (%d)",
							strerror(err), err);
				return -err;
			}
		}
	}

	memset(&dev, 0, sizeof(dev));
	if (name)
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE);

	dev.id.bustype = BUS_BLUETOOTH;
	dev.id.vendor  = 0x0000;
	dev.id.product = 0x0000;
	dev.id.version = 0x0000;

	if (write(fd, &dev, sizeof(dev)) < 0) {
		err = errno;
		error("Can't write device information: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	ioctl(fd, UI_SET_EVBIT, EV_KEY);
	ioctl(fd, UI_SET_EVBIT, EV_REL);
	ioctl(fd, UI_SET_EVBIT, EV_REP);

	ioctl(fd, UI_SET_KEYBIT, KEY_UP);
	ioctl(fd, UI_SET_KEYBIT, KEY_PAGEUP);
	ioctl(fd, UI_SET_KEYBIT, KEY_DOWN);
	ioctl(fd, UI_SET_KEYBIT, KEY_PAGEDOWN);

	if (ioctl(fd, UI_DEV_CREATE, NULL) < 0) {
		err = errno;
		error("Can't create uinput device: %s (%d)",
						strerror(err), err);
		close(fd);
		errno = err;
		return -err;
	}

	return fd;
}

static const char *create_input_path(uint8_t major, uint8_t minor)
{
	static char path[48];
	char subpath[32];
	static int next_id = 0;

	switch (major) {
	case 0x02: /* Phone */
		strcpy(subpath, "phone");
		break;
	case 0x04: /* Audio */
		switch (minor) {
		/* FIXME: Testing required */
		case 0x01: /* Wearable Headset Device */
			strcpy(subpath, "wearable");
			break;
		case 0x02: /* Hands-free */
			strcpy(subpath, "handsfree");
			break;
		case 0x06: /* Headphone */
			strcpy(subpath, "headphone");
			break;
		default:
			return NULL;
		}
		break;
	case 0x05: /* Peripheral */
		switch (minor & 0x30) {
		case 0x10:
			strcpy(subpath, "keyboard");
			break;
		case 0x20:
			strcpy(subpath, "pointing");
			break;
		case 0x30:
			strcpy(subpath, "combo");
			break;
		default:
			subpath[0] = '\0';
			break;
		}

		if ((minor & 0x0f) && (strlen(subpath) > 0))
			strcat(subpath, "/");

		switch (minor & 0x0f) {
		case 0x00:
			break;
		case 0x01:
			strcat(subpath, "joystick");
			break;
		case 0x02:
			strcat(subpath, "gamepad");
			break;
		case 0x03:
			strcat(subpath, "remotecontrol");
			break;
		case 0x04:
			strcat(subpath, "sensing");
			break;
		case 0x05:
			strcat(subpath, "digitizertablet");
			break;
		case 0x06:
			strcat(subpath, "cardreader");
			break;
		default:
			strcat(subpath, "reserved");
			break;
		}
		break;
	default:
			return NULL;
	}

	snprintf(path, 48, "%s/%s%d", INPUT_PATH, subpath, next_id++);
	return path;
}

static int decode_key(const char *str)
{
	static int mode = UPDOWN_ENABLED, gain = 0;

	uint16_t key;
	int new_gain;

	/* Switch from key up/down to page up/down */
	if (strncmp("AT+CKPD=200", str, 11) == 0) {
		mode = ~mode;
		return KEY_RESERVED;
	}

	if (strncmp("AT+VG", str, 5))
		return KEY_RESERVED;

	/* Gain key pressed */
	if (strlen(str) != 10)
		return KEY_RESERVED;

	new_gain = strtol(&str[7], NULL, 10);
	if (new_gain <= gain)
		key = (mode == UPDOWN_ENABLED ? KEY_UP : KEY_PAGEUP);
	else
		key = (mode == UPDOWN_ENABLED ? KEY_DOWN : KEY_PAGEDOWN);

	gain = new_gain;

	return key;
}

static void send_event(int fd, uint16_t type, uint16_t code, int32_t value)
{
	struct uinput_event event;
	int err;

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	err = write(fd, &event, sizeof(event));
}

static void send_key(int fd, uint16_t key)
{
	/* Key press */
	send_event(fd, EV_KEY, key, 1);
	send_event(fd, EV_SYN, SYN_REPORT, 0);
	/* Key release */
	send_event(fd, EV_KEY, key, 0);
	send_event(fd, EV_SYN, SYN_REPORT, 0);
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct fake_input *fake = data;
	const char *ok = "\r\nOK\r\n";
	char buf[BUF_SIZE];
	gsize bread = 0, bwritten;
	uint16_t key;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on rfcomm server socket");
		goto failed;
	}

	memset(buf, 0, BUF_SIZE);
	if (g_io_channel_read(chan, buf, sizeof(buf) - 1,
				&bread) != G_IO_ERROR_NONE) {
		error("IO Channel read error");
		goto failed;
	}

	debug("Received: %s", buf);

	if (g_io_channel_write(chan, ok, 6, &bwritten) != G_IO_ERROR_NONE) {
		error("IO Channel write error");
		goto failed;
	}

	key = decode_key(buf);
	if (key != KEY_RESERVED)
		send_key(fake->uinput, key);

	return TRUE;

failed:
	ioctl(fake->uinput, UI_DEV_DESTROY);
	close(fake->uinput);
	fake->uinput = -1;
	g_io_channel_unref(fake->io);

	return FALSE;
}

static inline DBusMessage *in_progress(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
				"Device connection already in progress");
}

static inline DBusMessage *already_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyConnected",
					"Already connected to a device");
}

static inline DBusMessage *connection_attempt_failed(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ConnectionAttemptFailed",
				err ? strerror(err) : "Connection attempt failed");
}

static void rfcomm_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct device *idev = user_data;
	struct fake_input *fake;
	DBusMessage *reply;
	const char *path;

	fake = idev->fake;
	fake->rfcomm = g_io_channel_unix_get_fd(chan);

	if (err < 0)
		goto failed;

	/*
	 * FIXME: Some headsets required a sco connection
	 * first to report volume gain key events
	 */
	fake->uinput = uinput_create(idev->name);
	if (fake->uinput < 0) {
		err = errno;
		goto failed;
	}

	fake->io = g_io_channel_unix_new(fake->rfcomm);
	g_io_channel_set_close_on_unref(fake->io, TRUE);
	g_io_add_watch(fake->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) rfcomm_io_cb, fake);

	/* Replying to the requestor */
	reply = dbus_message_new_method_return(idev->pending_connect);
	g_dbus_send_message(idev->conn, reply);

	/* Sending the Connected signal */
	path = dbus_message_get_path(idev->pending_connect);
	g_dbus_emit_signal(idev->conn, path,
			INPUT_DEVICE_INTERFACE, "Connected",
			DBUS_TYPE_INVALID);

	dbus_message_unref(idev->pending_connect);
	idev->pending_connect = NULL;

	return;

failed:
	reply = connection_attempt_failed(idev->pending_connect, err);
	g_dbus_send_message(idev->conn, reply);

	dbus_message_unref(idev->pending_connect);
	idev->pending_connect = NULL;
}

static int rfcomm_connect(struct device *idev)
{
	int err;

	err = bt_rfcomm_connect(&idev->src, &idev->dst, idev->fake->ch,
			rfcomm_connect_cb, idev);
	if (err < 0) {
		error("connect() failed: %s (%d)", strerror(-err), -err);
		return err;
	}

	return 0;
}

static gboolean intr_watch_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct device *idev = data;

	if (cond & (G_IO_HUP | G_IO_ERR))
		g_io_channel_close(chan);

	g_dbus_emit_signal(idev->conn,
			idev->path,
			INPUT_DEVICE_INTERFACE,
			"Disconnected",
			DBUS_TYPE_INVALID);

	g_source_remove(idev->ctrl_watch);
	idev->ctrl_watch = 0;
	idev->intr_watch = 0;

	/* Close control channel */
	if (idev->ctrl_sk > 0) {
		close(idev->ctrl_sk);
		idev->ctrl_sk = -1;
	}

	return FALSE;

}

static gboolean ctrl_watch_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct device *idev = data;

	if (cond & (G_IO_HUP | G_IO_ERR))
		g_io_channel_close(chan);

	g_dbus_emit_signal(idev->conn,
			idev->path,
			INPUT_DEVICE_INTERFACE,
			"Disconnected",
			DBUS_TYPE_INVALID);

	g_source_remove(idev->intr_watch);
	idev->intr_watch = 0;
	idev->ctrl_watch = 0;

	/* Close interrupt channel */
	if (idev->intr_sk > 0) {
		close(idev->intr_sk);
		idev->intr_sk = -1;
	}

	return FALSE;
}

static guint create_watch(int sk, GIOFunc cb, struct device *idev)
{
	guint id;
	GIOChannel *io;

	io = g_io_channel_unix_new(sk);
	id = g_io_add_watch(io, G_IO_HUP | G_IO_ERR | G_IO_NVAL, cb, idev);
	g_io_channel_unref(io);

	return id;
}

static int hidp_connadd(bdaddr_t *src, bdaddr_t *dst,
		int ctrl_sk, int intr_sk, int timeout, const char *name)
{
	struct hidp_connadd_req req;
	char addr[18];
	int ctl, err;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		error("Can't open HIDP interface");
		return -errno;
	}

	ba2str(dst, addr);

	memset(&req, 0, sizeof(req));
	req.ctrl_sock = ctrl_sk;
	req.intr_sock = intr_sk;
	req.flags     = 0;
	req.idle_to   = timeout;

	err = get_stored_device_info(src, dst, &req);
	if (err < 0) {
		error("Rejected connection from unknown device %s", addr);
		goto cleanup;
	}

	if (req.subclass & 0x40) {
		err = encrypt_link(src, dst);
		if (err < 0 && err != -EACCES)
			goto cleanup;
	}

	if (name)
		strncpy(req.name, name, 128);

	info("New input device %s (%s)", addr, req.name);

	if (req.vendor == 0x054c && req.product == 0x0268) {
		unsigned char buf[] = { 0x53, 0xf4,  0x42, 0x03, 0x00, 0x00 };
		err = write(ctrl_sk, buf, sizeof(buf));
	}

	err = ioctl(ctl, HIDPCONNADD, &req);

cleanup:
	close(ctl);

	if (req.rd_data)
		free(req.rd_data);

	return err;
}

static void interrupt_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct device *idev = user_data;
	DBusMessage *reply;

	if (err < 0) {
		error("connect(): %s (%d)", strerror(-err), -err);
		goto failed;
	}

	idev->intr_sk = g_io_channel_unix_get_fd(chan);
	err = hidp_connadd(&idev->src, &idev->dst,
				idev->ctrl_sk, idev->intr_sk,
					idev->timeout, idev->name);
	if (err < 0)
		goto failed;

	idev->intr_watch = create_watch(idev->intr_sk, intr_watch_cb, idev);
	idev->ctrl_watch = create_watch(idev->ctrl_sk, ctrl_watch_cb, idev);
	g_dbus_emit_signal(idev->conn,
			idev->path,
			INPUT_DEVICE_INTERFACE,
			"Connected",
			DBUS_TYPE_INVALID);

	/* Replying to the requestor */
	g_dbus_send_reply(idev->conn, idev->pending_connect, DBUS_TYPE_INVALID);

	goto cleanup;

failed:
	reply = connection_attempt_failed(idev->pending_connect, -err);
	g_dbus_send_message(idev->conn, reply);

	idev->intr_sk = -1;
	idev->ctrl_sk = -1;

cleanup:
	dbus_message_unref(idev->pending_connect);
	idev->pending_connect = NULL;
}

static void control_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct device *idev = user_data;

	if (err < 0) {
		error("connect(): %s (%d)", strerror(-err), -err);
		goto failed;
	}

	/* Set HID control channel */
	idev->ctrl_sk = g_io_channel_unix_get_fd(chan);

	/* Connect to the HID interrupt channel */
	err = bt_l2cap_connect(&idev->src, &idev->dst, L2CAP_PSM_HIDP_INTR, 0,
			interrupt_connect_cb, idev);
	if (err < 0) {
		error("L2CAP connect failed:%s (%d)", strerror(-err), -err);
		goto failed;
	}

	return;

failed:
	idev->ctrl_sk = -1;
	error_connection_attempt_failed(idev->conn,
			idev->pending_connect, -err);
	dbus_message_unref(idev->pending_connect);
	idev->pending_connect = NULL;
}

static int fake_disconnect(struct device *idev)
{
	struct fake_input *fake = idev->fake;

	if (!fake->io)
		return -ENOTCONN;

	g_io_channel_close(fake->io);
	g_io_channel_unref(fake->io);
	fake->io = NULL;

	if (fake->uinput >= 0) {
		ioctl(fake->uinput, UI_DEV_DESTROY);
		close(fake->uinput);
		fake->uinput = -1;
	}

	return 0;
}

static int disconnect(struct device *idev, uint32_t flags)
{
	struct fake_input *fake = idev->fake;
	struct hidp_conndel_req req;
	struct hidp_conninfo ci;
	int ctl, err;

	/* Fake input disconnect */
	if (fake) {
		err = fake->disconnect(idev);
		if (err == 0)
			fake->flags &= ~FI_FLAG_CONNECTED;
		return err;
	}

	/* Standard HID disconnect */
	if (idev->ctrl_sk >= 0) {
		close(idev->ctrl_sk);
		idev->ctrl_sk = -1;
	}
	if (idev->intr_sk >= 0) {
		close(idev->intr_sk);
		idev->intr_sk = -1;
	}

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		error("Can't open HIDP control socket");
		return -errno;
	}

	memset(&ci, 0, sizeof(ci));
	bacpy(&ci.bdaddr, &idev->dst);
	if ((ioctl(ctl, HIDPGETCONNINFO, &ci) < 0) ||
				(ci.state != BT_CONNECTED)) {
		errno = ENOTCONN;
		goto fail;
	}

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, &idev->dst);
	req.flags = flags;
	if (ioctl(ctl, HIDPCONNDEL, &req) < 0) {
		error("Can't delete the HID device: %s(%d)",
				strerror(errno), errno);
		goto fail;
	}

	close(ctl);

	return 0;

fail:
	err = errno;
	close(ctl);
	errno = err;

	return -err;
}

static int is_connected(struct device *idev)
{
	struct fake_input *fake = idev->fake;
	struct hidp_conninfo ci;
	int ctl;

	/* Fake input */
	if (fake)
		return fake->flags & FI_FLAG_CONNECTED;

	/* Standard HID */
	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0)
		return 0;

	memset(&ci, 0, sizeof(ci));
	bacpy(&ci.bdaddr, &idev->dst);
	if (ioctl(ctl, HIDPGETCONNINFO, &ci) < 0) {
		close(ctl);
		return 0;
	}

	close(ctl);

	if (ci.state != BT_CONNECTED)
		return 0;
	else
		return 1;
}

/*
 * Input Device methods
 */
static DBusMessage *device_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct device *idev = data;
	struct fake_input *fake = idev->fake;
	int err;

	if (idev->pending_connect)
		return in_progress(msg);

	if (is_connected(idev))
		return already_connected(msg);

	idev->pending_connect = dbus_message_ref(msg);

	/* Fake input device */
	if (fake) {
		if (fake->connect(idev) < 0) {
			int err = errno;
			const char *str = strerror(err);
			error("Connect failed: %s(%d)", str, err);
			dbus_message_unref(idev->pending_connect);
			idev->pending_connect = NULL;
			return connection_attempt_failed(msg, err);
		}
		fake->flags |= FI_FLAG_CONNECTED;
		return NULL;
	}

	/* HID devices */
	err = bt_l2cap_connect(&idev->src, &idev->dst, L2CAP_PSM_HIDP_CTRL,
						0, control_connect_cb, idev);
	if (err < 0) {
		error("L2CAP connect failed: %s(%d)", strerror(-err), -err);
		dbus_message_unref(idev->pending_connect);
		idev->pending_connect = NULL;
		return connection_attempt_failed(msg, -err);
	}

	return NULL;
}

static DBusMessage *device_disconnect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	int err;

	err = disconnect(idev, 0);
	if (err < 0)
		return create_errno_message(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *device_is_connected(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	dbus_bool_t connected = is_connected(idev);

	return g_dbus_create_reply(msg, DBUS_TYPE_BOOLEAN, &connected,
							DBUS_TYPE_INVALID);
}

static DBusMessage *device_get_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	char addr[18];
	const char *paddr = addr;

	ba2str(&idev->src, addr);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &paddr,
							DBUS_TYPE_INVALID);
}

static DBusMessage *device_get_address(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	char addr[18];
	const char *paddr = addr;

	ba2str(&idev->dst, addr);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &paddr,
							DBUS_TYPE_INVALID);
}

static DBusMessage *device_get_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	const char *pname = (idev->name ? idev->name : "");

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &pname,
							DBUS_TYPE_INVALID);
}

static DBusMessage *device_get_product_id(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;

	return g_dbus_create_reply(msg, DBUS_TYPE_UINT16, &idev->product,
							DBUS_TYPE_INVALID);
}

static DBusMessage *device_get_vendor_id(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;

	return g_dbus_create_reply(msg, DBUS_TYPE_UINT16, &idev->vendor,
							DBUS_TYPE_INVALID);
}

static void device_unregister(void *data)
{
	struct device *idev = data;

	/* Disconnect if applied */
	disconnect(idev, (1 << HIDP_VIRTUAL_CABLE_UNPLUG));
	device_free(idev);
}

static GDBusMethodTable device_methods[] = {
	{ "Connect",		"",	"",	device_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	device_disconnect	},
	{ "IsConnected",	"",	"b",	device_is_connected	},
	{ "GetAdapter",		"",	"s",	device_get_adapter	},
	{ "GetAddress",		"",	"s",	device_get_address	},
	{ "GetName",		"",	"s",	device_get_name		},
	{ "GetProductId",	"",	"q",	device_get_product_id	},
	{ "GetVendorId",	"",	"q",	device_get_vendor_id	},
	{ }
};

static GDBusSignalTable device_signals[] = {
	{ "Connected",		""	},
	{ "Disconnected",	""	},
	{ }
};

/*
 * Input registration functions
 */
static int register_path(DBusConnection *conn, const char *path, struct device *idev)
{
	if (g_dbus_register_interface(conn, path, INPUT_DEVICE_INTERFACE,
					device_methods, device_signals, NULL,
					idev, device_unregister) == FALSE) {
		error("Failed to register %s interface to %s",
					INPUT_DEVICE_INTERFACE, path);
		return -1;
	}

	devices = g_slist_append(devices, idev);

	info("Created input device: %s", path);

	return 0;
}

int input_device_register(DBusConnection *conn, bdaddr_t *src, bdaddr_t *dst,
				struct hidp_connadd_req *hid, const char **ppath)
{
	struct device *idev;
	const char *path;
	int err;

	idev = device_new(src, dst, hid->subclass, hid->idle_to);
	if (!idev)
		return -EINVAL;

	path = create_input_path(idev->major, idev->minor);
	if (!path) {
		device_free(idev);
		return -EINVAL;
	}

	idev->path	= g_strdup(path);
	idev->product	= hid->product;
	idev->vendor	= hid->vendor;
	idev->conn	= dbus_connection_ref(conn);

	err = register_path(conn, path, idev);

	if (!err && ppath)
		*ppath = path;

	return err;
}

int fake_input_register(DBusConnection *conn, bdaddr_t *src,
			bdaddr_t *dst, uint8_t ch, const char **ppath)
{
	struct device *idev;
	const char *path;
	int err;

	idev = device_new(src, dst, 0, 0);
	if (!idev)
		return -EINVAL;

	path = create_input_path(idev->major, idev->minor);
	if (!path) {
		device_free(idev);
		return -EINVAL;
	}

	idev->path = g_strdup(path);
	idev->conn = dbus_connection_ref(conn);

	/* FIXME: Missing set product and vendor */

	idev->fake = g_new0(struct fake_input, 1);
	idev->fake->ch = ch;
	idev->fake->connect = rfcomm_connect;
	idev->fake->disconnect = fake_disconnect;

	err = register_path(conn, path, idev);

	if (!err && ppath)
		*ppath = path;

	return err;
}

static struct device *find_device(const bdaddr_t *src, const bdaddr_t *dst)
{
	GSList *list;

	for (list = devices; list != NULL; list = list->next) {
		struct device *idev = list->data;

		if (!bacmp(&idev->src, src) && !bacmp(&idev->dst, dst))
			return idev;
	}

	return NULL;
}

static struct device *find_device_by_path(const char *path)
{
	GSList *list;

	for (list = devices; list != NULL; list = list->next) {
		struct device *idev = list->data;

		if (strcmp(idev->path, path) == 0)
			return idev;
	}

	return NULL;
}

int input_device_unregister(DBusConnection *conn, const char *path)
{
	struct device *idev;

	idev = find_device_by_path(path);
	if (idev == NULL)
		return -EINVAL;

	if (idev->pending_connect) {
		/* Pending connection running */
		return -EBUSY;
	}

	del_stored_device_info(&idev->src, &idev->dst);

	devices = g_slist_remove(devices, idev);

	/*
	 * Workaround: if connected, the watch will not be able
	 * to access the D-Bus data assigned to this path
	 * because the object path data was destroyed.
	 */
	if (idev->ctrl_watch)
		g_source_remove(idev->ctrl_watch);

	if (idev->intr_watch) {
		g_source_remove(idev->intr_watch);
		g_dbus_emit_signal(conn,
				path, INPUT_DEVICE_INTERFACE,
				"Disconnected", DBUS_TYPE_INVALID);
	}

	g_dbus_emit_signal(conn, INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceRemoved" ,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	g_dbus_unregister_interface(conn, path, INPUT_DEVICE_INTERFACE);

	return 0;
}

gboolean input_device_is_registered(bdaddr_t *src, bdaddr_t *dst)
{
	struct device *idev = find_device(src, dst);
	if (!idev)
		return FALSE;
	else
		return TRUE;
}

int input_device_set_channel(const bdaddr_t *src, const bdaddr_t *dst, int psm, int nsk)
{
	struct device *idev = find_device(src, dst);
	if (!idev)
		return -ENOENT;

	switch (psm) {
	case L2CAP_PSM_HIDP_CTRL:
		idev->ctrl_sk = nsk;
		break;
	case L2CAP_PSM_HIDP_INTR:
		idev->intr_sk = nsk;
		break;
	}

	return 0;
}

int input_device_close_channels(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct device *idev = find_device(src, dst);
	if (!idev)
		return -ENOENT;

	if (idev->ctrl_sk >= 0) {
		close(idev->ctrl_sk);
		idev->ctrl_sk = -1;
	}

	if (idev->intr_sk >= 0) {
		close(idev->intr_sk);
		idev->intr_sk = -1;
	}

	return 0;
}

static gboolean fake_hid_connect(struct device *dev)
{
	struct fake_hid *fhid = dev->fake->priv;

	return fhid->connect(dev->fake);
}

static int fake_hid_disconnect(struct device *dev)
{
	struct fake_hid *fhid = dev->fake->priv;

	return fhid->disconnect(dev->fake);
}

int input_device_connadd(bdaddr_t *src, bdaddr_t *dst)
{
	struct device *idev;
	struct fake_hid *fake_hid;
	struct fake_input *fake = NULL;
	int err;

	idev = find_device(src, dst);
	if (!idev)
		return -ENOENT;

	fake_hid = get_fake_hid(idev->vendor, idev->product);
	if (fake_hid) {
		fake = g_try_new0(struct fake_input, 1);
		if (!fake) {
			err = -ENOMEM;
			goto error;
		}

		fake->connect = fake_hid_connect;
		fake->disconnect = fake_hid_disconnect;
		fake->priv = fake_hid;
		err = fake_hid_connadd(fake, idev->intr_sk, fake_hid);
	} else
		err = hidp_connadd(src, dst, idev->ctrl_sk, idev->intr_sk,
						idev->timeout, idev->name);
	if (err < 0)
		goto error;

	idev->intr_watch = create_watch(idev->intr_sk, intr_watch_cb, idev);
	idev->ctrl_watch = create_watch(idev->ctrl_sk, ctrl_watch_cb, idev);
	g_dbus_emit_signal(idev->conn,
			idev->path,
			INPUT_DEVICE_INTERFACE,
			"Connected",
			DBUS_TYPE_INVALID);
	return 0;

error:
	close(idev->ctrl_sk);
	close(idev->intr_sk);
	idev->ctrl_sk = -1;
	idev->intr_sk = -1;
	g_free(fake);
	return err;
}
