/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"
#include "textfile.h"
#include "uinput.h"

#include "device.h"
#include "error.h"
#include "manager.h"
#include "storage.h"

#define INPUT_DEVICE_INTERFACE	"org.bluez.input.Device"

#define BUF_SIZE	16

#define UPDOWN_ENABLED		1

struct pending_connect {
	DBusConnection *conn;
	DBusMessage *msg;
};

struct fake_input {
	GIOChannel	*io;
	int		rfcomm; /* RFCOMM socket */
	int		uinput;	/* uinput socket */
	uint8_t		ch;	/* RFCOMM channel number */
};

struct device {
	bdaddr_t		src;
	bdaddr_t		dst;
	char			*name;
	uint8_t			major;
	uint8_t			minor;
	struct hidp_connadd_req hidp; /* FIXME: Use dynamic alloc? */
	struct fake_input	*fake;
	struct pending_connect *pending_connect;
};

static struct device *device_new(bdaddr_t *src, bdaddr_t *dst)
{
	struct device *idev;
	uint32_t cls;

	idev = g_new0(struct device, 1);

	bacpy(&idev->src, src);
	bacpy(&idev->dst, dst);

	read_device_name(src, dst, &idev->name);
	read_device_class(src, dst, &cls);

	idev->major = (cls >> 8) & 0x1f;
	idev->minor = (cls >> 2) & 0x3f;

	/* FIXME:  hidp could be alloc dynamically */
	snprintf(idev->hidp.name, 128, "%s", idev->name);

	return idev;
}

static void pending_connect_free(struct pending_connect *pc)
{
	if (!pc)
		return;
	if (pc->conn)
		dbus_connection_unref(pc->conn);
	if (pc->msg)
		dbus_message_unref(pc->msg);
	g_free(pc);
}

static void device_free(struct device *idev)
{
	if (!idev)
		return;
	if (idev->name)
		g_free(idev->name);
	if (idev->hidp.rd_data)
		g_free(idev->hidp.rd_data);
	if (idev->fake)
		g_free(idev->fake);
	if (idev->pending_connect) 
		pending_connect_free(idev->pending_connect);

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
	/* FIXME: Missing clean/free fake io channel */
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
	ioctl(fake->uinput, UI_DEV_DESTROY);
	close(fake->uinput);
	fake->uinput = -1;
	return FALSE;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan,
			GIOCondition cond, struct device *idev)
{
	struct fake_input *fake;
	DBusMessage *reply, *signal;
	const char *path;
	socklen_t len;
	int ret, err;

	fake = idev->fake;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		err = EIO;
		goto failed;
	}

	fake->rfcomm = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(fake->rfcomm, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(err), err);
		goto failed;
	}

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
	reply = dbus_message_new_method_return(idev->pending_connect->msg);
	send_message_and_unref(idev->pending_connect->conn, reply);

	/* Sending the Connected signal */
	path = dbus_message_get_path(idev->pending_connect->msg);
	signal = dbus_message_new_signal(path,
			INPUT_DEVICE_INTERFACE, "Connected");
	send_message_and_unref(idev->pending_connect->conn, signal);

	pending_connect_free(idev->pending_connect);
	idev->pending_connect = NULL;
	g_io_channel_unref(chan);
	return FALSE;

failed:
	err_connection_failed(idev->pending_connect->conn,
			idev->pending_connect->msg, strerror(err));
	pending_connect_free(idev->pending_connect);
	idev->pending_connect = NULL;
	g_io_channel_unref(chan);
	return FALSE;
}

static int rfcomm_connect(struct device *idev)
{
	struct sockaddr_rc addr;
	GIOChannel *io;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		err = errno;
		error("socket: %s (%d)", strerror(err), err);
		return -err;
	}

	io = g_io_channel_unix_new(sk);
	if (!io) {
		err = -EIO;
		error("channel_unix_new failed in rfcomm connect");
		goto failed;
	}

	g_io_channel_set_close_on_unref(io, FALSE);

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &idev->src);
	addr.rc_channel =  0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("bind: %s (%d)", strerror(err), err);
		goto failed;
	}

	if (set_nonblocking(sk) < 0) {
		err = errno;
		error("Set non blocking: %s (%d)", strerror(err), err);
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &idev->dst);
	addr.rc_channel = idev->fake->ch;
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		char peer[18]; /* FIXME: debug purpose */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect() failed: %s (%d)",
					strerror(err), err);
			goto failed;
		}

		ba2str(&idev->dst, peer);
		debug("RFCOMM connection in progress: %s channel:%d", peer, idev->fake->ch);
		g_io_add_watch(io, G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) rfcomm_connect_cb, idev);
	} else {
		debug("Connect succeeded with first try");
		rfcomm_connect_cb(io, G_IO_OUT, idev);
	}

	return 0;

failed:
	if (io)
		g_io_channel_unref(io);

	close(sk);
	errno = err;

	return -err;
}

static gboolean interrupt_connect_cb(GIOChannel *chan,
			GIOCondition cond, struct device *idev)
{
	int ctl, isk, ret, err;
	DBusMessage *signal;
	const char *path;
	socklen_t len;

	if (cond & G_IO_NVAL) {
		err = EHOSTDOWN;
		isk = -1;
		goto failed;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		err = EINTR;
		isk = -1;
		error("Hangup or error on HIDP interrupt socket");
		goto failed;

	}

	isk = g_io_channel_unix_get_fd(chan);
	idev->hidp.intr_sock = isk;
	idev->hidp.idle_to = 30 * 60;	/* 30 minutes */

	len = sizeof(ret);
	if (getsockopt(isk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		err = errno;
		error("Can't open HIDP control socket");
		goto failed;
	}

	if (idev->hidp.subclass & 0x40) {
		int ret;
		ret = encrypt_link(&idev->src, &idev->dst);
		if (ret < 0) {
			err = -ret;
			close(ctl);
			goto failed;
		}
	}

	if (ioctl(ctl, HIDPCONNADD, &idev->hidp) < 0) {
		err = errno;
		close(ctl);
		goto failed;
	}

	/* Replying to the requestor */
	send_message_and_unref(idev->pending_connect->conn,
		dbus_message_new_method_return(idev->pending_connect->msg));

	/* Sending the Connected signal */
	path = dbus_message_get_path(idev->pending_connect->msg);
	signal = dbus_message_new_signal(path,
			INPUT_DEVICE_INTERFACE, "Connected");
	send_message_and_unref(idev->pending_connect->conn, signal);

	close (ctl);
	goto cleanup;
failed:
	err_connection_failed(idev->pending_connect->conn,
				idev->pending_connect->msg, strerror(err));

cleanup:
	if (isk > 0)
		close(isk);

	close(idev->hidp.ctrl_sock);

	idev->hidp.intr_sock = -1;
	idev->hidp.ctrl_sock = -1;

	pending_connect_free(idev->pending_connect);
	idev->pending_connect = NULL;
	g_io_channel_unref(chan);

	return FALSE;
}

static gboolean control_connect_cb(GIOChannel *chan,
			GIOCondition cond, struct device *idev)
{
	int ret, csk, err;
	socklen_t len;

	if (cond & G_IO_NVAL) {
		err = EHOSTDOWN;
		csk = -1;
		goto failed;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		err = EINTR;
		csk = -1;
		error("Hangup or error on HIDP control socket");
		goto failed;

	}

	csk = g_io_channel_unix_get_fd(chan);
	/* Set HID control channel */
	idev->hidp.ctrl_sock = csk;

	len = sizeof(ret);
	if (getsockopt(csk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	/* Connect to the HID interrupt channel */
	if (l2cap_connect(&idev->src, &idev->dst, L2CAP_PSM_HIDP_INTR,
				(GIOFunc) interrupt_connect_cb, idev) < 0) {

		err = errno;
		error("L2CAP connect failed:%s (%d)", strerror(errno), errno);
		goto failed;
	}

	g_io_channel_unref(chan);
	return FALSE;

failed:
	if (csk > 0)
		close(csk);

	idev->hidp.ctrl_sock = -1;
	err_connection_failed(idev->pending_connect->conn,
			idev->pending_connect->msg, strerror(err));
	pending_connect_free(idev->pending_connect);
	idev->pending_connect = NULL;
	g_io_channel_unref(chan);

	return FALSE;
}

static int disconnect(struct device *idev, uint32_t flags)
{
	struct fake_input *fake = idev->fake;
	struct hidp_conndel_req req;
	struct hidp_conninfo ci;
	int ctl, err;

	/* Fake input disconnect */
	if (fake) {
		if (fake->io) {
			g_io_channel_close(fake->io);
			g_io_channel_unref(fake->io);
			fake->io = NULL;
		}
		if (fake->uinput >= 0) {
			ioctl(fake->uinput, UI_DEV_DESTROY);
			close(fake->uinput);
			fake->uinput = -1;
		}

		return 0;
	}

	/* Standard HID disconnect */

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0) {
		error("Can't open HIDP control socket");
		return -errno;
	}

	memset(&ci, 0, sizeof(struct hidp_conninfo));
	bacpy(&ci.bdaddr, &idev->dst);
	if ((ioctl(ctl, HIDPGETCONNINFO, &ci) < 0) ||
				(ci.state != BT_CONNECTED)) {
		errno = ENOTCONN;
		goto fail;
	}

	memset(&req, 0, sizeof(struct hidp_conndel_req));
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

	idev->hidp.intr_sock = -1;
	idev->hidp.ctrl_sock = -1;

	return -err;
}

static int is_connected(struct device *idev)
{
	struct fake_input *fake = idev->fake;
	struct hidp_conninfo ci;
	int ctl;

	/* Fake input */
	if (fake) {
		if (fake->io)
			return 1;
		else
			return 0;
	}

	/* Standard HID */
	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0)
		return 0;

	memset(&ci, 0, sizeof(struct hidp_conninfo));
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
static DBusHandlerResult device_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct device *idev = data;

	if (idev->pending_connect)
		return err_connection_failed(conn, msg, "Connection in progress");

	if (is_connected(idev))
		return err_already_connected(conn, msg);

	idev->pending_connect = g_try_new0(struct pending_connect, 1);
	if (!idev->pending_connect) {
		error("Out of memory when allocating new struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	idev->pending_connect->conn = dbus_connection_ref(conn);
	idev->pending_connect->msg = dbus_message_ref(msg);

	/* Fake input device */
	if (idev->fake) {
		if (rfcomm_connect(idev) < 0) {
			const char *str = strerror(errno);
			error("RFCOMM connect failed: %s(%d)", str, errno);
			pending_connect_free(idev->pending_connect);
			idev->pending_connect = NULL;
			return err_connection_failed(conn, msg, str);
		}
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* HID devices */
	if (l2cap_connect(&idev->src, &idev->dst, L2CAP_PSM_HIDP_CTRL,
				(GIOFunc) control_connect_cb, idev) < 0) {

		error("L2CAP connect failed: %s(%d)", strerror(errno), errno);
		pending_connect_free(idev->pending_connect);
		idev->pending_connect = NULL;
		return err_connection_failed(conn, msg, strerror(errno));
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult device_disconnect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	DBusMessage *signal;
	const char *path;

	if (disconnect(idev, 0) < 0)
		return err_failed(conn, msg, strerror(errno));

	/* Replying to the requestor */
	send_message_and_unref(conn,
			dbus_message_new_method_return(msg));

	/* Sending the Disconnect signal */ 
	path = dbus_message_get_path(msg);
	signal = dbus_message_new_signal(path,
			INPUT_DEVICE_INTERFACE, "Disconnected");
	return send_message_and_unref(conn, signal);
}

static DBusHandlerResult device_is_connected(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	DBusMessage *reply;
	dbus_bool_t connected;

	connected = is_connected(idev);
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &connected,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_get_address(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	DBusMessage *reply;
	char addr[18];
	const char *paddr = addr;

	ba2str(&idev->dst, addr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_get_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	DBusMessage *reply;
	const char *pname = idev->hidp.name;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_get_product_id(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_UINT16, &idev->hidp.product,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_get_vendor_id(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct device *idev = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_UINT16, &idev->hidp.vendor,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Accept messages from the input interface only */
	if (strcmp(INPUT_DEVICE_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "Connect") == 0)
		return device_connect(conn, msg, data);

	if (strcmp(member, "Disconnect") == 0)
		return device_disconnect(conn, msg, data);

	if (strcmp(member, "IsConnected") == 0)
		return device_is_connected(conn, msg, data);

	if (strcmp(member, "GetAddress") == 0)
		return device_get_address(conn, msg, data);

	if (strcmp(member, "GetName") == 0)
		return device_get_name(conn, msg, data);

	if (strcmp(member, "GetProductId") == 0)
		return device_get_product_id(conn, msg, data);

	if (strcmp(member, "GetVendorId") == 0)
		return device_get_vendor_id(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void device_unregister(DBusConnection *conn, void *data)
{
	struct device *idev = data;

	/* Disconnect if applied */
	disconnect(idev, (1 << HIDP_VIRTUAL_CABLE_UNPLUG));
	device_free(idev);
}

/* Virtual table to handle device object path hierarchy */
static const DBusObjectPathVTable device_table = {
	.message_function = device_message,
	.unregister_function = device_unregister,
};

/*
 * Input registration functions
 */
static int register_path(DBusConnection *conn, const char *path, struct device *idev)
{
	DBusMessage *msg;
	if (!dbus_connection_register_object_path(conn, path,
							&device_table, idev)) {
		error("Input device path registration failed");
		return -1;
	}

	msg = dbus_message_new_signal(INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceCreated");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	send_message_and_unref(conn, msg);

	info("Created input device: %s", path);

	return 0;
}

int input_device_register(DBusConnection *conn, bdaddr_t *src, bdaddr_t *dst,
				struct hidp_connadd_req *hid, const char **ppath)
{
	struct device *idev;
	const char *path;

	idev = device_new(src, dst);
	path = create_input_path(idev->major, idev->minor);

	/* rd_data must not be deallocated since the memory address is copied */
	memcpy(&idev->hidp, hid, sizeof(struct hidp_connadd_req));

	if (register_path(conn, path, idev) < 0)
		return -1;

	if (*ppath)
		*ppath = path;

	return 0;
}

int fake_input_register(DBusConnection *conn, bdaddr_t *src,
			bdaddr_t *dst, uint8_t ch, const char **ppath)
{
	struct device *idev;
	const char *path;

	idev = device_new(src, dst);
	path = create_input_path(idev->major, idev->minor);

	idev->fake = g_new0(struct fake_input, 1);
	idev->fake->ch = ch;

	if (register_path(conn, path, idev) < 0)
		return -1;

	if (*ppath)
		*ppath = path;

	return 0;
}

int input_device_unregister(DBusConnection *conn, const char *path)
{
	DBusMessage *msg;
	struct device *idev;

	if (!dbus_connection_get_object_path_data(conn,
						path, (void *) &idev))
		return -1;

	del_stored_device_info(&idev->src, &idev->dst);

	if (!dbus_connection_unregister_object_path(conn, path)) {
		error("Input device path unregister failed");
		return -1;
	}

	msg = dbus_message_new_signal(INPUT_PATH,
			INPUT_MANAGER_INTERFACE, "DeviceRemoved");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	send_message_and_unref(conn, msg);

	return 0;
}

int input_device_get_bdaddr(DBusConnection *conn, const char *path,
						bdaddr_t *src, bdaddr_t *dst)
{
	struct device *idev;

	if (!dbus_connection_get_object_path_data(conn, path,
							(void *) &idev))
		return -1;

	if (!idev)
		return -1;

	bacpy(src, &idev->src);
	bacpy(dst, &idev->dst);

	return 0;
}

int l2cap_connect(bdaddr_t *src, bdaddr_t *dst, unsigned short psm, GIOFunc cb, void *data)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk, err;

	if ((sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family  = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto failed;

	if (set_nonblocking(sk) < 0)
		goto failed;

	memset(&opts, 0, sizeof(opts));
	opts.imtu = HIDP_DEFAULT_MTU;
	opts.omtu = HIDP_DEFAULT_MTU;
	opts.flush_to = 0xffff;

	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts)) < 0)
		goto failed;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family  = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(psm);

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, FALSE);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			g_io_channel_unref(io);
			goto failed;
		}

		g_io_add_watch(io, G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) cb, data);
	} else {
		cb(io, G_IO_OUT, data);
	}

	return 0;

failed:
	err = errno;
	close(sk);
	errno = err;

	return -1;
}
