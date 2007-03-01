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
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hidp.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"
#include "textfile.h"
#include "uinput.h"

#include "storage.h"
#include "device.h"

#define INPUT_PATH "/org/bluez/input"
#define INPUT_MANAGER_INTERFACE	"org.bluez.input.Manager"
#define INPUT_DEVICE_INTERFACE	"org.bluez.input.Device"
#define INPUT_ERROR_INTERFACE	"org.bluez.Error"

#define L2CAP_PSM_HIDP_CTRL		0x11
#define L2CAP_PSM_HIDP_INTR		0x13

#define BUF_SIZE	16

#define UPDOWN_ENABLED		1

static DBusConnection *connection = NULL;

const char *pnp_uuid = "00001200-0000-1000-8000-00805f9b34fb";
const char *hid_uuid = "00001124-0000-1000-8000-00805f9b34fb";
const char *headset_uuid = "00001108-0000-1000-8000-00805f9b34fb";

struct fake_input {
	GIOChannel	*io;
	int		rfcomm; /* RFCOMM socket */
	int		uinput;	/* uinput socket */
	uint8_t		ch;	/* RFCOMM channel number */
};

struct pending_connect {
	DBusConnection *conn;
	DBusMessage *msg;
};

struct input_device {
	bdaddr_t src;
	bdaddr_t dst;
	uint8_t			major;
	uint8_t			minor;
	struct hidp_connadd_req hidp; /* FIXME: Use dynamic alloc? */
	struct fake_input	*fake;
	struct pending_connect *pending_connect;
};

struct input_manager {
	bdaddr_t src;		/* Local adapter BT address */
	GSList *paths;		/* Input registered paths */
};

struct pending_req {
	char *adapter_path;	/* Local adapter D-Bus path */
	bdaddr_t src;		/* Local adapter BT address */
	bdaddr_t dst;		/* Peer BT address */
	DBusConnection *conn;
	DBusMessage *msg;
	sdp_record_t *pnp_rec;
	sdp_record_t *hid_rec;
};

static struct input_device *input_device_new(bdaddr_t *src, bdaddr_t *dst, uint32_t cls)
{
	struct input_device *idev;

	idev = g_new0(struct input_device, 1);

	bacpy(&idev->src, src);
	bacpy(&idev->dst, dst);

	idev->major = (cls >> 8) & 0x1f;
	idev->minor = (cls >> 2) & 0x3f;

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

static void input_device_free(struct input_device *idev)
{
	if (!idev)
		return;
	if (idev->hidp.rd_data)
		g_free(idev->hidp.rd_data);
	if (idev->fake)
		g_free(idev->fake);
	if (idev->pending_connect) 
		pending_connect_free(idev->pending_connect);

	g_free(idev);
}

static struct pending_req *pending_req_new(DBusConnection *conn,
				DBusMessage *msg, const char *adapter_path,
						bdaddr_t *src, bdaddr_t *dst)
{
	struct pending_req *pr;
	pr = g_try_new0(struct pending_req, 1);
	if (!pr)
		return NULL;

	pr->adapter_path = g_strdup(adapter_path);
	bacpy(&pr->src, src);
	bacpy(&pr->dst, dst);
	pr->conn = dbus_connection_ref(conn);
	pr->msg = dbus_message_ref(msg);

	return pr;
}

static void pending_req_free(struct pending_req *pr)
{
	if (!pr)
		return;
	if (pr->adapter_path)
		g_free(pr->adapter_path);
	if (pr->conn)
		dbus_connection_unref(pr->conn);
	if (pr->msg)
		dbus_message_unref(pr->msg);
	if (pr->pnp_rec)
		sdp_record_free(pr->pnp_rec);
	if (pr->hid_rec)
		sdp_record_free(pr->hid_rec);
	g_free(pr);
}

/*
 * Common D-Bus BlueZ input error functions
 */
static DBusHandlerResult err_unknown_device(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".UnknownDevice",
				"Invalid device"));
}

static DBusHandlerResult err_unknown_method(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".UnknownMethod",
				"Unknown input method"));
}

static DBusHandlerResult err_failed(DBusConnection *conn, DBusMessage *msg,
				const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".Failed", str));
}

static DBusHandlerResult err_not_supported(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
			INPUT_ERROR_INTERFACE ".NotSupported",
			"The service is not supported by the remote device"));
}

static DBusHandlerResult err_connection_failed(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE".ConnectionAttemptFailed",
				str));
}

static DBusHandlerResult err_already_exists(DBusConnection *conn,
				DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".AlreadyExists", str));
}

static DBusHandlerResult err_does_not_exist(DBusConnection *conn,
				DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				INPUT_ERROR_INTERFACE ".DoesNotExist", str));
}

static DBusHandlerResult err_generic(DBusConnection *conn, DBusMessage *msg,
				const char *name, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg, name, str));

}

static void extract_hid_record(sdp_record_t *rec, struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist, *pdlist2;
	uint8_t attr_val;

	pdlist = sdp_data_get(rec, 0x0101);
	pdlist2 = sdp_data_get(rec, 0x0102);
	if (pdlist) {
		if (pdlist2) {
			if (strncmp(pdlist->val.str, pdlist2->val.str, 5)) {
				strncpy(req->name, pdlist2->val.str, 127);
				strcat(req->name, " ");
			}
			strncat(req->name, pdlist->val.str, 127 - strlen(req->name));
		} else
			strncpy(req->name, pdlist->val.str, 127);
	} else {
		pdlist2 = sdp_data_get(rec, 0x0100);
		if (pdlist2)
			strncpy(req->name, pdlist2->val.str, 127);
 	}
 
	pdlist = sdp_data_get(rec, SDP_ATTR_HID_PARSER_VERSION);
	req->parser = pdlist ? pdlist->val.uint16 : 0x0100;
 
	pdlist = sdp_data_get(rec, SDP_ATTR_HID_DEVICE_SUBCLASS);
	req->subclass = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_COUNTRY_CODE);
	req->country = pdlist ? pdlist->val.uint8 : 0;

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_VIRTUAL_CABLE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_VIRTUAL_CABLE_UNPLUG);

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_BOOT_DEVICE);
	attr_val = pdlist ? pdlist->val.uint8 : 0;
	if (attr_val)
		req->flags |= (1 << HIDP_BOOT_PROTOCOL_MODE);

	pdlist = sdp_data_get(rec, SDP_ATTR_HID_DESCRIPTOR_LIST);
	if (pdlist) {
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->val.dataseq;
		pdlist = pdlist->next;

		req->rd_data = g_try_malloc0(pdlist->unitSize);
		if (req->rd_data) {
			memcpy(req->rd_data, (unsigned char *) pdlist->val.str, pdlist->unitSize);
			req->rd_size = pdlist->unitSize;
		}
	}
}

static void extract_pnp_record(sdp_record_t *rec, struct hidp_connadd_req *req)
{
	sdp_data_t *pdlist;

	pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
	req->vendor = pdlist ? pdlist->val.uint16 : 0x0000;

	pdlist = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
	req->product = pdlist ? pdlist->val.uint16 : 0x0000;

	pdlist = sdp_data_get(rec, SDP_ATTR_VERSION);
	req->version = pdlist ? pdlist->val.uint16 : 0x0000;
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

	memset(&event, 0, sizeof(event));
	event.type	= type;
	event.code	= code;
	event.value	= value;

	write(fd, &event, sizeof(event));
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

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
						struct input_device *idev)
{
	struct fake_input *fake;
	DBusMessage *reply;
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

	fake->uinput = uinput_create("Fake input");
	if (fake->uinput < 0) {
		err = errno;
		goto failed;
	}

	fake->io = g_io_channel_unix_new(fake->rfcomm);
	g_io_channel_set_close_on_unref(fake->io, TRUE);
	g_io_add_watch(fake->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) rfcomm_io_cb, fake);

	reply = dbus_message_new_method_return(idev->pending_connect->msg);
	if (reply) {
		dbus_connection_send(connection, reply, NULL);
		dbus_message_unref(reply);
	}

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

static int rfcomm_connect(struct input_device *idev)
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

static int l2cap_connect(struct input_device *idev,
				unsigned short psm, GIOFunc cb)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	int sk, err;

	if ((sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)) < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family  = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &idev->src);

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
	bacpy(&addr.l2_bdaddr, &idev->dst);
	addr.l2_psm = htobs(psm);

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, FALSE);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS))
			goto failed;

		g_io_add_watch(io, G_IO_OUT, (GIOFunc) cb, idev);
	} else {
		cb(io, G_IO_OUT, idev);
	}

	return 0;

failed:
	err = errno;
	close(sk);
	errno = err;

	return -1;
}

static gboolean interrupt_connect_cb(GIOChannel *chan, GIOCondition cond,
						struct input_device *idev)
{
	int ctl, isk, ret, err;
	socklen_t len;

	if (cond & G_IO_NVAL) {
		err = EHOSTDOWN;
		isk = -1;
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
		err = encrypt_link(&idev->src, &idev->dst);
		if (err < 0) {
			close(ctl);
			goto failed;
		}
	}

	if (ioctl(ctl, HIDPCONNADD, &idev->hidp) < 0) {
		err = errno;
		close(ctl);
		goto failed;
	}


	send_message_and_unref(idev->pending_connect->conn,
		dbus_message_new_method_return(idev->pending_connect->msg));

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

static gboolean control_connect_cb(GIOChannel *chan, GIOCondition cond,
						struct input_device *idev)
{
	int ret, csk, err;
	socklen_t len;

	if (cond & G_IO_NVAL) {
		err = EHOSTDOWN;
		csk = -1;
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
	if (l2cap_connect(idev, L2CAP_PSM_HIDP_INTR,
			(GIOFunc) interrupt_connect_cb) < 0) {

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

static int disconnect(struct input_device *idev, uint32_t flags)
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

static int is_connected(struct input_device *idev)
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
	struct input_device *idev = data;

	if (idev->pending_connect)
		return err_connection_failed(conn, msg, "Connection in progress");

	if (is_connected(idev))
		return err_connection_failed(conn, msg, "Already connected");

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
	if (l2cap_connect(idev, L2CAP_PSM_HIDP_CTRL,
			(GIOFunc) control_connect_cb) < 0) {
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
	struct input_device *idev = data;

	if (disconnect(idev, 0) < 0)
		return err_failed(conn, msg, strerror(errno));

	return send_message_and_unref(conn,
			dbus_message_new_method_return(msg));
}

static DBusHandlerResult device_is_connected(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct input_device *idev = data;
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
	struct input_device *idev = data;
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
	struct input_device *idev = data;
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
	struct input_device *idev = data;
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
	struct input_device *idev = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_UINT16, &idev->hidp.vendor,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_set_timeout(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

	if (strcmp(member, "SetTimeout") == 0)
		return device_set_timeout(conn, msg, data);

	return err_unknown_method(conn, msg);
}

static void device_unregister(DBusConnection *conn, void *data)
{
	input_device_free(data);
}

/* Virtual table to handle device object path hierarchy */
static const DBusObjectPathVTable device_table = {
	.message_function = device_message,
	.unregister_function = device_unregister,
};

/*
 * Input Manager methods
 */
static void input_manager_free(struct input_manager *mgr)
{
	if (!mgr)
		return;

	if (mgr->paths) {
		g_slist_foreach(mgr->paths, (GFunc) free, NULL);
		g_slist_free(mgr->paths);
	}

	g_free(mgr);
}

static int register_input_device(DBusConnection *conn,
			struct input_device *idev, const char *path)
{
	DBusMessage *msg;
	struct input_manager *mgr;

	if (!dbus_connection_register_object_path(conn,
				path, &device_table, idev)) {
		error("Input device path registration failed");
		return -1;
	}

	dbus_connection_get_object_path_data(conn, INPUT_PATH, (void *) &mgr);
	mgr->paths = g_slist_append(mgr->paths, g_strdup(path));

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

static int unregister_input_device(DBusConnection *conn, const char *path)
{
	DBusMessage *msg;

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

static int path_bdaddr_cmp(const char *path, const bdaddr_t *bdaddr)
{
	struct input_device *idev;

	if (!dbus_connection_get_object_path_data(connection, path,
				(void *) &idev))
		return -1;

	if (!idev)
		return -1;

	return bacmp(&idev->dst, bdaddr);
}

static int get_record(struct pending_req *pr, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	ba2str(&pr->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static int get_class(bdaddr_t *src, bdaddr_t *dst, uint32_t *cls)
{
	char filename[PATH_MAX + 1], *str;
	char addr[18];

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "classes");

	ba2str(dst, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%x", cls) != 1) {
		g_free(str);
		return -ENOENT;
	}

	g_free(str);

	return 0;
}

static int get_handles(struct pending_req *pr, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char addr[18];
	const char *paddr = addr;

	msg  = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	ba2str(&pr->dst, addr);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);
	
	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void hid_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *pr_reply;
	struct pending_req *pr = data;
	struct input_device *idev;
	DBusError derr;
	uint8_t *rec_bin;
	const char *path;
	int len, scanned;
	uint32_t cls;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid HID service record length");
		goto fail;
	}

	pr->hid_rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!pr->hid_rec) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	if (get_class(&pr->src, &pr->dst, &cls) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Device class not available");
		goto fail;
	}

	idev = input_device_new(&pr->src, &pr->dst, cls);

	extract_hid_record(pr->hid_rec, &idev->hidp);
	if (pr->pnp_rec)
		extract_pnp_record(pr->pnp_rec, &idev->hidp);

	path = create_input_path(idev->major, idev->minor);

	if (register_input_device(pr->conn, idev, path) < 0) {
		err_failed(pr->conn, pr->msg, "D-Bus path registration failed");
		input_device_free(idev);
		goto fail;
	}

	pr_reply = dbus_message_new_method_return(pr->msg);
	dbus_message_append_args(pr_reply,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pr->conn, pr_reply);

	store_device_info(&pr->src, &pr->dst, &idev->hidp);
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void hid_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	uint32_t *phandle;
	DBusError derr;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID record handle not found");
		goto fail;
	}

	if (get_record(pr, *phandle, hid_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID service attribute request failed");
		goto fail;
	} else {
		/* Wait record reply */
		goto done;
	}
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void pnp_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint8_t *rec_bin;
	int len, scanned;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid PnP service record length");
		goto fail;
	}

	pr->pnp_rec = sdp_extract_pdu(rec_bin, &scanned);
	if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("HID service search request failed");
		goto fail;
	} else {
		/* Wait handle reply */
		goto done;
	}

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void pnp_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		/* PnP is optional: Ignore it and request the HID handle  */
		if (get_handles(pr, hid_uuid, hid_handle_reply) < 0) {
			err_not_supported(pr->conn, pr->msg);
			error("HID service search request failed");
			goto fail;
		}
	} else {
		/* Request PnP record */
		if (get_record(pr, *phandle, pnp_record_reply) < 0) {
			err_not_supported(pr->conn, pr->msg);
			error("PnP service attribute request failed");
			goto fail;
		}
	}

	/* Wait HID handle reply or PnP record reply */
	goto done;

fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void headset_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *pr_reply;
	DBusError derr;
	struct pending_req *pr = data;
	struct input_device *idev;
	uint8_t *rec_bin;
	sdp_record_t *rec;
	sdp_list_t *protos;
	const char *path;
	int len, scanned;
	uint32_t cls;
	uint8_t ch;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid headset service record length");
		goto fail;
	}

	rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!rec) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	if (sdp_get_access_protos(rec, &protos) < 0) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t)sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	sdp_record_free(rec);

	if (ch <= 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid RFCOMM channel");
		goto fail;
	}

	if (get_class(&pr->src, &pr->dst, &cls) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Device class not available");
		goto fail;
	}

	idev = input_device_new(&pr->src, &pr->dst, cls);

	idev->fake = g_new0(struct fake_input, 1);
	idev->fake->ch = ch;

	/* FIXME: Store the fake input data */

	path = create_input_path(idev->major, idev->minor);
	if (register_input_device(pr->conn, idev, path) < 0) {
		error("D-Bus path registration failed:%s", path);
		err_failed(pr->conn, pr->msg, "Path registration failed");
		input_device_free(idev);
		goto fail;
	}

	pr_reply = dbus_message_new_method_return(pr->msg);
	dbus_message_append_args(pr_reply,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pr->conn, pr_reply);
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static void headset_handle_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	struct pending_req *pr = data;
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_generic(pr->conn, pr->msg, derr.name, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Headset record handle not found");
		goto fail;
	}

	if (get_record(pr, *phandle, headset_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Headset service attribute request failed");
		goto fail;
	} else {
		/* Wait record reply */
		goto done;
	}
fail:
	dbus_error_free(&derr);
	pending_req_free(pr);
done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static DBusHandlerResult manager_create_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct input_manager *mgr = data;
	struct input_device *idev;
	DBusMessage *reply;
	DBusError derr;
	char adapter[18], adapter_path[32];
	const char *addr, *path;
	GSList *l;
	bdaddr_t dst;
	uint32_t cls = 0;
	int dev_id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID)) {
		err_generic(conn, msg, derr.name, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	str2ba(addr, &dst);
	l = g_slist_find_custom(mgr->paths, &dst,
			(GCompareFunc) path_bdaddr_cmp);
	if (l)
		return err_already_exists(conn, msg, "Input Already exists");

	ba2str(&mgr->src, adapter);
	dev_id = hci_devid(adapter);
	snprintf(adapter_path, 32, "/org/bluez/hci%d", dev_id);

	if (get_class(&mgr->src, &dst, &cls) < 0) {
		error("Device class not available");
		return err_not_supported(conn, msg);
	}

	idev = input_device_new(&mgr->src, &dst, cls);

	if (get_stored_device_info(&mgr->src, &idev->dst, &idev->hidp) < 0) {
		struct pending_req *pr;
		/* Data not found: create the input device later */
		input_device_free(idev);

		pr = pending_req_new(conn, msg, adapter_path, &mgr->src, &dst);
		if (!pr)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		switch (cls & 0x1f00) {
		case 0x0500: /* Peripheral */
			if (get_handles(pr, pnp_uuid, pnp_handle_reply) < 0) {
				pending_req_free(pr);
				return err_not_supported(conn, msg);
			}
			break;
		case 0x0400: /* Fake input */
			if (get_handles(pr, headset_uuid,
						headset_handle_reply) < 0) {
				pending_req_free(pr);
				return err_not_supported(conn, msg);
			}
			break;
		default:
			pending_req_free(pr);
			return err_not_supported(conn, msg);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	path = create_input_path(idev->major, idev->minor);
	if (register_input_device(conn, idev, path) < 0) {
		input_device_free(idev);
		return err_failed(conn, msg, "D-Bus path registration failed");
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		input_device_free(idev);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult manager_remove_device(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct input_manager *mgr = data;
	struct input_device *idev;
	DBusMessage *reply;
	DBusError derr;
	GSList *l;
	const char *path;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_generic(conn, msg, derr.name, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(mgr->paths, path, (GCompareFunc) strcmp);
	if (!l)
		return err_does_not_exist(conn, msg, "Input doesn't exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Try disconnect */
	if (dbus_connection_get_object_path_data(conn, path, (void *) &idev) && idev)
		disconnect(idev, (1 << HIDP_VIRTUAL_CABLE_UNPLUG));

	del_stored_device_info(&mgr->src, &idev->dst);

	if (unregister_input_device(conn, path) < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, "D-Bus path unregistration failed");
	}

	g_free(l->data);
	mgr->paths = g_slist_remove(mgr->paths, l->data);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult manager_list_devices(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct input_manager *mgr = data;
	DBusMessageIter iter, iter_array;
	DBusMessage *reply;
	GSList *paths;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (paths = mgr->paths; paths != NULL; paths = paths->next) {
		const char *ppath = paths->data;
		dbus_message_iter_append_basic(&iter_array,
				DBUS_TYPE_STRING, &ppath);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult manager_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *iface, *member;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Catching fallback paths */
	if (strcmp(INPUT_PATH, path) != 0)
		return err_unknown_device(conn, msg);

	/* Accept messages from the input manager interface only */
	if (strcmp(INPUT_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ListDevices") == 0)
		return manager_list_devices(conn, msg, data);

	if (strcmp(member, "CreateDevice") == 0)
		return manager_create_device(conn, msg, data);

	if (strcmp(member, "RemoveDevice") == 0)
		return manager_remove_device(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	struct input_manager *mgr = data;

	info("Unregistered manager path");

	input_manager_free(mgr);
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function = manager_message,
	.unregister_function = manager_unregister,
};

static void stored_input(char *key, char *value, void *data)
{
	bdaddr_t *src = data;
	struct input_device *idev;
	const char *path;
	bdaddr_t dst;
	uint32_t cls;

	str2ba(key, &dst);

	if (get_class(src, &dst, &cls) < 0)
		return;

	idev = input_device_new(src, &dst, cls);

	if (parse_stored_device_info(value, &idev->hidp) < 0) {
		input_device_free(idev);
		return;
	}

	path = create_input_path(idev->major, idev->minor);
	if (register_input_device(connection, idev, path) < 0)
		input_device_free(idev);
}

static int register_stored_inputs(bdaddr_t *src)
{
	char filename[PATH_MAX + 1];
	char addr[18];

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "input");
	textfile_foreach(filename, stored_input, src);

	return 0;
}

int input_dbus_init(void)
{
	struct input_manager *mgr;
	bdaddr_t src;
	int dev_id;

	connection = init_dbus(NULL, NULL, NULL);
	if (!connection)
		return -1;

	dbus_connection_set_exit_on_disconnect(connection, TRUE);

	mgr = g_new0(struct input_manager, 1);

	/* Fallback to catch invalid device path */
	if (!dbus_connection_register_fallback(connection, INPUT_PATH,
						&manager_table, mgr)) {
		error("D-Bus failed to register %s path", INPUT_PATH);
		goto fail;
	}

	info("Registered input manager path:%s", INPUT_PATH);

	/* Set the default adapter */
	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if (dev_id < 0) {
		error("Bluetooth device not available");
		goto fail;
	}

	if (hci_devba(dev_id, &src) < 0) {
		error("Can't get local adapter device info");
		goto fail;
	}

	bacpy(&mgr->src, &src);
	/* Register well known HID devices */
	register_stored_inputs(&src);

	return 0;

fail:
	input_manager_free(mgr);

	return -1;
}

void input_dbus_exit(void)
{
	dbus_connection_unregister_object_path(connection, INPUT_PATH);

	dbus_connection_unref(connection);
}

void internal_service(const char *identifier)
{
	DBusMessage *msg, *reply;
	const char *name = "Input Service Debug", *desc = "";

	info("Registering service");

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RegisterService");
	if (!msg) {
		error("Can't create service register method");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &identifier,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &desc, DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, NULL);
	if (!reply) {
		error("Can't register service");
		return;
	}

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	dbus_connection_flush(connection);
}
