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
#include <bluetooth/hidp.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "textfile.h"
#include "uinput.h"

#include "../src/storage.h"
#include "../src/manager.h"
#include "../src/dbus-common.h"
#include "adapter.h"
#include "../src/device.h"

#include "device.h"
#include "error.h"
#include "fakehid.h"
#include "glib-helper.h"
#include "btio.h"

#define INPUT_DEVICE_INTERFACE "org.bluez.Input"

#define BUF_SIZE		16

#define UPDOWN_ENABLED		1

#define FI_FLAG_CONNECTED	1

struct input_conn {
	struct fake_input	*fake;
	DBusMessage		*pending_connect;
	char			*uuid;
	char			*alias;
	GIOChannel		*ctrl_io;
	GIOChannel		*intr_io;
	guint			ctrl_watch;
	guint			intr_watch;
	int			timeout;
	struct input_device	*idev;
};

struct input_device {
	DBusConnection		*conn;
	char			*path;
	bdaddr_t		src;
	bdaddr_t		dst;
	uint32_t		handle;
	guint			dc_id;
	char			*name;
	struct btd_device	*device;
	GSList			*connections;
};

GSList *devices = NULL;

static struct input_device *find_device_by_path(GSList *list, const char *path)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct input_device *idev = l->data;

		if (!strcmp(idev->path, path))
			return idev;
	}

	return NULL;
}

static struct input_conn *find_connection(GSList *list, const char *pattern)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct input_conn *iconn = l->data;

		if (!strcasecmp(iconn->uuid, pattern))
			return iconn;

		if (!strcasecmp(iconn->alias, pattern))
			return iconn;
	}

	return NULL;
}

static void input_conn_free(struct input_conn *iconn)
{
	if (iconn->pending_connect)
		dbus_message_unref(iconn->pending_connect);

	if (iconn->ctrl_watch)
		g_source_remove(iconn->ctrl_watch);

	if (iconn->intr_watch)
		g_source_remove(iconn->intr_watch);

	if (iconn->intr_io)
		g_io_channel_unref(iconn->intr_io);

	if (iconn->ctrl_io)
		g_io_channel_unref(iconn->ctrl_io);

	g_free(iconn->uuid);
	g_free(iconn->alias);
	g_free(iconn->fake);
	g_free(iconn);
}

static void input_device_free(struct input_device *idev)
{
	if (idev->dc_id)
		device_remove_disconnect_watch(idev->device, idev->dc_id);

	dbus_connection_unref(idev->conn);
	btd_device_unref(idev->device);
	g_free(idev->name);
	g_free(idev->path);
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
		strncpy(dev.name, name, UINPUT_MAX_NAME_SIZE - 1);

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

	DBG("Received: %s", buf);

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

static inline DBusMessage *not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							"Not supported");
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

static inline DBusMessage *connection_attempt_failed(DBusMessage *msg,
							const char *err)
{
	return g_dbus_create_error(msg,
				ERROR_INTERFACE ".ConnectionAttemptFailed",
				err ? err : "Connection attempt failed");
}

static void rfcomm_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct input_conn *iconn = user_data;
	struct input_device *idev = iconn->idev;
	struct fake_input *fake = iconn->fake;
	DBusMessage *reply;

	if (err) {
		reply = connection_attempt_failed(iconn->pending_connect,
								err->message);
		goto failed;
	}

	fake->rfcomm = g_io_channel_unix_get_fd(chan);

	/*
	 * FIXME: Some headsets required a sco connection
	 * first to report volume gain key events
	 */
	fake->uinput = uinput_create(idev->name);
	if (fake->uinput < 0) {
		g_io_channel_shutdown(chan, TRUE, NULL);
		reply = connection_attempt_failed(iconn->pending_connect,
							strerror(errno));
		goto failed;
	}

	fake->io = g_io_channel_unix_new(fake->rfcomm);
	g_io_channel_set_close_on_unref(fake->io, TRUE);
	g_io_add_watch(fake->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						(GIOFunc) rfcomm_io_cb, fake);

	/* Replying to the requestor */
	reply = dbus_message_new_method_return(iconn->pending_connect);
	g_dbus_send_message(idev->conn, reply);

	dbus_message_unref(iconn->pending_connect);
	iconn->pending_connect = NULL;

	return;

failed:
	g_dbus_send_message(idev->conn, reply);
	dbus_message_unref(iconn->pending_connect);
	iconn->pending_connect = NULL;
}

static gboolean rfcomm_connect(struct input_conn *iconn, GError **err)
{
	struct input_device *idev = iconn->idev;
	GIOChannel *io;

	io = bt_io_connect(BT_IO_RFCOMM, rfcomm_connect_cb, iconn,
				NULL, err,
				BT_IO_OPT_SOURCE_BDADDR, &idev->src,
				BT_IO_OPT_DEST_BDADDR, &idev->dst,
				BT_IO_OPT_INVALID);
	if (!io)
		return FALSE;

	g_io_channel_unref(io);

	return TRUE;
}

static gboolean intr_watch_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct input_conn *iconn = data;
	struct input_device *idev = iconn->idev;
	gboolean connected = FALSE;

	/* Checking for ctrl_watch avoids a double g_io_channel_shutdown since
	 * it's likely that ctrl_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && iconn->ctrl_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	emit_property_changed(idev->conn, idev->path, INPUT_DEVICE_INTERFACE,
				"Connected", DBUS_TYPE_BOOLEAN, &connected);

	device_remove_disconnect_watch(idev->device, idev->dc_id);
	idev->dc_id = 0;

	iconn->intr_watch = 0;

	g_io_channel_unref(iconn->intr_io);
	iconn->intr_io = NULL;

	/* Close control channel */
	if (iconn->ctrl_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(iconn->ctrl_io, TRUE, NULL);

	return FALSE;
}

static gboolean ctrl_watch_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct input_conn *iconn = data;

	/* Checking for intr_watch avoids a double g_io_channel_shutdown since
	 * it's likely that intr_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && iconn->intr_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	iconn->ctrl_watch = 0;

	g_io_channel_unref(iconn->ctrl_io);
	iconn->ctrl_io = NULL;

	/* Close interrupt channel */
	if (iconn->intr_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(iconn->intr_io, TRUE, NULL);

	return FALSE;
}

static gboolean fake_hid_connect(struct input_conn *iconn, GError **err)
{
	struct fake_hid *fhid = iconn->fake->priv;

	return fhid->connect(iconn->fake, err);
}

static int fake_hid_disconnect(struct input_conn *iconn)
{
	struct fake_hid *fhid = iconn->fake->priv;

	return fhid->disconnect(iconn->fake);
}

static void epox_endian_quirk(unsigned char *data, int size)
{
	/* USAGE_PAGE (Keyboard)	05 07
	 * USAGE_MINIMUM (0)		19 00
	 * USAGE_MAXIMUM (65280)	2A 00 FF   <= must be FF 00
	 * LOGICAL_MINIMUM (0)		15 00
	 * LOGICAL_MAXIMUM (65280)	26 00 FF   <= must be FF 00
	 */
	unsigned char pattern[] = { 0x05, 0x07, 0x19, 0x00, 0x2a, 0x00, 0xff,
						0x15, 0x00, 0x26, 0x00, 0xff };
	unsigned int i;

	if (!data)
		return;

	for (i = 0; i < size - sizeof(pattern); i++) {
		if (!memcmp(data + i, pattern, sizeof(pattern))) {
			data[i + 5] = 0xff;
			data[i + 6] = 0x00;
			data[i + 10] = 0xff;
			data[i + 11] = 0x00;
		}
	}
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
			memcpy(req->rd_data, (unsigned char *) pdlist->val.str,
								pdlist->unitSize);
			req->rd_size = pdlist->unitSize;
			epox_endian_quirk(req->rd_data, req->rd_size);
		}
	}
}

static int ioctl_connadd(struct hidp_connadd_req *req)
{
	int ctl, err = 0;

	ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HIDP);
	if (ctl < 0)
		return -errno;

	if (ioctl(ctl, HIDPCONNADD, req) < 0)
		err = errno;

	close(ctl);

	return -err;
}

static void encrypt_completed(uint8_t status, gpointer user_data)
{
	struct hidp_connadd_req *req = user_data;
	int err;

	if (status) {
		error("Encryption failed: %s(0x%x)",
				strerror(bt_error(status)), status);
		goto failed;
	}

	err = ioctl_connadd(req);
	if (err == 0)
		goto cleanup;

	error("ioctl_connadd(): %s(%d)", strerror(-err), -err);
failed:
	close(req->intr_sock);
	close(req->ctrl_sock);

cleanup:
	free(req->rd_data);

	g_free(req);
}

static int hidp_add_connection(const struct input_device *idev,
				const struct input_conn *iconn)
{
	struct hidp_connadd_req *req;
	struct fake_hid *fake_hid;
	struct fake_input *fake;
	sdp_record_t *rec;
	char src_addr[18], dst_addr[18];
	int err;

	req = g_new0(struct hidp_connadd_req, 1);
	req->ctrl_sock = g_io_channel_unix_get_fd(iconn->ctrl_io);
	req->intr_sock = g_io_channel_unix_get_fd(iconn->intr_io);
	req->flags     = 0;
	req->idle_to   = iconn->timeout;

	ba2str(&idev->src, src_addr);
	ba2str(&idev->dst, dst_addr);

	rec = fetch_record(src_addr, dst_addr, idev->handle);
	if (!rec) {
		error("Rejected connection from unknown device %s", dst_addr);
		err = -EPERM;
		goto cleanup;
	}

	extract_hid_record(rec, req);
	sdp_record_free(rec);

	read_device_id(src_addr, dst_addr, NULL,
				&req->vendor, &req->product, &req->version);

	fake_hid = get_fake_hid(req->vendor, req->product);
	if (fake_hid) {
		fake = g_new0(struct fake_input, 1);
		fake->connect = fake_hid_connect;
		fake->disconnect = fake_hid_disconnect;
		fake->priv = fake_hid;
		err = fake_hid_connadd(fake, iconn->intr_io, fake_hid);
		goto cleanup;
	}

	if (idev->name)
		strncpy(req->name, idev->name, sizeof(req->name) - 1);

	/* Encryption is mandatory for keyboards */
	if (req->subclass & 0x40) {
		err = bt_acl_encrypt(&idev->src, &idev->dst, encrypt_completed, req);
		if (err == 0) {
			/* Waiting async encryption */
			return 0;
		} else if (err != -EALREADY) {
			error("bt_acl_encrypt(): %s(%d)", strerror(-err), -err);
			goto cleanup;
		}
	}

	err = ioctl_connadd(req);

cleanup:
	free(req->rd_data);
	g_free(req);

	return err;
}

static int is_connected(struct input_conn *iconn)
{
	struct input_device *idev = iconn->idev;
	struct fake_input *fake = iconn->fake;
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

static int connection_disconnect(struct input_conn *iconn, uint32_t flags)
{
	struct input_device *idev = iconn->idev;
	struct fake_input *fake = iconn->fake;
	struct hidp_conndel_req req;
	struct hidp_conninfo ci;
	int ctl, err;

	/* Fake input disconnect */
	if (fake) {
		err = fake->disconnect(iconn);
		if (err == 0)
			fake->flags &= ~FI_FLAG_CONNECTED;
		return err;
	}

	/* Standard HID disconnect */
	if (iconn->intr_io)
		g_io_channel_shutdown(iconn->intr_io, TRUE, NULL);
	if (iconn->ctrl_io)
		g_io_channel_shutdown(iconn->ctrl_io, TRUE, NULL);

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

static int disconnect(struct input_device *idev, uint32_t flags)
{
	struct input_conn *iconn = NULL;
	GSList *l;

	for (l = idev->connections; l; l = l->next) {
		iconn = l->data;

		if (is_connected(iconn))
			break;
	}

	if (!iconn)
		return ENOTCONN;

	return connection_disconnect(iconn, flags);
}

static void disconnect_cb(struct btd_device *device, gboolean removal,
				void *user_data)
{
	struct input_device *idev = user_data;
	int flags;

	info("Input: disconnect %s", idev->path);

	flags = removal ? (1 << HIDP_VIRTUAL_CABLE_UNPLUG) : 0;

	disconnect(idev, flags);
}

static int input_device_connected(struct input_device *idev,
						struct input_conn *iconn)
{
	dbus_bool_t connected;
	int err;

	if (iconn->intr_io == NULL || iconn->ctrl_io == NULL)
		return -ENOTCONN;

	err = hidp_add_connection(idev, iconn);
	if (err < 0)
		return err;

	iconn->intr_watch = g_io_add_watch(iconn->intr_io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					intr_watch_cb, iconn);
	iconn->ctrl_watch = g_io_add_watch(iconn->ctrl_io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					ctrl_watch_cb, iconn);

	connected = TRUE;
	emit_property_changed(idev->conn, idev->path, INPUT_DEVICE_INTERFACE,
				"Connected", DBUS_TYPE_BOOLEAN, &connected);

	idev->dc_id = device_add_disconnect_watch(idev->device, disconnect_cb,
							idev, NULL);

	return 0;
}

static void interrupt_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct input_conn *iconn = user_data;
	struct input_device *idev = iconn->idev;
	DBusMessage *reply;
	int err;
	const char *err_msg;

	if (conn_err) {
		err_msg = conn_err->message;
		g_io_channel_unref(iconn->intr_io);
		iconn->intr_io = NULL;
		goto failed;
	}

	err = input_device_connected(idev, iconn);
	if (err < 0) {
		err_msg = strerror(-err);
		goto failed;
	}

	/* Replying to the requestor */
	g_dbus_send_reply(idev->conn, iconn->pending_connect, DBUS_TYPE_INVALID);

	dbus_message_unref(iconn->pending_connect);
	iconn->pending_connect = NULL;

	return;

failed:
	error("%s", err_msg);
	reply = connection_attempt_failed(iconn->pending_connect, err_msg);
	g_dbus_send_message(idev->conn, reply);

	if (iconn->ctrl_io)
		g_io_channel_shutdown(iconn->ctrl_io, FALSE, NULL);

	if (iconn->intr_io) {
		if (!conn_err)
			g_io_channel_shutdown(iconn->intr_io, FALSE, NULL);
		g_io_channel_unref(iconn->intr_io);
		iconn->intr_io = NULL;
	}
}

static void control_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct input_conn *iconn = user_data;
	struct input_device *idev = iconn->idev;
	DBusMessage *reply;
	GIOChannel *io;
	GError *err = NULL;

	if (conn_err) {
		error("%s", conn_err->message);
		reply = connection_attempt_failed(iconn->pending_connect,
							conn_err->message);
		goto failed;
	}

	/* Connect to the HID interrupt channel */
	io = bt_io_connect(BT_IO_L2CAP, interrupt_connect_cb, iconn,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &idev->src,
				BT_IO_OPT_DEST_BDADDR, &idev->dst,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		reply = connection_attempt_failed(iconn->pending_connect,
							err->message);
		g_error_free(err);
		g_io_channel_shutdown(chan, TRUE, NULL);
		goto failed;
	}

	iconn->intr_io = io;

	return;

failed:
	g_dbus_send_message(idev->conn, reply);
	dbus_message_unref(iconn->pending_connect);
	iconn->pending_connect = NULL;
}

static int fake_disconnect(struct input_conn *iconn)
{
	struct fake_input *fake = iconn->fake;

	if (!fake->io)
		return -ENOTCONN;

	g_io_channel_shutdown(fake->io, TRUE, NULL);
	g_io_channel_unref(fake->io);
	fake->io = NULL;

	if (fake->uinput >= 0) {
		ioctl(fake->uinput, UI_DEV_DESTROY);
		close(fake->uinput);
		fake->uinput = -1;
	}

	return 0;
}

/*
 * Input Device methods
 */
static DBusMessage *input_device_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct input_device *idev = data;
	struct input_conn *iconn;
	struct fake_input *fake;
	DBusMessage *reply;
	GError *err = NULL;

	iconn = find_connection(idev->connections, "HID");
	if (!iconn)
		return not_supported(msg);

	if (iconn->pending_connect)
		return in_progress(msg);

	if (is_connected(iconn))
		return already_connected(msg);

	iconn->pending_connect = dbus_message_ref(msg);
	fake = iconn->fake;

	if (fake) {
		/* Fake input device */
		if (fake->connect(iconn, &err))
			fake->flags |= FI_FLAG_CONNECTED;
	} else {
		/* HID devices */
		GIOChannel *io;

		io = bt_io_connect(BT_IO_L2CAP, control_connect_cb, iconn,
					NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &idev->src,
					BT_IO_OPT_DEST_BDADDR, &idev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
		iconn->ctrl_io = io;
	}

	if (err == NULL)
		return NULL;

	error("%s", err->message);
	dbus_message_unref(iconn->pending_connect);
	iconn->pending_connect = NULL;
	reply = connection_attempt_failed(msg, err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *create_errno_message(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							strerror(err));
}

static DBusMessage *input_device_disconnect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct input_device *idev = data;
	int err;

	err = disconnect(idev, 0);
	if (err < 0)
		return create_errno_message(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void device_unregister(void *data)
{
	struct input_device *idev = data;

	DBG("Unregistered interface %s on path %s", INPUT_DEVICE_INTERFACE,
								idev->path);

	devices = g_slist_remove(devices, idev);
	input_device_free(idev);
}

static gint connected_cmp(gpointer a, gpointer b)
{
	struct input_conn *iconn = a;

	return !is_connected(iconn);
}

static DBusMessage *input_device_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct input_device *idev = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	connected = !!g_slist_find_custom(idev->connections, NULL,
					(GCompareFunc) connected_cmp);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &connected);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable device_methods[] = {
	{ "Connect",		"",	"",	input_device_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	input_device_disconnect	},
	{ "GetProperties",	"",	"a{sv}",input_device_get_properties },
	{ }
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

static struct input_device *input_device_new(DBusConnection *conn,
					struct btd_device *device, const char *path,
					const bdaddr_t *src, const bdaddr_t *dst,
					const uint32_t handle)
{
	struct input_device *idev;
	char name[249], src_addr[18], dst_addr[18];

	idev = g_new0(struct input_device, 1);
	bacpy(&idev->src, src);
	bacpy(&idev->dst, dst);
	idev->device = btd_device_ref(device);
	idev->path = g_strdup(path);
	idev->conn = dbus_connection_ref(conn);
	idev->handle = handle;

	ba2str(src, src_addr);
	ba2str(dst, dst_addr);
	if (read_device_name(src_addr, dst_addr, name) == 0)
		idev->name = g_strdup(name);

	if (g_dbus_register_interface(conn, idev->path, INPUT_DEVICE_INTERFACE,
					device_methods, device_signals, NULL,
					idev, device_unregister) == FALSE) {
		error("Failed to register interface %s on path %s",
			INPUT_DEVICE_INTERFACE, path);
		input_device_free(idev);
		return NULL;
	}

	DBG("Registered interface %s on path %s",
			INPUT_DEVICE_INTERFACE, idev->path);

	return idev;
}

static struct input_conn *input_conn_new(struct input_device *idev,
					const char *uuid, const char *alias,
					int timeout)
{
	struct input_conn *iconn;

	iconn = g_new0(struct input_conn, 1);
	iconn->timeout = timeout;
	iconn->uuid = g_strdup(uuid);
	iconn->alias = g_strdup(alias);
	iconn->idev = idev;

	return iconn;
}

int input_device_register(DBusConnection *conn, struct btd_device *device,
			const char *path, const bdaddr_t *src,
			const bdaddr_t *dst, const char *uuid,
			uint32_t handle, int timeout)
{
	struct input_device *idev;
	struct input_conn *iconn;

	idev = find_device_by_path(devices, path);
	if (!idev) {
		idev = input_device_new(conn, device, path, src, dst, handle);
		if (!idev)
			return -EINVAL;
		devices = g_slist_append(devices, idev);
	}

	iconn = input_conn_new(idev, uuid, "hid", timeout);
	if (!iconn)
		return -EINVAL;

	idev->connections = g_slist_append(idev->connections, iconn);

	return 0;
}

int fake_input_register(DBusConnection *conn, struct btd_device *device,
			const char *path, bdaddr_t *src, bdaddr_t *dst,
			const char *uuid, uint8_t channel)
{
	struct input_device *idev;
	struct input_conn *iconn;

	idev = find_device_by_path(devices, path);
	if (!idev) {
		idev = input_device_new(conn, device, path, src, dst, 0);
		if (!idev)
			return -EINVAL;
		devices = g_slist_append(devices, idev);
	}

	iconn = input_conn_new(idev, uuid, "hsp", 0);
	if (!iconn)
		return -EINVAL;

	iconn->fake = g_new0(struct fake_input, 1);
	iconn->fake->ch = channel;
	iconn->fake->connect = rfcomm_connect;
	iconn->fake->disconnect = fake_disconnect;

	idev->connections = g_slist_append(idev->connections, iconn);

	return 0;
}

static struct input_device *find_device(const bdaddr_t *src,
					const bdaddr_t *dst)
{
	GSList *list;

	for (list = devices; list != NULL; list = list->next) {
		struct input_device *idev = list->data;

		if (!bacmp(&idev->src, src) && !bacmp(&idev->dst, dst))
			return idev;
	}

	return NULL;
}

int input_device_unregister(const char *path, const char *uuid)
{
	struct input_device *idev;
	struct input_conn *iconn;

	idev = find_device_by_path(devices, path);
	if (idev == NULL)
		return -EINVAL;

	iconn = find_connection(idev->connections, uuid);
	if (iconn == NULL)
		return -EINVAL;

	if (iconn->pending_connect) {
		/* Pending connection running */
		return -EBUSY;
	}

	idev->connections = g_slist_remove(idev->connections, iconn);
	input_conn_free(iconn);
	if (idev->connections)
		return 0;

	g_dbus_unregister_interface(idev->conn, path, INPUT_DEVICE_INTERFACE);

	return 0;
}

static int input_device_connadd(struct input_device *idev,
				struct input_conn *iconn)
{
	int err;

	err = input_device_connected(idev, iconn);
	if (err < 0)
		goto error;

	return 0;

error:
	if (iconn->ctrl_io) {
		g_io_channel_shutdown(iconn->ctrl_io, FALSE, NULL);
		g_io_channel_unref(iconn->ctrl_io);
		iconn->ctrl_io = NULL;
	}
	if (iconn->intr_io) {
		g_io_channel_shutdown(iconn->intr_io, FALSE, NULL);
		g_io_channel_unref(iconn->intr_io);
		iconn->intr_io = NULL;
	}

	return err;
}

int input_device_set_channel(const bdaddr_t *src, const bdaddr_t *dst, int psm,
								GIOChannel *io)
{
	struct input_device *idev = find_device(src, dst);
	struct input_conn *iconn;

	if (!idev)
		return -ENOENT;

	iconn = find_connection(idev->connections, "hid");
	if (!iconn)
		return -ENOENT;

	switch (psm) {
	case L2CAP_PSM_HIDP_CTRL:
		if (iconn->ctrl_io)
			return -EALREADY;
		iconn->ctrl_io = g_io_channel_ref(io);
		break;
	case L2CAP_PSM_HIDP_INTR:
		if (iconn->intr_io)
			return -EALREADY;
		iconn->intr_io = g_io_channel_ref(io);
		break;
	}

	if (iconn->intr_io && iconn->ctrl_io)
		input_device_connadd(idev, iconn);

	return 0;
}

int input_device_close_channels(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct input_device *idev = find_device(src, dst);
	struct input_conn *iconn;

	if (!idev)
		return -ENOENT;

	iconn = find_connection(idev->connections, "hid");
	if (!iconn)
		return -ENOENT;

	if (iconn->intr_io)
		g_io_channel_shutdown(iconn->intr_io, TRUE, NULL);

	if (iconn->ctrl_io)
		g_io_channel_shutdown(iconn->ctrl_io, TRUE, NULL);

	return 0;
}
