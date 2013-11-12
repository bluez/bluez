/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>

#include "btio/btio.h"
#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "lib/uuid.h"
#include "src/shared/mgmt.h"
#include "src/sdp-client.h"
#include "src/glib-helper.h"
#include "profiles/input/uhid_copy.h"

#include "log.h"
#include "hal-msg.h"
#include "ipc.h"
#include "hidhost.h"
#include "utils.h"

#define L2CAP_PSM_HIDP_CTRL	0x11
#define L2CAP_PSM_HIDP_INTR	0x13
#define UHID_DEVICE_FILE	"/dev/uhid"

/* HID message types */
#define HID_MSG_CONTROL		0x10
#define HID_MSG_GET_REPORT	0x40
#define HID_MSG_SET_REPORT	0x50
#define HID_MSG_GET_PROTOCOL	0x60
#define HID_MSG_SET_PROTOCOL	0x70
#define HID_MSG_DATA		0xa0

/* HID data types */
#define HID_DATA_TYPE_INPUT	0x01
#define HID_DATA_TYPE_OUTPUT	0x02
#define HID_DATA_TYPE_FEATURE	0x03

/* HID protocol header parameters */
#define HID_PROTO_BOOT		0x00
#define HID_PROTO_REPORT	0x01

/* HID GET REPORT Size Field */
#define HID_GET_REPORT_SIZE_FIELD	0x08

/* HID Virtual Cable Unplug */
#define HID_VIRTUAL_CABLE_UNPLUG	0x05

static bdaddr_t adapter_addr;

static int notification_sk = -1;
static GIOChannel *ctrl_io = NULL;
static GIOChannel *intr_io = NULL;
static GSList *devices = NULL;

struct hid_device {
	bdaddr_t	dst;
	uint8_t		state;
	uint8_t		subclass;
	uint16_t	vendor;
	uint16_t	product;
	uint16_t	version;
	uint8_t		country;
	int		rd_size;
	void		*rd_data;
	uint8_t		boot_dev;
	GIOChannel	*ctrl_io;
	GIOChannel	*intr_io;
	guint		ctrl_watch;
	guint		intr_watch;
	int		uhid_fd;
	guint		uhid_watch_id;
	uint8_t		last_hid_msg;
};

static int device_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct hid_device *dev = s;
	const bdaddr_t *dst = user_data;

	return bacmp(&dev->dst, dst);
}

static void uhid_destroy(int fd)
{
	struct uhid_event ev;

	/* destroy uHID device */
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;

	if (write(fd, &ev, sizeof(ev)) < 0)
		error("Failed to destroy uHID device: %s (%d)",
						strerror(errno), errno);

	close(fd);
}

static void hid_device_free(struct hid_device *dev)
{
	if (dev->ctrl_watch > 0)
		g_source_remove(dev->ctrl_watch);

	if (dev->intr_watch > 0)
		g_source_remove(dev->intr_watch);

	if (dev->intr_io)
		g_io_channel_unref(dev->intr_io);

	if (dev->ctrl_io)
		g_io_channel_unref(dev->ctrl_io);

	if (dev->uhid_watch_id) {
		g_source_remove(dev->uhid_watch_id);
		dev->uhid_watch_id = 0;
	}

	if (dev->uhid_fd > 0)
		uhid_destroy(dev->uhid_fd);

	g_free(dev->rd_data);

	devices = g_slist_remove(devices, dev);
	g_free(dev);
}

static void handle_uhid_event(struct hid_device *dev, struct uhid_event *ev)
{
	int fd, i;
	uint8_t *req = NULL;
	uint8_t req_size = 0;

	if (!(dev->ctrl_io))
		return;

	req_size = 1 + (ev->u.output.size / 2);
	req = g_try_malloc0(req_size);
	if (!req)
		return;

	req[0] = HID_MSG_SET_REPORT | ev->u.output.rtype;
	for (i = 0; i < (req_size - 1); i++)
		sscanf((char *) &(ev->u.output.data)[i * 2],
							"%hhx", &req[1 + i]);

	fd = g_io_channel_unix_get_fd(dev->ctrl_io);

	if (write(fd, req, req_size) < 0)
		error("error writing set_report: %s (%d)",
						strerror(errno), errno);

	g_free(req);
}

static gboolean uhid_event_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct hid_device *dev = user_data;
	struct uhid_event ev;
	ssize_t bread;
	int fd;

	DBG("");

	if (cond & (G_IO_ERR | G_IO_NVAL))
		goto failed;

	fd = g_io_channel_unix_get_fd(io);
	memset(&ev, 0, sizeof(ev));

	bread = read(fd, &ev, sizeof(ev));
	if (bread < 0) {
		DBG("read: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	DBG("uHID event type %d received", ev.type);

	switch (ev.type) {
	case UHID_START:
	case UHID_STOP:
		/* These are called to start and stop the underlying hardware.
		 * We open the channels before creating the device so the
		 * hardware is always ready. No need to handle these.
		 * The kernel never destroys a device itself! Only an explicit
		 * UHID_DESTROY request can remove a device. */

		break;
	case UHID_OPEN:
	case UHID_CLOSE:
		/* OPEN/CLOSE are sent whenever user-space opens any interface
		 * provided by the kernel HID device. Whenever the open-count
		 * is non-zero we must be ready for I/O. As long as it is zero,
		 * we can decide to drop all I/O and put the device
		 * asleep This is optional, though. */
		break;
	case UHID_OUTPUT:
	case UHID_FEATURE:
		handle_uhid_event(dev, &ev);
		break;
	case UHID_OUTPUT_EV:
		/* This is only sent by kernels prior to linux-3.11. It
		 * requires us to parse HID-descriptors in user-space to
		 * properly handle it. This is redundant as the kernel
		 * does it already. That's why newer kernels assemble
		 * the output-reports and send it to us via UHID_OUTPUT. */
		DBG("UHID_OUTPUT_EV unsupported");
		break;
	default:
		warn("unexpected uHID event");
	}

	return TRUE;

failed:
	dev->uhid_watch_id = 0;
	return FALSE;
}

static gboolean intr_io_watch_cb(GIOChannel *chan, gpointer data)
{
	struct hid_device *dev = data;
	uint8_t buf[UHID_DATA_MAX];
	struct uhid_event ev;
	int fd, bread;

	/* Wait uHID if not ready */
	if (dev->uhid_fd < 0)
		return TRUE;

	fd = g_io_channel_unix_get_fd(chan);
	bread = read(fd, buf, sizeof(buf));
	if (bread < 0) {
		error("read: %s(%d)", strerror(errno), -errno);
		return TRUE;
	}

	/* Discard non-data packets */
	if (bread == 0 || buf[0] != (HID_MSG_DATA | HID_DATA_TYPE_INPUT))
		return TRUE;

	/* send data to uHID device skipping HIDP header byte */
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = bread - 1;
	memcpy(ev.u.input.data, &buf[1], ev.u.input.size);

	if (write(dev->uhid_fd, &ev, sizeof(ev)) < 0)
		DBG("uhid write: %s (%d)", strerror(errno), errno);

	return TRUE;
}

static void bt_hid_notify_state(struct hid_device *dev, uint8_t state)
{
	struct hal_ev_hidhost_conn_state ev;
	char address[18];

	if (dev->state == state)
		return;

	dev->state = state;

	ba2str(&dev->dst, address);
	DBG("device %s state %u", address, state);

	bdaddr2android(&dev->dst, ev.bdaddr);
	ev.state = state;

	ipc_send(notification_sk, HAL_SERVICE_ID_HIDHOST,
			HAL_EV_HIDHOST_CONN_STATE, sizeof(ev), &ev, -1);
}

static gboolean intr_watch_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct hid_device *dev = data;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		goto error;

	if (cond & G_IO_IN)
		return intr_io_watch_cb(chan, data);

error:
	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTED);

	/* Checking for ctrl_watch avoids a double g_io_channel_shutdown since
	 * it's likely that ctrl_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && dev->ctrl_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	/* Close control channel */
	if (dev->ctrl_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(dev->ctrl_io, TRUE, NULL);

	hid_device_free(dev);

	return FALSE;
}

static void bt_hid_notify_proto_mode(struct hid_device *dev, uint8_t *buf,
									int len)
{
	struct hal_ev_hidhost_proto_mode ev;
	char address[18];

	ba2str(&dev->dst, address);
	DBG("device %s", address);

	memset(&ev, 0, sizeof(ev));
	bdaddr2android(&dev->dst, ev.bdaddr);

	if (buf[0] == HID_MSG_DATA) {
		ev.status = HAL_HIDHOST_STATUS_OK;
		if (buf[1] == HID_PROTO_REPORT)
			ev.mode = HAL_HIDHOST_REPORT_PROTOCOL;
		else if (buf[1] == HID_PROTO_BOOT)
			ev.mode = HAL_HIDHOST_BOOT_PROTOCOL;
		else
			ev.mode = HAL_HIDHOST_UNSUPPORTED_PROTOCOL;

	} else {
		ev.status = buf[0];
		ev.mode = HAL_HIDHOST_UNSUPPORTED_PROTOCOL;
	}

	ipc_send(notification_sk, HAL_SERVICE_ID_HIDHOST,
			HAL_EV_HIDHOST_PROTO_MODE, sizeof(ev), &ev, -1);
}

static void bt_hid_notify_get_report(struct hid_device *dev, uint8_t *buf,
									int len)
{
	struct hal_ev_hidhost_get_report *ev;
	int ev_len;
	char address[18];

	ba2str(&dev->dst, address);
	DBG("device %s", address);

	ev_len = sizeof(*ev) + sizeof(struct hal_ev_hidhost_get_report) + 1;

	if (!((buf[0] == (HID_MSG_DATA | HID_DATA_TYPE_INPUT)) ||
			(buf[0] == (HID_MSG_DATA | HID_DATA_TYPE_OUTPUT)) ||
			(buf[0]	== (HID_MSG_DATA | HID_DATA_TYPE_FEATURE)))) {
		ev = g_malloc0(ev_len);
		ev->status = buf[0];
		bdaddr2android(&dev->dst, ev->bdaddr);
		goto send;
	}

	/* Report porotocol mode reply contains id after hdr, in boot
	 * protocol mode id doesn't exist */
	ev_len += (dev->boot_dev) ? (len - 1) : (len - 2);
	ev = g_malloc0(ev_len);
	ev->status = HAL_HIDHOST_STATUS_OK;
	bdaddr2android(&dev->dst, ev->bdaddr);

	/* Report porotocol mode reply contains id after hdr, in boot
	 * protocol mode id doesn't exist */
	if (dev->boot_dev) {
		ev->len = len - 1;
		memcpy(ev->data, buf + 1, ev->len);
	} else {
		ev->len = len - 2;
		memcpy(ev->data, buf + 2, ev->len);
	}

send:
	ipc_send(notification_sk, HAL_SERVICE_ID_HIDHOST,
				HAL_EV_HIDHOST_GET_REPORT, ev_len, ev, -1);
	g_free(ev);
}

static void bt_hid_notify_virtual_unplug(struct hid_device *dev,
							uint8_t *buf, int len)
{
	struct hal_ev_hidhost_virtual_unplug ev;
	char address[18];

	ba2str(&dev->dst, address);
	DBG("device %s", address);
	bdaddr2android(&dev->dst, ev.bdaddr);

	ev.status = HAL_HIDHOST_GENERAL_ERROR;

	/* Wait either channels to HUP */
	if (dev->intr_io && dev->ctrl_io) {
		g_io_channel_shutdown(dev->intr_io, TRUE, NULL);
		g_io_channel_shutdown(dev->ctrl_io, TRUE, NULL);
		bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTING);
		ev.status = HAL_HIDHOST_STATUS_OK;
	}

	ipc_send(notification_sk, HAL_SERVICE_ID_HIDHOST,
			HAL_EV_HIDHOST_VIRTUAL_UNPLUG, sizeof(ev), &ev, -1);

}

static gboolean ctrl_io_watch_cb(GIOChannel *chan, gpointer data)
{
	struct hid_device *dev = data;
	int fd, bread;
	uint8_t buf[UHID_DATA_MAX];

	DBG("");

	fd = g_io_channel_unix_get_fd(chan);
	bread = read(fd, buf, sizeof(buf));
	if (bread < 0) {
		error("read: %s(%d)", strerror(errno), -errno);
		return TRUE;
	}

	switch (dev->last_hid_msg) {
	case HID_MSG_GET_PROTOCOL:
	case HID_MSG_SET_PROTOCOL:
		bt_hid_notify_proto_mode(dev, buf, bread);
		break;
	case HID_MSG_GET_REPORT:
		bt_hid_notify_get_report(dev, buf, bread);
		break;
	}

	if (buf[0] == (HID_MSG_CONTROL | HID_VIRTUAL_CABLE_UNPLUG))
		bt_hid_notify_virtual_unplug(dev, buf, bread);

	/* reset msg type request */
	dev->last_hid_msg = 0;

	return TRUE;
}

static gboolean ctrl_watch_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct hid_device *dev = data;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		goto error;

	if (cond & G_IO_IN)
		return ctrl_io_watch_cb(chan, data);

error:
	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTED);

	/* Checking for intr_watch avoids a double g_io_channel_shutdown since
	 * it's likely that intr_watch_cb has been queued for dispatching in
	 * this mainloop iteration */
	if ((cond & (G_IO_HUP | G_IO_ERR)) && dev->intr_watch)
		g_io_channel_shutdown(chan, TRUE, NULL);

	if (dev->intr_io && !(cond & G_IO_NVAL))
		g_io_channel_shutdown(dev->intr_io, TRUE, NULL);

	hid_device_free(dev);

	return FALSE;
}

static void bt_hid_set_info(struct hid_device *dev)
{
	struct hal_ev_hidhost_info ev;

	DBG("");

	bdaddr2android(&dev->dst, ev.bdaddr);
	ev.attr = 0; /* TODO: Check what is this field */
	ev.subclass = dev->subclass;
	ev.app_id = 0; /* TODO: Check what is this field */
	ev.vendor = dev->vendor;
	ev.product = dev->product;
	ev.version = dev->version;
	ev.country = dev->country;
	ev.descr_len = dev->rd_size;
	memset(ev.descr, 0, sizeof(ev.descr));
	memcpy(ev.descr, dev->rd_data, ev.descr_len);

	ipc_send(notification_sk, HAL_SERVICE_ID_HIDHOST, HAL_EV_HIDHOST_INFO,
							sizeof(ev), &ev, -1);
}

static int uhid_create(struct hid_device *dev)
{
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_NVAL;
	GIOChannel *io;
	struct uhid_event ev;

	dev->uhid_fd = open(UHID_DEVICE_FILE, O_RDWR | O_CLOEXEC);
	if (dev->uhid_fd < 0) {
		error("Failed to open uHID device: %s", strerror(errno));
		bt_hid_notify_state(dev, HAL_HIDHOST_STATE_NO_HID);
		return -errno;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE;
	strcpy((char *) ev.u.create.name, "bluez-input-device");
	ev.u.create.bus = BUS_BLUETOOTH;
	ev.u.create.vendor = dev->vendor;
	ev.u.create.product = dev->product;
	ev.u.create.version = dev->version;
	ev.u.create.country = dev->country;
	ev.u.create.rd_size = dev->rd_size;
	ev.u.create.rd_data = dev->rd_data;

	if (write(dev->uhid_fd, &ev, sizeof(ev)) < 0) {
		error("Failed to create uHID device: %s", strerror(errno));
		close(dev->uhid_fd);
		dev->uhid_fd = -1;
		bt_hid_notify_state(dev, HAL_HIDHOST_STATE_NO_HID);
		return -errno;
	}

	io = g_io_channel_unix_new(dev->uhid_fd);
	g_io_channel_set_encoding(io, NULL, NULL);
	dev->uhid_watch_id = g_io_add_watch(io, cond, uhid_event_cb, dev);
	g_io_channel_unref(io);

	bt_hid_set_info(dev);

	return 0;
}

static void interrupt_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct hid_device *dev = user_data;

	DBG("");

	if (conn_err) {
		error("%s", conn_err->message);
		goto failed;
	}

	if (uhid_create(dev) < 0)
		goto failed;

	dev->intr_watch = g_io_add_watch(dev->intr_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				intr_watch_cb, dev);

	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_CONNECTED);

	return;

failed:
	hid_device_free(dev);
}

static void control_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct hid_device *dev = user_data;
	GError *err = NULL;

	DBG("");

	if (conn_err) {
		bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTED);
		error("%s", conn_err->message);
		goto failed;
	}

	/* Connect to the HID interrupt channel */
	dev->intr_io = bt_io_connect(interrupt_connect_cb, dev, NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (!dev->intr_io) {
		error("%s", err->message);
		g_error_free(err);
		goto failed;
	}

	dev->ctrl_watch = g_io_add_watch(dev->ctrl_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				ctrl_watch_cb, dev);

	return;

failed:
	hid_device_free(dev);
}

static void hid_sdp_search_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct hid_device *dev = data;
	sdp_list_t *list;
	GError *gerr = NULL;

	DBG("");

	if (err < 0) {
		error("Unable to get SDP record: %s", strerror(-err));
		goto fail;
	}

	if (!recs || !recs->data) {
		error("No SDP records found");
		goto fail;
	}

	for (list = recs; list != NULL; list = list->next) {
		sdp_record_t *rec = list->data;
		sdp_data_t *data;

		data = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
		if (data)
			dev->vendor = data->val.uint16;

		data = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
		if (data)
			dev->product = data->val.uint16;

		data = sdp_data_get(rec, SDP_ATTR_VERSION);
		if (data)
			dev->version = data->val.uint16;

		data = sdp_data_get(rec, SDP_ATTR_HID_COUNTRY_CODE);
		if (data)
			dev->country = data->val.uint8;

		data = sdp_data_get(rec, SDP_ATTR_HID_DEVICE_SUBCLASS);
		if (data)
			dev->subclass = data->val.uint8;

		data = sdp_data_get(rec, SDP_ATTR_HID_BOOT_DEVICE);
		if (data)
			dev->boot_dev = data->val.uint8;

		data = sdp_data_get(rec, SDP_ATTR_HID_DESCRIPTOR_LIST);
		if (data) {
			if (!SDP_IS_SEQ(data->dtd))
				goto fail;

			/* First HIDDescriptor */
			data = data->val.dataseq;
			if (!SDP_IS_SEQ(data->dtd))
				goto fail;

			/* ClassDescriptorType */
			data = data->val.dataseq;
			if (data->dtd != SDP_UINT8)
				goto fail;

			/* ClassDescriptorData */
			data = data->next;
			if (!data || !SDP_IS_TEXT_STR(data->dtd))
				goto fail;

			dev->rd_size = data->unitSize;
			dev->rd_data = g_memdup(data->val.str, data->unitSize);
		}
	}

	if (dev->ctrl_io) {
		if (uhid_create(dev) < 0)
			goto fail;
		return;
	}

	dev->ctrl_io = bt_io_connect(control_connect_cb, dev, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		goto fail;
	}

	return;

fail:
	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTED);
	hid_device_free(dev);
}

static uint8_t bt_hid_connect(struct hal_cmd_hidhost_connect *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	char addr[18];
	bdaddr_t dst;
	GSList *l;
	uuid_t uuid;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (l)
		return HAL_STATUS_FAILED;

	dev = g_new0(struct hid_device, 1);
	bacpy(&dev->dst, &dst);
	dev->uhid_fd = -1;

	ba2str(&dev->dst, addr);
	DBG("connecting to %s", addr);

	bt_string2uuid(&uuid, HID_UUID);
	if (bt_search_service(&adapter_addr, &dev->dst, &uuid,
					hid_sdp_search_cb, dev, NULL) < 0) {
		error("Failed to search sdp details");
		hid_device_free(dev);
		return HAL_STATUS_FAILED;
	}

	devices = g_slist_append(devices, dev);
	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_CONNECTING);

	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_disconnect(struct hal_cmd_hidhost_disconnect *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	/* Wait either channels to HUP */
	if (dev->intr_io)
		g_io_channel_shutdown(dev->intr_io, TRUE, NULL);

	if (dev->ctrl_io)
		g_io_channel_shutdown(dev->ctrl_io, TRUE, NULL);

	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTING);

	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_virtual_unplug(struct hal_cmd_hidhost_virtual_unplug *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;
	uint8_t hdr;
	int fd;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	if (!(dev->ctrl_io))
		return HAL_STATUS_FAILED;

	hdr = HID_MSG_CONTROL | HID_VIRTUAL_CABLE_UNPLUG;

	fd = g_io_channel_unix_get_fd(dev->ctrl_io);

	if (write(fd, &hdr, sizeof(hdr)) < 0) {
		error("error writing virtual unplug command: %s (%d)",
						strerror(errno), errno);
		return HAL_STATUS_FAILED;
	}

	/* Wait either channels to HUP */
	if (dev->intr_io)
		g_io_channel_shutdown(dev->intr_io, TRUE, NULL);

	if (dev->ctrl_io)
		g_io_channel_shutdown(dev->ctrl_io, TRUE, NULL);

	bt_hid_notify_state(dev, HAL_HIDHOST_STATE_DISCONNECTING);

	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_info(struct hal_cmd_hidhost_set_info *cmd, uint16_t len)
{
	/* Data from hal_cmd_hidhost_set_info is usefull only when we create
	 * UHID device. Once device is created all the transactions will be
	 * done through the fd. There is no way to use this information
	 * once device is created with HID internals. */
	DBG("Not supported");

	return HAL_STATUS_UNSUPPORTED;
}

static uint8_t bt_hid_get_protocol(struct hal_cmd_hidhost_get_protocol *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;
	int fd;
	uint8_t hdr;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	if (dev->boot_dev)
		return HAL_STATUS_UNSUPPORTED;

	hdr = HID_MSG_GET_PROTOCOL | cmd->mode;
	fd = g_io_channel_unix_get_fd(dev->ctrl_io);

	if (write(fd, &hdr, sizeof(hdr)) < 0) {
		error("error writing device_get_protocol: %s (%d)",
						strerror(errno), errno);
		return HAL_STATUS_FAILED;
	}

	dev->last_hid_msg = HID_MSG_GET_PROTOCOL;
	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_set_protocol(struct hal_cmd_hidhost_set_protocol *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;
	int fd;
	uint8_t hdr;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	if (dev->boot_dev)
		return HAL_STATUS_UNSUPPORTED;

	hdr = HID_MSG_SET_PROTOCOL | cmd->mode;
	fd = g_io_channel_unix_get_fd(dev->ctrl_io);

	if (write(fd, &hdr, sizeof(hdr)) < 0) {
		error("error writing device_set_protocol: %s (%d)",
						strerror(errno), errno);
		return HAL_STATUS_FAILED;
	}

	dev->last_hid_msg = HID_MSG_SET_PROTOCOL;
	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_get_report(struct hal_cmd_hidhost_get_report *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;
	int fd;
	uint8_t *req;
	uint8_t req_size;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;
	req_size = (cmd->buf_size > 0) ? 4 : 2;
	req = g_try_malloc0(req_size);
	if (!req)
		return HAL_STATUS_NOMEM;

	req[0] = HID_MSG_GET_REPORT | cmd->type;
	req[1] = cmd->id;

	if (cmd->buf_size > 0) {
		req[0] = req[0] | HID_GET_REPORT_SIZE_FIELD;
		bt_put_le16(cmd->buf_size, &req[2]);
	}

	fd = g_io_channel_unix_get_fd(dev->ctrl_io);

	if (write(fd, req, req_size) < 0) {
		error("error writing hid_get_report: %s (%d)",
						strerror(errno), errno);
		g_free(req);
		return HAL_STATUS_FAILED;
	}

	dev->last_hid_msg = HID_MSG_GET_REPORT;
	g_free(req);
	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_set_report(struct hal_cmd_hidhost_set_report *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;
	int i, fd;
	uint8_t *req;
	uint8_t req_size;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	if (!(dev->ctrl_io))
		return HAL_STATUS_FAILED;

	req_size = 1 + (cmd->len / 2);
	req = g_try_malloc0(req_size);
	if (!req)
		return HAL_STATUS_NOMEM;

	req[0] = HID_MSG_SET_REPORT | cmd->type;
	/* Report data coming to HAL is in ascii format, HAL sends
	 * data in hex to daemon, so convert to binary. */
	for (i = 0; i < (req_size - 1); i++)
		sscanf((char *) &(cmd->data)[i * 2], "%hhx", &(req + 1)[i]);

	fd = g_io_channel_unix_get_fd(dev->ctrl_io);

	if (write(fd, req, req_size) < 0) {
		error("error writing hid_set_report: %s (%d)",
						strerror(errno), errno);
		g_free(req);
		return HAL_STATUS_FAILED;
	}

	dev->last_hid_msg = HID_MSG_SET_REPORT;
	g_free(req);
	return HAL_STATUS_SUCCESS;
}

static uint8_t bt_hid_send_data(struct hal_cmd_hidhost_send_data *cmd,
								uint16_t len)
{
	struct hid_device *dev;
	GSList *l;
	bdaddr_t dst;
	int i, fd;
	uint8_t *req;
	uint8_t req_size;

	DBG("");

	if (len < sizeof(*cmd))
		return HAL_STATUS_INVALID;

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l)
		return HAL_STATUS_FAILED;

	dev = l->data;

	if (!(dev->intr_io))
		return HAL_STATUS_FAILED;

	req_size = 1 + (cmd->len / 2);
	req = g_try_malloc0(req_size);
	if (!req)
		return HAL_STATUS_NOMEM;

	req[0] = HID_MSG_DATA | HID_DATA_TYPE_OUTPUT;
	/* Report data coming to HAL is in ascii format, HAL sends
	 * data in hex to daemon, so convert to binary. */
	for (i = 0; i < (req_size - 1); i++)
		sscanf((char *) &(cmd->data)[i * 2], "%hhx", &(req + 1)[i]);

	fd = g_io_channel_unix_get_fd(dev->intr_io);

	if (write(fd, req, req_size) < 0) {
		error("error writing data to HID device: %s (%d)",
						strerror(errno), errno);
		g_free(req);
		return HAL_STATUS_FAILED;
	}

	g_free(req);
	return HAL_STATUS_SUCCESS;
}

void bt_hid_handle_cmd(int sk, uint8_t opcode, void *buf, uint16_t len)
{
	uint8_t status = HAL_STATUS_FAILED;

	switch (opcode) {
	case HAL_OP_HIDHOST_CONNECT:
		status = bt_hid_connect(buf, len);
		break;
	case HAL_OP_HIDHOST_DISCONNECT:
		status = bt_hid_disconnect(buf, len);
		break;
	case HAL_OP_HIDHOST_VIRTUAL_UNPLUG:
		status = bt_hid_virtual_unplug(buf, len);
		break;
	case HAL_OP_HIDHOST_SET_INFO:
		status = bt_hid_info(buf, len);
		break;
	case HAL_OP_HIDHOST_GET_PROTOCOL:
		status = bt_hid_get_protocol(buf, len);
		break;
	case HAL_OP_HIDHOST_SET_PROTOCOL:
		status = bt_hid_set_protocol(buf, len);
		break;
	case HAL_OP_HIDHOST_GET_REPORT:
		status = bt_hid_get_report(buf, len);
		break;
	case HAL_OP_HIDHOST_SET_REPORT:
		status = bt_hid_set_report(buf, len);
		break;
	case HAL_OP_HIDHOST_SEND_DATA:
		status = bt_hid_send_data(buf, len);
		break;
	default:
		DBG("Unhandled command, opcode 0x%x", opcode);
		break;
	}

	ipc_send_rsp(sk, HAL_SERVICE_ID_HIDHOST, status);
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct hid_device *dev;
	bdaddr_t src, dst;
	char address[18];
	uint16_t psm;
	GError *gerr = NULL;
	GSList *l;
	uuid_t uuid;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_PSM, &psm,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_io_channel_shutdown(chan, TRUE, NULL);
		g_error_free(gerr);
		return;
	}

	ba2str(&dst, address);
	DBG("Incoming connection from %s on PSM %d", address, psm);

	switch (psm) {
	case L2CAP_PSM_HIDP_CTRL:
		l = g_slist_find_custom(devices, &dst, device_cmp);
		if (l)
			return;

		dev = g_new0(struct hid_device, 1);
		bacpy(&dev->dst, &dst);
		dev->ctrl_io = g_io_channel_ref(chan);
		dev->uhid_fd = -1;

		bt_string2uuid(&uuid, HID_UUID);
		if (bt_search_service(&src, &dev->dst, &uuid,
					hid_sdp_search_cb, dev, NULL) < 0) {
			error("failed to search sdp details");
			hid_device_free(dev);
			return;
		}

		devices = g_slist_append(devices, dev);

		dev->ctrl_watch = g_io_add_watch(dev->ctrl_io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					ctrl_watch_cb, dev);
		bt_hid_notify_state(dev, HAL_HIDHOST_STATE_CONNECTING);
		break;

	case L2CAP_PSM_HIDP_INTR:
		l = g_slist_find_custom(devices, &dst, device_cmp);
		if (!l)
			return;

		dev = l->data;
		dev->intr_io = g_io_channel_ref(chan);
		dev->intr_watch = g_io_add_watch(dev->intr_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				intr_watch_cb, dev);
		bt_hid_notify_state(dev, HAL_HIDHOST_STATE_CONNECTED);
		break;
	}
}

bool bt_hid_register(int sk, const bdaddr_t *addr)
{
	GError *err = NULL;

	DBG("");

	bacpy(&adapter_addr, addr);

	ctrl_io = bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!ctrl_io) {
		error("Failed to listen on ctrl channel: %s", err->message);
		g_error_free(err);
		return false;
	}

	intr_io = bt_io_listen(connect_cb, NULL, NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!intr_io) {
		error("Failed to listen on intr channel: %s", err->message);
		g_io_channel_unref(ctrl_io);
		g_error_free(err);
		return false;
	}

	notification_sk = sk;

	return true;
}

void bt_hid_unregister(void)
{
	DBG("");

	notification_sk = -1;

	if (ctrl_io) {
		g_io_channel_shutdown(ctrl_io, TRUE, NULL);
		g_io_channel_unref(ctrl_io);
		ctrl_io = NULL;
	}

	if (intr_io) {
		g_io_channel_shutdown(intr_io, TRUE, NULL);
		g_io_channel_unref(intr_io);
		intr_io = NULL;
	}
}
