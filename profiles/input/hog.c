/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "uhid_copy.h"

#include <bluetooth/bluetooth.h>

#include <glib.h>

#include "log.h"

#include "lib/uuid.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"

#include "plugin.h"
#include "suspend.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attio.h"
#include "attrib/gatt.h"

#define HOG_UUID		"00001812-0000-1000-8000-00805f9b34fb"

#define HOG_INFO_UUID		0x2A4A
#define HOG_REPORT_MAP_UUID	0x2A4B
#define HOG_REPORT_UUID		0x2A4D
#define HOG_PROTO_MODE_UUID	0x2A4E
#define HOG_CONTROL_POINT_UUID	0x2A4C

#define HOG_REPORT_TYPE_INPUT	1
#define HOG_REPORT_TYPE_OUTPUT	2
#define HOG_REPORT_TYPE_FEATURE	3

#define HOG_PROTO_MODE_BOOT    0
#define HOG_PROTO_MODE_REPORT  1

#define UHID_DEVICE_FILE	"/dev/uhid"

#define HOG_REPORT_MAP_MAX_SIZE        512
#define HID_INFO_SIZE			4

struct hog_device {
	uint16_t		id;
	struct btd_device	*device;
	GAttrib			*attrib;
	guint			attioid;
	struct gatt_primary	*hog_primary;
	GSList			*reports;
	int			uhid_fd;
	gboolean		has_report_id;
	guint			uhid_watch_id;
	uint16_t		bcdhid;
	uint8_t			bcountrycode;
	uint16_t		proto_mode_handle;
	uint16_t		ctrlpt_handle;
	uint8_t			flags;
};

struct report {
	uint8_t			id;
	uint8_t			type;
	guint			notifyid;
	struct gatt_char	*decl;
	struct hog_device	*hogdev;
};

struct disc_desc_cb_data {
	uint16_t end;
	gpointer data;
};

static gboolean suspend_supported = FALSE;
static GSList *devices = NULL;

static void report_value_cb(const uint8_t *pdu, uint16_t len,
							gpointer user_data)
{
	struct report *report = user_data;
	struct hog_device *hogdev = report->hogdev;
	struct uhid_event ev;
	uint16_t report_size = len - 3;
	uint8_t *buf;

	if (len < 3) { /* 1-byte opcode + 2-byte handle */
		error("Malformed ATT notification");
		return;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	ev.u.input.size = MIN(report_size, UHID_DATA_MAX);

	buf = ev.u.input.data;
	if (hogdev->has_report_id) {
		*buf = report->id;
		buf++;
		ev.u.input.size++;
	}

	memcpy(buf, &pdu[3], MIN(report_size, UHID_DATA_MAX));

	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("uHID write failed: %s", strerror(errno));
	else
		DBG("Report from HoG device 0x%04X written to uHID fd %d",
						hogdev->id, hogdev->uhid_fd);
}

static void report_ccc_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct report *report = user_data;
	struct hog_device *hogdev = report->hogdev;

	if (status != 0) {
		error("Write report characteristic descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	report->notifyid = g_attrib_register(hogdev->attrib,
					ATT_OP_HANDLE_NOTIFY,
					report->decl->value_handle,
					report_value_cb, report, NULL);

	DBG("Report characteristic descriptor written: notifications enabled");
}

static void write_ccc(uint16_t handle, gpointer user_data)
{
	struct report *report = user_data;
	struct hog_device *hogdev = report->hogdev;
	uint8_t value[] = { 0x01, 0x00 };

	gatt_write_char(hogdev->attrib, handle, value, sizeof(value),
					report_ccc_written_cb, report);
}

static void report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct report *report = user_data;

	if (status != 0) {
		error("Read Report Reference descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	if (plen != 3) {
		error("Malformed ATT read response");
		return;
	}

	report->id = pdu[1];
	report->type = pdu[2];
	DBG("Report ID: 0x%02x Report type: 0x%02x", pdu[1], pdu[2]);
}

static void external_report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data);


static void discover_descriptor_cb(guint8 status, const guint8 *pdu,
					guint16 len, gpointer user_data)
{
	struct disc_desc_cb_data *ddcb_data = user_data;
	struct report *report;
	struct hog_device *hogdev;
	struct att_data_list *list = NULL;
	GAttrib *attrib = NULL;
	uint8_t format;
	uint16_t handle = 0xffff;
	uint16_t end = ddcb_data->end;
	int i;

	if (status == ATT_ECODE_ATTR_NOT_FOUND) {
		DBG("Discover all characteristic descriptors finished");
		goto done;
	}

	if (status != 0) {
		error("Discover all characteristic descriptors failed: %s",
							att_ecode2str(status));
		goto done;
	}

	list = dec_find_info_resp(pdu, len, &format);
	if (list == NULL)
		return;

	if (format != ATT_FIND_INFO_RESP_FMT_16BIT)
		goto done;

	for (i = 0; i < list->num; i++) {
		uint16_t uuid16;
		uint8_t *value;

		value = list->data[i];
		handle = att_get_u16(value);
		uuid16 = att_get_u16(&value[2]);

		switch (uuid16) {
		case GATT_CLIENT_CHARAC_CFG_UUID:
			report = ddcb_data->data;
			attrib = report->hogdev->attrib;
			write_ccc(handle, report);
			break;
		case GATT_REPORT_REFERENCE:
			report = ddcb_data->data;
			attrib = report->hogdev->attrib;
			gatt_read_char(attrib, handle,
						report_reference_cb, report);
			break;
		case GATT_EXTERNAL_REPORT_REFERENCE:
			hogdev = ddcb_data->data;
			attrib = hogdev->attrib;
			gatt_read_char(attrib, handle,
					external_report_reference_cb, hogdev);
			break;
		}
	}

done:
	att_data_list_free(list);

	if (handle != 0xffff && handle < end)
		gatt_discover_char_desc(attrib, handle + 1, end,
					discover_descriptor_cb, ddcb_data);
	else
		g_free(ddcb_data);
}

static void discover_descriptor(GAttrib *attrib, uint16_t start, uint16_t end,
							gpointer user_data)
{
	struct disc_desc_cb_data *ddcb_data;

	if (start > end)
		return;

	ddcb_data = g_new0(struct disc_desc_cb_data, 1);
	ddcb_data->end = end;
	ddcb_data->data = user_data;

	gatt_discover_char_desc(attrib, start, end, discover_descriptor_cb,
								ddcb_data);
}

static void external_service_char_cb(uint8_t status, GSList *chars,
								void *user_data)
{
	struct hog_device *hogdev = user_data;
	struct gatt_primary *prim = hogdev->hog_primary;
	struct report *report;
	GSList *l;

	if (status != 0) {
		const char *str = att_ecode2str(status);
		DBG("Discover external service characteristic failed: %s", str);
		return;
	}

	for (l = chars; l; l = g_slist_next(l)) {
		struct gatt_char *chr, *next;
		uint16_t start, end;

		chr = l->data;
		next = l->next ? l->next->data : NULL;

		DBG("0x%04x UUID: %s properties: %02x",
				chr->handle, chr->uuid, chr->properties);

		report = g_new0(struct report, 1);
		report->hogdev = hogdev;
		report->decl = g_memdup(chr, sizeof(*chr));
		hogdev->reports = g_slist_append(hogdev->reports, report);
		start = chr->value_handle + 1;
		end = (next ? next->handle - 1 : prim->range.end);
		discover_descriptor(hogdev->attrib, start, end, report);
	}
}

static void external_report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	uint16_t uuid16;
	bt_uuid_t uuid;

	if (status != 0) {
		error("Read External Report Reference descriptor failed: %s",
							att_ecode2str(status));
		return;
	}

	if (plen != 3) {
		error("Malformed ATT read response");
		return;
	}

	uuid16 = att_get_u16(&pdu[1]);
	DBG("External report reference read, external report characteristic "
						"UUID: 0x%04x", uuid16);
	bt_uuid16_create(&uuid, uuid16);
	gatt_discover_char(hogdev->attrib, 0x00, 0xff, &uuid,
					external_service_char_cb, hogdev);
}

static void report_map_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	uint8_t value[HOG_REPORT_MAP_MAX_SIZE];
	struct uhid_event ev;
	uint16_t vendor_src, vendor, product, version;
	ssize_t vlen;
	int i;

	if (status != 0) {
		error("Report Map read failed: %s", att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, plen, value, sizeof(value));
	if (vlen < 0) {
		error("ATT protocol error");
		return;
	}

	DBG("Report MAP:");
	for (i = 0; i < vlen; i++) {
		switch (value[i]) {
		case 0x85:
		case 0x86:
		case 0x87:
			hogdev->has_report_id = TRUE;
		}

		if (i % 2 == 0) {
			if (i + 1 == vlen)
				DBG("\t %02x", value[i]);
			else
				DBG("\t %02x %02x", value[i], value[i + 1]);
		}
	}

	vendor_src = btd_device_get_vendor_src(hogdev->device);
	vendor = btd_device_get_vendor(hogdev->device);
	product = btd_device_get_product(hogdev->device);
	version = btd_device_get_version(hogdev->device);
	DBG("DIS information: vendor_src=0x%X, vendor=0x%X, product=0x%X, "
			"version=0x%X",	vendor_src, vendor, product, version);

	/* create uHID device */
	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_CREATE;
	strcpy((char *) ev.u.create.name, "bluez-hog-device");
	ev.u.create.vendor = vendor;
	ev.u.create.product = product;
	ev.u.create.version = version;
	ev.u.create.country = hogdev->bcountrycode;
	ev.u.create.bus = BUS_BLUETOOTH;
	ev.u.create.rd_data = value;
	ev.u.create.rd_size = vlen;

	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("Failed to create uHID device: %s", strerror(errno));
}

static void info_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	uint8_t value[HID_INFO_SIZE];
	ssize_t vlen;

	if (status != 0) {
		error("HID Information read failed: %s",
						att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, plen, value, sizeof(value));
	if (vlen != 4) {
		error("ATT protocol error");
		return;
	}

	hogdev->bcdhid = att_get_u16(&value[0]);
	hogdev->bcountrycode = value[2];
	hogdev->flags = value[3];

	DBG("bcdHID: 0x%04X bCountryCode: 0x%02X Flags: 0x%02X",
			hogdev->bcdhid, hogdev->bcountrycode, hogdev->flags);
}

static void proto_mode_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	uint8_t value;
	ssize_t vlen;

	if (status != 0) {
		error("Protocol Mode characteristic read failed: %s",
							att_ecode2str(status));
		return;
	}

	vlen = dec_read_resp(pdu, plen, &value, sizeof(value));
	if (vlen < 0) {
		error("ATT protocol error");
		return;
	}

	if (value == HOG_PROTO_MODE_BOOT) {
		uint8_t nval = HOG_PROTO_MODE_REPORT;

		DBG("HoG device 0x%04X is operating in Boot Procotol Mode",
								hogdev->id);

		gatt_write_cmd(hogdev->attrib, hogdev->proto_mode_handle, &nval,
						sizeof(nval), NULL, NULL);
	} else if (value == HOG_PROTO_MODE_REPORT)
		DBG("HoG device 0x%04X is operating in Report Protocol Mode",
								hogdev->id);
}

static void char_discovered_cb(uint8_t status, GSList *chars, void *user_data)
{
	struct hog_device *hogdev = user_data;
	struct gatt_primary *prim = hogdev->hog_primary;
	bt_uuid_t report_uuid, report_map_uuid, info_uuid;
	bt_uuid_t proto_mode_uuid, ctrlpt_uuid;
	struct report *report;
	GSList *l;
	uint16_t info_handle = 0, proto_mode_handle = 0;

	if (status != 0) {
		const char *str = att_ecode2str(status);
		DBG("Discover all characteristics failed: %s", str);
		return;
	}

	bt_uuid16_create(&report_uuid, HOG_REPORT_UUID);
	bt_uuid16_create(&report_map_uuid, HOG_REPORT_MAP_UUID);
	bt_uuid16_create(&info_uuid, HOG_INFO_UUID);
	bt_uuid16_create(&proto_mode_uuid, HOG_PROTO_MODE_UUID);
	bt_uuid16_create(&ctrlpt_uuid, HOG_CONTROL_POINT_UUID);

	for (l = chars; l; l = g_slist_next(l)) {
		struct gatt_char *chr, *next;
		bt_uuid_t uuid;
		uint16_t start, end;

		chr = l->data;
		next = l->next ? l->next->data : NULL;

		DBG("0x%04x UUID: %s properties: %02x",
				chr->handle, chr->uuid, chr->properties);

		bt_string_to_uuid(&uuid, chr->uuid);

		start = chr->value_handle + 1;
		end = (next ? next->handle - 1 : prim->range.end);

		if (bt_uuid_cmp(&uuid, &report_uuid) == 0) {
			report = g_new0(struct report, 1);
			report->hogdev = hogdev;
			report->decl = g_memdup(chr, sizeof(*chr));
			hogdev->reports = g_slist_append(hogdev->reports,
								report);
			discover_descriptor(hogdev->attrib, start, end, report);
		} else if (bt_uuid_cmp(&uuid, &report_map_uuid) == 0) {
			gatt_read_char(hogdev->attrib, chr->value_handle,
						report_map_read_cb, hogdev);
			discover_descriptor(hogdev->attrib, start, end, hogdev);
		} else if (bt_uuid_cmp(&uuid, &info_uuid) == 0)
			info_handle = chr->value_handle;
		else if (bt_uuid_cmp(&uuid, &proto_mode_uuid) == 0)
			proto_mode_handle = chr->value_handle;
		else if (bt_uuid_cmp(&uuid, &ctrlpt_uuid) == 0)
			hogdev->ctrlpt_handle = chr->value_handle;
	}

	if (proto_mode_handle) {
		hogdev->proto_mode_handle = proto_mode_handle;
		gatt_read_char(hogdev->attrib, proto_mode_handle,
						proto_mode_read_cb, hogdev);
	}

	if (info_handle)
		gatt_read_char(hogdev->attrib, info_handle, info_read_cb,
									hogdev);
}

static void output_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	if (status != 0) {
		error("Write output report failed: %s", att_ecode2str(status));
		return;
	}
}

static int report_type_cmp(gconstpointer a, gconstpointer b)
{
	const struct report *report = a;
	uint8_t type = GPOINTER_TO_UINT(b);

	return report->type - type;
}

static void forward_report(struct hog_device *hogdev,
						struct uhid_event *ev)
{
	struct report *report;
	GSList *l;
	void *data;
	int size;
	guint type;

	if (hogdev->has_report_id) {
		data = ev->u.output.data + 1;
		size = ev->u.output.size - 1;
	} else {
		data = ev->u.output.data;
		size = ev->u.output.size;
	}

	switch (ev->type) {
	case UHID_OUTPUT:
		type = HOG_REPORT_TYPE_OUTPUT;
		break;
	case UHID_FEATURE:
		type = HOG_REPORT_TYPE_FEATURE;
		break;
	default:
		return;
	}

	l = g_slist_find_custom(hogdev->reports, GUINT_TO_POINTER(type),
							report_type_cmp);
	if (!l)
		return;

	report = l->data;

	DBG("Sending report type %d to device 0x%04X handle 0x%X", type,
				hogdev->id, report->decl->value_handle);

	if (hogdev->attrib == NULL)
		return;

	if (report->decl->properties & ATT_CHAR_PROPER_WRITE)
		gatt_write_char(hogdev->attrib, report->decl->value_handle,
				data, size, output_written_cb, hogdev);
	else if (report->decl->properties & ATT_CHAR_PROPER_WRITE_WITHOUT_RESP)
		gatt_write_cmd(hogdev->attrib, report->decl->value_handle,
						data, size, NULL, NULL);
}

static gboolean uhid_event_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event ev;
	ssize_t bread;
	int fd;

	if (cond & (G_IO_ERR | G_IO_NVAL))
		goto failed;

	fd = g_io_channel_unix_get_fd(io);
	memset(&ev, 0, sizeof(ev));

	bread = read(fd, &ev, sizeof(ev));
	if (bread < 0) {
		int err = -errno;
		DBG("uhid-dev read: %s(%d)", strerror(-err), -err);
		goto failed;
	}

	DBG("uHID event type %d received", ev.type);

	switch (ev.type) {
	case UHID_START:
	case UHID_STOP:
		/* These are called to start and stop the underlying hardware.
		 * For HoG we open the channels before creating the device so
		 * the hardware is always ready. No need to handle these.
		 * Note that these are also called when the kernel switches
		 * between device-drivers loaded on the HID device. But we can
		 * simply keep the hardware alive during transitions and it
		 * works just fine.
		 * The kernel never destroys a device itself! Only an explicit
		 * UHID_DESTROY request can remove a device. */
		break;
	case UHID_OPEN:
	case UHID_CLOSE:
		/* OPEN/CLOSE are sent whenever user-space opens any interface
		 * provided by the kernel HID device. Whenever the open-count
		 * is non-zero we must be ready for I/O. As long as it is zero,
		 * we can decide to drop all I/O and put the device
		 * asleep This is optional, though. Moreover, some
		 * special device drivers are buggy in that regard, so
		 * maybe we just keep I/O always awake like HIDP in the
		 * kernel does. */
		break;
	case UHID_OUTPUT:
	case UHID_FEATURE:
		forward_report(hogdev, &ev);
		break;
	case UHID_OUTPUT_EV:
		/* This is only sent by kernels prior to linux-3.11. It
		 * requires us to parse HID-descriptors in user-space to
		 * properly handle it. This is redundant as the kernel
		 * does it already. That's why newer kernels assemble
		 * the output-reports and send it to us via UHID_OUTPUT.
		 * We never implemented this, so we rely on users to use
		 * recent-enough kernels if they want this feature. No reason
		 * to implement this for older kernels. */
		DBG("Unsupported uHID output event: type %d code %d value %d",
			ev.u.output_ev.type, ev.u.output_ev.code,
			ev.u.output_ev.value);
		break;
	default:
		warn("unexpected uHID event");
		break;
	}

	return TRUE;

failed:
	hogdev->uhid_watch_id = 0;
	return FALSE;
}

static void attio_connected_cb(GAttrib *attrib, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct gatt_primary *prim = hogdev->hog_primary;
	GSList *l;

	DBG("HoG connected");

	hogdev->attrib = g_attrib_ref(attrib);

	if (hogdev->reports == NULL) {
		gatt_discover_char(hogdev->attrib, prim->range.start,
						prim->range.end, NULL,
						char_discovered_cb, hogdev);
		return;
	}

	for (l = hogdev->reports; l; l = l->next) {
		struct report *r = l->data;

		r->notifyid = g_attrib_register(hogdev->attrib,
					ATT_OP_HANDLE_NOTIFY,
					r->decl->value_handle,
					report_value_cb, r, NULL);
	}
}

static void attio_disconnected_cb(gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	GSList *l;

	DBG("HoG disconnected");

	for (l = hogdev->reports; l; l = l->next) {
		struct report *r = l->data;

		g_attrib_unregister(hogdev->attrib, r->notifyid);
	}

	g_attrib_unref(hogdev->attrib);
	hogdev->attrib = NULL;
}

static struct hog_device *hog_new_device(struct btd_device *device,
								uint16_t id)
{
	struct hog_device *hogdev;

	hogdev = g_try_new0(struct hog_device, 1);
	if (!hogdev)
		return NULL;

	hogdev->id = id;
	hogdev->device = btd_device_ref(device);

	return hogdev;
}

static void report_free(void *data)
{
	struct report *report = data;
	struct hog_device *hogdev = report->hogdev;

	if (hogdev->attrib)
		g_attrib_unregister(hogdev->attrib, report->notifyid);

	g_free(report->decl);
	g_free(report);
}

static void hog_free_device(struct hog_device *hogdev)
{
	btd_device_unref(hogdev->device);
	g_slist_free_full(hogdev->reports, report_free);
	g_attrib_unref(hogdev->attrib);
	g_free(hogdev->hog_primary);
	g_free(hogdev);
}

static struct hog_device *hog_register_device(struct btd_device *device,
						struct gatt_primary *prim)
{
	struct hog_device *hogdev;
	GIOCondition cond = G_IO_IN | G_IO_ERR | G_IO_NVAL;
	GIOChannel *io;

	hogdev = hog_new_device(device, prim->range.start);
	if (!hogdev)
		return NULL;

	hogdev->uhid_fd = open(UHID_DEVICE_FILE, O_RDWR | O_CLOEXEC);
	if (hogdev->uhid_fd < 0) {
		error("Failed to open uHID device: %s(%d)", strerror(errno),
									errno);
		hog_free_device(hogdev);
		return NULL;
	}

	io = g_io_channel_unix_new(hogdev->uhid_fd);
	g_io_channel_set_encoding(io, NULL, NULL);
	hogdev->uhid_watch_id = g_io_add_watch(io, cond, uhid_event_cb,
								hogdev);
	g_io_channel_unref(io);

	hogdev->hog_primary = g_memdup(prim, sizeof(*prim));

	hogdev->attioid = btd_device_add_attio_callback(device,
							attio_connected_cb,
							attio_disconnected_cb,
							hogdev);

	return hogdev;
}

static int hog_unregister_device(struct hog_device *hogdev)
{
	struct uhid_event ev;

	btd_device_remove_attio_callback(hogdev->device, hogdev->attioid);

	if (hogdev->uhid_watch_id) {
		g_source_remove(hogdev->uhid_watch_id);
		hogdev->uhid_watch_id = 0;
	}

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_DESTROY;
	if (write(hogdev->uhid_fd, &ev, sizeof(ev)) < 0)
		error("Failed to destroy uHID device: %s", strerror(errno));

	close(hogdev->uhid_fd);
	hogdev->uhid_fd = -1;

	hog_free_device(hogdev);

	return 0;
}

static int set_control_point(struct hog_device *hogdev, gboolean suspend)
{
	uint8_t value = suspend ? 0x00 : 0x01;

	if (hogdev->attrib == NULL)
		return -ENOTCONN;

	DBG("0x%4X HID Control Point: %s", hogdev->id, suspend ?
						"Suspend" : "Exit Suspend");

	if (hogdev->ctrlpt_handle == 0)
		return -ENOTSUP;

	gatt_write_cmd(hogdev->attrib, hogdev->ctrlpt_handle, &value,
					sizeof(value), NULL, NULL);

	return 0;
}

static void set_suspend(gpointer data, gpointer user_data)
{
	struct hog_device *hogdev = data;
	gboolean suspend = GPOINTER_TO_INT(user_data);

	set_control_point(hogdev, suspend);
}

static void suspend_callback(void)
{
	gboolean suspend = TRUE;

	DBG("Suspending ...");

	g_slist_foreach(devices, set_suspend, GINT_TO_POINTER(suspend));
}

static void resume_callback(void)
{
	gboolean suspend = FALSE;

	DBG("Resuming ...");

	g_slist_foreach(devices, set_suspend, GINT_TO_POINTER(suspend));
}

static int hog_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	GSList *primaries, *l;

	DBG("path %s", path);

	primaries = btd_device_get_primaries(device);
	if (primaries == NULL)
		return -EINVAL;

	for (l = primaries; l; l = g_slist_next(l)) {
		struct gatt_primary *prim = l->data;
		struct hog_device *hogdev;

		if (strcmp(prim->uuid, HOG_UUID) != 0)
			continue;

		hogdev = hog_register_device(device, prim);
		if (hogdev == NULL)
			continue;

		devices = g_slist_append(devices, hogdev);
	}

	return 0;
}

static void remove_device(gpointer a, gpointer b)
{
	struct hog_device *hogdev = a;
	struct btd_device *device = b;

	if (hogdev->device != device)
		return;

	devices = g_slist_remove(devices, hogdev);
	hog_unregister_device(hogdev);
}

static void hog_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);

	DBG("path %s", path);

	g_slist_foreach(devices, remove_device, device);
}

static struct btd_profile hog_profile = {
	.name		= "input-hog",
	.remote_uuid	= HOG_UUID,
	.device_probe	= hog_probe,
	.device_remove	= hog_remove,
};

static int hog_init(void)
{
	int err;

	err = suspend_init(suspend_callback, resume_callback);
	if (err < 0)
		error("Loading suspend plugin failed: %s (%d)", strerror(-err),
									-err);
	else
		suspend_supported = TRUE;

	return btd_profile_register(&hog_profile);
}

static void hog_exit(void)
{
	if (suspend_supported)
		suspend_exit();

	btd_profile_unregister(&hog_profile);
}

BLUETOOTH_PLUGIN_DEFINE(hog, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							hog_init, hog_exit)
