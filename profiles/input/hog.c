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

#include <bluetooth/bluetooth.h>

#include <glib.h>

#include "src/log.h"

#include "lib/uuid.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/util.h"
#include "src/shared/uhid.h"

#include "src/plugin.h"

#include "suspend.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "src/attio.h"
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

#define HOG_REPORT_MAP_MAX_SIZE        512
#define HID_INFO_SIZE			4
#define ATT_NOTIFICATION_HEADER_SIZE	3

struct hog_device {
	uint16_t		id;
	struct btd_device	*device;
	GAttrib			*attrib;
	guint			attioid;
	struct gatt_primary	*hog_primary;
	GSList			*reports;
	struct bt_uhid		*uhid;
	gboolean		has_report_id;
	uint16_t		bcdhid;
	uint8_t			bcountrycode;
	uint16_t		proto_mode_handle;
	uint16_t		ctrlpt_handle;
	uint8_t			flags;
	guint			getrep_att;
	uint16_t		getrep_id;
	guint			setrep_att;
	uint16_t		setrep_id;
};

struct report {
	uint8_t			id;
	uint8_t			type;
	guint			notifyid;
	struct gatt_char	*decl;
	struct hog_device	*hogdev;
};

static gboolean suspend_supported = FALSE;
static GSList *devices = NULL;

static void report_value_cb(const guint8 *pdu, guint16 len, gpointer user_data)
{
	struct report *report = user_data;
	struct hog_device *hogdev = report->hogdev;
	struct uhid_event ev;
	uint8_t *buf;
	int err;

	if (len < ATT_NOTIFICATION_HEADER_SIZE) {
		error("Malformed ATT notification");
		return;
	}

	pdu += ATT_NOTIFICATION_HEADER_SIZE;
	len -= ATT_NOTIFICATION_HEADER_SIZE;

	memset(&ev, 0, sizeof(ev));
	ev.type = UHID_INPUT;
	buf = ev.u.input.data;

	if (hogdev->has_report_id) {
		buf[0] = report->id;
		len = MIN(len, sizeof(ev.u.input.data) - 1);
		memcpy(buf + 1, pdu, len);
		ev.u.input.size = ++len;
	} else {
		len = MIN(len, sizeof(ev.u.input.data));
		memcpy(buf, pdu, len);
		ev.u.input.size = len;
	}

	err = bt_uhid_send(hogdev->uhid, &ev);
	if (err < 0) {
		error("bt_uhid_send: %s (%d)", strerror(-err), -err);
		return;
	}

	DBG("HoG report (%u bytes)", ev.u.input.size);
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


static void discover_descriptor_cb(uint8_t status, GSList *descs,
								void *user_data)
{
	struct report *report;
	struct hog_device *hogdev;
	GAttrib *attrib = NULL;

	if (status != 0) {
		error("Discover all descriptors failed: %s",
							att_ecode2str(status));
		return;
	}

	for ( ; descs; descs = descs->next) {
		struct gatt_desc *desc = descs->data;

		switch (desc->uuid16) {
		case GATT_CLIENT_CHARAC_CFG_UUID:
			report = user_data;
			write_ccc(desc->handle, report);
			break;
		case GATT_REPORT_REFERENCE:
			report = user_data;
			attrib = report->hogdev->attrib;
			gatt_read_char(attrib, desc->handle,
						report_reference_cb, report);
			break;
		case GATT_EXTERNAL_REPORT_REFERENCE:
			hogdev = user_data;
			attrib = hogdev->attrib;
			gatt_read_char(attrib, desc->handle,
					external_report_reference_cb, hogdev);
			break;
		}
	}
}

static void discover_descriptor(GAttrib *attrib, uint16_t start, uint16_t end,
							gpointer user_data)
{
	if (start > end)
		return;

	gatt_discover_desc(attrib, start, end, NULL,
					discover_descriptor_cb, user_data);
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

	uuid16 = get_le16(&pdu[1]);
	DBG("External report reference read, external report characteristic "
						"UUID: 0x%04x", uuid16);
	bt_uuid16_create(&uuid, uuid16);
	gatt_discover_char(hogdev->attrib, 0x00, 0xff, &uuid,
					external_service_char_cb, hogdev);
}

static int report_cmp(gconstpointer a, gconstpointer b)
{
	const struct report *ra = a, *rb = b;

	/* sort by type first.. */
	if (ra->type != rb->type)
		return ra->type - rb->type;

	/* ..then by id */
	return ra->id - rb->id;
}

static void output_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	if (status != 0) {
		error("Write output report failed: %s", att_ecode2str(status));
		return;
	}
}

static struct report *find_report(struct hog_device *hogdev, uint8_t type, uint8_t id)
{
	struct report cmp;
	GSList *l;

	switch (type) {
	case UHID_FEATURE_REPORT:
		cmp.type = HOG_REPORT_TYPE_FEATURE;
		break;
	case UHID_OUTPUT_REPORT:
		cmp.type = HOG_REPORT_TYPE_OUTPUT;
		break;
	case UHID_INPUT_REPORT:
		cmp.type = HOG_REPORT_TYPE_INPUT;
		break;
	default:
		return NULL;
	}

	cmp.id = hogdev->has_report_id ? id : 0;

	l = g_slist_find_custom(hogdev->reports, &cmp, report_cmp);

	return l ? l->data : NULL;
}

static void forward_report(struct uhid_event *ev, void *user_data)
{
	struct hog_device *hogdev = user_data;
	struct report *report;
	void *data;
	int size;

	report = find_report(hogdev, ev->u.output.rtype, ev->u.output.data[0]);
	if (!report)
		return;

	data = ev->u.output.data;
	size = ev->u.output.size;
	if (hogdev->has_report_id && size > 0) {
		data++;
		--size;
	}

	DBG("Sending report type %d ID %d to handle 0x%X", report->type,
				report->id, report->decl->value_handle);

	if (hogdev->attrib == NULL)
		return;

	if (report->decl->properties & GATT_CHR_PROP_WRITE)
		gatt_write_char(hogdev->attrib, report->decl->value_handle,
				data, size, output_written_cb, hogdev);
	else if (report->decl->properties & GATT_CHR_PROP_WRITE_WITHOUT_RESP)
		gatt_write_cmd(hogdev->attrib, report->decl->value_handle,
						data, size, NULL, NULL);
}

static void set_report_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event rsp;
	int err;

	hogdev->setrep_att = 0;

	memset(&rsp, 0, sizeof(rsp));
	rsp.type = UHID_SET_REPORT_REPLY;
	rsp.u.set_report_reply.id = hogdev->setrep_id;
	rsp.u.set_report_reply.err = status;

	if (status != 0)
		error("Error setting Report value: %s", att_ecode2str(status));

	err = bt_uhid_send(hogdev->uhid, &rsp);
	if (err < 0)
		error("bt_uhid_send: %s", strerror(-err));
}

static void set_report(struct uhid_event *ev, void *user_data)
{
	struct hog_device *hogdev = user_data;
	struct report *report;
	void *data;
	int size;
	int err;

	/* uhid never sends reqs in parallel; if there's a req, it timed out */
	if (hogdev->setrep_att) {
		g_attrib_cancel(hogdev->attrib, hogdev->setrep_att);
		hogdev->setrep_att = 0;
	}

	hogdev->setrep_id = ev->u.set_report.id;

	report = find_report(hogdev, ev->u.set_report.rtype,
							ev->u.set_report.rnum);
	if (!report) {
		err = ENOTSUP;
		goto fail;
	}

	data = ev->u.set_report.data;
	size = ev->u.set_report.size;
	if (hogdev->has_report_id && size > 0) {
		data++;
		--size;
	}

	DBG("Sending report type %d ID %d to handle 0x%X", report->type,
				report->id, report->decl->value_handle);

	if (hogdev->attrib == NULL)
		return;

	hogdev->setrep_att = gatt_write_char(hogdev->attrib,
						report->decl->value_handle,
						data, size, set_report_cb,
						hogdev);
	if (!hogdev->setrep_att) {
		err = ENOMEM;
		goto fail;
	}

	return;
fail:
	/* cancel the request on failure */
	set_report_cb(err, NULL, 0, hogdev);
}

static void get_report_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct uhid_event rsp;
	int err;

	hogdev->getrep_att = 0;

	memset(&rsp, 0, sizeof(rsp));
	rsp.type = UHID_GET_REPORT_REPLY;
	rsp.u.get_report_reply.id = hogdev->getrep_id;

	if (status != 0) {
		error("Error reading Report value: %s", att_ecode2str(status));
		goto exit;
	}

	if (len == 0) {
		error("Error reading Report, length %d", len);
		status = EIO;
		goto exit;
	}

	if (pdu[0] != 0x0b) {
		error("Error reading Report, invalid response: %02x", pdu[0]);
		status = EPROTO;
		goto exit;
	}

	--len;
	++pdu;
	if (hogdev->has_report_id && len > 0) {
		--len;
		++pdu;
	}

	rsp.u.get_report_reply.size = len;
	memcpy(rsp.u.get_report_reply.data, pdu, len);

exit:
	rsp.u.get_report_reply.err = status;
	err = bt_uhid_send(hogdev->uhid, &rsp);
	if (err < 0)
		error("bt_uhid_send: %s", strerror(-err));
}

static void get_report(struct uhid_event *ev, void *user_data)
{
	struct hog_device *hogdev = user_data;
	struct report *report;
	guint8 err;

	/* uhid never sends reqs in parallel; if there's a req, it timed out */
	if (hogdev->getrep_att) {
		g_attrib_cancel(hogdev->attrib, hogdev->getrep_att);
		hogdev->getrep_att = 0;
	}

	hogdev->getrep_id = ev->u.get_report.id;

	report = find_report(hogdev, ev->u.get_report.rtype,
							ev->u.get_report.rnum);
	if (!report) {
		err = ENOTSUP;
		goto fail;
	}

	hogdev->getrep_att = gatt_read_char(hogdev->attrib,
						report->decl->value_handle,
						get_report_cb, hogdev);
	if (!hogdev->getrep_att) {
		err = ENOMEM;
		goto fail;
	}

	return;

fail:
	/* cancel the request on failure */
	get_report_cb(err, NULL, 0, hogdev);
}

static bool get_descriptor_item_info(uint8_t *buf, ssize_t blen, ssize_t *len,
								bool *is_long)
{
	if (!blen)
		return false;

	*is_long = (buf[0] == 0xfe);

	if (*is_long) {
		if (blen < 3)
			return false;

		/*
		 * long item:
		 * byte 0 -> 0xFE
		 * byte 1 -> data size
		 * byte 2 -> tag
		 * + data
		 */

		*len = buf[1] + 3;
	} else {
		uint8_t b_size;

		/*
		 * short item:
		 * byte 0[1..0] -> data size (=0, 1, 2, 4)
		 * byte 0[3..2] -> type
		 * byte 0[7..4] -> tag
		 * + data
		 */

		b_size = buf[0] & 0x03;
		*len = (b_size ? 1 << (b_size - 1) : 0) + 1;
	}

	/* item length should be no more than input buffer length */
	return *len <= blen;
}

static char *item2string(char *str, uint8_t *buf, uint8_t len)
{
	char *p = str;
	int i;

	/*
	 * Since long item tags are not defined except for vendor ones, we
	 * just ensure that short items are printed properly (up to 5 bytes).
	 */
	for (i = 0; i < 6 && i < len; i++)
		p += sprintf(p, " %02x", buf[i]);

	/*
	 * If there are some data left, just add continuation mark to indicate
	 * this.
	 */
	if (i < len)
		sprintf(p, " ...");

	return str;
}

static void report_map_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct hog_device *hogdev = user_data;
	struct btd_adapter *adapter = device_get_adapter(hogdev->device);
	uint8_t value[HOG_REPORT_MAP_MAX_SIZE];
	struct uhid_event ev;
	uint16_t vendor_src, vendor, product, version;
	ssize_t vlen;
	char itemstr[20]; /* 5x3 (data) + 4 (continuation) + 1 (null) */
	int i, err;

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
	for (i = 0; i < vlen;) {
		ssize_t ilen = 0;
		bool long_item = false;

		if (get_descriptor_item_info(&value[i], vlen - i, &ilen,
								&long_item)) {
			/* Report ID is short item with prefix 100001xx */
			if (!long_item && (value[i] & 0xfc) == 0x84)
				hogdev->has_report_id = TRUE;

			DBG("\t%s", item2string(itemstr, &value[i], ilen));

			i += ilen;
		} else {
			error("Report Map parsing failed at %d", i);

			/* Just print remaining items at once and break */
			DBG("\t%s", item2string(itemstr, &value[i], vlen - i));
			break;
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
	if (device_name_known(hogdev->device))
		device_get_name(hogdev->device, (char *) ev.u.create.name,
						sizeof(ev.u.create.name));
	else
		strcpy((char *) ev.u.create.name, "bluez-hog-device");
	ba2str(btd_adapter_get_address(adapter), (char *) ev.u.create.phys);
	ba2str(device_get_address(hogdev->device), (char *) ev.u.create.uniq);
	ev.u.create.vendor = vendor;
	ev.u.create.product = product;
	ev.u.create.version = version;
	ev.u.create.country = hogdev->bcountrycode;
	ev.u.create.bus = BUS_BLUETOOTH;
	ev.u.create.rd_data = value;
	ev.u.create.rd_size = vlen;

	err = bt_uhid_send(hogdev->uhid, &ev);
	if (err < 0) {
		error("bt_uhid_send: %s", strerror(-err));
		return;
	}

	bt_uhid_register(hogdev->uhid, UHID_OUTPUT, forward_report, hogdev);
	bt_uhid_register(hogdev->uhid, UHID_SET_REPORT, set_report, hogdev);
	bt_uhid_register(hogdev->uhid, UHID_GET_REPORT, get_report, hogdev);
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

	hogdev->bcdhid = get_le16(&value[0]);
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

	hogdev = hog_new_device(device, prim->range.start);
	if (!hogdev)
		return NULL;

	hogdev->uhid = bt_uhid_new_default();
	if (!hogdev->uhid) {
		error("bt_uhid_new_default: failed");
		hog_free_device(hogdev);
		return NULL;
	}

	hogdev->hog_primary = g_memdup(prim, sizeof(*prim));

	hogdev->attioid = btd_device_add_attio_callback(device,
							attio_connected_cb,
							attio_disconnected_cb,
							hogdev);

	return hogdev;
}

static int hog_unregister_device(struct hog_device *hogdev)
{
	btd_device_remove_attio_callback(hogdev->device, hogdev->attioid);
	bt_uhid_unref(hogdev->uhid);
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
