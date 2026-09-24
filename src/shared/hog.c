// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation.
 *  Copyright (C) 2012  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/l2cap.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "src/shared/uhid.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/hog.h"

#define DBG(_hog, fmt, arg...) \
	hog_debug(_hog, "%s:%s() " fmt, __FILE__, __func__, ##arg)

#define HOG_UUID16		0x1812

#define HOG_INFO_UUID		0x2A4A
#define HOG_REPORT_MAP_UUID	0x2A4B
#define HOG_REPORT_UUID		0x2A4D
#define HOG_PROTO_MODE_UUID	0x2A4E
#define HOG_CP_UUID		0x2A4C
#define HOG_SCI_MODE_UUID	0x2C39
#define HOG_SCI_INFO_UUID	0x2C3A

#define HOG_REPORT_TYPE_INPUT	1
#define HOG_REPORT_TYPE_OUTPUT	2
#define HOG_REPORT_TYPE_FEATURE	3

#define HOG_PROTO_MODE_BOOT    0
#define HOG_PROTO_MODE_REPORT  1

#define HOG_INFO_FLAG_SCI_SUPPORTED	0x04
#define HOG_INFO_FLAG_SCI_LOW_POWER	0x08

#define HID_INFO_SIZE			4

struct bt_hog {
	int			ref_count;
	char			*name;
	uint16_t		vendor;
	uint16_t		product;
	uint16_t		version;
	uint8_t			type;
	struct gatt_db		*db;
	struct gatt_db_attribute *attr;
	struct bt_gatt_client	*client;
	struct queue		*reports;
	struct bt_uhid		*uhid;
	int			uhid_fd;
	uint64_t		uhid_flags;
	uint16_t		bcdhid;
	uint8_t			bcountrycode;
	uint16_t		proto_mode_handle;
	uint16_t		cp_handle;
	uint8_t			flags;
	unsigned int		getrep_att;
	uint32_t		getrep_id;
	unsigned int		setrep_att;
	uint32_t		setrep_id;
	unsigned int		report_map_id;
	struct gatt_db_attribute *report_map_attr;
	uint16_t		sci_mode_handle;
	uint8_t			sci_mode_props;
	unsigned int		sci_mode_id;
	uint8_t			sci_mode;
	uint16_t		sci_info_handle;
	bt_hog_sci_mode_func_t	sci_mode_func;
	void			*sci_mode_data;
	/* Requests to cancel when detaching */
	struct queue		*reqs;
	/* Reads pending before reading the Report Map */
	unsigned int		pending;
	struct queue		*instances;
	bt_hog_debug_func_t	debug_func;
	bt_hog_destroy_func_t	debug_destroy;
	void			*debug_data;
};

struct report {
	struct bt_hog		*hog;
	bool			numbered;
	uint8_t			id;
	uint8_t			type;
	uint16_t		handle;
	uint16_t		value_handle;
	uint8_t			properties;
	uint16_t		ccc_handle;
	unsigned int		notify_id;
	uint16_t		len;
	uint8_t			*value;
};

/* Request tracked so it is cancelled when detaching, freed once complete or
 * cancelled.
 */
struct hog_req {
	struct bt_hog		*hog;
	void			*data;
	unsigned int		id;
};

static void hog_debug(struct bt_hog *hog, const char *format, ...)
{
	va_list ap;

	if (!hog || !format || !hog->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(hog->debug_func, hog->debug_data, format, ap);
	va_end(ap);
}

static void read_report_map(struct bt_hog *hog);

static void req_free(void *data)
{
	struct hog_req *req = data;

	if (req->hog)
		queue_remove(req->hog->reqs, req);

	free(req);
}

static struct hog_req *req_new(struct bt_hog *hog, void *data)
{
	struct hog_req *req;

	req = new0(struct hog_req, 1);
	req->hog = hog;
	req->data = data;

	return req;
}

static bool req_track(struct hog_req *req, unsigned int id)
{
	if (!id) {
		free(req);
		return false;
	}

	req->id = id;
	queue_push_tail(req->hog->reqs, req);

	return true;
}

static void req_cancel(void *data)
{
	struct hog_req *req = data;
	struct bt_gatt_client *client = req->hog->client;

	/* Already removed from the queue, req is freed by req_free */
	req->hog = NULL;
	bt_gatt_client_cancel(client, req->id);
}

static unsigned int read_char(struct bt_hog *hog, uint16_t handle,
				bt_gatt_client_read_callback_t func,
				void *data)
{
	struct hog_req *req = req_new(hog, data);

	if (!req_track(req, bt_gatt_client_read_value(hog->client, handle,
						func, req, req_free))) {
		DBG(hog, "Could not read handle 0x%04x", handle);
		return 0;
	}

	hog->pending++;

	return req->id;
}

static void req_done(struct hog_req *req, bool success)
{
	struct bt_hog *hog = req->hog;

	if (hog->pending)
		hog->pending--;

	/* Report Map must be read last since that can result in uhid being
	 * created and the driver may start to use UHID_SET_REPORT which
	 * requires the report->id to be known what attribute to send to.
	 *
	 * Read it even if a request failed, e.g. reading an optional
	 * attribute, otherwise the uHID device would never be created.
	 */
	if (!hog->pending)
		read_report_map(hog);
}

static const char *type_to_string(uint8_t type)
{
	switch (type) {
	case HOG_REPORT_TYPE_INPUT:
		return "input";
	case HOG_REPORT_TYPE_OUTPUT:
		return "output";
	case HOG_REPORT_TYPE_FEATURE:
		return "feature";
	}

	return NULL;
}

static void report_value_cb(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct report *report = user_data;
	struct bt_hog *hog = report->hog;
	bool numbered = report->numbered;
	int err;

	/* Drop the reports until the uHID device is created, as they would be
	 * queued with no limit until then, e.g. if the HID device never lets
	 * the Report Map be read.
	 */
	if (!bt_uhid_created(hog->uhid))
		return;

	/* Until UHID_START tells which reports are numbered, rely on the
	 * Report ID since it is 0 when the Report Map does not use them.
	 */
	if (!bt_uhid_started(hog->uhid))
		numbered = report->id;

	err = bt_uhid_input(hog->uhid, numbered ? report->id : 0, value,
								length);
	if (err < 0)
		DBG(hog, "bt_uhid_input: %s (%d)", strerror(-err), -err);
}

static void report_notify_registered(uint16_t att_ecode, void *user_data)
{
	struct report *report = user_data;
	struct bt_hog *hog = report->hog;

	if (att_ecode) {
		DBG(hog, "Unable to enable notifications: handle 0x%04x "
					"error 0x%02x", report->value_handle,
					att_ecode);
		return;
	}

	DBG(hog, "Report 0x%04x: notifications enabled",
						report->value_handle);
}

static void report_enable_notify(struct report *report)
{
	struct bt_hog *hog = report->hog;

	if (report->notify_id || !hog->client ||
			report->type != HOG_REPORT_TYPE_INPUT ||
			!(report->properties & BT_GATT_CHRC_PROP_NOTIFY))
		return;

	report->notify_id = bt_gatt_client_register_notify(hog->client,
					report->value_handle,
					report_notify_registered,
					report_value_cb, report, NULL);
	if (!report->notify_id)
		DBG(hog, "Unable to register report notification: "
				"handle 0x%04x", report->value_handle);
}

static void ccc_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct report *report = req->data;

	if (!success)
		DBG(req->hog, "Error reading CCC value: 0x%02x", att_ecode);
	else if (length == 2)
		DBG(req->hog, "Report 0x%04x: CCC 0x%04x",
				report->value_handle, get_le16(value));

	/* Enable notifications regardless, as the HID Device may not
	 * persist them.
	 */
	report_enable_notify(report);

	req_done(req, success);
}

static void report_reference_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct report *report = req->data;
	struct bt_hog *hog = req->hog;

	if (!success) {
		DBG(hog, "Read Report Reference descriptor failed: 0x%02x",
								att_ecode);
		goto done;
	}

	if (length != 2) {
		DBG(hog, "Malformed Report Reference: length %u", length);
		goto done;
	}

	report->id = value[0];
	report->type = value[1];

	DBG(hog, "Report 0x%04x: id 0x%02x type %s", report->value_handle,
				report->id, type_to_string(report->type));

	/* Enable notifications only for Input Reports, reading the CCC
	 * first to know its current value.
	 */
	if (report->type == HOG_REPORT_TYPE_INPUT && report->ccc_handle)
		read_char(hog, report->ccc_handle, ccc_read_cb, report);
	else
		report_enable_notify(report);

done:
	req_done(req, success);
}

static void report_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct report *report = req->data;

	if (!success) {
		DBG(req->hog, "Error reading Report value: 0x%02x", att_ecode);
		goto done;
	}

	free(report->value);
	report->value = util_memdup(value, length);
	report->len = length;

done:
	req_done(req, success);
}

static void foreach_hog_report(struct gatt_db_attribute *attr, void *user_data)
{
	struct report *report = user_data;
	struct bt_hog *hog = report->hog;
	const bt_uuid_t *uuid;
	bt_uuid_t ref_uuid, ccc_uuid;
	uint16_t handle;

	handle = gatt_db_attribute_get_handle(attr);
	uuid = gatt_db_attribute_get_type(attr);

	bt_uuid16_create(&ref_uuid, GATT_REPORT_REFERENCE);
	if (!bt_uuid_cmp(&ref_uuid, uuid)) {
		read_char(hog, handle, report_reference_cb, report);
		return;
	}

	bt_uuid16_create(&ccc_uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	if (!bt_uuid_cmp(&ccc_uuid, uuid))
		report->ccc_handle = handle;
}

static bool match_report_handle(const void *data, const void *match_data)
{
	const struct report *report = data;
	uint16_t handle = PTR_TO_UINT(match_data);

	return report->handle == handle;
}

static struct report *report_add(struct bt_hog *hog,
					struct gatt_db_attribute *attr)
{
	struct report *report;
	uint16_t handle = gatt_db_attribute_get_handle(attr);

	/* Skip if report already exists, e.g. when reconnecting, only
	 * enabling its notifications again.
	 */
	report = queue_find(hog->reports, match_report_handle,
						UINT_TO_PTR(handle));
	if (report) {
		report_enable_notify(report);
		return report;
	}

	report = new0(struct report, 1);
	report->hog = hog;

	gatt_db_attribute_get_char_data(attr, &report->handle,
					&report->value_handle,
					&report->properties,
					NULL, NULL);

	queue_push_tail(hog->reports, report);

	read_char(hog, report->value_handle, report_read_cb, report);

	gatt_db_service_foreach_desc(attr, foreach_hog_report, report);

	return report;
}

static void foreach_external_report(struct gatt_db_attribute *attr,
							void *user_data)
{
	struct bt_hog *hog = user_data;
	bt_uuid_t uuid, report_uuid;

	gatt_db_attribute_get_char_data(attr, NULL, NULL, NULL, NULL, &uuid);

	bt_uuid16_create(&report_uuid, HOG_REPORT_UUID);
	if (!bt_uuid_cmp(&report_uuid, &uuid))
		report_add(hog, attr);
}

static void foreach_external_service(struct gatt_db_attribute *attr,
							void *user_data)
{
	bt_uuid_t uuid, hog_uuid;

	gatt_db_attribute_get_service_uuid(attr, &uuid);

	/* Reports of HID services belong to their own instance */
	bt_uuid16_create(&hog_uuid, HOG_UUID16);
	if (!bt_uuid_cmp(&hog_uuid, &uuid))
		return;

	gatt_db_service_foreach_char(attr, foreach_external_report, user_data);
}

static void external_report_reference_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct bt_hog *hog = req->hog;
	uint16_t uuid16;

	if (!success) {
		DBG(hog, "Read External Report Reference descriptor failed: "
							"0x%02x", att_ecode);
		goto done;
	}

	if (length != 2) {
		DBG(hog, "Malformed External Report Reference: length %u",
								length);
		goto done;
	}

	uuid16 = get_le16(value);
	DBG(hog, "External report reference read, external report "
				"characteristic UUID: 0x%04x", uuid16);

	/* Do not add if is not a Report */
	if (uuid16 != HOG_REPORT_UUID)
		goto done;

	gatt_db_foreach_service(hog->db, NULL, foreach_external_service, hog);

done:
	req_done(req, success);
}

static void foreach_hog_external(struct gatt_db_attribute *attr,
							void *user_data)
{
	struct bt_hog *hog = user_data;
	const bt_uuid_t *uuid;
	bt_uuid_t ext_uuid;

	uuid = gatt_db_attribute_get_type(attr);

	bt_uuid16_create(&ext_uuid, GATT_EXTERNAL_REPORT_REFERENCE);
	if (!bt_uuid_cmp(&ext_uuid, uuid))
		read_char(hog, gatt_db_attribute_get_handle(attr),
					external_report_reference_cb, hog);
}

static int report_cmp(const struct report *ra, const struct report *rb)
{
	/* sort by type first.. */
	if (ra->type != rb->type)
		return ra->type - rb->type;

	/* skip id check in case of reports not being numbered  */
	if (!ra->numbered && !rb->numbered)
		return 0;

	/* ..then by id */
	return ra->id - rb->id;
}

static bool match_report(const void *data, const void *match_data)
{
	return !report_cmp(data, match_data);
}

static struct report *find_report(struct bt_hog *hog, uint8_t type, uint8_t id)
{
	struct report cmp;

	memset(&cmp, 0, sizeof(cmp));
	cmp.type = type;
	cmp.id = id;

	switch (type) {
	case HOG_REPORT_TYPE_FEATURE:
		if (hog->uhid_flags & UHID_DEV_NUMBERED_FEATURE_REPORTS)
			cmp.numbered = true;
		break;
	case HOG_REPORT_TYPE_OUTPUT:
		if (hog->uhid_flags & UHID_DEV_NUMBERED_OUTPUT_REPORTS)
			cmp.numbered = true;
		break;
	case HOG_REPORT_TYPE_INPUT:
		if (hog->uhid_flags & UHID_DEV_NUMBERED_INPUT_REPORTS)
			cmp.numbered = true;
		break;
	}

	return queue_find(hog->reports, match_report, &cmp);
}

static struct report *find_report_by_rtype(struct bt_hog *hog, uint8_t rtype,
								uint8_t id)
{
	uint8_t type;

	switch (rtype) {
	case UHID_FEATURE_REPORT:
		type = HOG_REPORT_TYPE_FEATURE;
		break;
	case UHID_OUTPUT_REPORT:
		type = HOG_REPORT_TYPE_OUTPUT;
		break;
	case UHID_INPUT_REPORT:
		type = HOG_REPORT_TYPE_INPUT;
		break;
	default:
		return NULL;
	}

	return find_report(hog, type, id);
}

static void output_written_cb(bool success, uint8_t att_ecode,
							void *user_data)
{
	struct hog_req *req = user_data;

	if (!success)
		DBG(req->hog, "Write output report failed: 0x%02x", att_ecode);
}

static void write_output(struct bt_hog *hog, struct report *report,
					const uint8_t *data, size_t size)
{
	struct hog_req *req = req_new(hog, report);

	if (!req_track(req, bt_gatt_client_write_value(hog->client,
					report->value_handle, data, size,
					output_written_cb, req, req_free)))
		DBG(hog, "Could not write report 0x%04x",
						report->value_handle);
}

static void write_report(struct bt_hog *hog, struct report *report,
					const uint8_t *data, size_t size)
{
	if (report->properties & BT_GATT_CHRC_PROP_WRITE)
		write_output(hog, report, data, size);
	else if (report->properties & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP)
		bt_gatt_client_write_without_response(hog->client,
						report->value_handle, false,
						data, size);
}

static void forward_report(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct report *report;
	uint8_t *data;
	int size;

	report = find_report_by_rtype(hog, ev->u.output.rtype,
							ev->u.output.data[0]);
	if (!report)
		return;

	data = ev->u.output.data;
	size = ev->u.output.size;

	if (report->numbered && size > 0) {
		data++;
		--size;
	}

	DBG(hog, "Sending report type %d ID %d to handle 0x%X", report->type,
				report->id, report->value_handle);

	if (!hog->client)
		return;

	write_report(hog, report, data, size);
}

static void set_numbered(void *data, void *user_data)
{
	struct report *report = data;
	struct bt_hog *hog = user_data;

	switch (report->type) {
	case HOG_REPORT_TYPE_INPUT:
		if (hog->uhid_flags & UHID_DEV_NUMBERED_INPUT_REPORTS)
			report->numbered = true;
		break;
	case HOG_REPORT_TYPE_OUTPUT:
		if (hog->uhid_flags & UHID_DEV_NUMBERED_OUTPUT_REPORTS)
			report->numbered = true;
		break;
	case HOG_REPORT_TYPE_FEATURE:
		if (hog->uhid_flags & UHID_DEV_NUMBERED_FEATURE_REPORTS)
			report->numbered = true;
		break;
	}
}

static void start_flags(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;

	hog->uhid_flags = ev->u.start.dev_flags;

	DBG(hog, "uHID device flags: 0x%16" PRIx64, hog->uhid_flags);

	if (hog->uhid_flags)
		queue_foreach(hog->reports, set_numbered, hog);
}

static void uhid_destroy(struct bt_hog *hog, bool force)
{
	int err;

	if (!hog->uhid)
		return;

	bt_uhid_unregister_all(hog->uhid);

	err = bt_uhid_destroy(hog->uhid, force);
	if (err < 0)
		DBG(hog, "bt_uhid_destroy: %s", strerror(-err));
}

static void set_report_reply(struct bt_hog *hog, uint8_t status)
{
	int err;

	hog->setrep_att = 0;

	err = bt_uhid_set_report_reply(hog->uhid, hog->setrep_id, status);
	if (err < 0)
		DBG(hog, "bt_uhid_set_report_reply: %s", strerror(-err));
}

static void set_report_cb(bool success, uint8_t att_ecode, void *user_data)
{
	struct bt_hog *hog = user_data;

	if (!success)
		DBG(hog, "Error setting Report value: 0x%02x", att_ecode);

	set_report_reply(hog, success ? 0 : att_ecode);
}

static void set_report(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct report *report;
	uint8_t *data;
	int size;

	/* Destroy input device if there is an attempt to communicate with it
	 * while disconnected.
	 */
	if (!hog->client) {
		uhid_destroy(hog, true);
		return;
	}

	/* uhid never sends reqs in parallel; if there's a req, it timed out */
	if (hog->setrep_att) {
		bt_gatt_client_cancel(hog->client, hog->setrep_att);
		hog->setrep_att = 0;
	}

	hog->setrep_id = ev->u.set_report.id;

	report = find_report_by_rtype(hog, ev->u.set_report.rtype,
							ev->u.set_report.rnum);
	if (!report) {
		set_report_reply(hog, ENOTSUP);
		return;
	}

	data = ev->u.set_report.data;
	size = ev->u.set_report.size;

	if (report->numbered && size > 0) {
		data++;
		--size;
	}

	DBG(hog, "Sending report type %d ID %d to handle 0x%X", report->type,
				report->id, report->value_handle);

	hog->setrep_att = bt_gatt_client_write_value(hog->client,
						report->value_handle,
						data, size, set_report_cb,
						hog, NULL);
	if (!hog->setrep_att)
		set_report_reply(hog, ENOMEM);
}

static void report_reply(struct bt_hog *hog, uint8_t status, uint8_t id,
			uint16_t len, const uint8_t *data)
{
	int err;

	hog->getrep_att = 0;

	err = bt_uhid_get_report_reply(hog->uhid, hog->getrep_id, id, status,
					data, len);
	if (err < 0)
		DBG(hog, "bt_uhid_get_report_reply: %s", strerror(-err));
}

static void get_report_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct report *report = user_data;
	struct bt_hog *hog = report->hog;
	uint8_t status = 0;

	if (!success) {
		DBG(hog, "Error reading Report value: 0x%02x", att_ecode);
		status = att_ecode;
	} else if (!length) {
		DBG(hog, "Error reading Report, length %d", length);
		status = EIO;
	}

	report_reply(hog, status, report->numbered ? report->id : 0,
					status ? 0 : length, value);
}

static void get_report(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct report *report;

	/* Destroy input device if there is an attempt to communicate with it
	 * while disconnected.
	 */
	if (!hog->client) {
		uhid_destroy(hog, true);
		return;
	}

	/* uhid never sends reqs in parallel; if there's a req, it timed out */
	if (hog->getrep_att) {
		bt_gatt_client_cancel(hog->client, hog->getrep_att);
		hog->getrep_att = 0;
	}

	hog->getrep_id = ev->u.get_report.id;

	report = find_report_by_rtype(hog, ev->u.get_report.rtype,
							ev->u.get_report.rnum);
	if (!report) {
		report_reply(hog, ENOTSUP, 0, 0, NULL);
		return;
	}

	hog->getrep_att = bt_gatt_client_read_value(hog->client,
						report->value_handle,
						get_report_cb, report, NULL);
	if (!hog->getrep_att)
		report_reply(hog, ENOMEM, 0, 0, NULL);
}

static void get_addrs(struct bt_hog *hog, bdaddr_t *src, bdaddr_t *dst)
{
	struct sockaddr_l2 addr;
	socklen_t len;
	int fd;

	bacpy(src, BDADDR_ANY);
	bacpy(dst, BDADDR_ANY);

	fd = bt_att_get_fd(bt_gatt_client_get_att(hog->client));
	if (fd < 0)
		return;

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	if (!getsockname(fd, (struct sockaddr *) &addr, &len) &&
					addr.l2_family == AF_BLUETOOTH)
		bacpy(src, &addr.l2_bdaddr);

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	if (!getpeername(fd, (struct sockaddr *) &addr, &len) &&
					addr.l2_family == AF_BLUETOOTH)
		bacpy(dst, &addr.l2_bdaddr);
}

static void uhid_register(struct bt_hog *hog)
{
	/* The handlers are unregistered when detaching, even if the uHID
	 * device is kept, e.g. keyboards.
	 */
	bt_uhid_unregister_all(hog->uhid);

	bt_uhid_register(hog->uhid, UHID_START, start_flags, hog);
	bt_uhid_register(hog->uhid, UHID_OUTPUT, forward_report, hog);
	bt_uhid_register(hog->uhid, UHID_GET_REPORT, get_report, hog);
	bt_uhid_register(hog->uhid, UHID_SET_REPORT, set_report, hog);
}

static bool uhid_create(struct bt_hog *hog, const uint8_t *report_map,
							size_t report_map_len)
{
	bdaddr_t src, dst;
	int err;

	get_addrs(hog, &src, &dst);

	err = bt_uhid_create(hog->uhid, hog->name, &src, &dst,
				hog->vendor, hog->product, hog->version,
				hog->bcountrycode, hog->type,
				(void *) report_map, report_map_len);
	if (err < 0) {
		DBG(hog, "bt_uhid_create: %s", strerror(-err));
		return false;
	}

	uhid_register(hog);

	DBG(hog, "HoG created uHID device");

	return true;
}

static void db_report_map_write_value_cb(struct gatt_db_attribute *attr,
						int err, void *user_data)
{
	struct bt_hog *hog = user_data;

	if (err)
		DBG(hog, "Error writing report map value to gatt db");
}

static void report_map_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct bt_hog *hog = user_data;

	hog->report_map_id = 0;

	if (!success) {
		DBG(hog, "Report Map read failed: 0x%02x", att_ecode);
		return;
	}

	if (!uhid_create(hog, value, length))
		return;

	/* Cache the report map, once known to be usable */
	gatt_db_attribute_write(hog->report_map_attr, 0, value, length, 0,
					NULL, db_report_map_write_value_cb,
					hog);
}

static void read_report_map(struct bt_hog *hog)
{
	uint16_t handle;

	if (!hog->client || !hog->report_map_attr ||
			bt_uhid_created(hog->uhid) || hog->report_map_id)
		return;

	handle = gatt_db_attribute_get_handle(hog->report_map_attr);

	/* The Report Map is usually longer than the MTU, which is handled
	 * by reading it with Read Blob.
	 */
	hog->report_map_id = bt_gatt_client_read_long_value(hog->client,
						handle, 0, report_map_read_cb,
						hog, NULL);
	if (!hog->report_map_id)
		DBG(hog, "Could not read Report Map");
}

static void sci_mode_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct bt_hog *hog = req->hog;

	if (!success) {
		DBG(hog, "HID SCI Mode read failed: 0x%02x", att_ecode);
		goto done;
	}

	if (length != 1) {
		DBG(hog, "Malformed HID SCI Mode: length %u", length);
		goto done;
	}

	hog->sci_mode = value[0];

	DBG(hog, "SCI Mode: 0x%02X", value[0]);

done:
	req_done(req, success);
}

static void sci_info_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct bt_hog *hog = req->hog;
	uint8_t min_conn_interval;
	uint8_t num_grps;
	uint8_t i;

	if (!success) {
		DBG(hog, "HID SCI Information read failed: 0x%02x", att_ecode);
		goto done;
	}

	if (length < 2) {
		DBG(hog, "Malformed HID SCI Information: length %u", length);
		goto done;
	}

	min_conn_interval = value[0];
	num_grps = value[1];

	DBG(hog, "SCI Info: Minimum Supported Connection Interval: %.3f ms "
		"(0x%02x) Number of Supported Subgroups: %d",
		min_conn_interval * 0.125, min_conn_interval, num_grps);

	for (i = 0; i < num_grps && (2 + i * 6 + 5) < length; i++) {
		uint16_t min, max, stride;
		size_t off = 2 + i * 6;

		min = get_le16(&value[off]);
		max = get_le16(&value[off + 2]);
		stride = get_le16(&value[off + 4]);

		DBG(hog, "  Subgroup[%u]: Min %.3f ms Max %.3f ms "
				"Stride %.3f ms", i, min * 0.125, max * 0.125,
				stride * 0.125);
	}

done:
	req_done(req, success);
}

static void sci_mode_notify_cb(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct bt_hog *hog = user_data;

	if (length != 1) {
		DBG(hog, "Malformed HID SCI Mode notification: length %u",
								length);
		return;
	}

	hog->sci_mode = value[0];

	DBG(hog, "SCI Mode changed: 0x%02X", hog->sci_mode);

	if (hog->sci_mode_func)
		hog->sci_mode_func(hog->sci_mode, hog->sci_mode_data);
}

static void sci_mode_registered(uint16_t att_ecode, void *user_data)
{
	struct bt_hog *hog = user_data;

	if (att_ecode)
		DBG(hog, "Unable to enable SCI Mode notifications: 0x%02x",
								att_ecode);
}

static void sci_mode_enable_notify(struct bt_hog *hog)
{
	if (hog->sci_mode_id || !hog->client || !hog->sci_mode_handle ||
			!(hog->flags & HOG_INFO_FLAG_SCI_SUPPORTED) ||
			!(hog->sci_mode_props & BT_GATT_CHRC_PROP_NOTIFY))
		return;

	hog->sci_mode_id = bt_gatt_client_register_notify(hog->client,
					hog->sci_mode_handle,
					sci_mode_registered,
					sci_mode_notify_cb, hog, NULL);
	if (!hog->sci_mode_id)
		DBG(hog, "Unable to register SCI Mode notification");
}

static void info_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct bt_hog *hog = req->hog;

	if (!success) {
		DBG(hog, "HID Information read failed: 0x%02x", att_ecode);
		goto done;
	}

	if (length != HID_INFO_SIZE) {
		DBG(hog, "Malformed HID Information: length %u", length);
		goto done;
	}

	hog->bcdhid = get_le16(&value[0]);
	hog->bcountrycode = value[2];
	hog->flags = value[3];

	DBG(hog, "bcdHID: 0x%04X bCountryCode: 0x%02X Flags: 0x%02X",
			hog->bcdhid, hog->bcountrycode, hog->flags);

	/* Read SCI attributes if SCI is supported */
	if (hog->flags & HOG_INFO_FLAG_SCI_SUPPORTED) {
		if (hog->sci_mode_handle)
			read_char(hog, hog->sci_mode_handle, sci_mode_read_cb,
									hog);
		if (hog->sci_info_handle)
			read_char(hog, hog->sci_info_handle, sci_info_read_cb,
									hog);

		/* The HID Device notifies the mode once changed */
		sci_mode_enable_notify(hog);
	}

done:
	req_done(req, success);
}

static void proto_mode_read_cb(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct hog_req *req = user_data;
	struct bt_hog *hog = req->hog;

	if (!success) {
		DBG(hog, "Protocol Mode characteristic read failed: 0x%02x",
								att_ecode);
		goto done;
	}

	if (length < 1) {
		DBG(hog, "Malformed Protocol Mode: length %u", length);
		goto done;
	}

	if (value[0] == HOG_PROTO_MODE_BOOT) {
		uint8_t nval = HOG_PROTO_MODE_REPORT;

		DBG(hog, "HoG is operating in Boot Protocol Mode");

		bt_gatt_client_write_without_response(hog->client,
						hog->proto_mode_handle, false,
						&nval, sizeof(nval));
	} else if (value[0] == HOG_PROTO_MODE_REPORT)
		DBG(hog, "HoG is operating in Report Protocol Mode");

done:
	req_done(req, success);
}

static void db_report_map_read_value_cb(struct gatt_db_attribute *attrib,
						int err, const uint8_t *value,
						size_t length, void *user_data)
{
	struct iovec *map = user_data;

	if (err || !length)
		return;

	map->iov_len = length;
	map->iov_base = (void *) value;
}

static void foreach_hog_chrc(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_hog *hog = user_data;
	bt_uuid_t uuid, report_uuid, report_map_uuid, info_uuid;
	bt_uuid_t proto_mode_uuid, cp_uuid, sci_mode_uuid, sci_info_uuid;
	uint16_t handle, value_handle;
	uint8_t props;
	struct iovec map = {};

	gatt_db_attribute_get_char_data(attr, &handle, &value_handle, &props,
					NULL, &uuid);

	bt_uuid16_create(&report_uuid, HOG_REPORT_UUID);
	if (!bt_uuid_cmp(&report_uuid, &uuid)) {
		report_add(hog, attr);
		return;
	}

	bt_uuid16_create(&report_map_uuid, HOG_REPORT_MAP_UUID);
	if (!bt_uuid_cmp(&report_map_uuid, &uuid)) {
		/* Try to read the cache of report map if available */
		hog->report_map_attr = gatt_db_get_attribute(hog->db,
								value_handle);
		gatt_db_attribute_read(hog->report_map_attr, 0,
					BT_ATT_OP_READ_REQ, NULL,
					db_report_map_read_value_cb, &map);

		if (map.iov_len) {
			/* Report map found in the cache, straight to creating
			 * UHID to optimize reconnection.
			 */
			uhid_create(hog, map.iov_base, map.iov_len);
		}

		gatt_db_service_foreach_desc(attr, foreach_hog_external, hog);
		return;
	}

	bt_uuid16_create(&info_uuid, HOG_INFO_UUID);
	if (!bt_uuid_cmp(&info_uuid, &uuid)) {
		read_char(hog, value_handle, info_read_cb, hog);
		return;
	}

	bt_uuid16_create(&proto_mode_uuid, HOG_PROTO_MODE_UUID);
	if (!bt_uuid_cmp(&proto_mode_uuid, &uuid)) {
		hog->proto_mode_handle = value_handle;
		read_char(hog, value_handle, proto_mode_read_cb, hog);
		return;
	}

	bt_uuid16_create(&cp_uuid, HOG_CP_UUID);
	if (!bt_uuid_cmp(&cp_uuid, &uuid)) {
		hog->cp_handle = value_handle;
		return;
	}

	bt_uuid16_create(&sci_mode_uuid, HOG_SCI_MODE_UUID);
	if (!bt_uuid_cmp(&sci_mode_uuid, &uuid)) {
		hog->sci_mode_handle = value_handle;
		hog->sci_mode_props = props;
		return;
	}

	bt_uuid16_create(&sci_info_uuid, HOG_SCI_INFO_UUID);
	if (!bt_uuid_cmp(&sci_info_uuid, &uuid))
		hog->sci_info_handle = value_handle;
}

static void report_free(void *data)
{
	struct report *report = data;

	free(report->value);
	free(report);
}

static void hog_free(struct bt_hog *hog)
{
	bt_hog_detach(hog, true);
	uhid_destroy(hog, true);

	queue_destroy(hog->instances, (void *) bt_hog_unref);
	bt_uhid_unref(hog->uhid);
	queue_destroy(hog->reports, report_free);
	queue_destroy(hog->reqs, NULL);
	free(hog->name);
	gatt_db_unref(hog->db);

	if (hog->debug_destroy)
		hog->debug_destroy(hog->debug_data);

	free(hog);
}

static struct bt_hog *hog_new(int fd, const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type,
					struct gatt_db_attribute *attr)
{
	struct bt_uhid *uhid;
	struct bt_hog *hog;

	if (fd < 0)
		uhid = bt_uhid_new_default();
	else
		uhid = bt_uhid_new(fd);

	if (!uhid)
		return NULL;

	hog = new0(struct bt_hog, 1);
	hog->reports = queue_new();
	hog->instances = queue_new();
	hog->reqs = queue_new();
	hog->uhid_fd = fd;
	hog->uhid = uhid;
	hog->name = strdup(name ? name : "");
	hog->vendor = vendor;
	hog->product = product;
	hog->version = version;
	hog->type = type;
	hog->attr = attr;

	return hog;
}

static void foreach_hog_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct bt_hog *instance;

	if (!hog->attr) {
		hog->attr = attr;
		return;
	}

	instance = hog_new(hog->uhid_fd, hog->name, hog->vendor, hog->product,
				hog->version, hog->type, attr);
	if (!instance)
		return;

	instance->db = gatt_db_ref(hog->db);

	/* The debug callback is owned by the parent */
	instance->debug_func = hog->debug_func;
	instance->debug_data = hog->debug_data;
	instance->sci_mode_func = hog->sci_mode_func;
	instance->sci_mode_data = hog->sci_mode_data;

	queue_push_tail(hog->instances, bt_hog_ref(instance));
}

static bool hog_set_db(struct bt_hog *hog, struct gatt_db *db)
{
	bt_uuid_t uuid;

	hog->db = gatt_db_ref(db);

	/* Handle the HID services */
	bt_uuid16_create(&uuid, HOG_UUID16);
	gatt_db_foreach_service(db, &uuid, foreach_hog_service, hog);

	if (!hog->attr) {
		/* Look up the services again on the next attempt */
		gatt_db_unref(hog->db);
		hog->db = NULL;
		return false;
	}

	return true;
}

struct bt_hog *bt_hog_new(int fd, const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type, struct gatt_db *db)
{
	struct bt_hog *hog;

	hog = hog_new(fd, name, vendor, product, version, type, NULL);
	if (!hog)
		return NULL;

	/* Without a db the services are looked up once attached */
	if (db && !hog_set_db(hog, db)) {
		hog_free(hog);
		return NULL;
	}

	return bt_hog_ref(hog);
}

struct bt_hog *bt_hog_new_default(const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type, struct gatt_db *db)
{
	return bt_hog_new(-1, name, vendor, product, version, type, db);
}

struct bt_hog *bt_hog_ref(struct bt_hog *hog)
{
	if (!hog)
		return NULL;

	__sync_fetch_and_add(&hog->ref_count, 1);

	return hog;
}

void bt_hog_unref(struct bt_hog *hog)
{
	if (!hog)
		return;

	if (__sync_sub_and_fetch(&hog->ref_count, 1))
		return;

	hog_free(hog);
}

static void instance_set_debug(void *data, void *user_data)
{
	struct bt_hog *instance = data;
	struct bt_hog *hog = user_data;

	instance->debug_func = hog->debug_func;
	instance->debug_data = hog->debug_data;
}

bool bt_hog_set_debug(struct bt_hog *hog, bt_hog_debug_func_t func,
			void *user_data, bt_hog_destroy_func_t destroy)
{
	if (!hog)
		return false;

	if (hog->debug_destroy)
		hog->debug_destroy(hog->debug_data);

	hog->debug_func = func;
	hog->debug_destroy = destroy;
	hog->debug_data = user_data;

	queue_foreach(hog->instances, instance_set_debug, hog);

	return true;
}

void bt_hog_set_ids(struct bt_hog *hog, uint16_t vendor, uint16_t product,
							uint16_t version)
{
	const struct queue_entry *entry;

	if (!hog)
		return;

	hog->vendor = vendor;
	hog->product = product;
	hog->version = version;

	for (entry = queue_get_entries(hog->instances); entry;
							entry = entry->next)
		bt_hog_set_ids(entry->data, vendor, product, version);
}

static void report_reattach(void *data, void *user_data)
{
	report_enable_notify(data);
}

bool bt_hog_attach(struct bt_hog *hog, struct bt_gatt_client *client)
{
	const struct queue_entry *entry;

	if (!hog || !client || hog->client)
		return false;

	if (!hog->db && !hog_set_db(hog, bt_gatt_client_get_db(client))) {
		DBG(hog, "No HID service found");
		return false;
	}

	hog->client = bt_gatt_client_ref(client);

	for (entry = queue_get_entries(hog->instances); entry;
							entry = entry->next)
		bt_hog_attach(entry->data, client);

	/* The uHID device may have been kept while detached, e.g. keyboards,
	 * in which case its handlers have to be registered again.
	 */
	if (bt_uhid_created(hog->uhid)) {
		uhid_register(hog);
	} else {
		DBG(hog, "HoG discovering characteristics");
		gatt_db_service_foreach_char(hog->attr, foreach_hog_chrc, hog);

		/* Nothing to wait for before reading the Report Map */
		if (!hog->pending)
			read_report_map(hog);

		/* Unless created with the Report Map in the cache, wait for it
		 * to be read.
		 */
		if (!bt_uhid_created(hog->uhid))
			return true;
	}

	/* If UHID is already created, set up the report value handlers to
	 * optimize reconnection, as reports already known from a previous
	 * connection are not read again when discovering them.
	 */
	queue_foreach(hog->reports, report_reattach, NULL);
	sci_mode_enable_notify(hog);

	/* Replay any pending input reports sent while disconnected, e.g.
	 * when the device was reconnected by pressing a key.
	 */
	bt_uhid_replay(hog->uhid);

	return true;
}

static void report_detach(void *data, void *user_data)
{
	struct report *report = data;
	struct bt_hog *hog = user_data;

	if (!report->notify_id)
		return;

	bt_gatt_client_unregister_notify(hog->client, report->notify_id);
	report->notify_id = 0;
}

void bt_hog_detach(struct bt_hog *hog, bool force)
{
	const struct queue_entry *entry;
	struct bt_gatt_client *client;

	if (!hog)
		return;

	if (!hog->client)
		goto done;

	for (entry = queue_get_entries(hog->instances); entry;
							entry = entry->next)
		bt_hog_detach(entry->data, force);

	queue_foreach(hog->reports, report_detach, hog);

	if (hog->sci_mode_id) {
		bt_gatt_client_unregister_notify(hog->client,
							hog->sci_mode_id);
		hog->sci_mode_id = 0;
	}

	/* Cancel the pending requests, as the client may still be in use,
	 * e.g. the notifications are disabled when still connected.
	 */
	queue_remove_all(hog->reqs, NULL, NULL, req_cancel);

	if (hog->getrep_att) {
		bt_gatt_client_cancel(hog->client, hog->getrep_att);
		hog->getrep_att = 0;
	}

	if (hog->setrep_att) {
		bt_gatt_client_cancel(hog->client, hog->setrep_att);
		hog->setrep_att = 0;
	}

	if (hog->report_map_id) {
		bt_gatt_client_cancel(hog->client, hog->report_map_id);
		hog->report_map_id = 0;
	}

	hog->pending = 0;

	client = hog->client;
	hog->client = NULL;
	bt_gatt_client_unref(client);

done:
	uhid_destroy(hog, force);
}

int bt_hog_set_control_point(struct bt_hog *hog, bool suspend)
{
	uint8_t value = suspend ? 0x00 : 0x01;

	if (!hog)
		return -EINVAL;

	if (!hog->client)
		return -ENOTCONN;

	if (!hog->cp_handle)
		return -ENOTSUP;

	bt_gatt_client_write_without_response(hog->client, hog->cp_handle,
						false, &value, sizeof(value));

	return 0;
}

int bt_hog_send_report(struct bt_hog *hog, void *data, size_t size, int type)
{
	const struct queue_entry *entry;
	struct report *report;

	if (!hog)
		return -EINVAL;

	if (!hog->client)
		return -ENOTCONN;

	report = find_report(hog, type, 0);
	if (!report)
		return -ENOTSUP;

	DBG(hog, "Write report, handle 0x%X", report->value_handle);

	if (report->properties & BT_GATT_CHRC_PROP_WRITE)
		write_output(hog, report, data, size);

	if (report->properties & BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP)
		bt_gatt_client_write_without_response(hog->client,
						report->value_handle, false,
						data, size);

	for (entry = queue_get_entries(hog->instances); entry;
							entry = entry->next)
		bt_hog_send_report(entry->data, data, size, type);

	return 0;
}

static struct bt_hog *find_cp(struct bt_hog *hog)
{
	const struct queue_entry *entry;

	if (hog->cp_handle)
		return hog;

	for (entry = queue_get_entries(hog->instances); entry;
							entry = entry->next) {
		struct bt_hog *instance = entry->data;

		if (instance->cp_handle)
			return instance;
	}

	return NULL;
}

int bt_hog_set_sci_mode(struct bt_hog *hog, uint8_t mode)
{
	struct bt_hog *cp;

	if (!hog)
		return -EINVAL;

	if (mode < BT_HOG_SCI_MODE_DEFAULT || mode > BT_HOG_SCI_MODE_FULL_RANGE)
		return -EINVAL;

	if (!hog->client)
		return -ENOTCONN;

	if (!(hog->flags & HOG_INFO_FLAG_SCI_SUPPORTED))
		return -ENOTSUP;

	if (mode == BT_HOG_SCI_MODE_LOW_POWER &&
			!(hog->flags & HOG_INFO_FLAG_SCI_LOW_POWER))
		return -ENOTSUP;

	/* The command affects the whole HID Device, regardless of the
	 * instance of HID Service the HID Control Point belongs to.
	 */
	cp = find_cp(hog);
	if (!cp || !cp->client)
		return -ENOTSUP;

	DBG(hog, "Enable SCI mode 0x%02x", mode);

	if (!bt_gatt_client_write_without_response(cp->client,
					cp->cp_handle, false,
					&mode, sizeof(mode)))
		return -EIO;

	return 0;
}

uint8_t bt_hog_get_sci_mode(struct bt_hog *hog)
{
	if (!hog)
		return 0;

	return hog->sci_mode;
}

bool bt_hog_set_sci_mode_callback(struct bt_hog *hog,
					bt_hog_sci_mode_func_t func,
					void *user_data)
{
	const struct queue_entry *entry;

	if (!hog)
		return false;

	hog->sci_mode_func = func;
	hog->sci_mode_data = user_data;

	for (entry = queue_get_entries(hog->instances); entry;
							entry = entry->next)
		bt_hog_set_sci_mode_callback(entry->data, func, user_data);

	return true;
}
