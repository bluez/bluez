// SPDX-License-Identifier: GPL-2.0-or-later
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
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "src/shared/uhid.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/log.h"

#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"

#include "btio/btio.h"

#include "profiles/scanparam/scpp.h"
#include "profiles/deviceinfo/dis.h"
#include "profiles/battery/bas.h"
#include "profiles/input/hog-lib.h"

#define HOG_UUID16		0x1812

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

#define HID_INFO_SIZE			4
#define ATT_NOTIFICATION_HEADER_SIZE	3

struct bt_hog {
	int			ref_count;
	char			*name;
	uint16_t		vendor;
	uint16_t		product;
	uint16_t		version;
	uint8_t			type;
	struct gatt_db_attribute *attr;
	struct gatt_primary	*primary;
	GAttrib			*attrib;
	GSList			*reports;
	struct bt_uhid		*uhid;
	int			uhid_fd;
	uint64_t		uhid_flags;
	uint16_t		bcdhid;
	uint8_t			bcountrycode;
	uint16_t		proto_mode_handle;
	uint16_t		ctrlpt_handle;
	uint8_t			flags;
	unsigned int		getrep_att;
	uint16_t		getrep_id;
	unsigned int		setrep_att;
	uint16_t		setrep_id;
	unsigned int		report_map_id;
	struct bt_scpp		*scpp;
	struct bt_dis		*dis;
	struct queue		*bas;
	GSList			*instances;
	struct queue		*gatt_op;
	struct gatt_db		*gatt_db;
	struct gatt_db_attribute	*report_map_attr;
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
	guint			notifyid;
	uint16_t		len;
	uint8_t			*value;
};

struct gatt_request {
	unsigned int id;
	struct bt_hog *hog;
	void *user_data;
};

static struct gatt_request *create_request(struct bt_hog *hog,
							void *user_data)
{
	struct gatt_request *req;

	req = new0(struct gatt_request, 1);
	if (!req)
		return NULL;

	req->user_data = user_data;
	req->hog = bt_hog_ref(hog);

	return req;
}

static bool set_and_store_gatt_req(struct bt_hog *hog,
						struct gatt_request *req,
						unsigned int id)
{
	req->id = id;
	return queue_push_head(hog->gatt_op, req);
}

static void destroy_gatt_req(void *data)
{
	struct gatt_request *req = data;

	bt_hog_unref(req->hog);
	free(req);
}

static void read_report_map(struct bt_hog *hog);

static void remove_gatt_req(struct gatt_request *req, uint8_t status)
{
	struct bt_hog *hog = req->hog;

	queue_remove(hog->gatt_op, req);

	if (!status && queue_isempty(hog->gatt_op)) {
		/* Report Map must be read last since that can result
		 * in uhid being created and the driver may start to
		 * use UHID_SET_REPORT which requires the report->id to
		 * be known what attribute to send to.
		 */
		read_report_map(hog);
	}

	destroy_gatt_req(req);
}

static void write_char(struct bt_hog *hog, GAttrib *attrib, uint16_t handle,
					const uint8_t *value, size_t vlen,
					GAttribResultFunc func,
					gpointer user_data)
{
	struct gatt_request *req;
	unsigned int id;

	req = create_request(hog, user_data);
	if (!req)
		return;

	id = gatt_write_char(attrib, handle, value, vlen, func, req);
	if (!id) {
		error("hog: Could not write char");
		return;
	}

	if (!set_and_store_gatt_req(hog, req, id)) {
		error("hog: Failed to queue write char req");
		g_attrib_cancel(attrib, id);
		free(req);
	}
}

static unsigned int read_char(struct bt_hog *hog, GAttrib *attrib,
				uint16_t handle, GAttribResultFunc func,
				gpointer user_data)
{
	struct gatt_request *req;
	unsigned int id;

	req = create_request(hog, user_data);
	if (!req)
		return 0;

	id = gatt_read_char(attrib, handle, func, req);
	if (!id) {
		error("hog: Could not read char");
		return 0;
	}

	if (!set_and_store_gatt_req(hog, req, id)) {
		error("hog: Failed to queue read char req");
		g_attrib_cancel(attrib, id);
		free(req);
		return 0;
	}

	return id;
}

static void discover_desc(struct bt_hog *hog, GAttrib *attrib,
				uint16_t start, uint16_t end, gatt_cb_t func,
				gpointer user_data)
{
	struct gatt_request *req;
	unsigned int id;

	req = create_request(hog, user_data);
	if (!req)
		return;

	id = gatt_discover_desc(attrib, start, end, NULL, func, req);
	if (!id) {
		error("hog: Could not discover descriptors");
		return;
	}

	if (!set_and_store_gatt_req(hog, req, id)) {
		error("hog: Failed to queue discover descriptors req");
		g_attrib_cancel(attrib, id);
		free(req);
	}
}

static void discover_char(struct bt_hog *hog, GAttrib *attrib,
						uint16_t start, uint16_t end,
						bt_uuid_t *uuid, gatt_cb_t func,
						gpointer user_data)
{
	struct gatt_request *req;
	unsigned int id;

	req = create_request(hog, user_data);
	if (!req)
		return;

	id = gatt_discover_char(attrib, start, end, uuid, func, req);
	if (!id) {
		error("hog: Could not discover characteristic");
		return;
	}

	if (!set_and_store_gatt_req(hog, req, id)) {
		error("hog: Failed to queue discover characteristic req");
		g_attrib_cancel(attrib, id);
		free(req);
	}
}

static void discover_primary(struct bt_hog *hog, GAttrib *attrib,
						bt_uuid_t *uuid, gatt_cb_t func,
						gpointer user_data)
{
	struct gatt_request *req;
	unsigned int id;

	req = create_request(hog, user_data);
	if (!req)
		return;

	id = gatt_discover_primary(attrib, uuid, func, req);
	if (!id) {
		error("hog: Could not send discover primary");
		return;
	}

	if (!set_and_store_gatt_req(hog, req, id)) {
		error("hog: Failed to queue discover primary req");
		g_attrib_cancel(attrib, id);
		free(req);
	}
}

static void find_included(struct bt_hog *hog, GAttrib *attrib,
					uint16_t start, uint16_t end,
					gatt_cb_t func, gpointer user_data)
{
	struct gatt_request *req;
	unsigned int id;

	req = create_request(hog, user_data);
	if (!req)
		return;

	id = gatt_find_included(attrib, start, end, func, req);
	if (!id) {
		error("hog: Could not find included");
		return;
	}

	if (!set_and_store_gatt_req(hog, req, id)) {
		error("hog: Failed to queue find included req");
		g_attrib_cancel(attrib, id);
		free(req);
	}
}

static void report_value_cb(const guint8 *pdu, guint16 len, gpointer user_data)
{
	struct report *report = user_data;
	struct bt_hog *hog = report->hog;
	int err;

	if (len < ATT_NOTIFICATION_HEADER_SIZE) {
		error("Malformed ATT notification");
		return;
	}

	pdu += ATT_NOTIFICATION_HEADER_SIZE;
	len -= ATT_NOTIFICATION_HEADER_SIZE;

	err = bt_uhid_input(hog->uhid, report->numbered ? report->id : 0, pdu,
				len);
	if (err < 0)
		error("bt_uhid_input: %s (%d)", strerror(-err), -err);
}

static void report_notify_destroy(void *user_data)
{
	struct report *report = user_data;

	DBG("");

	report->notifyid = 0;
}

static void report_ccc_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct report *report = req->user_data;
	struct bt_hog *hog = report->hog;

	if (status != 0) {
		error("Write report characteristic descriptor failed: %s",
							att_ecode2str(status));
		goto remove;
	}

	if (report->notifyid)
		goto remove;

	report->notifyid = g_attrib_register(hog->attrib,
					ATT_OP_HANDLE_NOTIFY,
					report->value_handle,
					report_value_cb, report,
					report_notify_destroy);
	if (!report->notifyid) {
		error("Unable to register report notification: handle 0x%04x",
					report->value_handle);
		goto remove;
	}

	DBG("Report characteristic descriptor written: notifications enabled");

remove:
	remove_gatt_req(req, status);
}

static void write_ccc(struct bt_hog *hog, GAttrib *attrib, uint16_t handle,
							void *user_data)
{
	uint8_t value[2];

	put_le16(GATT_CLIENT_CHARAC_CFG_NOTIF_BIT, value);

	write_char(hog, attrib, handle, value, sizeof(value),
					report_ccc_written_cb, user_data);
}

static void ccc_read_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct report *report = req->user_data;

	if (status != 0) {
		error("Error reading CCC value: %s", att_ecode2str(status));
		goto remove;
	}

	write_ccc(report->hog, report->hog->attrib, report->ccc_handle, report);

remove:
	remove_gatt_req(req, status);
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

static void report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct report *report = req->user_data;

	if (status != 0) {
		error("Read Report Reference descriptor failed: %s",
							att_ecode2str(status));
		goto remove;
	}

	if (plen != 3) {
		error("Malformed ATT read response");
		goto remove;
	}

	report->id = pdu[1];
	report->type = pdu[2];

	DBG("Report 0x%04x: id 0x%02x type %s", report->value_handle,
				report->id, type_to_string(report->type));

	/* Enable notifications only for Input Reports */
	if (report->type == HOG_REPORT_TYPE_INPUT)
		read_char(report->hog, report->hog->attrib, report->ccc_handle,
							ccc_read_cb, report);

remove:
	remove_gatt_req(req, status);
}

static void external_report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data);

static void discover_external_cb(uint8_t status, GSList *descs, void *user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;

	if (status != 0) {
		error("Discover external descriptors failed: %s",
							att_ecode2str(status));
		goto remove;
	}

	for ( ; descs; descs = descs->next) {
		struct gatt_desc *desc = descs->data;

		read_char(hog, hog->attrib, desc->handle,
						external_report_reference_cb,
						hog);
	}

remove:
	remove_gatt_req(req, status);
}

static void discover_external(struct bt_hog *hog, GAttrib *attrib,
						uint16_t start, uint16_t end,
						gpointer user_data)
{
	bt_uuid_t uuid;

	if (start > end)
		return;

	bt_uuid16_create(&uuid, GATT_EXTERNAL_REPORT_REFERENCE);

	discover_desc(hog, attrib, start, end, discover_external_cb,
								user_data);
}

static void discover_report_cb(uint8_t status, GSList *descs, void *user_data)
{
	struct gatt_request *req = user_data;
	struct report *report = req->user_data;
	struct bt_hog *hog = report->hog;

	if (status != 0) {
		error("Discover report descriptors failed: %s",
							att_ecode2str(status));
		goto remove;
	}

	for ( ; descs; descs = descs->next) {
		struct gatt_desc *desc = descs->data;

		switch (desc->uuid16) {
		case GATT_CLIENT_CHARAC_CFG_UUID:
			report->ccc_handle = desc->handle;
			break;
		case GATT_REPORT_REFERENCE:
			read_char(hog, hog->attrib, desc->handle,
						report_reference_cb, report);
			break;
		}
	}

remove:
	remove_gatt_req(req, status);
}

static void discover_report(struct bt_hog *hog, GAttrib *attrib,
						uint16_t start, uint16_t end,
							gpointer user_data)
{
	if (start > end)
		return;

	discover_desc(hog, attrib, start, end, discover_report_cb, user_data);
}

static void report_read_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct report *report = req->user_data;

	if (status != 0) {
		error("Error reading Report value: %s", att_ecode2str(status));
		goto remove;
	}

	if (report->value)
		free(report->value);

	report->value = util_memdup(pdu, len);
	report->len = len;

remove:
	remove_gatt_req(req, status);
}

static int report_chrc_cmp(const void *data, const void *user_data)
{
	const struct report *report = data;
	const struct gatt_char *decl = user_data;

	return report->handle - decl->handle;
}

static struct report *report_new(struct bt_hog *hog, struct gatt_char *chr)
{
	struct report *report;
	GSList *l;

	if (!chr)
		return NULL;

	/* Skip if report already exists */
	l = g_slist_find_custom(hog->reports, chr, report_chrc_cmp);
	if (l)
		return l->data;

	report = g_new0(struct report, 1);
	report->hog = hog;
	report->handle = chr->handle;
	report->value_handle = chr->value_handle;
	report->properties = chr->properties;
	hog->reports = g_slist_append(hog->reports, report);

	read_char(hog, hog->attrib, chr->value_handle, report_read_cb, report);

	return report;
}

static void external_service_char_cb(uint8_t status, GSList *chars,
								void *user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	struct gatt_primary *primary = hog->primary;
	struct report *report;
	GSList *l;

	if (status != 0) {
		const char *str = att_ecode2str(status);

		DBG("Discover external service characteristic failed: %s", str);
		goto remove;
	}

	for (l = chars; l; l = g_slist_next(l)) {
		struct gatt_char *chr, *next;
		uint16_t start, end;

		chr = l->data;
		next = l->next ? l->next->data : NULL;

		if (!chr)
			continue;

		DBG("0x%04x UUID: %s properties: %02x",
				chr->handle, chr->uuid, chr->properties);

		report = report_new(hog, chr);
		start = chr->value_handle + 1;
		end = (next ? next->handle - 1 : primary->range.end);
		discover_report(hog, hog->attrib, start, end, report);
	}

remove:
	remove_gatt_req(req, status);
}

static void external_report_reference_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	uint16_t uuid16;
	bt_uuid_t uuid;

	if (status != 0) {
		error("Read External Report Reference descriptor failed: %s",
							att_ecode2str(status));
		goto remove;
	}

	if (plen != 3) {
		error("Malformed ATT read response");
		goto remove;
	}

	uuid16 = get_le16(&pdu[1]);
	DBG("External report reference read, external report characteristic "
						"UUID: 0x%04x", uuid16);

	/* Do not discover if is not a Report */
	if (uuid16 != HOG_REPORT_UUID)
		goto remove;

	bt_uuid16_create(&uuid, uuid16);
	discover_char(hog, hog->attrib, 0x0001, 0xffff, &uuid,
					external_service_char_cb, hog);

remove:
	remove_gatt_req(req, status);
}

static int report_cmp(gconstpointer a, gconstpointer b)
{
	const struct report *ra = a, *rb = b;

	/* sort by type first.. */
	if (ra->type != rb->type)
		return ra->type - rb->type;

	/* skip id check in case of reports not being numbered  */
	if (!ra->numbered && !rb->numbered)
		return 0;

	/* ..then by id */
	return ra->id - rb->id;
}

static struct report *find_report(struct bt_hog *hog, uint8_t type, uint8_t id)
{
	struct report cmp;
	GSList *l;

	memset(&cmp, 0, sizeof(cmp));
	cmp.type = type;
	cmp.id = id;

	switch (type) {
	case HOG_REPORT_TYPE_FEATURE:
		if (hog->flags & UHID_DEV_NUMBERED_FEATURE_REPORTS)
			cmp.numbered = true;
		break;
	case HOG_REPORT_TYPE_OUTPUT:
		if (hog->flags & UHID_DEV_NUMBERED_OUTPUT_REPORTS)
			cmp.numbered = true;
		break;
	case HOG_REPORT_TYPE_INPUT:
		if (hog->flags & UHID_DEV_NUMBERED_INPUT_REPORTS)
			cmp.numbered = true;
		break;
	}

	l = g_slist_find_custom(hog->reports, &cmp, report_cmp);

	return l ? l->data : NULL;
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

static void output_written_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct gatt_request *req = user_data;

	if (status != 0)
		error("Write output report failed: %s", att_ecode2str(status));

	remove_gatt_req(req, status);
}

static void forward_report(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct report *report;
	void *data;
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

	DBG("Sending report type %d ID %d to handle 0x%X", report->type,
				report->id, report->value_handle);

	if (hog->attrib == NULL)
		return;

	if (report->properties & GATT_CHR_PROP_WRITE)
		write_char(hog, hog->attrib, report->value_handle,
				data, size, output_written_cb, hog);
	else if (report->properties & GATT_CHR_PROP_WRITE_WITHOUT_RESP)
		gatt_write_cmd(hog->attrib, report->value_handle,
						data, size, NULL, NULL);
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

	DBG("uHID device flags: 0x%16" PRIx64, hog->uhid_flags);

	if (hog->uhid_flags)
		g_slist_foreach(hog->reports, set_numbered, hog);
}

static void set_report_cb(guint8 status, const guint8 *pdu,
					guint16 plen, gpointer user_data)
{
	struct bt_hog *hog = user_data;
	int err;

	hog->setrep_att = 0;

	if (status != 0)
		error("Error setting Report value: %s", att_ecode2str(status));

	err = bt_uhid_set_report_reply(hog->uhid, hog->setrep_id, status);
	if (err < 0)
		error("bt_uhid_set_report_reply: %s", strerror(-err));
}

static void uhid_destroy(struct bt_hog *hog, bool force)
{
	int err;

	if (!hog->uhid)
		return;

	bt_uhid_unregister_all(hog->uhid);

	err = bt_uhid_destroy(hog->uhid, force);
	if (err < 0) {
		error("bt_uhid_destroy: %s", strerror(-err));
		return;
	}
}

static void set_report(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct report *report;
	void *data;
	int size;
	int err;

	/* Destroy input device if there is an attempt to communicate with it
	 * while disconnected.
	 */
	if (hog->attrib == NULL) {
		uhid_destroy(hog, true);
		return;
	}

	/* uhid never sends reqs in parallel; if there's a req, it timed out */
	if (hog->setrep_att) {
		g_attrib_cancel(hog->attrib, hog->setrep_att);
		hog->setrep_att = 0;
	}

	hog->setrep_id = ev->u.set_report.id;

	report = find_report_by_rtype(hog, ev->u.set_report.rtype,
							ev->u.set_report.rnum);
	if (!report) {
		err = ENOTSUP;
		goto fail;
	}

	data = ev->u.set_report.data;
	size = ev->u.set_report.size;

	if (report->numbered && size > 0) {
		data++;
		--size;
	}

	DBG("Sending report type %d ID %d to handle 0x%X", report->type,
				report->id, report->value_handle);

	hog->setrep_att = gatt_write_char(hog->attrib,
						report->value_handle,
						data, size, set_report_cb,
						hog);
	if (!hog->setrep_att) {
		err = ENOMEM;
		goto fail;
	}

	return;
fail:
	/* cancel the request on failure */
	set_report_cb(err, NULL, 0, hog);
}

static void report_reply(struct bt_hog *hog, uint8_t status, uint8_t id,
			uint16_t len, const uint8_t *data)
{
	int err;

	hog->getrep_att = 0;

	err = bt_uhid_get_report_reply(hog->uhid, hog->getrep_id, id, status,
					data, len);
	if (err < 0)
		error("bt_uhid_get_report_reply: %s", strerror(-err));
}

static void get_report_cb(guint8 status, const guint8 *pdu, guint16 len,
							gpointer user_data)
{
	struct report *report = user_data;
	struct bt_hog *hog = report->hog;

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

exit:
	report_reply(hog, status, report->numbered ? report->id : 0, len, pdu);
}

static void get_report(struct uhid_event *ev, void *user_data)
{
	struct bt_hog *hog = user_data;
	struct report *report;
	guint8 err;

	/* Destroy input device if there is an attempt to communicate with it
	 * while disconnected.
	 */
	if (hog->attrib == NULL) {
		uhid_destroy(hog, true);
		return;
	}

	/* uhid never sends reqs in parallel; if there's a req, it timed out */
	if (hog->getrep_att) {
		g_attrib_cancel(hog->attrib, hog->getrep_att);
		hog->getrep_att = 0;
	}

	hog->getrep_id = ev->u.get_report.id;

	report = find_report_by_rtype(hog, ev->u.get_report.rtype,
							ev->u.get_report.rnum);
	if (!report) {
		err = ENOTSUP;
		goto fail;
	}

	hog->getrep_att = gatt_read_char(hog->attrib,
						report->value_handle,
						get_report_cb, report);
	if (!hog->getrep_att) {
		err = ENOMEM;
		goto fail;
	}

	return;

fail:
	/* reply with an error on failure */
	report_reply(hog, err, 0, 0, NULL);
}

static void uhid_create(struct bt_hog *hog, uint8_t *report_map,
							size_t report_map_len)
{
	uint8_t *value = report_map;
	size_t vlen = report_map_len;
	int err;
	GError *gerr = NULL;
	bdaddr_t src, dst;

	bt_io_get(g_attrib_get_channel(hog->attrib), &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("Failed to connection details: %s", gerr->message);
		g_error_free(gerr);
		return;
	}

	err = bt_uhid_create(hog->uhid, hog->name, &src, &dst,
				hog->vendor, hog->product, hog->version,
				hog->bcountrycode, hog->type, value, vlen);
	if (err < 0) {
		error("bt_uhid_create: %s", strerror(-err));
		return;
	}

	bt_uhid_register(hog->uhid, UHID_START, start_flags, hog);
	bt_uhid_register(hog->uhid, UHID_OUTPUT, forward_report, hog);
	bt_uhid_register(hog->uhid, UHID_GET_REPORT, get_report, hog);
	bt_uhid_register(hog->uhid, UHID_SET_REPORT, set_report, hog);

	DBG("HoG created uHID device");
}

static void db_report_map_write_value_cb(struct gatt_db_attribute *attr,
						int err, void *user_data)
{
	if (err)
		error("Error writing report map value to gatt db");
}

static void report_map_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	uint8_t *value;
	ssize_t vlen;

	remove_gatt_req(req, status);

	if (status != 0) {
		error("Report Map read failed: %s", att_ecode2str(status));
		return;
	}

	value = new0(uint8_t, plen);

	vlen = dec_read_resp(pdu, plen, value, plen);
	if (vlen < 0) {
		error("ATT protocol error");
		goto done;
	}

	uhid_create(hog, value, vlen);

	/* Cache the report map if gatt_db is available  */
	if (hog->report_map_attr) {
		gatt_db_attribute_write(hog->report_map_attr, 0, value, vlen, 0,
					NULL, db_report_map_write_value_cb,
					NULL);
	}

done:
	free(value);
}

static void read_report_map(struct bt_hog *hog)
{
	uint16_t handle;

	if (!hog->report_map_attr || bt_uhid_created(hog->uhid) ||
			hog->report_map_id)
		return;

	handle = gatt_db_attribute_get_handle(hog->report_map_attr);

	hog->report_map_id = read_char(hog, hog->attrib, handle,
						report_map_read_cb, hog);
}

static void info_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	uint8_t value[HID_INFO_SIZE];
	ssize_t vlen;

	if (status != 0) {
		error("HID Information read failed: %s",
						att_ecode2str(status));
		goto remove;
	}

	vlen = dec_read_resp(pdu, plen, value, sizeof(value));
	if (vlen != 4) {
		error("ATT protocol error");
		goto remove;
	}

	hog->bcdhid = get_le16(&value[0]);
	hog->bcountrycode = value[2];
	hog->flags = value[3];

	DBG("bcdHID: 0x%04X bCountryCode: 0x%02X Flags: 0x%02X",
			hog->bcdhid, hog->bcountrycode, hog->flags);

remove:
	remove_gatt_req(req, status);
}

static void proto_mode_read_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	uint8_t value;
	ssize_t vlen;

	if (status != 0) {
		error("Protocol Mode characteristic read failed: %s",
							att_ecode2str(status));
		goto remove;
	}

	vlen = dec_read_resp(pdu, plen, &value, sizeof(value));
	if (vlen < 0) {
		error("ATT protocol error");
		goto remove;
	}

	if (value == HOG_PROTO_MODE_BOOT) {
		uint8_t nval = HOG_PROTO_MODE_REPORT;

		DBG("HoG is operating in Boot Protocol Mode");

		gatt_write_cmd(hog->attrib, hog->proto_mode_handle, &nval,
						sizeof(nval), NULL, NULL);
	} else if (value == HOG_PROTO_MODE_REPORT)
		DBG("HoG is operating in Report Protocol Mode");

remove:
	remove_gatt_req(req, status);
}

static void char_discovered_cb(uint8_t status, GSList *chars, void *user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	struct gatt_primary *primary = hog->primary;
	bt_uuid_t report_uuid, report_map_uuid, info_uuid;
	bt_uuid_t proto_mode_uuid, ctrlpt_uuid;
	struct report *report;
	GSList *l;
	uint16_t info_handle = 0, proto_mode_handle = 0;

	DBG("HoG inspecting characteristics");

	if (status != 0) {
		DBG("Discover all characteristics failed: %s",
					att_ecode2str(status));
		goto remove;
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

		if (!chr)
			continue;

		DBG("0x%04x UUID: %s properties: %02x",
				chr->handle, chr->uuid, chr->properties);

		bt_string_to_uuid(&uuid, chr->uuid);

		start = chr->value_handle + 1;
		end = (next ? next->handle - 1 : primary->range.end);

		if (bt_uuid_cmp(&uuid, &report_uuid) == 0) {
			report = report_new(hog, chr);
			discover_report(hog, hog->attrib, start, end, report);
		} else if (bt_uuid_cmp(&uuid, &report_map_uuid) == 0) {
			DBG("HoG discovering report map");
			read_char(hog, hog->attrib, chr->value_handle,
						report_map_read_cb, hog);
			discover_external(hog, hog->attrib, start, end, hog);
		} else if (bt_uuid_cmp(&uuid, &info_uuid) == 0)
			info_handle = chr->value_handle;
		else if (bt_uuid_cmp(&uuid, &proto_mode_uuid) == 0)
			proto_mode_handle = chr->value_handle;
		else if (bt_uuid_cmp(&uuid, &ctrlpt_uuid) == 0)
			hog->ctrlpt_handle = chr->value_handle;
	}

	if (proto_mode_handle) {
		hog->proto_mode_handle = proto_mode_handle;
		read_char(hog, hog->attrib, proto_mode_handle,
						proto_mode_read_cb, hog);
	}

	if (info_handle)
		read_char(hog, hog->attrib, info_handle, info_read_cb, hog);

remove:
	remove_gatt_req(req, status);
}

static void report_free(void *data)
{
	struct report *report = data;

	free(report->value);
	g_free(report);
}

static bool cancel_gatt_req(const void *data, const void *user_data)
{
	struct gatt_request *req = (void *) data;
	const struct bt_hog *hog = user_data;

	return g_attrib_cancel(hog->attrib, req->id);
}

static void hog_free(void *data)
{
	struct bt_hog *hog = data;

	bt_hog_detach(hog, true);
	uhid_destroy(hog, true);

	queue_destroy(hog->bas, (void *) bt_bas_unref);
	g_slist_free_full(hog->instances, hog_free);

	bt_scpp_unref(hog->scpp);
	bt_dis_unref(hog->dis);
	bt_uhid_unref(hog->uhid);
	g_slist_free_full(hog->reports, report_free);
	g_free(hog->name);
	free(hog->primary);
	queue_destroy(hog->gatt_op, (void *) destroy_gatt_req);
	if (hog->gatt_db)
		gatt_db_unref(hog->gatt_db);
	g_free(hog);
}

struct bt_hog *bt_hog_new_default(const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type, struct gatt_db *db)
{
	return bt_hog_new(-1, name, vendor, product, version, type, db);
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
		read_char(hog, hog->attrib, handle, report_reference_cb,
								report);
		return;
	}

	bt_uuid16_create(&ccc_uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	if (!bt_uuid_cmp(&ccc_uuid, uuid))
		report->ccc_handle = handle;
}

static int report_attr_cmp(const void *data, const void *user_data)
{
	const struct report *report = data;
	const struct gatt_db_attribute *attr = user_data;

	return report->handle - gatt_db_attribute_get_handle(attr);
}

static struct report *report_add(struct bt_hog *hog,
					struct gatt_db_attribute *attr)
{
	struct report *report;
	GSList *l;

	/* Skip if report already exists */
	l = g_slist_find_custom(hog->reports, attr, report_attr_cmp);
	if (l)
		return l->data;

	report = g_new0(struct report, 1);
	report->hog = hog;

	gatt_db_attribute_get_char_data(attr, &report->handle,
					&report->value_handle,
					&report->properties,
					NULL, NULL);

	hog->reports = g_slist_append(hog->reports, report);

	read_char(hog, hog->attrib, report->value_handle, report_read_cb,
								report);

	return report;
}

static void foreach_hog_external(struct gatt_db_attribute *attr,
							void *user_data)
{
	struct bt_hog *hog = user_data;
	const bt_uuid_t *uuid;
	bt_uuid_t ext_uuid;
	uint16_t handle;

	handle = gatt_db_attribute_get_handle(attr);
	uuid = gatt_db_attribute_get_type(attr);

	bt_uuid16_create(&ext_uuid, GATT_EXTERNAL_REPORT_REFERENCE);
	if (!bt_uuid_cmp(&ext_uuid, uuid))
		read_char(hog, hog->attrib, handle,
					external_report_reference_cb, hog);
}

static void db_report_map_read_value_cb(struct gatt_db_attribute *attrib,
						int err, const uint8_t *value,
						size_t length, void *user_data)
{
	struct iovec *map = user_data;

	if (err) {
		error("Error reading report map from gatt db %s",
								strerror(-err));
		return;
	}

	if (!length)
		return;


	map->iov_len = length;
	map->iov_base = (void *) value;
}

static void foreach_hog_chrc(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_hog *hog = user_data;
	bt_uuid_t uuid, report_uuid, report_map_uuid, info_uuid;
	bt_uuid_t proto_mode_uuid, ctrlpt_uuid;
	uint16_t handle, value_handle;
	struct iovec map = {};

	gatt_db_attribute_get_char_data(attr, &handle, &value_handle, NULL,
					NULL, &uuid);

	bt_uuid16_create(&report_uuid, HOG_REPORT_UUID);
	if (!bt_uuid_cmp(&report_uuid, &uuid)) {
		struct report *report = report_add(hog, attr);
		gatt_db_service_foreach_desc(attr, foreach_hog_report, report);
		return;
	}

	bt_uuid16_create(&report_map_uuid, HOG_REPORT_MAP_UUID);
	if (!bt_uuid_cmp(&report_map_uuid, &uuid)) {

		if (hog->gatt_db) {
			/* Try to read the cache of report map if available */
			hog->report_map_attr = gatt_db_get_attribute(
								hog->gatt_db,
								value_handle);
			gatt_db_attribute_read(hog->report_map_attr, 0,
						BT_ATT_OP_READ_REQ, NULL,
						db_report_map_read_value_cb,
						&map);
		}

		if (map.iov_len) {
			/* Report map found in the cache, straight to creating
			 * UHID to optimize reconnection.
			 */
			uhid_create(hog, map.iov_base, map.iov_len);
		}

		gatt_db_service_foreach_desc(attr, foreach_hog_external, hog);
	}

	bt_uuid16_create(&info_uuid, HOG_INFO_UUID);
	if (!bt_uuid_cmp(&info_uuid, &uuid)) {
		read_char(hog, hog->attrib, value_handle, info_read_cb, hog);
		return;
	}

	bt_uuid16_create(&proto_mode_uuid, HOG_PROTO_MODE_UUID);
	if (!bt_uuid_cmp(&proto_mode_uuid, &uuid)) {
		hog->proto_mode_handle = value_handle;
		read_char(hog, hog->attrib, value_handle, proto_mode_read_cb,
									hog);
	}

	bt_uuid16_create(&ctrlpt_uuid, HOG_CONTROL_POINT_UUID);
	if (!bt_uuid_cmp(&ctrlpt_uuid, &uuid))
		hog->ctrlpt_handle = value_handle;
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

	if (!uhid) {
		DBG("Unable to create UHID");
		return NULL;
	}

	hog = g_try_new0(struct bt_hog, 1);
	if (!hog)
		return NULL;

	hog->gatt_op = queue_new();
	hog->bas = queue_new();
	hog->uhid_fd = fd;
	hog->uhid = uhid;

	if (!hog->gatt_op || !hog->bas) {
		hog_free(hog);
		return NULL;
	}

	hog->name = g_strdup(name);
	hog->vendor = vendor;
	hog->product = product;
	hog->version = version;
	hog->type = type;
	hog->attr = attr;

	return hog;
}

static void hog_attach_instance(struct bt_hog *hog,
				struct gatt_db_attribute *attr)
{
	struct bt_hog *instance;

	if (!hog->attr) {
		hog->attr = attr;
		return;
	}

	instance = hog_new(hog->uhid_fd, hog->name, hog->vendor, hog->product,
				hog->version, hog->type, attr);
	if (!instance)
		return;

	instance->gatt_db = gatt_db_ref(hog->gatt_db);
	hog->instances = g_slist_append(hog->instances, bt_hog_ref(instance));
}

static void foreach_hog_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_hog *hog = user_data;

	hog_attach_instance(hog, attr);
}

static void dis_notify(uint8_t source, uint16_t vendor, uint16_t product,
					uint16_t version, void *user_data)
{
	struct bt_hog *hog = user_data;
	GSList *l;

	hog->vendor = vendor;
	hog->product = product;
	hog->version = version;

	for (l = hog->instances; l; l = l->next) {
		struct bt_hog *instance = l->data;

		instance->vendor = vendor;
		instance->product = product;
		instance->version = version;
	}
}

struct bt_hog *bt_hog_new(int fd, const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type, struct gatt_db *db)
{
	struct bt_hog *hog;

	hog = hog_new(fd, name, vendor, product, version, type, NULL);
	if (!hog)
		return NULL;

	hog->gatt_db = gatt_db_ref(db);

	if (db) {
		bt_uuid_t uuid;

		/* Handle the HID services */
		bt_uuid16_create(&uuid, HOG_UUID16);
		gatt_db_foreach_service(db, &uuid, foreach_hog_service, hog);
		if (!hog->attr) {
			hog_free(hog);
			return NULL;
		}

		/* Try creating a DIS instance in case pid/vid are not set */
		if (!vendor && !product) {
			hog->dis = bt_dis_new(db);
			bt_dis_set_notification(hog->dis, dis_notify, hog);
		}
	}

	return bt_hog_ref(hog);
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

static void find_included_cb(uint8_t status, GSList *services, void *user_data)
{
	struct gatt_request *req = user_data;
	GSList *l;

	DBG("");

	if (status) {
		DBG("Find included failed: %s", att_ecode2str(status));
		goto remove;
	}

	for (l = services; l; l = l->next) {
		struct gatt_included *include = l->data;

		DBG("included: handle %x, uuid %s",
			include->handle, include->uuid);
	}

remove:
	remove_gatt_req(req, status);
}

static void hog_attach_scpp(struct bt_hog *hog, struct gatt_primary *primary)
{
	if (hog->scpp) {
		bt_scpp_attach(hog->scpp, hog->attrib);
		return;
	}

	hog->scpp = bt_scpp_new(primary);
	if (hog->scpp)
		bt_scpp_attach(hog->scpp, hog->attrib);
}

static void hog_attach_dis(struct bt_hog *hog, struct gatt_primary *primary)
{
	if (hog->dis) {
		bt_dis_attach(hog->dis, hog->attrib);
		return;
	}

	hog->dis = bt_dis_new_primary(primary);
	if (hog->dis) {
		bt_dis_set_notification(hog->dis, dis_notify, hog);
		bt_dis_attach(hog->dis, hog->attrib);
	}
}

static void hog_attach_bas(struct bt_hog *hog, struct gatt_primary *primary)
{
	struct bt_bas *instance;

	instance = bt_bas_new(primary);

	bt_bas_attach(instance, hog->attrib);
	queue_push_head(hog->bas, instance);
}

static void hog_attach_hog(struct bt_hog *hog, struct gatt_primary *primary)
{
	struct bt_hog *instance;

	if (!hog->primary) {
		hog->primary = util_memdup(primary, sizeof(*primary));
		discover_char(hog, hog->attrib, primary->range.start,
						primary->range.end, NULL,
						char_discovered_cb, hog);
		find_included(hog, hog->attrib, primary->range.start,
				primary->range.end, find_included_cb, hog);
		return;
	}

	instance = bt_hog_new(hog->uhid_fd, hog->name, hog->vendor,
					hog->product, hog->version,
					hog->type, hog->gatt_db);
	if (!instance)
		return;

	instance->primary = util_memdup(primary, sizeof(*primary));
	find_included(instance, hog->attrib, primary->range.start,
			primary->range.end, find_included_cb, instance);

	bt_hog_attach(instance, hog->attrib);
	hog->instances = g_slist_append(hog->instances, instance);
}

static void primary_cb(uint8_t status, GSList *services, void *user_data)
{
	struct gatt_request *req = user_data;
	struct bt_hog *hog = req->user_data;
	struct gatt_primary *primary;
	GSList *l;

	DBG("");

	if (status) {
		DBG("Discover primary failed: %s", att_ecode2str(status));
		goto remove;
	}

	if (!services) {
		DBG("No primary service found");
		goto remove;
	}

	for (l = services; l; l = l->next) {
		primary = l->data;

		if (strcmp(primary->uuid, SCAN_PARAMETERS_UUID) == 0) {
			hog_attach_scpp(hog, primary);
			continue;
		}

		if (strcmp(primary->uuid, DEVICE_INFORMATION_UUID) == 0) {
			hog_attach_dis(hog, primary);
			continue;
		}

		if (strcmp(primary->uuid, BATTERY_UUID) == 0) {
			hog_attach_bas(hog, primary);
			continue;
		}

		if (strcmp(primary->uuid, HOG_UUID) == 0)
			hog_attach_hog(hog, primary);
	}

remove:
	remove_gatt_req(req, status);
}

bool bt_hog_attach(struct bt_hog *hog, void *gatt)
{
	GSList *l;

	if (hog->attrib)
		return false;

	hog->attrib = g_attrib_ref(gatt);

	if (!hog->attr && !hog->primary) {
		discover_primary(hog, hog->attrib, NULL, primary_cb, hog);
		return true;
	}

	if (hog->scpp)
		bt_scpp_attach(hog->scpp, gatt);

	if (hog->dis)
		bt_dis_attach(hog->dis, gatt);

	queue_foreach(hog->bas, (void *) bt_bas_attach, gatt);

	for (l = hog->instances; l; l = l->next) {
		struct bt_hog *instance = l->data;

		bt_hog_attach(instance, gatt);
	}

	if (!bt_uhid_created(hog->uhid)) {
		DBG("HoG discovering characteristics");
		if (hog->attr)
			gatt_db_service_foreach_char(hog->attr,
							foreach_hog_chrc, hog);
		else
			discover_char(hog, hog->attrib,
					hog->primary->range.start,
					hog->primary->range.end, NULL,
					char_discovered_cb, hog);
	}

	if (!bt_uhid_created(hog->uhid))
		return true;

	/* If UHID is already created, set up the report value handlers to
	 * optimize reconnection.
	 */
	for (l = hog->reports; l; l = l->next) {
		struct report *r = l->data;

		if (r->notifyid)
			continue;

		r->notifyid = g_attrib_register(hog->attrib,
					ATT_OP_HANDLE_NOTIFY,
					r->value_handle,
					report_value_cb, r,
					report_notify_destroy);
		if (!r->notifyid)
			error("Unable to register report notification: "
				"handle 0x%04x", r->value_handle);
	}

	/* Attempt to replay get/set report messages since the driver might not
	 * be aware the device has been disconnected in the meantime.
	 */
	bt_uhid_replay(hog->uhid);

	return true;
}

void bt_hog_detach(struct bt_hog *hog, bool force)
{
	GSList *l;

	if (!hog)
		return;

	if (!hog->attrib)
		goto done;

	queue_foreach(hog->bas, (void *) bt_bas_detach, NULL);

	for (l = hog->instances; l; l = l->next) {
		struct bt_hog *instance = l->data;

		bt_hog_detach(instance, force);
	}

	for (l = hog->reports; l; l = l->next) {
		struct report *r = l->data;

		if (r->notifyid > 0) {
			g_attrib_unregister(hog->attrib, r->notifyid);
			r->notifyid = 0;
		}
	}

	if (hog->scpp)
		bt_scpp_detach(hog->scpp);

	if (hog->dis)
		bt_dis_detach(hog->dis);

	queue_remove_all(hog->gatt_op, cancel_gatt_req, hog, destroy_gatt_req);
	g_attrib_unref(hog->attrib);
	hog->attrib = NULL;

done:
	uhid_destroy(hog, force);
}

int bt_hog_set_control_point(struct bt_hog *hog, bool suspend)
{
	uint8_t value = suspend ? 0x00 : 0x01;

	if (hog->attrib == NULL)
		return -ENOTCONN;

	if (hog->ctrlpt_handle == 0)
		return -ENOTSUP;

	gatt_write_cmd(hog->attrib, hog->ctrlpt_handle, &value,
					sizeof(value), NULL, NULL);

	return 0;
}

int bt_hog_send_report(struct bt_hog *hog, void *data, size_t size, int type)
{
	struct report *report;
	GSList *l;

	if (!hog)
		return -EINVAL;

	if (!hog->attrib)
		return -ENOTCONN;

	report = find_report(hog, type, 0);
	if (!report)
		return -ENOTSUP;

	DBG("hog: Write report, handle 0x%X", report->value_handle);

	if (report->properties & GATT_CHR_PROP_WRITE)
		write_char(hog, hog->attrib, report->value_handle,
				data, size, output_written_cb, hog);

	if (report->properties & GATT_CHR_PROP_WRITE_WITHOUT_RESP)
		gatt_write_cmd(hog->attrib, report->value_handle,
						data, size, NULL, NULL);

	for (l = hog->instances; l; l = l->next) {
		struct bt_hog *instance = l->data;

		bt_hog_send_report(instance, data, size, type);
	}

	return 0;
}
