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

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "glib-helper.h"
#include "log.h"
#include "gdbus.h"
#include "btio.h"

#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "client.h"

#define CHAR_INTERFACE "org.bluez.Characteristic"

struct gatt_service {
	int id;
	bdaddr_t sba;
	bdaddr_t dba;
	char *path;
	GIOChannel *io;
	GSList *chars;
	GSList *primary;
	/* FIXME: remove this when we have a command queue */
	GSList *cur_prim;
	GAttrib *attrib;
	int psm;
	guint atid;
};

struct characteristic {
	uuid_t *uuid;
	char *path;
};

struct primary {
	uuid_t *uuid;
	uint16_t start;
	uint16_t end;
	char *path;
	GSList *chars;
};

static int service_id = 0;
static int char_id = 0;
static GSList *services = NULL;

static DBusConnection *connection;

static void characteristic_free(void *user_data)
{
	struct characteristic *chr = user_data;

	g_free(chr->path);
	g_free(chr);
}

static void primary_free(void *user_data)
{
	struct primary *prim = user_data;

	g_free(prim->path);
	g_free(prim->uuid);
	g_free(prim);
}

static void gatt_service_free(void *user_data)
{
	struct gatt_service *gatt = user_data;

	g_slist_foreach(gatt->chars, (GFunc) characteristic_free, NULL);
	g_slist_foreach(gatt->primary, (GFunc) primary_free, NULL);
	g_attrib_unref(gatt->attrib);
	g_free(gatt->path);
	g_free(gatt);
}

static int gatt_path_cmp(const struct gatt_service *gatt, const char *path)
{
	return strcmp(gatt->path, path);
}

static DBusMessage *get_characteristics(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *register_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable char_methods[] = {
	{ "GetCharacteristics",	"",	"a{oa{sv}}", get_characteristics},
	{ "RegisterCharacteristicsWatcher",	"o", "",
						register_watcher	},
	{ "UnregisterCharacteristicsWatcher",	"o", "",
						unregister_watcher	},
	{ }
};

static void char_discovered_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_service *gatt = user_data;
	struct att_data_list *list;
	int i;

	if (status == ATT_ECODE_ATTR_NOT_FOUND) {
		struct primary *prim;

		if (gatt->cur_prim == NULL)
			return;

		gatt->cur_prim = gatt->cur_prim->next;

		/* Fetch characteristics of the NEXT primary service */
		prim = gatt->cur_prim->data;
		gatt_discover_char(gatt->attrib, prim->start, prim->end,
						char_discovered_cb, gatt);
		return;
	}

	if (status != 0) {
		DBG("Discover all characteristics failed: %s",
						att_ecode2str(status));

		goto fail;
	}

	DBG("Read by Type Response received");

	list = dec_read_by_type_resp(pdu, plen);
	if (list == NULL)
		return;

	for (i = 0; i < list->num; i++) {
		/* FIXME: parse each data element */
	}

	att_data_list_free(list);

	return;

fail:
	gatt_service_free(gatt);
}

static void primary_cb(guint8 status, const guint8 *pdu, guint16 plen,
							gpointer user_data)
{
	struct gatt_service *gatt = user_data;
	unsigned int i;
	uint8_t length;
	uint16_t end, start;

	if (status == ATT_ECODE_ATTR_NOT_FOUND) {
		struct primary *prim;

		if (gatt->primary == NULL)
			return;

		gatt->cur_prim = gatt->primary;
		prim = gatt->cur_prim->data;

		gatt_discover_char(gatt->attrib, prim->start, prim->end,
						char_discovered_cb, gatt);
		return;
	}

	if (status != 0) {
		error("Discover all primary services failed: %s",
						att_ecode2str(status));
		goto fail;
	}

	if (pdu[0] != ATT_OP_READ_BY_GROUP_RESP) {
		error("Protocol error");
		goto fail;
	}

	DBG("Read by Group Type Response received");

	length = pdu[1];
	for (i = 2, end = 0; i < plen; i += length) {
		struct primary *prim;
		uuid_t *uuid;
		uint16_t *p16;

		p16 = (void *) &pdu[i];
		start = btohs(*p16);
		p16++;
		end = btohs(*p16);
		p16++;
		uuid = bt_malloc(sizeof(uuid_t));
		if (length == 6) {
			uint16_t u16 = btohs(*p16);
			uuid = sdp_uuid16_create(uuid, u16);

			DBG("Service => start: 0x%04x, end: 0x%04x, "
					"uuid: 0x%04x", start, end, u16);
		} else if (length == 20) {
			/* FIXME: endianness */
			uuid = sdp_uuid128_create(uuid, p16);
		} else {
			DBG("ATT: Invalid Length field");
			goto fail;
		}

		prim = g_new0(struct primary, 1);
		prim->start = start;
		prim->end = end;
		prim->uuid = uuid;

		gatt->primary = g_slist_append(gatt->primary, prim);
	}

	if (end == 0) {
		DBG("ATT: Invalid PDU format");
		goto fail;
	}

	/*
	 * Discover all primary services sub-procedure shall send another
	 * Read by Group Type Request until Error Response is received and
	 * the Error Code is set to Attribute Not Found.
	 */
	gatt->atid = gatt_discover_primary(gatt->attrib,
				end + 1, 0xffff, primary_cb, gatt);
	if (gatt->atid == 0)
		goto fail;

	return;
fail:
	gatt_service_free(gatt);
}

static void connect_cb(GIOChannel *chan, GError *gerr, gpointer user_data)
{
	struct gatt_service *gatt = user_data;
	GAttrib *attrib;
	guint atid;

	if (gerr) {
		error("%s", gerr->message);
		goto fail;
	}

	DBG("GATT connection established.");

	attrib = g_attrib_new(chan);

	atid = gatt_discover_primary(attrib, 0x0001, 0xffff, primary_cb, gatt);
	if (atid == 0) {
		g_attrib_unref(attrib);
		goto fail;
	}

	gatt->attrib = attrib;
	gatt->atid = atid;

	services = g_slist_append(services, gatt);

	return;
fail:
	g_io_channel_unref(gatt->io);
	gatt_service_free(gatt);
}

int attrib_client_register(bdaddr_t *sba, bdaddr_t *dba, const char *path,
									int psm)
{
	struct gatt_service *gatt;
	struct characteristic *chr;
	GError *gerr = NULL;
	GIOChannel *io;

	/*
	 * Registering fake services/characteristics. The following
	 * paths/interfaces shall be registered after discover primary
	 * services only.
	 */

	gatt = g_new0(struct gatt_service, 1);
	gatt->id = service_id;
	gatt->path = g_strdup(path);
	bacpy(&gatt->sba, sba);
	bacpy(&gatt->dba, dba);
	gatt->psm = psm;

	chr = g_new0(struct characteristic, 1);
	chr->path = g_strdup_printf("%s/service%d/characteristic%d",
						path, service_id, char_id);
	gatt->chars = g_slist_append(gatt->chars, chr);

	if (!g_dbus_register_interface(connection, chr->path, CHAR_INTERFACE,
						char_methods, NULL, NULL, chr,
						characteristic_free)) {
		error("D-Bus failed to register %s interface", CHAR_INTERFACE);
		gatt_service_free(gatt);
		return -1;
	}

	if (psm < 0) {
		/*
		 * FIXME: when PSM is not given means that L2CAP fixed
		 * channel shall be used. For this case, ATT CID(0x0004).
		 */

		DBG("GATT over LE");

		return 0;
	}

	io = bt_io_connect(BT_IO_L2CAP, connect_cb, gatt, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, sba,
					BT_IO_OPT_DEST_BDADDR, dba,
					BT_IO_OPT_PSM, psm,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);

	if (!io) {
		error("%s", gerr->message);
		g_error_free(gerr);
		gatt_service_free(gatt);
		return -1;
	}

	gatt->io = io;

	return 0;
}

void attrib_client_unregister(const char *path)
{
	struct gatt_service *gatt;
	GSList *l;

	l = g_slist_find_custom(services, path, (GCompareFunc) gatt_path_cmp);
	if (!l)
		return;

	gatt = l->data;
	services = g_slist_remove(services, gatt);
	gatt_service_free(gatt);
}

int attrib_client_init(DBusConnection *conn)
{

	connection = dbus_connection_ref(conn);

	/*
	 * FIXME: if the adapter supports BLE start scanning. Temporary
	 * solution, this approach doesn't allow to control scanning based
	 * on the discoverable property.
	 */

	return 0;
}

void attrib_client_exit(void)
{
	dbus_connection_unref(connection);
}
