/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdbool.h>
#include <glib.h>
#include <bluetooth/uuid.h>

#include "att.h"
#include "adapter.h"
#include "device.h"
#include "att-database.h"
#include "log.h"
#include "gatt-service.h"
#include "gattrib.h"
#include "attrib-server.h"
#include "gatt.h"
#include "server.h"
#include "profile.h"

#define PHONE_ALERT_STATUS_SVC_UUID		0x180E

#define ALERT_STATUS_CHR_UUID		0x2A3F
#define RINGER_CP_CHR_UUID		0x2A40
#define RINGER_SETTING_CHR_UUID		0x2A41

/* Ringer Setting characteristic values */
enum {
	RINGER_SILENT,
	RINGER_NORMAL,
};

static uint8_t ringer_setting = RINGER_NORMAL;
static uint8_t alert_status = 0;

static uint8_t ringer_cp_write(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	DBG("a = %p", a);

	return 0;
}

static uint8_t alert_status_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	DBG("a = %p", a);

	if (a->data == NULL || a->data[0] != alert_status)
		attrib_db_update(adapter, a->handle, NULL, &alert_status,
						sizeof(alert_status), NULL);

	return 0;
}

static uint8_t ringer_setting_read(struct attribute *a,
						struct btd_device *device,
						gpointer user_data)
{
	struct btd_adapter *adapter = user_data;

	DBG("a = %p", a);

	if (a->data == NULL || a->data[0] != ringer_setting)
		attrib_db_update(adapter, a->handle, NULL, &ringer_setting,
						sizeof(ringer_setting), NULL);

	return 0;
}

static void register_phone_alert_service(struct btd_adapter *adapter)
{
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, PHONE_ALERT_STATUS_SVC_UUID);

	/* Phone Alert Status Service */
	gatt_service_add(adapter, GATT_PRIM_SVC_UUID, &uuid,
			/* Alert Status characteristic */
			GATT_OPT_CHR_UUID, ALERT_STATUS_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			alert_status_read, adapter,
			/* Ringer Control Point characteristic */
			GATT_OPT_CHR_UUID, RINGER_CP_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_WRITE_WITHOUT_RESP,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_WRITE,
			ringer_cp_write, NULL,
			/* Ringer Setting characteristic */
			GATT_OPT_CHR_UUID, RINGER_SETTING_CHR_UUID,
			GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
			GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
			ringer_setting_read, adapter,
			GATT_OPT_INVALID);
}

static int alert_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	register_phone_alert_service(adapter);

	return 0;
}

static void alert_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
}

static struct btd_profile alert_profile = {
	.name = "gatt-alert-server",
	.adapter_probe = alert_server_probe,
	.adapter_remove = alert_server_remove,
};

int alert_server_init(void)
{
	btd_profile_register(&alert_profile);

	return 0;
}

void alert_server_exit(void)
{
	btd_profile_unregister(&alert_profile);
}
