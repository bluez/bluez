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

#include <glib.h>
#include <time.h>
#include <errno.h>
#include <bluetooth/uuid.h>
#include <adapter.h>

#include "att.h"
#include "gattrib.h"
#include "attrib-server.h"
#include "gatt-service.h"
#include "log.h"
#include "server.h"

#define CURRENT_TIME_SVC_UUID		0x1805

#define LOCAL_TIME_INFO_CHR_UUID	0x2A0F
#define CT_TIME_CHR_UUID		0x2A2B

static int encode_current_time(uint8_t value[10])
{
	struct timespec tp;
	struct tm tm;

	if (clock_gettime(CLOCK_REALTIME, &tp) == -1) {
		int err = -errno;

		error("clock_gettime: %s", strerror(-err));
		return err;
	}

	if (localtime_r(&tp.tv_sec, &tm) == NULL) {
		error("localtime_r() failed");
		/* localtime_r() does not set errno */
		return -EINVAL;
	}

	att_put_u16(1900 + tm.tm_year, &value[0]); /* Year */
	value[2] = tm.tm_mon + 1; /* Month */
	value[3] = tm.tm_mday; /* Day */
	value[4] = tm.tm_hour; /* Hours */
	value[5] = tm.tm_min; /* Minutes */
	value[6] = tm.tm_sec; /* Seconds */
	value[7] = tm.tm_wday == 0 ? 7 : tm.tm_wday; /* Day of Week */
	/* From Time Profile spec: "The number of 1/256 fractions of a second."
	 * In 1s there are 256 fractions, in 1ns there are 256/10^9 fractions.
	 * To avoid integer overflow, we use the equivalent 1/3906250 ratio. */
	value[8] = tp.tv_nsec / 3906250; /* Fractions256 */
	value[9] = 0x00; /* Adjust Reason */

	return 0;
}

static uint8_t current_time_read(struct attribute *a, gpointer user_data)
{
	uint8_t value[10];

	if (encode_current_time(value) < 0)
		return ATT_ECODE_IO;

	/* FIXME: Provide the adapter in next function */
	attrib_db_update(NULL, a->handle, NULL, value, sizeof(value), NULL);

	return 0;
}

static uint8_t local_time_info_read(struct attribute *a, gpointer user_data)
{
	uint8_t value[2];

	DBG("a=%p", a);

	tzset();

	/* FIXME: POSIX "daylight" variable only indicates whether there is DST
	 * for the local time or not. The offset is unknown. */
	value[0] = daylight ? 0xff : 0x00;

	/* Convert POSIX "timezone" (seconds West of GMT) to Time Profile
	 * format (offset from UTC in number of 15 minutes increments). */
	value[1] = (uint8_t) (-1 * timezone / (60 * 15));

	/* FIXME: Provide the adapter in next function */
	attrib_db_update(NULL, a->handle, NULL, value, sizeof(value), NULL);

	return 0;
}

static void register_current_time_service(void)
{
	/* Current Time service */
	/* FIXME: Provide the adapter in next function */
	gatt_service_add(NULL, GATT_PRIM_SVC_UUID, CURRENT_TIME_SVC_UUID,
				/* CT Time characteristic */
				GATT_OPT_CHR_UUID, CT_TIME_CHR_UUID,
				GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ |
							ATT_CHAR_PROPER_NOTIFY,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
						current_time_read, NULL,

				/* Local Time Information characteristic */
				GATT_OPT_CHR_UUID, LOCAL_TIME_INFO_CHR_UUID,
				GATT_OPT_CHR_PROPS, ATT_CHAR_PROPER_READ,
				GATT_OPT_CHR_VALUE_CB, ATTRIB_READ,
						local_time_info_read, NULL,

				GATT_OPT_INVALID);
}

int time_server_init(void)
{
	register_current_time_service();

	return 0;
}

void time_server_exit(void)
{
}
