/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <btio/btio.h>
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "glib-helper.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"

#include "log.h"
#include "error.h"
#include "avdtp.h"
#include "media.h"
#include "a2dp.h"
#include "sink.h"
#include "source.h"
#include "avrcp.h"
#include "control.h"
#include "manager.h"
#include "sdpd.h"

static GKeyFile *config = NULL;

int audio_manager_init(GKeyFile *conf)
{
	if (conf)
		config = conf;

	return 0;
}

void audio_manager_exit(void)
{
	if (config) {
		g_key_file_free(config);
		config = NULL;
	}
}

static void set_fast_connectable(struct btd_adapter *adapter,
							gpointer user_data)
{
	gboolean enable = GPOINTER_TO_UINT(user_data);

	if (btd_adapter_set_fast_connectable(adapter, enable))
		error("Changing fast connectable for hci%d failed",
					btd_adapter_get_index(adapter));
}

void manager_set_fast_connectable(gboolean enable)
{
	adapter_foreach(set_fast_connectable, GUINT_TO_POINTER(enable));
}
