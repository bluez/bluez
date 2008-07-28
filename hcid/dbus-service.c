/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "hcid.h"
#include "server.h"
#include "dbus-common.h"
#include "error.h"
#include "manager.h"
#include "adapter.h"
#include "agent.h"
#include "device.h"
#include "dbus-service.h"
#include "dbus-hci.h"

struct service_auth {
	service_auth_cb cb;
	void *user_data;
};

static void agent_auth_cb(struct agent *agent, DBusError *derr, void *user_data)
{
	struct service_auth *auth = user_data;

	auth->cb(derr, auth->user_data);

	g_free(auth);
}

int service_req_auth(const bdaddr_t *src, const bdaddr_t *dst,
		const char *uuid, service_auth_cb cb, void *user_data)
{
	struct service_auth *auth;
	struct adapter *adapter;
	struct btd_device *device;
	struct agent *agent;
	char address[18];
	gboolean trusted;
	const gchar *dev_path;

	if (src == NULL || dst == NULL)
		return -EINVAL;

	adapter = manager_find_adapter(src);
	if (!adapter)
		return -EPERM;

	/* Device connected? */
	if (!g_slist_find_custom(adapter->active_conn,
				dst, active_conn_find_by_bdaddr))
		return -ENOTCONN;

	ba2str(dst, address);
	trusted = read_trust(src, address, GLOBAL_TRUST);

	if (trusted) {
		cb(NULL, user_data);
		return 0;
	}

	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	agent = device_get_agent(device);

	if (!agent)
		agent =  adapter->agent;

	if (!agent)
		return -EPERM;

	auth = g_try_new0(struct service_auth, 1);
	if (!auth)
		return -ENOMEM;

	auth->cb = cb;
	auth->user_data = user_data;

	dev_path = device_get_path(device);

	return agent_authorize(agent, dev_path, uuid, agent_auth_cb, auth);
}

int service_cancel_auth(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct adapter *adapter = manager_find_adapter(src);
	struct btd_device *device;
	struct agent *agent;
	char address[18];

	if (!adapter)
		return -EPERM;

	ba2str(dst, address);
	device = adapter_find_device(adapter, address);
	if (!device)
		return -EPERM;

	/*
	 * FIXME: Cancel fails if authorization is requested to adapter's
	 * agent and in the meanwhile CreatePairedDevice is called.
	 */

	agent = device_get_agent(device);

	if (!agent)
		agent =  adapter->agent;

	if (!agent)
		return -EPERM;

	return agent_cancel(agent);
}
