/*
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
#include "lib/bnep.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/glib-helper.h"
#include "profiles/network/bnep.h"

#include "log.h"
#include "pan.h"
#include "hal-msg.h"
#include "ipc.h"
#include "utils.h"
#include "bluetooth.h"

static bdaddr_t adapter_addr;
GSList *devices = NULL;
uint8_t local_role = HAL_PAN_ROLE_NONE;

struct pan_device {
	char		iface[16];
	bdaddr_t	dst;
	uint8_t		conn_state;
	uint8_t		role;
	GIOChannel	*io;
	guint		watch;
};

static int device_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct pan_device *dev = s;
	const bdaddr_t *dst = user_data;

	return bacmp(&dev->dst, dst);
}

static void pan_device_free(struct pan_device *dev)
{
	local_role = HAL_PAN_ROLE_NONE;

	if (dev->watch > 0) {
		g_source_remove(dev->watch);
		dev->watch = 0;
	}

	if (dev->io) {
		g_io_channel_unref(dev->io);
		dev->io = NULL;
	}

	devices = g_slist_remove(devices, dev);
	g_free(dev);
}

static void bt_pan_notify_conn_state(struct pan_device *dev, uint8_t state)
{
	struct hal_ev_pan_conn_state ev;
	char addr[18];

	if (dev->conn_state == state)
		return;

	dev->conn_state = state;
	ba2str(&dev->dst, addr);
	DBG("device %s state %u", addr, state);

	bdaddr2android(&dev->dst, ev.bdaddr);
	ev.state = state;
	ev.local_role = local_role;
	ev.remote_role = dev->role;
	ev.status = HAL_STATUS_SUCCESS;

	ipc_send_notif(HAL_SERVICE_ID_PAN, HAL_EV_PAN_CONN_STATE, sizeof(ev),
									&ev);
}

static void bt_pan_notify_ctrl_state(struct pan_device *dev, uint8_t state)
{
	struct hal_ev_pan_ctrl_state ev;

	DBG("");

	ev.state = state;
	ev.local_role = local_role;
	ev.status = HAL_STATUS_SUCCESS;
	memset(ev.name, 0, sizeof(ev.name));
	memcpy(ev.name, dev->iface, sizeof(dev->iface));

	ipc_send_notif(HAL_SERVICE_ID_PAN, HAL_EV_PAN_CTRL_STATE, sizeof(ev),
									&ev);
}

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	struct pan_device *dev = data;

	DBG("%s disconnected", dev->iface);

	bt_pan_notify_conn_state(dev, HAL_PAN_STATE_DISCONNECTED);
	pan_device_free(dev);

	return FALSE;
}

static void bnep_conn_cb(GIOChannel *chan, char *iface, int err, void *data)
{
	struct pan_device *dev = data;

	DBG("");

	if (err < 0) {
		error("bnep connect req failed: %s", strerror(-err));
		bt_pan_notify_conn_state(dev, HAL_PAN_STATE_DISCONNECTED);
		pan_device_free(dev);
		return;
	}

	memcpy(dev->iface, iface, sizeof(dev->iface));

	DBG("%s connected", dev->iface);

	bt_pan_notify_ctrl_state(dev, HAL_PAN_CTRL_ENABLED);
	bt_pan_notify_conn_state(dev, HAL_PAN_STATE_CONNECTED);

	dev->watch = g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							bnep_watchdog_cb, dev);
	g_io_channel_unref(dev->io);
	dev->io = NULL;
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct pan_device *dev = data;
	uint16_t src, dst;
	int perr, sk;

	DBG("");

	if (err) {
		error("%s", err->message);
		goto fail;
	}

	src = (local_role == HAL_PAN_ROLE_NAP) ? BNEP_SVC_NAP : BNEP_SVC_PANU;
	dst = (dev->role == HAL_PAN_ROLE_NAP) ? BNEP_SVC_NAP : BNEP_SVC_PANU;
	sk = g_io_channel_unix_get_fd(dev->io);

	perr = bnep_connect(sk, src, dst, bnep_conn_cb, dev);
	if (perr < 0) {
		error("bnep connect req failed: %s", strerror(-perr));
		goto fail;
	}

	return;

fail:
	bt_pan_notify_conn_state(dev, HAL_PAN_STATE_DISCONNECTED);
	pan_device_free(dev);
}

static void bt_pan_connect(const void *buf, uint16_t len)
{
	const struct hal_cmd_pan_connect *cmd = buf;
	struct pan_device *dev;
	uint8_t status;
	bdaddr_t dst;
	char addr[18];
	GSList *l;
	GError *gerr = NULL;

	DBG("");

	switch (cmd->local_role) {
	case HAL_PAN_ROLE_NAP:
		if (cmd->remote_role != HAL_PAN_ROLE_PANU) {
			status = HAL_STATUS_UNSUPPORTED;
			goto failed;
		}
		break;
	case HAL_PAN_ROLE_PANU:
		if (cmd->remote_role != HAL_PAN_ROLE_NAP &&
					cmd->remote_role != HAL_PAN_ROLE_PANU) {
			status = HAL_STATUS_UNSUPPORTED;
			goto failed;
		}
		break;
	default:
		status = HAL_STATUS_UNSUPPORTED;
		goto failed;
	}

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (l) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	dev = g_new0(struct pan_device, 1);
	bacpy(&dev->dst, &dst);
	local_role = cmd->local_role;
	dev->role = cmd->remote_role;

	ba2str(&dev->dst, addr);
	DBG("connecting to %s %s", addr, dev->iface);

	dev->io = bt_io_connect(connect_cb, dev, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, &adapter_addr,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_PSM, BNEP_PSM,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_OMTU, BNEP_MTU,
					BT_IO_OPT_IMTU, BNEP_MTU,
					BT_IO_OPT_INVALID);
	if (!dev->io) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_free(dev);
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	devices = g_slist_append(devices, dev);
	bt_pan_notify_conn_state(dev, HAL_PAN_STATE_CONNECTING);

	status =  HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_PAN, HAL_OP_PAN_CONNECT, status);
}

static void bt_pan_disconnect(const void *buf, uint16_t len)
{
	const struct hal_cmd_pan_disconnect *cmd = buf;
	struct pan_device *dev;
	uint8_t status;
	GSList *l;
	bdaddr_t dst;

	DBG("");

	android2bdaddr(&cmd->bdaddr, &dst);

	l = g_slist_find_custom(devices, &dst, device_cmp);
	if (!l) {
		status = HAL_STATUS_FAILED;
		goto failed;
	}

	dev = l->data;

	if (dev->watch) {
		g_source_remove(dev->watch);
		dev->watch = 0;
	}

	bnep_if_down(dev->iface);
	bnep_kill_connection(&dst);

	bt_pan_notify_conn_state(dev, HAL_PAN_STATE_DISCONNECTED);
	pan_device_free(dev);

	status = HAL_STATUS_SUCCESS;

failed:
	ipc_send_rsp(HAL_SERVICE_ID_PAN, HAL_OP_PAN_DISCONNECT, status);
}

static void bt_pan_enable(const void *buf, uint16_t len)
{
	const struct hal_cmd_pan_enable *cmd = buf;
	uint8_t status;

	switch (cmd->local_role) {
	case HAL_PAN_ROLE_PANU:
	case HAL_PAN_ROLE_NAP:
		DBG("Not Implemented");
		status  = HAL_STATUS_FAILED;
		break;
	default:
		status = HAL_STATUS_UNSUPPORTED;
		break;
	}

	ipc_send_rsp(HAL_SERVICE_ID_PAN, HAL_OP_PAN_ENABLE, status);
}

static void bt_pan_get_role(const void *buf, uint16_t len)
{
	struct hal_rsp_pan_get_role rsp;

	DBG("");

	rsp.local_role = local_role;
	ipc_send_rsp_full(HAL_SERVICE_ID_PAN, HAL_OP_PAN_GET_ROLE, sizeof(rsp),
								&rsp, -1);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_PAN_ENABLE */
	{ bt_pan_enable, false, sizeof(struct hal_cmd_pan_enable) },
	/* HAL_OP_PAN_GET_ROLE */
	{ bt_pan_get_role, false, 0 },
	/* HAL_OP_PAN_CONNECT */
	{ bt_pan_connect, false, sizeof(struct hal_cmd_pan_connect) },
	/* HAL_OP_PAN_DISCONNECT */
	{ bt_pan_disconnect, false, sizeof(struct hal_cmd_pan_disconnect) },
};

bool bt_pan_register(const bdaddr_t *addr)
{
	int err;

	DBG("");

	bacpy(&adapter_addr, addr);

	err = bnep_init();
	if (err) {
		error("bnep init failed");
		return false;
	}

	ipc_register(HAL_SERVICE_ID_PAN, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_pan_unregister(void)
{
	DBG("");

	bnep_cleanup();

	ipc_unregister(HAL_SERVICE_ID_PAN);
}
