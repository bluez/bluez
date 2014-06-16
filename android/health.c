/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
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
#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/log.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"

#include "hal-msg.h"
#include "ipc-common.h"
#include "ipc.h"
#include "utils.h"
#include "bluetooth.h"
#include "health.h"

static bdaddr_t adapter_addr;
static struct ipc *hal_ipc = NULL;
static struct queue *apps = NULL;

struct mdep_cfg {
	uint8_t role;
	uint16_t data_type;
	uint8_t channel_type;
	char *descr;

	uint8_t id; /* mdep id */
};

struct health_app {
	char *app_name;
	char *provider_name;
	char *service_name;
	char *service_descr;
	uint8_t num_of_mdep;
	struct queue *mdeps;

	uint16_t id; /* app id */
};

static void free_mdep_cfg(void *data)
{
	struct mdep_cfg *cfg = data;

	if (!cfg)
		return;

	free(cfg->descr);
	free(cfg);
}

static void free_health_app(void *data)
{
	struct health_app *app = data;

	if (!app)
		return;

	free(app->app_name);
	free(app->provider_name);
	free(app->service_name);
	free(app->service_descr);
	queue_destroy(app->mdeps, free_mdep_cfg);
	free(app);
}

static bool app_by_app_id(const void *data, const void *user_data)
{
	const struct health_app *app = data;
	uint16_t app_id = PTR_TO_INT(user_data);

	return app->id == app_id;
}

static struct health_app *create_health_app(const char *app_name,
				const char *provider, const char *srv_name,
				const char *srv_descr, uint8_t mdeps)
{
	struct health_app *app;
	static unsigned int app_id = 1;

	DBG("");

	app = new0(struct health_app, 1);
	if (!app)
		return NULL;

	app->id = app_id++;
	app->num_of_mdep = mdeps;
	app->app_name = strdup(app_name);

	if (provider) {
		app->provider_name = strdup(provider);
		if (!app->provider_name)
			goto fail;
	}

	if (srv_name) {
		app->service_name = strdup(srv_name);
		if (!app->service_name)
			goto fail;
	}

	if (srv_descr) {
		app->service_descr = strdup(srv_descr);
		if (!app->service_descr)
			goto fail;
	}

	return app;

fail:
	free_health_app(app);
	return NULL;
}

static void bt_health_register_app(const void *buf, uint16_t len)
{
	const struct hal_cmd_health_reg_app *cmd = buf;
	struct hal_rsp_health_reg_app rsp;
	struct health_app *app;
	uint16_t off;
	uint16_t app_name_len, provider_len, srv_name_len, srv_descr_len;
	char *app_name, *provider = NULL, *srv_name = NULL, *srv_descr = NULL;

	DBG("");

	if (len != sizeof(*cmd) + cmd->len ||
			cmd->app_name_off > cmd->provider_name_off ||
			cmd->provider_name_off > cmd->service_name_off ||
			cmd->service_name_off > cmd->service_descr_off ||
			cmd->service_descr_off > cmd->len) {
		error("health: Invalid register app command, terminating");
		raise(SIGTERM);
		return;
	}

	app_name = (char *) cmd->data;
	app_name_len = cmd->provider_name_off - cmd->app_name_off;

	off = app_name_len;
	provider_len = cmd->service_name_off - off;
	if (provider_len > 0)
		provider = (char *) cmd->data + off;

	off += provider_len;
	srv_name_len = cmd->service_descr_off - off;
	if (srv_name_len > 0)
		srv_name = (char *) cmd->data + off;

	off += srv_name_len;
	srv_descr_len = cmd->len - off;
	if (srv_descr_len > 0)
		srv_descr = (char *) cmd->data + off;

	app = create_health_app(app_name, provider, srv_name, srv_descr,
							cmd->num_of_mdep);

	if (!queue_push_tail(apps, app))
		goto fail;

	rsp.app_id = app->id;
	ipc_send_rsp_full(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_REG_APP,
							sizeof(rsp), &rsp, -1);
	return;

fail:
	free_health_app(app);
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_MDEP,
							HAL_STATUS_FAILED);
}

static void bt_health_mdep_cfg_data(const void *buf, uint16_t len)
{
	const struct hal_cmd_health_mdep *cmd = buf;
	struct health_app *app;
	struct mdep_cfg *mdep = NULL;
	uint8_t status;

	DBG("");

	app = queue_find(apps, app_by_app_id, INT_TO_PTR(cmd->app_id));
	if (!app) {
		status = HAL_STATUS_INVALID;
		goto fail;
	}

	mdep = new0(struct mdep_cfg, 1);
	if (!mdep) {
		status = HAL_STATUS_INVALID;
		goto fail;
	}

	mdep->role = cmd->role;
	mdep->data_type = cmd->data_type;
	mdep->channel_type = cmd->channel_type;
	mdep->id = queue_length(app->mdeps) + 1;

	if (cmd->descr_len > 0) {
		mdep->descr = malloc0(cmd->descr_len);
		memcpy(mdep->descr, cmd->descr, cmd->descr_len);
	}

	if (app->num_of_mdep > 0 && !app->mdeps) {
		app->mdeps = queue_new();
		if (!app->mdeps) {
			status = HAL_STATUS_FAILED;
			goto fail;
		}
	}

	if (!queue_push_tail(app->mdeps, mdep)) {
		status = HAL_STATUS_FAILED;
		goto fail;
	}

	if (app->num_of_mdep != queue_length(app->mdeps))
		goto send_rsp;

	/* TODO: Create MCAP instance and prepare SDP profile */
send_rsp:
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_MDEP,
							HAL_STATUS_SUCCESS);
	return;

fail:
	if (status != HAL_STATUS_SUCCESS) {
		free_mdep_cfg(mdep);
		queue_remove(apps, app);
		free_health_app(app);
	}

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_MDEP,
								status);
}

static void bt_health_unregister_app(const void *buf, uint16_t len)
{
	const struct hal_cmd_health_unreg_app *cmd = buf;
	struct health_app *app;

	DBG("");

	app = queue_remove_if(apps, app_by_app_id, INT_TO_PTR(cmd->app_id));
	if (!app) {
		ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
				HAL_OP_HEALTH_UNREG_APP, HAL_STATUS_INVALID);
		return;
	}

	free_health_app(app);
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
				HAL_OP_HEALTH_UNREG_APP, HAL_STATUS_SUCCESS);
}

static void bt_health_connect_channel(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
			HAL_OP_HEALTH_CONNECT_CHANNEL, HAL_STATUS_UNSUPPORTED);
}

static void bt_health_destroy_channel(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
			HAL_OP_HEALTH_DESTROY_CHANNEL, HAL_STATUS_UNSUPPORTED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_HEALTH_REG_APP */
	{ bt_health_register_app, true,
				sizeof(struct hal_cmd_health_reg_app) },
	/* HAL_OP_HEALTH_MDEP */
	{ bt_health_mdep_cfg_data, true,
				sizeof(struct hal_cmd_health_mdep) },
	/* HAL_OP_HEALTH_UNREG_APP */
	{ bt_health_unregister_app, false,
				sizeof(struct hal_cmd_health_unreg_app) },
	/* HAL_OP_HEALTH_CONNECT_CHANNEL */
	{ bt_health_connect_channel, false,
				sizeof(struct hal_cmd_health_connect_channel) },
	/* HAL_OP_HEALTH_DESTROY_CHANNEL */
	{ bt_health_destroy_channel, false,
				sizeof(struct hal_cmd_health_destroy_channel) },
};

bool bt_health_register(struct ipc *ipc, const bdaddr_t *addr, uint8_t mode)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	hal_ipc = ipc;
	apps = queue_new();
	if (!apps)
		return false;

	ipc_register(hal_ipc, HAL_SERVICE_ID_HEALTH, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_health_unregister(void)
{
	DBG("");

	queue_destroy(apps, free_health_app);
	ipc_unregister(hal_ipc, HAL_SERVICE_ID_HEALTH);
	hal_ipc = NULL;
}
