/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
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

#include "btio/btio.h"
#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "lib/uuid.h"
#include "lib/l2cap.h"
#include "src/log.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/uuid-helper.h"
#include "src/sdp-client.h"

#include "hal-msg.h"
#include "ipc-common.h"
#include "ipc.h"
#include "utils.h"
#include "bluetooth.h"
#include "health.h"
#include "mcap-lib.h"

#define SVC_HINT_HEALTH			0x00
#define HDP_VERSION			0x0101
#define DATA_EXCHANGE_SPEC_11073	0x01

#define CHANNEL_TYPE_ANY       0x00
#define CHANNEL_TYPE_RELIABLE  0x01
#define CHANNEL_TYPE_STREAM    0x02

static bdaddr_t adapter_addr;
static struct ipc *hal_ipc = NULL;
static struct queue *apps = NULL;
static struct mcap_instance *mcap = NULL;
static uint32_t record_id = 0;
static uint32_t record_state = 0;

struct mdep_cfg {
	uint8_t role;
	uint16_t data_type;
	uint8_t channel_type;
	char *descr;

	uint8_t id; /* mdep id */
};

struct health_device {
	bdaddr_t dst;
	uint16_t app_id;

	struct mcap_mcl *mcl;
	bool mcl_conn;

	struct queue *channels;     /* data channels */

	uint16_t ccpsm;
	uint16_t dcpsm;
};

struct health_channel {
	uint8_t mdep_id;
	uint8_t type;

	struct health_device *dev;

	uint16_t id; /* channel id */
};

struct health_app {
	char *app_name;
	char *provider_name;
	char *service_name;
	char *service_descr;
	uint8_t num_of_mdep;
	struct queue *mdeps;

	uint16_t id; /* app id */
	struct queue *devices;
};

static void free_health_channel(void *data)
{
	struct health_channel *channel = data;

	if (!channel)
		return;

	free(channel);
}

static void destroy_channel(void *data)
{
	struct health_channel *channel = data;

	if (!channel)
		return;

	/* TODO: Notify channel connection status DESTROYED */
	queue_remove(channel->dev->channels, channel);
	free_health_channel(channel);
}

static void unref_mcl(struct health_device *dev)
{
	if (!dev || !dev->mcl)
		return;

	mcap_close_mcl(dev->mcl, FALSE);
	mcap_mcl_unref(dev->mcl);
	dev->mcl = NULL;
	dev->mcl_conn = false;
}

static void free_health_device(void *data)
{
	struct health_device *dev = data;

	if (!dev)
		return;

	unref_mcl(dev);
	queue_destroy(dev->channels, free_health_channel);
	free(dev);
}

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
	queue_destroy(app->devices, free_health_device);
	free(app);
}

static void send_app_reg_notify(struct health_app *app, uint8_t state)
{
	struct hal_ev_health_app_reg_state ev;

	DBG("");

	ev.id = app->id;
	ev.state = state;

	ipc_send_notif(hal_ipc, HAL_SERVICE_ID_HEALTH,
				HAL_EV_HEALTH_APP_REG_STATE, sizeof(ev), &ev);
}

static void send_channel_state_notify(struct health_channel *channel,
						uint8_t state, int fd)
{
	struct hal_ev_health_channel_state ev;

	DBG("");

	bdaddr2android(&channel->dev->dst, ev.bdaddr);
	ev.app_id = channel->dev->app_id;
	ev.mdep_index = channel->mdep_id;
	ev.channel_id = channel->id;
	ev.channel_state = state;

	ipc_send_notif_with_fd(hal_ipc, HAL_SERVICE_ID_HEALTH,
					HAL_EV_HEALTH_CHANNEL_STATE,
					sizeof(ev), &ev, fd);
}

static bool mdep_by_mdep_role(const void *data, const void *user_data)
{
	const struct mdep_cfg *mdep = data;
	uint16_t role = PTR_TO_INT(user_data);

	return mdep->role == role;
}

static bool mdep_by_mdep_id(const void *data, const void *user_data)
{
	const struct mdep_cfg *mdep = data;
	uint16_t mdep_id = PTR_TO_INT(user_data);

	return mdep->id == mdep_id;
}

static bool app_by_app_id(const void *data, const void *user_data)
{
	const struct health_app *app = data;
	uint16_t app_id = PTR_TO_INT(user_data);

	return app->id == app_id;
}

static int register_service_protocols(sdp_record_t *rec,
					struct health_app *app)
{
	uuid_t l2cap_uuid, mcap_c_uuid;
	sdp_list_t *l2cap_list, *proto_list = NULL, *mcap_list = NULL;
	sdp_list_t *access_proto_list = NULL;
	sdp_data_t *psm = NULL, *mcap_ver = NULL;
	uint32_t ccpsm;
	uint16_t version = MCAP_VERSION;
	GError *err = NULL;
	int ret = -1;

	DBG("");

	/* set l2cap information */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	l2cap_list = sdp_list_append(NULL, &l2cap_uuid);
	if (!l2cap_list)
		goto fail;

	ccpsm = mcap_get_ctrl_psm(mcap, &err);
	if (err)
		goto fail;

	psm = sdp_data_alloc(SDP_UINT16, &ccpsm);
	if (!psm)
		goto fail;

	if (!sdp_list_append(l2cap_list, psm))
		goto fail;

	proto_list = sdp_list_append(NULL, l2cap_list);
	if (!proto_list)
		goto fail;

	/* set mcap information */
	sdp_uuid16_create(&mcap_c_uuid, MCAP_CTRL_UUID);
	mcap_list = sdp_list_append(NULL, &mcap_c_uuid);
	if (!mcap_list)
		goto fail;

	mcap_ver = sdp_data_alloc(SDP_UINT16, &version);
	if (!mcap_ver)
		goto fail;

	if (!sdp_list_append(mcap_list, mcap_ver))
		goto fail;

	if (!sdp_list_append(proto_list, mcap_list))
		goto fail;

	/* attach protocol information to service record */
	access_proto_list = sdp_list_append(NULL, proto_list);
	if (!access_proto_list)
		goto fail;

	sdp_set_access_protos(rec, access_proto_list);
	ret = 0;

fail:
	sdp_list_free(l2cap_list, NULL);
	sdp_list_free(mcap_list, NULL);
	sdp_list_free(proto_list, NULL);
	sdp_list_free(access_proto_list, NULL);

	if (psm)
		sdp_data_free(psm);

	if (mcap_ver)
		sdp_data_free(mcap_ver);

	if (err)
		g_error_free(err);

	return ret;
}

static int register_service_profiles(sdp_record_t *rec)
{
	int ret;
	sdp_list_t *profile_list;
	sdp_profile_desc_t hdp_profile;

	DBG("");

	/* set hdp information */
	sdp_uuid16_create(&hdp_profile.uuid, HDP_SVCLASS_ID);
	hdp_profile.version = HDP_VERSION;
	profile_list = sdp_list_append(NULL, &hdp_profile);
	if (!profile_list)
		return -1;

	/* set profile descriptor list */
	ret = sdp_set_profile_descs(rec, profile_list);
	sdp_list_free(profile_list, NULL);

	return ret;
}

static int register_service_additional_protocols(sdp_record_t *rec,
						struct health_app *app)
{
	int ret = -1;
	uuid_t l2cap_uuid, mcap_d_uuid;
	sdp_list_t *l2cap_list, *proto_list = NULL, *mcap_list = NULL;
	sdp_list_t *access_proto_list = NULL;
	sdp_data_t *psm = NULL;
	uint32_t dcpsm;
	GError *err = NULL;

	DBG("");

	/* set l2cap information */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	l2cap_list = sdp_list_append(NULL, &l2cap_uuid);
	if (!l2cap_list)
		goto fail;

	dcpsm = mcap_get_ctrl_psm(mcap, &err);
	if (err)
		goto fail;

	psm = sdp_data_alloc(SDP_UINT16, &dcpsm);
	if (!psm)
		goto fail;

	if (!sdp_list_append(l2cap_list, psm))
		goto fail;

	proto_list = sdp_list_append(NULL, l2cap_list);
	if (!proto_list)
		goto fail;

	/* set mcap information */
	sdp_uuid16_create(&mcap_d_uuid, MCAP_DATA_UUID);
	mcap_list = sdp_list_append(NULL, &mcap_d_uuid);
	if (!mcap_list)
		goto fail;

	if (!sdp_list_append(proto_list, mcap_list))
		goto fail;

	/* attach protocol information to service record */
	access_proto_list = sdp_list_append(NULL, proto_list);
	if (!access_proto_list)
		goto fail;

	sdp_set_add_access_protos(rec, access_proto_list);
	ret = 0;

fail:
	sdp_list_free(l2cap_list, NULL);
	sdp_list_free(mcap_list, NULL);
	sdp_list_free(proto_list, NULL);
	sdp_list_free(access_proto_list, NULL);

	if (psm)
		sdp_data_free(psm);

	if (err)
		g_error_free(err);

	return ret;
}

static sdp_list_t *mdeps_to_sdp_features(struct mdep_cfg *mdep)
{
	sdp_data_t *mdepid, *dtype = NULL, *role = NULL, *descr = NULL;
	sdp_list_t *f_list = NULL;

	DBG("");

	mdepid = sdp_data_alloc(SDP_UINT8, &mdep->id);
	if (!mdepid)
		return NULL;

	dtype = sdp_data_alloc(SDP_UINT16, &mdep->data_type);
	if (!dtype)
		goto fail;

	role = sdp_data_alloc(SDP_UINT8, &mdep->role);
	if (!role)
		goto fail;

	if (mdep->descr) {
		descr = sdp_data_alloc(SDP_TEXT_STR8, mdep->descr);
		if (!descr)
			goto fail;
	}

	f_list = sdp_list_append(NULL, mdepid);
	if (!f_list)
		goto fail;

	if (!sdp_list_append(f_list, dtype))
		goto fail;

	if (!sdp_list_append(f_list, role))
		goto fail;

	if (descr && !sdp_list_append(f_list, descr))
		goto fail;

	return f_list;

fail:
	sdp_list_free(f_list, NULL);

	if (mdepid)
		sdp_data_free(mdepid);

	if (dtype)
		sdp_data_free(dtype);

	if (role)
		sdp_data_free(role);

	if (descr)
		sdp_data_free(descr);

	return NULL;
}

static void free_hdp_list(void *list)
{
	sdp_list_t *hdp_list = list;

	sdp_list_free(hdp_list, (sdp_free_func_t)sdp_data_free);
}

static void register_features(void *data, void *user_data)
{
	struct mdep_cfg *mdep = data;
	sdp_list_t **sup_features = user_data;
	sdp_list_t *hdp_feature;

	DBG("");

	hdp_feature = mdeps_to_sdp_features(mdep);
	if (!hdp_feature)
		return;

	if (!*sup_features) {
		*sup_features = sdp_list_append(NULL, hdp_feature);
		if (!*sup_features)
			sdp_list_free(hdp_feature,
					(sdp_free_func_t)sdp_data_free);
	} else if (!sdp_list_append(*sup_features, hdp_feature)) {
		sdp_list_free(hdp_feature,
					(sdp_free_func_t)sdp_data_free);
	}
}

static int register_service_sup_features(sdp_record_t *rec,
						struct health_app *app)
{
	sdp_list_t *sup_features = NULL;

	DBG("");

	queue_foreach(app->mdeps, register_features, &sup_features);
	if (!sup_features)
		return -1;

	if (sdp_set_supp_feat(rec, sup_features) < 0) {
		sdp_list_free(sup_features, free_hdp_list);
		return -1;
	}

	sdp_list_free(sup_features, free_hdp_list);
	return 0;
}

static int register_data_exchange_spec(sdp_record_t *rec)
{
	sdp_data_t *spec;
	uint8_t data_spec = DATA_EXCHANGE_SPEC_11073;
	/* As of now only 11073 is supported, so we set it as default */

	DBG("");

	spec = sdp_data_alloc(SDP_UINT8, &data_spec);
	if (!spec)
		return -1;

	if (sdp_attr_add(rec, SDP_ATTR_DATA_EXCHANGE_SPEC, spec) < 0) {
		sdp_data_free(spec);
		return -1;
	}

	return 0;
}

static int register_mcap_features(sdp_record_t *rec)
{
	sdp_data_t *mcap_proc;
	uint8_t mcap_sup_proc = MCAP_SUP_PROC;

	DBG("");

	mcap_proc = sdp_data_alloc(SDP_UINT8, &mcap_sup_proc);
	if (!mcap_proc)
		return -1;

	if (sdp_attr_add(rec, SDP_ATTR_MCAP_SUPPORTED_PROCEDURES,
							mcap_proc) < 0) {
		sdp_data_free(mcap_proc);
		return -1;
	}

	return 0;
}

static int set_sdp_services_uuid(sdp_record_t *rec, uint8_t role)
{
	uuid_t source, sink;
	sdp_list_t *list = NULL;

	sdp_uuid16_create(&sink, HDP_SINK_SVCLASS_ID);
	sdp_uuid16_create(&source, HDP_SOURCE_SVCLASS_ID);
	sdp_get_service_classes(rec, &list);

	switch (role) {
	case HAL_HEALTH_MDEP_ROLE_SOURCE:
		if (!sdp_list_find(list, &source, sdp_uuid_cmp))
			list = sdp_list_append(list, &source);
		break;
	case HAL_HEALTH_MDEP_ROLE_SINK:
		if (!sdp_list_find(list, &sink, sdp_uuid_cmp))
			list = sdp_list_append(list, &sink);
		break;
	}

	if (sdp_set_service_classes(rec, list) < 0) {
		sdp_list_free(list, NULL);
		return -1;
	}

	sdp_list_free(list, NULL);

	return 0;
}

static int update_sdp_record(struct health_app *app)
{
	sdp_record_t *rec;
	uint8_t role;

	DBG("");

	if (record_id > 0) {
		bt_adapter_remove_record(record_id);
		record_id = 0;
	}

	rec = sdp_record_alloc();
	if (!rec)
		return -1;

	role = HAL_HEALTH_MDEP_ROLE_SOURCE;
	if (queue_find(app->mdeps, mdep_by_mdep_role, INT_TO_PTR(role)))
		set_sdp_services_uuid(rec, role);

	role = HAL_HEALTH_MDEP_ROLE_SINK;
	if (queue_find(app->mdeps, mdep_by_mdep_role, INT_TO_PTR(role)))
		set_sdp_services_uuid(rec, role);

	sdp_set_info_attr(rec, app->service_name, app->provider_name,
							app->service_descr);

	if (register_service_protocols(rec, app) < 0)
		goto fail;

	if (register_service_profiles(rec) < 0)
		goto fail;

	if (register_service_additional_protocols(rec, app) < 0)
		goto fail;

	if (register_service_sup_features(rec, app) < 0)
		goto fail;

	if (register_data_exchange_spec(rec) < 0)
		goto fail;

	if (register_mcap_features(rec) < 0)
		goto fail;

	if (sdp_set_record_state(rec, record_state++) < 0)
		goto fail;

	if (bt_adapter_add_record(rec, SVC_HINT_HEALTH) < 0) {
		error("Failed to register HEALTH record");
		goto fail;
	}

	record_id = rec->handle;

	return 0;

fail:
	sdp_record_free(rec);

	return -1;
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

static uint8_t android2channel_type(uint8_t type)
{
	switch (type) {
	case HAL_HEALTH_CHANNEL_TYPE_RELIABLE:
		return CHANNEL_TYPE_RELIABLE;
	case HAL_HEALTH_CHANNEL_TYPE_STREAMING:
		return CHANNEL_TYPE_STREAM;
	default:
		return CHANNEL_TYPE_ANY;
	}
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
	mdep->channel_type = android2channel_type(cmd->channel_type);
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

	/* add sdp record from app configuration data */
	/*
	 * TODO: Check what to be done if mupltple applications are trying to
	 * register with different role and different configurations.
	 * 1) Does device supports SOURCE and SINK at the same time ?
	 * 2) Does it require different SDP records or one record with
	 *    multile MDEP configurations ?
	 */
	if (update_sdp_record(app) < 0) {
		error("Error creating HDP SDP record");
		status = HAL_STATUS_FAILED;
		goto fail;
	}

	send_app_reg_notify(app, HAL_HEALTH_APP_REG_SUCCESS);

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

	send_app_reg_notify(app, HAL_HEALTH_APP_DEREG_SUCCESS);

	if (record_id > 0) {
		bt_adapter_remove_record(record_id);
		record_id = 0;
	}

	free_health_app(app);
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
				HAL_OP_HEALTH_UNREG_APP, HAL_STATUS_SUCCESS);
}

static int get_prot_desc_entry(sdp_data_t *entry, int type, guint16 *val)
{
	sdp_data_t *iter;
	int proto;

	if (!entry || !SDP_IS_SEQ(entry->dtd))
		return -1;

	iter = entry->val.dataseq;
	if (!(iter->dtd & SDP_UUID_UNSPEC))
		return -1;

	proto = sdp_uuid_to_proto(&iter->val.uuid);
	if (proto != type)
		return -1;

	if (!val)
		return 0;

	iter = iter->next;
	if (iter->dtd != SDP_UINT16)
		return -1;

	*val = iter->val.uint16;

	return 0;
}

static int get_prot_desc_list(const sdp_record_t *rec, uint16_t *psm,
							uint16_t *version)
{
	sdp_data_t *pdl, *p0, *p1;

	if (!psm && !version)
		return -1;

	pdl = sdp_data_get(rec, SDP_ATTR_PROTO_DESC_LIST);
	if (!pdl || !SDP_IS_SEQ(pdl->dtd))
		return -1;

	p0 = pdl->val.dataseq;
	if (get_prot_desc_entry(p0, L2CAP_UUID, psm) < 0)
		return -1;

	p1 = p0->next;
	if (get_prot_desc_entry(p1, MCAP_CTRL_UUID, version) < 0)
		return -1;

	return 0;
}

static int get_ccpsm(sdp_list_t *recs, uint16_t *ccpsm)
{
	sdp_list_t *l;

	for (l = recs; l; l = l->next) {
		sdp_record_t *rec = l->data;

		if (!get_prot_desc_list(rec, ccpsm, NULL))
			return 0;
	}

	return -1;
}

static int get_add_prot_desc_list(const sdp_record_t *rec, uint16_t *psm)
{
	sdp_data_t *pdl, *p0, *p1;

	if (!psm)
		return -1;

	pdl = sdp_data_get(rec, SDP_ATTR_ADD_PROTO_DESC_LIST);
	if (!pdl || pdl->dtd != SDP_SEQ8)
		return -1;

	pdl = pdl->val.dataseq;
	if (pdl->dtd != SDP_SEQ8)
		return -1;

	p0 = pdl->val.dataseq;

	if (get_prot_desc_entry(p0, L2CAP_UUID, psm) < 0)
		return -1;

	p1 = p0->next;
	if (get_prot_desc_entry(p1, MCAP_DATA_UUID, NULL) < 0)
		return -1;

	return 0;
}

static int get_dcpsm(sdp_list_t *recs, uint16_t *dcpsm)
{
	sdp_list_t *l;

	for (l = recs; l; l = l->next) {
		sdp_record_t *rec = l->data;

		if (!get_add_prot_desc_list(rec, dcpsm))
			return 0;
	}

	return -1;
}

static void mcap_mdl_connected_cb(struct mcap_mdl *mdl, void *data)
{
	DBG("Not Implemeneted");
}

static void mcap_mdl_closed_cb(struct mcap_mdl *mdl, void *data)
{
	DBG("Not Implemeneted");
}

static void mcap_mdl_deleted_cb(struct mcap_mdl *mdl, void *data)
{
	DBG("Not Implemeneted");
}

static void mcap_mdl_aborted_cb(struct mcap_mdl *mdl, void *data)
{
	DBG("Not Implemeneted");
}

static void mcap_mdl_conn_req_cb(struct mcap_mcl *mcl, uint8_t mdepid,
				uint16_t mdlid, uint8_t *conf, void *data)
{
	DBG("Not Implemeneted");
}

static void mcap_mdl_reconn_req_cb(struct mcap_mdl *mdl, void *data)
{
	DBG("Not Implemeneted");
}

static void create_mcl_cb(struct mcap_mcl *mcl, GError *err, gpointer data)
{
	struct health_channel *channel = data;
	gboolean ret;
	GError *gerr = NULL;

	DBG("");

	if (err) {
		error("error creating MCL : %s", err->message);
		goto fail;
	}

	if (!channel->dev->mcl)
		channel->dev->mcl = mcap_mcl_ref(mcl);

	channel->dev->mcl_conn = true;
	DBG("MCL connected");

	ret = mcap_mcl_set_cb(channel->dev->mcl, channel, &gerr,
			MCAP_MDL_CB_CONNECTED, mcap_mdl_connected_cb,
			MCAP_MDL_CB_CLOSED, mcap_mdl_closed_cb,
			MCAP_MDL_CB_DELETED, mcap_mdl_deleted_cb,
			MCAP_MDL_CB_ABORTED, mcap_mdl_aborted_cb,
			MCAP_MDL_CB_REMOTE_CONN_REQ, mcap_mdl_conn_req_cb,
			MCAP_MDL_CB_REMOTE_RECONN_REQ, mcap_mdl_reconn_req_cb,
			MCAP_MDL_CB_INVALID);
	if (!ret) {
		error("error setting mdl callbacks on mcl");

		if (gerr)
			g_error_free(gerr);

		goto fail;
	}

	/* TODO : create mdl */
	return;

fail:
	destroy_channel(channel);
}

static void search_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct health_channel *channel = data;
	GError *gerr = NULL;

	DBG("");

	if (err < 0 || !recs) {
		error("Error getting remote SDP records");
		goto fail;
	}

	if (get_ccpsm(recs, &channel->dev->ccpsm) < 0) {
		error("Can't get remote PSM for control channel");
		goto fail;
	}

	if (get_dcpsm(recs, &channel->dev->dcpsm) < 0) {
		error("Can't get remote PSM for data channel");
		goto fail;
	}

	if (!mcap_create_mcl(mcap, &channel->dev->dst, channel->dev->ccpsm,
					create_mcl_cb, channel, NULL, &gerr)) {
		error("error creating mcl %s", gerr->message);

		if (gerr)
			g_error_free(gerr);

		goto fail;
	}

	send_channel_state_notify(channel, HAL_HEALTH_CHANNEL_CONNECTING, -1);
	return;

fail:
	send_channel_state_notify(channel, HAL_HEALTH_CHANNEL_DESTROYED, -1);

	queue_remove(channel->dev->channels, channel);
	free_health_channel(channel);
}

static int connect_mcl(struct health_channel *channel)
{
	uuid_t uuid;

	DBG("");

	bt_string2uuid(&uuid, HDP_UUID);

	return bt_search_service(&adapter_addr, &channel->dev->dst, &uuid,
						search_cb, channel, NULL, 0);
}

static struct health_device *create_device(uint16_t app_id, const uint8_t *addr)
{
	struct health_device *dev;

	dev = new0(struct health_device, 1);
	if (!dev)
		return NULL;

	android2bdaddr(addr, &dev->dst);
	dev->app_id = app_id;

	return dev;
}

static struct health_channel *create_channel(uint16_t app_id,
						uint8_t mdep_index)
{
	struct health_app *app;
	struct mdep_cfg *mdep;
	struct health_channel *channel;
	uint8_t index;
	static unsigned int channel_id = 1;

	app = queue_find(apps, app_by_app_id, INT_TO_PTR(app_id));
	if (!app)
		return NULL;

	index = mdep_index + 1;
	mdep = queue_find(app->mdeps, mdep_by_mdep_id, INT_TO_PTR(index));
	if (!mdep)
		return NULL;

	channel = new0(struct health_channel, 1);
	if (!channel)
		return NULL;

	channel->mdep_id = mdep_index;
	channel->type = mdep->channel_type;
	channel->id = channel_id++;

	return channel;
}

static void bt_health_connect_channel(const void *buf, uint16_t len)
{
	const struct hal_cmd_health_connect_channel *cmd = buf;
	struct hal_rsp_health_connect_channel rsp;
	struct health_app *app;
	struct health_device *dev = NULL;
	struct health_channel *channel = NULL;

	DBG("");

	app = queue_find(apps, app_by_app_id, INT_TO_PTR(cmd->app_id));
	if (!app)
		goto fail;

	dev = create_device(cmd->app_id, cmd->bdaddr);
	if (!dev)
		goto fail;

	channel = create_channel(cmd->app_id, cmd->mdep_index);
	if (!channel)
		goto fail;

	channel->dev = dev;

	if (!app->devices) {
		app->devices = queue_new();
		if (!app->devices)
			goto fail;
	}

	if (!queue_push_tail(app->devices, dev))
		goto fail;

	if (!dev->channels) {
		dev->channels = queue_new();
		if (!dev->channels)
			goto fail;
	}

	if (!queue_push_tail(dev->channels, channel)) {
		queue_remove(app->devices, dev);
		goto fail;
	}

	if (connect_mcl(channel) < 0) {
		error("error retrieving HDP SDP record");
		queue_remove(app->devices, dev);
		goto fail;
	}

	rsp.channel_id = channel->id;
	ipc_send_rsp_full(hal_ipc, HAL_SERVICE_ID_HEALTH,
				HAL_OP_HEALTH_CONNECT_CHANNEL,
				sizeof(rsp), &rsp, -1);
	return;

fail:
	free_health_channel(channel);
	free_health_device(dev);
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
			HAL_OP_HEALTH_CONNECT_CHANNEL, HAL_STATUS_FAILED);
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

static void mcl_connected(struct mcap_mcl *mcl, gpointer data)
{
	DBG("Not implemented");
}

static void mcl_reconnected(struct mcap_mcl *mcl, gpointer data)
{
	DBG("Not implemented");
}

static void mcl_disconnected(struct mcap_mcl *mcl, gpointer data)
{
	DBG("Not implemented");
}

static void mcl_uncached(struct mcap_mcl *mcl, gpointer data)
{
	DBG("Not implemented");
}

bool bt_health_register(struct ipc *ipc, const bdaddr_t *addr, uint8_t mode)
{
	GError *err = NULL;

	DBG("");

	bacpy(&adapter_addr, addr);

	mcap = mcap_create_instance(&adapter_addr, BT_IO_SEC_MEDIUM, 0, 0,
					mcl_connected, mcl_reconnected,
					mcl_disconnected, mcl_uncached,
					NULL, /* CSP is not used right now */
					NULL, &err);

	if (!mcap) {
		error("Error creating MCAP instance : %s", err->message);
		g_error_free(err);
		return false;
	}

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

	mcap_instance_unref(mcap);
	queue_destroy(apps, free_health_app);
	ipc_unregister(hal_ipc, HAL_SERVICE_ID_HEALTH);
	hal_ipc = NULL;
}
