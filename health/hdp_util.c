/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *  Authors:
 *  Santiago Carot Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#include <gdbus.h>

#include <adapter.h>
#include <stdint.h>
#include <hdp_types.h>
#include <hdp_util.h>
#include <mcap.h>

#include <sdpd.h>
#include <sdp_lib.h>

typedef gboolean (*parse_item_f)(DBusMessageIter *iter, gpointer user_data,
								GError **err);

struct dict_entry_func {
	char		*key;
	parse_item_f	func;
};

static gboolean parse_dict_entry(struct dict_entry_func dict_context[],
							DBusMessageIter *iter,
							GError **err,
							gpointer user_data)
{
	DBusMessageIter entry;
	char *key;
	int ctype, i;
	struct dict_entry_func df;

	dbus_message_iter_recurse(iter, &entry);
	ctype = dbus_message_iter_get_arg_type(&entry);
	if (ctype != DBUS_TYPE_STRING) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"Dictionary entries should have a string as key");
		return FALSE;
	}

	dbus_message_iter_get_basic(&entry, &key);
	dbus_message_iter_next(&entry);
	/* Find function and call it */
	for (i = 0, df = dict_context[0]; df.key; i++, df = dict_context[i]) {
		if (g_ascii_strcasecmp(df.key, key) == 0)
			return df.func(&entry, user_data, err);
	}

	g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"No function found for parsing value for key %s", key);
	return FALSE;
}

static gboolean parse_dict(struct dict_entry_func dict_context[],
							DBusMessageIter *iter,
							GError **err,
							gpointer user_data)
{
	int ctype;
	DBusMessageIter dict;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype != DBUS_TYPE_ARRAY) {
		g_set_error(err, HDP_ERROR, HDP_DIC_PARSE_ERROR,
					"Dictionary should be an array");
		return FALSE;
	}

	dbus_message_iter_recurse(iter, &dict);
	while ((ctype = dbus_message_iter_get_arg_type(&dict)) !=
							DBUS_TYPE_INVALID) {
		if (ctype != DBUS_TYPE_DICT_ENTRY) {
			g_set_error(err, HDP_ERROR, HDP_DIC_PARSE_ERROR,
						"Dictionary array should "
						"contain dict entries");
			return FALSE;
		}

		/* Start parsing entry */
		if (!parse_dict_entry(dict_context, &dict, err,
							user_data))
			return FALSE;
		/* Finish entry parsing */

		dbus_message_iter_next(&dict);
	}

	return TRUE;
}

static gboolean parse_data_type(DBusMessageIter *iter, gpointer data,
								GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter *value, variant;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(iter);
	value = iter;
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &variant);
		ctype = dbus_message_iter_get_arg_type(&variant);
		value = &variant;
	}

	if (ctype != DBUS_TYPE_UINT16) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"Final value for data type should be uint16");
		return FALSE;
	}

	dbus_message_iter_get_basic(value, &app->data_type);
	app->data_type_set = TRUE;
	return TRUE;
}

static gboolean parse_role(DBusMessageIter *iter, gpointer data, GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter value;
	DBusMessageIter *string;
	int ctype;
	const char *role;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &value);
		ctype = dbus_message_iter_get_arg_type(&value);
		string = &value;
	} else
		string = iter;

	if (ctype != DBUS_TYPE_STRING) {
		g_set_error(err, HDP_ERROR, HDP_UNSPECIFIED_ERROR,
				"Value data spec should be variable or string");
		return FALSE;
	}

	dbus_message_iter_get_basic(string, &role);
	if (g_ascii_strcasecmp(role, HDP_SINK_ROLE_AS_STRING) == 0)
		app->role = HDP_SINK;
	else if (g_ascii_strcasecmp(role, HDP_SOURCE_ROLE_AS_STRING) == 0)
		app->role = HDP_SOURCE;
	else {
		g_set_error(err, HDP_ERROR, HDP_UNSPECIFIED_ERROR,
			"Role value should be \"source\" or \"sink\"");
		return FALSE;
	}

	app->role_set = TRUE;
	return TRUE;
}

static gboolean parse_desc(DBusMessageIter *iter, gpointer data, GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter *string, variant;
	int ctype;
	const char *desc;

	ctype = dbus_message_iter_get_arg_type(iter);
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &variant);
		ctype = dbus_message_iter_get_arg_type(&variant);
		string = &variant;
	} else
		string = iter;

	if (ctype != DBUS_TYPE_STRING) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
				"Value data spec should be variable or string");
		return FALSE;
	}

	dbus_message_iter_get_basic(string, &desc);
	app->description = g_strdup(desc);
	return TRUE;
}

static gboolean parse_chan_type(DBusMessageIter *iter, gpointer data,
								GError **err)
{
	struct hdp_application *app = data;
	DBusMessageIter *value, variant;
	int ctype;

	ctype = dbus_message_iter_get_arg_type(iter);
	value = iter;
	if (ctype == DBUS_TYPE_VARIANT) {
		/* Get value inside the variable */
		dbus_message_iter_recurse(iter, &variant);
		ctype = dbus_message_iter_get_arg_type(&variant);
		value = &variant;
	}

	if (ctype != DBUS_TYPE_UINT16) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
			"Final value for channel type should be a uint16");
		return FALSE;
	}

	dbus_message_iter_get_basic(value, &app->data_type);
	if (app->data_type < HDP_RELIABLE_DC ||
					app->data_type > HDP_STREAMING_DC) {
		g_set_error(err, HDP_ERROR, HDP_DIC_ENTRY_PARSE_ERROR,
						"Invalid value for data type");
		return FALSE;
	}

	app->data_type_set = TRUE;
	return TRUE;
}

static struct dict_entry_func dict_parser[] = {
	{"DataType",		parse_data_type},
	{"Role",		parse_role},
	{"Description",		parse_desc},
	{"ChannelType",		parse_chan_type},
	{NULL, NULL}
};

struct hdp_application *hdp_get_app_config(DBusMessageIter *iter, GError **err)
{
	struct hdp_application *app;

	app = g_new0(struct hdp_application, 1);
	if (!parse_dict(dict_parser, iter, err, app))
		goto fail;
	if (!app->data_type_set || !app->role_set) {
		g_set_error(err, HDP_ERROR, HDP_DIC_PARSE_ERROR,
						"Mandatory fields aren't set");
		goto fail;
	}
	return app;

fail:
	g_free(app);
	return NULL;
}

static gboolean is_app_role(GSList *app_list, HdpRole role)
{
	struct hdp_application *app;
	GSList *l;

	for (l = app_list; l; l = l->next) {
		app = l->data;
		if (app->role == role)
			return TRUE;
	}

	return FALSE;
}

static gboolean set_sdp_services_uuid(sdp_record_t *record, HdpRole role)
{
	uuid_t svc_uuid_source, svc_uuid_sink;
	sdp_list_t *svc_list = NULL;

	sdp_uuid16_create(&svc_uuid_sink, HDP_SINK_SVCLASS_ID);
	sdp_uuid16_create(&svc_uuid_source, HDP_SOURCE_SVCLASS_ID);

	sdp_get_service_classes(record, &svc_list);

	if (role == HDP_SOURCE) {
		if (!sdp_list_find(svc_list, &svc_uuid_source, sdp_uuid_cmp))
			svc_list = sdp_list_append(svc_list, &svc_uuid_source);
	} else if (role == HDP_SINK) {
		if (!sdp_list_find(svc_list, &svc_uuid_sink, sdp_uuid_cmp))
			svc_list = sdp_list_append(svc_list, &svc_uuid_sink);
	}

	if (sdp_set_service_classes(record, svc_list) < 0) {
		sdp_list_free(svc_list, NULL);
		return FALSE;
	}

	sdp_list_free(svc_list, NULL);
	return TRUE;
}

static gboolean register_service_protocols(struct hdp_adapter *adapter,
						sdp_record_t *sdp_record)
{
	gboolean ret;
	uuid_t l2cap_uuid, mcap_c_uuid;
	sdp_list_t *l2cap_list, *proto_list, *mcap_list, *access_proto_list;
	sdp_data_t *psm, *mcap_ver;
	uint16_t version = MCAP_VERSION;

	/* set l2cap information */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	l2cap_list = sdp_list_append(NULL, &l2cap_uuid);
	if (!l2cap_list) {
		ret = FALSE;
		goto end;
	}

	psm = sdp_data_alloc(SDP_UINT16, &adapter->ccpsm);
	if (!psm) {
		ret = FALSE;
		goto end;
	}

	if (!sdp_list_append(l2cap_list, psm)) {
		ret = FALSE;
		goto end;
	}

	proto_list = sdp_list_append(NULL, l2cap_list);
	if (!proto_list) {
		ret = FALSE;
		goto end;
	}

	/* set mcap information */
	sdp_uuid16_create(&mcap_c_uuid, MCAP_CTRL_UUID);
	mcap_list = sdp_list_append(NULL, &mcap_c_uuid);
	if (!mcap_list) {
		ret = FALSE;
		goto end;
	}

	mcap_ver = sdp_data_alloc(SDP_UINT16, &version);
	if (!mcap_ver) {
		ret = FALSE;
		goto end;
	}

	if (!sdp_list_append( mcap_list, mcap_ver)) {
		ret = FALSE;
		goto end;
	}

	if (!sdp_list_append( proto_list, mcap_list)) {
		ret = FALSE;
		goto end;
	}

	/* attach protocol information to service record */
	access_proto_list = sdp_list_append(NULL, proto_list);
	if (!access_proto_list) {
		ret = FALSE;
		goto end;
	}

	if (sdp_set_access_protos(sdp_record, access_proto_list) < 0) {
		ret = FALSE;
		goto end;
	}
	ret = TRUE;

end:
	if (l2cap_list)
		sdp_list_free(l2cap_list, NULL);
	if (mcap_list)
		sdp_list_free(mcap_list, NULL);
	if (proto_list)
		sdp_list_free(proto_list, NULL);
	if (access_proto_list)
		sdp_list_free(access_proto_list, NULL);
	if (psm)
		sdp_data_free(psm);
	if (mcap_ver)
		sdp_data_free(mcap_ver);

	return ret;
}

static gboolean register_service_profiles(sdp_record_t *sdp_record)
{
	gboolean ret;
	sdp_list_t *profile_list;
	sdp_profile_desc_t hdp_profile;

	/* set hdp information */
	sdp_uuid16_create( &hdp_profile.uuid, HDP_SVCLASS_ID);
	hdp_profile.version = HDP_VERSION;
	profile_list = sdp_list_append(NULL, &hdp_profile);
	if (!profile_list)
		return FALSE;

	/* set profile descriptor list */
	if (sdp_set_profile_descs(sdp_record, profile_list) < 0)
		ret = FALSE;
	else
		ret = TRUE;

	sdp_list_free(profile_list, NULL);
	return ret;
}

static gboolean register_service_aditional_protocols(
						struct hdp_adapter *adapter,
						sdp_record_t *sdp_record)
{
	gboolean ret;
	uuid_t l2cap_uuid, mcap_d_uuid;
	sdp_list_t *l2cap_list, *proto_list, *mcap_list, *access_proto_list;
	sdp_data_t *psm = NULL;

	/* set l2cap information */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	l2cap_list = sdp_list_append(NULL, &l2cap_uuid);
	if (!l2cap_list) {
		ret = FALSE;
		goto end;
	}

	psm = sdp_data_alloc(SDP_UINT16, &adapter->dcpsm);
	if (!psm) {
		ret = FALSE;
		goto end;
	}

	if (!sdp_list_append(l2cap_list, psm)) {
		ret = FALSE;
		goto end;
	}

	proto_list = sdp_list_append(NULL, l2cap_list);
	if (!proto_list) {
		ret = FALSE;
		goto end;
	}

	/* set mcap information */
	sdp_uuid16_create(&mcap_d_uuid, MCAP_DATA_UUID);
	mcap_list = sdp_list_append(NULL, &mcap_d_uuid);
	if (!mcap_list) {
		ret = FALSE;
		goto end;
	}

	if (!sdp_list_append( proto_list, mcap_list)) {
		ret = FALSE;
		goto end;
	}

	/* attach protocol information to service record */
	access_proto_list = sdp_list_append(NULL, proto_list);
	if (!access_proto_list) {
		ret = FALSE;
		goto end;
	}

	if (sdp_set_add_access_protos(sdp_record, access_proto_list) < 0)
		ret = FALSE;
	else
		ret = TRUE;

end:
	if (l2cap_list)
		sdp_list_free(l2cap_list, NULL);
	if (mcap_list)
		sdp_list_free(mcap_list, NULL);
	if (proto_list)
		sdp_list_free(proto_list, NULL);
	if (access_proto_list)
		sdp_list_free(access_proto_list, NULL);
	if (psm)
		sdp_data_free(psm);

	return ret;
}

static sdp_list_t *app_to_sdplist(struct hdp_application *app)
{
	sdp_data_t *mdepid, *dtype, *role, *desc;
	sdp_list_t *f_list;

	mdepid = sdp_data_alloc(SDP_UINT8, &app->id);
	if (!mdepid)
		return NULL;

	dtype = sdp_data_alloc(SDP_UINT16, &app->data_type);
	if (!dtype)
		goto fail;

	role = sdp_data_alloc(SDP_UINT8, &app->role);
	if (!role)
		goto fail;

	if (app->description) {
		desc = sdp_data_alloc(SDP_TEXT_STR8, app->description);
		if (!desc)
			goto fail;
	}

	f_list = sdp_list_append(NULL, mdepid);
	if (!f_list)
		goto fail;

	if (!sdp_list_append(f_list, dtype))
		goto fail;

	if (!sdp_list_append(f_list, role))
		goto fail;

	if (desc)
		if (!sdp_list_append(f_list, desc))
			goto fail;

	return f_list;

fail:
	if (f_list)
		sdp_list_free(f_list, NULL);
	if (mdepid)
		sdp_data_free(mdepid);
	if (dtype)
		sdp_data_free(dtype);
	if (role)
		sdp_data_free(role);
	if (desc)
		sdp_data_free(desc);

	return NULL;
}

static gboolean register_features(struct hdp_application *app,
						sdp_list_t **sup_features)
{
	sdp_list_t *hdp_feature;

	hdp_feature = app_to_sdplist(app);
	if (!hdp_feature)
		goto fail;

	if (!*sup_features) {
		*sup_features = sdp_list_append(NULL, hdp_feature);
		if (!*sup_features)
			goto fail;
	} else if (!sdp_list_append(*sup_features, hdp_feature)) {
		goto fail;
	}

	return TRUE;

fail:
	if (hdp_feature)
		sdp_list_free(hdp_feature, (sdp_free_func_t)sdp_data_free);
	return FALSE;
}

static void free_hdp_list(void *list)
{
	sdp_list_t *hdp_list = list;

	sdp_list_free(hdp_list, (sdp_free_func_t)sdp_data_free);
}

static gboolean register_service_sup_features(GSList *app_list,
						sdp_record_t *sdp_record)
{
	GSList *l;
	sdp_list_t *sup_features = NULL;

	for (l = app_list; l; l = l->next) {
		if (!register_features(l->data, &sup_features))
			return FALSE;
	}

	if (sdp_set_supp_feat(sdp_record, sup_features) < 0) {
		sdp_list_free(sup_features, free_hdp_list);
		return FALSE;
	}

	return TRUE;
}

static gboolean register_data_exchange_spec(sdp_record_t *record)
{
	sdp_data_t *spec;
	uint8_t data_spec = DATA_EXCHANGE_SPEC_11073;
	/* As by now 11073 is the only supported we set it by default */

	spec = sdp_data_alloc(SDP_UINT8, &data_spec);
	if (!spec)
		return FALSE;

	if (sdp_attr_add(record, SDP_ATTR_DATA_EXCHANGE_SPEC, spec) < 0) {
		sdp_data_free(spec);
		return FALSE;
	}

	return TRUE;
}

static gboolean register_mcap_features(sdp_record_t *sdp_record)
{
	sdp_data_t *mcap_proc;
	uint8_t mcap_sup_proc = MCAP_SUP_PROC;

	mcap_proc = sdp_data_alloc(SDP_UINT8, &mcap_sup_proc);
	if (!mcap_proc)
		return FALSE;

	if (sdp_attr_add(sdp_record, SDP_ATTR_MCAP_SUPPORTED_PROCEDURES,
							mcap_proc) < 0) {
		sdp_data_free(mcap_proc);
		return FALSE;
	}

	return TRUE;
}

gboolean hdp_update_sdp_record(struct hdp_adapter *adapter, GSList *app_list)
{
	sdp_record_t *sdp_record;
	bdaddr_t addr;

	if (adapter->sdp_handler)
		remove_record_from_server(adapter->sdp_handler);

	if (!app_list) {
		adapter->sdp_handler = 0;
		return TRUE;
	}

	sdp_record = sdp_record_alloc();
	if (!sdp_record)
		return FALSE;

	if (adapter->sdp_handler)
		sdp_record->handle = adapter->sdp_handler;
	else
		sdp_record->handle = 0xffffffff; /* Set automatically */

	if (is_app_role(app_list, HDP_SINK))
		set_sdp_services_uuid(sdp_record, HDP_SINK);
	if (is_app_role(app_list, HDP_SOURCE))
		set_sdp_services_uuid(sdp_record, HDP_SOURCE);

	if (!register_service_protocols(adapter, sdp_record))
		goto fail;
	if (!register_service_profiles(sdp_record))
		goto fail;
	if (!register_service_aditional_protocols(adapter, sdp_record))
		goto fail;

	sdp_set_info_attr(sdp_record, HDP_SERVICE_NAME, HDP_SERVICE_PROVIDER,
							HDP_SERVICE_DSC);
	if (!register_service_sup_features(app_list, sdp_record))
		goto fail;
	if (!register_data_exchange_spec(sdp_record))
		goto fail;

	register_mcap_features(sdp_record);

	if (sdp_set_record_state(sdp_record, adapter->record_state++))
		goto fail;

	adapter_get_address(adapter->btd_adapter, &addr);

	if (add_record_to_server(&addr, sdp_record) < 0)
		goto fail;
	adapter->sdp_handler = sdp_record->handle;
	return TRUE;

fail:
	if (sdp_record)
		sdp_record_free(sdp_record);
	return FALSE;
}
