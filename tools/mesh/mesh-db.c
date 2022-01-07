// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019-2020  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <ell/ell.h>
#include <json-c/json.h>

#include "mesh/mesh-defs.h"
#include "mesh/util.h"

#include "tools/mesh/keys.h"
#include "tools/mesh/remote.h"
#include "tools/mesh/cfgcli.h"
#include "tools/mesh/model.h"
#include "tools/mesh/mesh-db.h"

#define KEY_IDX_INVALID NET_IDX_INVALID
#define DEFAULT_LOCATION 0x0000

struct mesh_db {
	json_object *jcfg;
	char *cfg_fname;
	uint8_t token[8];
};

static struct mesh_db *cfg;
static const char *bak_ext = ".bak";
static const char *tmp_ext = ".tmp";

static const char *js_schema = "http://json-schema.org/draft-04/schema#";
static const char *schema_id = "http://www.bluetooth.com/specifications/"
				"assigned-numbers/mesh-profile/"
				"cdb-schema.json#";
const char *schema_version = "1.0.0";


static bool add_string(json_object *jobj, const char *desc, const char *str)
{
	json_object *jstring = json_object_new_string(str);

	if (!jstring)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, desc);

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static bool set_timestamp(json_object *jobj)
{
	time_t time_raw;
	struct tm *tp;
	char buf[80];

	time(&time_raw);
	tp = gmtime(&time_raw);

	strftime(buf, 80, "%FT%TZ", tp);

	return add_string(jobj, "timestamp", buf);
}

static bool save_config_file(const char *fname)
{
	FILE *outfile;
	const char *str;
	bool result = false;

	outfile = fopen(fname, "w");
	if (!outfile) {
		l_error("Failed to save configuration to %s", cfg->cfg_fname);
		return false;
	}

	set_timestamp(cfg->jcfg);

	str = json_object_to_json_string_ext(cfg->jcfg,
						JSON_C_TO_STRING_PRETTY);

	if (fwrite(str, sizeof(char), strlen(str), outfile) < strlen(str))
		l_warn("Incomplete write of mesh configuration");
	else
		result = true;

	fclose(outfile);

	return result;
}

static bool save_config(void)
{
	char *fname_tmp, *fname_bak, *fname_cfg;
	bool result = false;

	fname_cfg = cfg->cfg_fname;
	fname_tmp = l_strdup_printf("%s%s", fname_cfg, tmp_ext);
	fname_bak = l_strdup_printf("%s%s", fname_cfg, bak_ext);
	remove(fname_tmp);

	result = save_config_file(fname_tmp);

	if (result) {
		remove(fname_bak);
		rename(fname_cfg, fname_bak);
		rename(fname_tmp, fname_cfg);
	}

	remove(fname_tmp);

	l_free(fname_tmp);
	l_free(fname_bak);

	return result;
}

static void release_config(void)
{
	l_free(cfg->cfg_fname);
	json_object_put(cfg->jcfg);
	l_free(cfg);
	cfg = NULL;
}

static json_object *get_node_by_unicast(json_object *jcfg, uint16_t unicast)
{
	json_object *jarray;
	int i, sz;

	if (!json_object_object_get_ex(jcfg, "nodes", &jarray))
		return NULL;

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return NULL;

	sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		uint16_t addr;
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "unicastAddress",
								&jval))
			return NULL;

		str = json_object_get_string(jval);
		if (sscanf(str, "%04hx", &addr) != 1)
			continue;

		if (addr == unicast)
			return jentry;
	}

	return NULL;
}

static bool get_int(json_object *jobj, const char *keyword, int *value)
{
	json_object *jvalue;

	if (!json_object_object_get_ex(jobj, keyword, &jvalue))
		return false;

	*value = json_object_get_int(jvalue);
	if (errno == EINVAL) {
		l_error("Error: %s should contain an integer value\n",
								keyword);
		return false;
	}

	return true;
}

static bool write_int(json_object *jobj, const char *keyword, int val)
{
	json_object *jval;

	jval = json_object_new_int(val);
	if (!jval)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, keyword);

	json_object_object_add(jobj, keyword, jval);
	return true;
}

static bool get_bool(json_object *jobj, const char *keyword, bool *value)
{
	json_object *jvalue;

	if (!json_object_object_get_ex(jobj, keyword, &jvalue))
		return false;

	if (json_object_get_type(jvalue) != json_type_boolean) {
		l_error("Error: %s should contain a boolean value\n",
								keyword);
		return false;
	}

	*value = json_object_get_boolean(jvalue);

	return true;
}

static bool write_bool(json_object *jobj, const char *keyword, bool val)
{
	json_object *jval;

	jval = json_object_new_boolean(val);
	if (!jval)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, keyword);

	json_object_object_add(jobj, keyword, jval);
	return true;
}

static json_object *get_key_object(json_object *jarray, uint16_t idx)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		int jidx;

		jentry = json_object_array_get_idx(jarray, i);
		if (!get_int(jentry, "index", &jidx))
			return NULL;

		if (jidx == idx)
			return jentry;
	}

	return NULL;
}

static bool write_uint16_hex(json_object *jobj, const char *desc,
							uint16_t value)
{
	json_object *jstring;
	char buf[5];

	snprintf(buf, 5, "%4.4x", value);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, desc);

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static bool write_uint32_hex(json_object *jobj, const char *desc, uint32_t val)
{
	json_object *jstring;
	char buf[9];

	snprintf(buf, 9, "%8.8x", val);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, desc);

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static json_object *get_node_by_uuid(json_object *jcfg, uint8_t uuid[16])
{
	json_object *jarray = NULL;
	char buf[37];
	int i, sz;

	if (!l_uuid_to_string(uuid, buf, sizeof(buf)))
		return NULL;

	json_object_object_get_ex(jcfg, "nodes", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return NULL;

	sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "UUID", &jval))
			return NULL;

		str = json_object_get_string(jval);
		if (strlen(str) != 36)
			continue;

		if (!strcmp(buf, str))
			return jentry;
	}

	return NULL;
}

static bool add_u8_8(json_object *jobj, const char *desc,
							const uint8_t value[8])
{
	json_object *jstring;
	char buf[17];

	hex2str((uint8_t *) value, 8, buf, 17);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, desc);

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static bool add_u8_16(json_object *jobj, const char *desc,
							const uint8_t value[16])
{
	json_object *jstring;
	char buf[33];

	hex2str((uint8_t *) value, 16, buf, 33);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	/* Overwrite old value if present */
	json_object_object_del(jobj, desc);

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static bool get_token(json_object *jobj, uint8_t token[8])
{
	json_object *jval;
	const char *str;

	if (!token)
		return false;

	if (!json_object_object_get_ex(jobj, "token", &jval))
		return false;

	str = json_object_get_string(jval);
	if (!str2hex(str, strlen(str), token, 8))
		return false;

	return true;
}

static uint16_t node_parse_key(json_object *jarray, int i)
{
	json_object *jkey;
	int idx;

	jkey = json_object_array_get_idx(jarray, i);
	if (!jkey)
		return KEY_IDX_INVALID;

	if (!get_int(jkey, "index", &idx))
		return KEY_IDX_INVALID;

	return (uint16_t)idx;
}

static bool node_check_key_updated(json_object *jarray, int i, bool *updated)
{
	json_object *jkey;

	jkey = json_object_array_get_idx(jarray, i);
	if (!jkey)
		return false;

	if (!get_bool(jkey, "updated", updated))
		return false;

	return true;
}

static int compare_group_addr(const void *a, const void *b, void *user_data)
{
	const struct mesh_group *grp0 = a;
	const struct mesh_group *grp1 = b;

	if (grp0->addr < grp1->addr)
		return -1;

	if (grp0->addr > grp1->addr)
		return 1;

	return 0;
}

static bool load_composition(json_object *jnode, uint16_t unicast)
{
	json_object *jarray;
	int i, ele_cnt;

	if (!json_object_object_get_ex(jnode, "elements", &jarray))
		return false;

	if (json_object_get_type(jarray) != json_type_array)
		return false;

	ele_cnt = json_object_array_length(jarray);

	for (i = 0; i < ele_cnt; ++i) {
		json_object *jentry, *jval, *jmods;
		int32_t index;
		int k, mod_cnt;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "index", &jval))
			return false;

		index = json_object_get_int(jval);
		if (index > 0xff)
			return false;

		if (!json_object_object_get_ex(jentry, "models", &jmods))
			return false;

		mod_cnt = json_object_array_length(jmods);

		for (k = 0; k < mod_cnt; ++k) {
			json_object *jmod, *jid;
			uint32_t mod_id, len;
			const char *str;

			jmod = json_object_array_get_idx(jmods, k);
			if (!json_object_object_get_ex(jmod, "modelId", &jid))
				return false;

			str = json_object_get_string(jid);
			len = strlen(str);

			if (len != 4 && len != 8)
				return false;

			if ((len == 4) && (sscanf(str, "%04x", &mod_id) != 1))
				return false;

			if ((len == 8) && (sscanf(str, "%08x", &mod_id) != 1))
				return false;

			remote_set_model(unicast, index, mod_id, len == 8);
		}
	}

	return true;
}

static void load_remotes(json_object *jcfg)
{
	json_object *jnodes;
	int i, sz, node_count = 0;

	json_object_object_get_ex(jcfg, "nodes", &jnodes);
	if (!jnodes || json_object_get_type(jnodes) != json_type_array)
		return;

	sz = json_object_array_length(jnodes);

	for (i = 0; i < sz; ++i) {
		json_object *jnode, *jval, *jarray;
		uint8_t uuid[16];
		uint16_t unicast, key_idx;
		const char *str;
		int ele_cnt, key_cnt;
		int j;

		jnode = json_object_array_get_idx(jnodes, i);
		if (!jnode)
			continue;

		if (!json_object_object_get_ex(jnode, "UUID", &jval))
			continue;

		str = json_object_get_string(jval);
		if (strlen(str) != 36)
			continue;

		if (!l_uuid_from_string(str, uuid))
			continue;

		if (!json_object_object_get_ex(jnode, "unicastAddress", &jval))
			continue;

		str = json_object_get_string(jval);
		if (sscanf(str, "%04hx", &unicast) != 1)
			continue;

		json_object_object_get_ex(jnode, "elements", &jarray);
		if (!jarray || json_object_get_type(jarray) != json_type_array)
			continue;

		ele_cnt = json_object_array_length(jarray);

		if (ele_cnt > MAX_ELE_COUNT)
			continue;

		json_object_object_get_ex(jnode, "netKeys", &jarray);
		if (!jarray || json_object_get_type(jarray) != json_type_array)
			continue;

		key_cnt = json_object_array_length(jarray);
		if (key_cnt < 0)
			continue;

		key_idx = node_parse_key(jarray, 0);
		if (key_idx == KEY_IDX_INVALID)
			continue;

		remote_add_node((const uint8_t *)uuid, unicast, ele_cnt,
								key_idx);
		for (j = 1; j < key_cnt; j++) {
			bool updated = false;

			key_idx = node_parse_key(jarray, j);

			if (key_idx == KEY_IDX_INVALID)
				continue;

			remote_add_net_key(unicast, key_idx, false);

			node_check_key_updated(jarray, j, &updated);
			remote_update_net_key(unicast, key_idx, updated, false);
		}

		json_object_object_get_ex(jnode, "appKeys", &jarray);
		if (!jarray || json_object_get_type(jarray) != json_type_array)
			continue;

		key_cnt = json_object_array_length(jarray);

		for (j = 0; j < key_cnt; j++) {
			bool updated = false;

			key_idx = node_parse_key(jarray, j);

			if (key_idx == KEY_IDX_INVALID)
				continue;

			remote_add_app_key(unicast, key_idx, false);

			node_check_key_updated(jarray, j, &updated);
			remote_update_app_key(unicast, key_idx, updated, false);
		}

		if (!load_composition(jnode, unicast))
			continue;

		/* If "crpl" is present, composition's is available */
		jval = NULL;
		if (json_object_object_get_ex(jnode, "crpl", &jval) && jval)
			remote_set_composition(unicast, true);

		/* TODO: Add the rest of the configuration */

		node_count++;
	}

	if (node_count != sz)
		l_warn("The remote node configuration load is incomplete!");

}

static bool add_app_key(json_object *jobj, uint16_t net_idx, uint16_t app_idx)
{
	json_object *jkey, *jarray;
	char buf[12];

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = json_object_new_object();

	snprintf(buf, 12, "AppKey %4.4x", app_idx);

	if (!add_string(jkey, "name", buf))
		goto fail;

	if (!write_int(jkey, "boundNetKey", (int)net_idx))
		goto fail;

	if (!write_int(jkey, "index", (int)app_idx))
		goto fail;

	json_object_array_add(jarray, jkey);

	return true;
fail:
	json_object_put(jkey);
	return false;
}

static bool add_node_key(json_object *jobj, const char *desc, uint16_t idx)
{
	json_object *jkey, *jarray;

	json_object_object_get_ex(jobj, desc, &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = json_object_new_object();

	if (!write_int(jkey, "index", (int)idx))
		goto fail;

	if (!write_bool(jkey, "updated", false))
		goto fail;

	json_object_array_add(jarray, jkey);

	return save_config();

fail:
	json_object_put(jkey);
	return false;
}

bool mesh_db_node_set_ttl(uint16_t unicast, uint8_t ttl)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	if (!write_int(jnode, "defaultTTL", ttl))
		return false;

	return save_config();
}

static bool add_transmit_info(json_object *jobj, int cnt, int interval,
							const char *desc)
{
	json_object *jtxmt;

	json_object_object_del(jobj, desc);
	jtxmt = json_object_new_object();

	if (!write_int(jtxmt, "count", cnt))
		goto fail;

	if (!write_int(jtxmt, "interval", interval))
		goto fail;

	json_object_object_add(jobj, desc, jtxmt);
	return true;

fail:
	json_object_put(jtxmt);
	return false;
}

bool mesh_db_node_set_net_transmit(uint16_t unicast, uint8_t cnt,
							uint16_t interval)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	if (!add_transmit_info(jnode, cnt, interval, "networkTransmit"))
		return false;

	return save_config();
}

static bool set_feature(json_object *jnode, const char *desc, uint8_t feature)
{
	json_object *jobj;

	if (feature > MESH_MODE_UNSUPPORTED)
		return false;

	jobj = json_object_object_get(jnode, "features");
	if (!jobj) {
		jobj = json_object_new_object();
		json_object_object_add(jnode, "features", jobj);
	}

	if (!write_int(jobj, desc, feature))
		return false;

	return save_config();
}

bool mesh_db_node_set_relay(uint16_t unicast, uint8_t relay, uint8_t cnt,
							uint16_t interval)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	if (relay < MESH_MODE_UNSUPPORTED &&
		!add_transmit_info(jnode, cnt, interval, "relayRetransmit"))
		return false;

	return set_feature(jnode, "relay", relay);
}

bool mesh_db_node_set_proxy(uint16_t unicast, uint8_t proxy)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	return set_feature(jnode, "proxy", proxy);
}

bool mesh_db_node_set_friend(uint16_t unicast, uint8_t friend)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	return set_feature(jnode, "friend", friend);
}

bool mesh_db_node_set_beacon(uint16_t unicast, bool enabled)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	if (!write_bool(jnode, "secureNetworkBeacon", enabled))
		return false;

	return save_config();
}

static json_object *get_element(uint16_t unicast, uint16_t ele_addr)
{
	json_object *jnode, *jarray;
	int i, ele_cnt;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	if (!json_object_object_get_ex(jnode, "elements", &jarray))
		return NULL;

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return NULL;

	ele_cnt = json_object_array_length(jarray);

	for (i = 0; i < ele_cnt; ++i) {
		json_object *jentry, *jval;
		int32_t index;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "index", &jval))
			return NULL;

		index = json_object_get_int(jval);
		if (index > 0xff)
			return NULL;

		if (ele_addr == unicast + index)
			return jentry;
	}

	return NULL;
}

static json_object *get_model(uint16_t unicast, uint16_t ele_addr,
						uint32_t mod_id, bool vendor)
{
	json_object *jelement, *jarray;
	int i, sz;

	jelement = get_element(unicast, ele_addr);
	if (!jelement)
		return false;

	if (!json_object_object_get_ex(jelement, "models", &jarray))
		return NULL;

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return NULL;

	if (!vendor)
		mod_id = mod_id & ~VENDOR_ID_MASK;

	sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		uint32_t id, len;
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "modelId",
								&jval))
			return NULL;

		str = json_object_get_string(jval);
		len = strlen(str);
		if (len != 4 && len != 8)
			return NULL;

		if ((len == 4 && vendor) || (len == 8 && !vendor))
			continue;

		if (sscanf(str, "%08x", &id) != 1)
			return NULL;

		if (id == mod_id)
			return jentry;
	}

	return NULL;
}

static void jarray_int_del(json_object *jarray, int val)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;

		jentry = json_object_array_get_idx(jarray, i);

		if (val == json_object_get_int(jentry)) {
			json_object_array_del_idx(jarray, i, 1);
			return;
		}
	}
}

static bool update_model_int_array(uint16_t unicast, uint16_t ele_addr,
					bool vendor, uint32_t mod_id,
					int val, const char *keyword, bool add)
{
	json_object *jarray, *jmod, *jvalue;

	if (!cfg || !cfg->jcfg)
		return false;

	jmod = get_model(unicast, ele_addr, mod_id, vendor);
	if (!jmod)
		return false;

	if (!json_object_object_get_ex(jmod, keyword, &jarray))
		return false;

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jarray_int_del(jarray, val);

	if (!add)
		return true;

	jvalue = json_object_new_int(val);
	if (!jvalue)
		return false;

	json_object_array_add(jarray, jvalue);

	return save_config();
}

bool mesh_db_node_model_bind(uint16_t unicast, uint16_t ele_addr, bool vendor,
					uint32_t mod_id, uint16_t app_idx)
{
	char buf[5];

	snprintf(buf, 5, "%4.4x", app_idx);

	return update_model_int_array(unicast, ele_addr, vendor, mod_id,
						(int) app_idx, "bind", true);
}

bool mesh_db_node_model_unbind(uint16_t unicast, uint16_t ele_addr, bool vendor,
					uint32_t mod_id, uint16_t app_idx)
{
	char buf[5];

	snprintf(buf, 5, "%4.4x", app_idx);

	return update_model_int_array(unicast, ele_addr, vendor, mod_id,
						(int) app_idx, "bind", false);
}

static void jarray_string_del(json_object *jarray, const char *str, size_t len)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		char *str_entry;

		jentry = json_object_array_get_idx(jarray, i);
		str_entry = (char *)json_object_get_string(jentry);

		if (str_entry && (strlen(str_entry) == len) &&
						!strncmp(str, str_entry, len)) {
			json_object_array_del_idx(jarray, i, 1);
			return;
		}
	}
}

static bool add_array_string(json_object *jarray, const char *str)
{
	json_object *jstring;

	jstring = json_object_new_string(str);
	if (!jstring)
		return false;

	json_object_array_add(jarray, jstring);
	return true;
}

static bool update_model_string_array(uint16_t unicast, uint16_t ele_addr,
						bool vendor, uint32_t mod_id,
						const char *str, uint32_t len,
						const char *keyword, bool add)
{
	json_object *jarray, *jmod;

	if (!cfg || !cfg->jcfg)
		return false;

	jmod = get_model(unicast, ele_addr, mod_id, vendor);
	if (!jmod)
		return false;

	if (!json_object_object_get_ex(jmod, keyword, &jarray))
		return false;

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jarray_string_del(jarray, str, len);

	if (!add)
		return true;

	if (!add_array_string(jarray, str))
		return false;

	return save_config();
}

bool mesh_db_node_model_add_sub(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, uint16_t addr)
{
	char buf[5];

	snprintf(buf, 5, "%4.4x", addr);

	return update_model_string_array(unicast, ele, vendor, mod_id, buf, 4,
							"subscribe", true);
}

bool mesh_db_node_model_del_sub(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, uint16_t addr)
{
	char buf[5];

	snprintf(buf, 5, "%4.4x", addr);

	return update_model_string_array(unicast, ele, vendor, mod_id, buf, 4,
							"subscribe", false);
}

bool mesh_db_node_model_add_sub_virt(uint16_t unicast, uint16_t ele,
						bool vendor, uint32_t mod_id,
								uint8_t *label)
{
	char buf[33];

	hex2str(label, 16, buf, sizeof(buf));

	return update_model_string_array(unicast, ele, vendor, mod_id, buf, 32,
							"subscribe", true);

}

bool mesh_db_node_model_del_sub_virt(uint16_t unicast, uint16_t ele,
						bool vendor, uint32_t mod_id,
								uint8_t *label)
{
	char buf[33];

	hex2str(label, 16, buf, sizeof(buf));

	return update_model_string_array(unicast, ele, vendor, mod_id, buf, 32,
							"subscribe", false);
}

static json_object *delete_subs(uint16_t unicast, uint16_t ele, bool vendor,
								uint32_t mod_id)
{
	json_object *jarray, *jmod;

	if (!cfg || !cfg->jcfg)
		return NULL;

	jmod = get_model(unicast, ele, mod_id, vendor);
	if (!jmod)
		return NULL;

	json_object_object_del(jmod, "subscribe");

	jarray = json_object_new_array();
	if (!jarray)
		return NULL;

	json_object_object_add(jmod, "subscribe", jarray);

	return jarray;
}

bool mesh_db_node_model_del_sub_all(uint16_t unicast, uint16_t ele, bool vendor,
								uint32_t mod_id)
{

	if (!delete_subs(unicast, ele, vendor, mod_id))
		return false;

	return save_config();
}

static bool sub_overwrite(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, char *buf)
{
	json_object *jarray, *jstring;

	jarray = delete_subs(unicast, ele, vendor, mod_id);
	if (!jarray)
		return false;

	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_array_add(jarray, jstring);

	return save_config();
}

bool mesh_db_node_model_overwrt_sub(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, uint16_t addr)
{
	char buf[5];

	snprintf(buf, 5, "%4.4x", addr);

	return sub_overwrite(unicast, ele, vendor, mod_id, buf);
}

bool mesh_db_node_model_overwrt_sub_virt(uint16_t unicast, uint16_t ele,
						bool vendor, uint32_t mod_id,
								uint8_t *label)
{
	char buf[33];

	hex2str(label, 16, buf, sizeof(buf));

	return sub_overwrite(unicast, ele, vendor, mod_id, buf);
}

bool mesh_db_node_model_set_pub(uint16_t unicast, uint16_t ele_addr,
					bool vendor, uint32_t mod_id,
					struct model_pub *pub, bool virt)
{
	json_object *jmod, *jpub, *jobj = NULL;

	if (!cfg || !cfg->jcfg)
		return false;

	jmod = get_model(unicast, ele_addr, mod_id, vendor);
	if (!jmod)
		return false;

	jpub = json_object_new_object();

	if (!virt && !write_uint16_hex(jpub, "address", pub->u.addr))
		goto fail;

	if (virt) {
		char buf[33];

		hex2str(pub->u.label, 16, buf, sizeof(buf));

		if (!add_string(jpub, "address", buf))
			goto fail;
	}

	if (!write_int(jpub, "index", pub->app_idx))
		goto fail;

	if (!write_int(jpub, "ttl", pub->ttl))
		goto fail;

	if (!write_int(jpub, "credentials", pub->cred ? 1 : 0))
		goto fail;

	if (!add_transmit_info(jpub, pub->rtx_cnt, pub->rtx_interval,
							"retransmit"))
		goto fail;

	jobj = json_object_new_object();

	if (!write_int(jobj, "numberOfSteps", pub->prd_steps))
		goto fail;

	if (!write_int(jobj, "resolution", pub->prd_res))
		goto fail;

	json_object_object_add(jpub, "period", jobj);

	json_object_object_del(jmod, "publish");
	json_object_object_add(jmod, "publish", jpub);

	return save_config();

fail:
	if (jobj)
		json_object_put(jobj);

	json_object_put(jpub);
	return false;
}

bool mesh_db_node_set_hb_pub(uint16_t unicast, uint16_t dst, uint16_t net_idx,
						uint8_t period_log, uint8_t ttl,
							uint16_t features)
{
	json_object *jnode, *jpub, *jarray = NULL;
	uint32_t period;

	if (!cfg || !cfg->jcfg)
		return false;

	if (period_log > 0x12 || ttl > 0x7F)
		return  false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	jpub = json_object_new_object();

	if (!write_uint16_hex(jpub, "address", dst))
		goto fail;

	period = period_log ? 1 << (period_log - 1) : 0;

	if (!write_int(jpub, "period", period))
		goto fail;

	if (!write_int(jpub, "ttl", ttl))
		goto fail;

	if (!write_int(jpub, "index", net_idx))
		goto fail;

	jarray = json_object_new_array();

	if (features & FEATURE_PROXY)
		if (!add_array_string(jarray, "proxy"))
			goto fail;

	if (features & FEATURE_RELAY)
		if (!add_array_string(jarray, "relay"))
			goto fail;

	if (features & FEATURE_FRIEND)
		if (!add_array_string(jarray, "friend"))
			goto fail;

	if (features & FEATURE_LPN)
		if (!add_array_string(jarray, "lowPower"))
			goto fail;

	json_object_object_add(jpub, "features", jarray);
	json_object_object_del(jnode, "heartbeatPub");
	json_object_object_add(jnode, "heartbeatPub", jpub);

	return save_config();

fail:
	if (jarray)
		json_object_put(jarray);

	json_object_put(jpub);
	return false;
}

bool mesh_db_node_set_hb_sub(uint16_t unicast, uint16_t src, uint16_t dst)
{
	json_object *jnode, *jsub;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	jsub = json_object_new_object();

	if (!write_uint16_hex(jsub, "source", src))
		goto fail;

	if (!write_uint16_hex(jsub, "destination", dst))
		goto fail;

	json_object_object_del(jnode, "heartbeatSub");
	json_object_object_add(jnode, "heartbeatSub", jsub);

	return save_config();

fail:
	json_object_put(jsub);
	return false;
}

static void jarray_key_del(json_object *jarray, int16_t idx)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		int val;

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_int(jentry, "index", &val))
			continue;

		if (val == idx) {
			json_object_array_del_idx(jarray, i, 1);
			return;
		}

	}
}

static bool delete_key(json_object *jobj, const char *desc, uint16_t idx)
{
	json_object *jarray;

	if (!json_object_object_get_ex(jobj, desc, &jarray))
		return true;

	jarray_key_del(jarray, idx);

	return save_config();
}

bool mesh_db_node_add_net_key(uint16_t unicast, uint16_t idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	return add_node_key(jnode, "netKeys", idx);
}

bool mesh_db_node_del_net_key(uint16_t unicast, uint16_t net_idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	return delete_key(jnode, "netKeys", net_idx);
}

static bool key_update(uint16_t unicast, int16_t idx, bool updated,
							const char *desc)
{
	json_object *jnode, *jarray;
	int i, sz;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	if (!json_object_object_get_ex(jnode, desc, &jarray))
		return false;

	sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		int val;

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_int(jentry, "index", &val))
			continue;

		if ((val == idx) && write_bool(jentry, "updated", updated))
			return save_config();
	}

	return false;
}

bool mesh_db_node_update_net_key(uint16_t unicast, uint16_t idx, bool updated)
{
	return key_update(unicast, idx, updated, "netKeys");
}

bool mesh_db_node_add_app_key(uint16_t unicast, uint16_t idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	return add_node_key(jnode, "appKeys", idx);
}

bool mesh_db_node_del_app_key(uint16_t unicast, uint16_t idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	return delete_key(jnode, "appKeys", idx);
}

bool mesh_db_node_update_app_key(uint16_t unicast, uint16_t idx, bool updated)
{
	return key_update(unicast, idx, updated, "appKeys");
}

static bool load_keys(json_object *jobj)
{
	json_object *jarray, *jentry;
	int net_idx, app_idx;
	int i, key_cnt;

	json_object_object_get_ex(jobj, "netKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	key_cnt = json_object_array_length(jarray);
	if (key_cnt < 0)
		return false;

	for (i = 0; i < key_cnt; ++i) {
		int phase;

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_int(jentry, "index", &net_idx))
			return false;

		keys_add_net_key((uint16_t) net_idx);

		if (!get_int(jentry, "phase", &phase))
			return false;

		keys_set_net_key_phase(net_idx, (uint8_t) phase, false);
	}

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	key_cnt = json_object_array_length(jarray);
	if (key_cnt < 0)
		return false;

	for (i = 0; i < key_cnt; ++i) {

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_int(jentry, "boundNetKey", &net_idx))
			return false;

		if (!get_int(jentry, "index", &app_idx))
			return false;

		keys_add_app_key((uint16_t) net_idx, (uint16_t) app_idx);
	}

	return true;
}

bool mesh_db_add_net_key(uint16_t net_idx)
{
	json_object *jkey, *jarray;
	char buf[12];

	if (!cfg || !cfg->jcfg)
		return false;

	json_object_object_get_ex(cfg->jcfg, "netKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	if (get_key_object(jarray, net_idx))
		return true;

	jkey = json_object_new_object();

	snprintf(buf, 12, "Subnet %4.4x", net_idx);

	if (!add_string(jkey, "name", buf))
		goto fail;

	if (!write_int(jkey, "index", net_idx))
		goto fail;

	if (!write_int(jkey, "phase", KEY_REFRESH_PHASE_NONE))
		goto fail;

	if (!add_string(jkey, "minSecurity", "secure"))
		goto fail;

	if (!set_timestamp(jkey))
		goto fail;

	json_object_array_add(jarray, jkey);

	return save_config();

fail:
	json_object_put(jkey);
	return false;
}

bool mesh_db_del_net_key(uint16_t net_idx)
{
	if (!cfg || !cfg->jcfg)
		return false;

	return delete_key(cfg->jcfg, "netKeys", net_idx);
}

bool mesh_db_set_net_key_phase(uint16_t net_idx, uint8_t phase)
{
	json_object *jval, *jarray, *jkey;

	if (!cfg || !cfg->jcfg)
		return false;

	json_object_object_get_ex(cfg->jcfg, "netKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = get_key_object(jarray, net_idx);
	if (!jkey)
		return false;

	jval = json_object_new_int(phase);
	if (!jval)
		return false;

	json_object_object_add(jkey, "phase", jval);

	return save_config();
}

bool mesh_db_add_app_key(uint16_t net_idx, uint16_t app_idx)
{
	if (!cfg || !cfg->jcfg)
		return false;

	if (!add_app_key(cfg->jcfg, net_idx, app_idx))
		return false;

	return save_config();
}

bool mesh_db_del_app_key(uint16_t app_idx)
{
	if (!cfg || !cfg->jcfg)
		return false;

	return delete_key(cfg->jcfg, "appKeys", app_idx);
}

bool mesh_db_add_group(struct mesh_group *grp)
{
	json_object *jgroup, *jgroups, *jval;
	char buf[16];

	if (!cfg || !cfg->jcfg)
		return false;

	if (!json_object_object_get_ex(cfg->jcfg, "groups", &jgroups))
		return false;

	jgroup = json_object_new_object();
	if (!jgroup)
		return false;

	snprintf(buf, 11, "Group_%4.4x", grp->addr);
	jval = json_object_new_string(buf);
	json_object_object_add(jgroup, "name", jval);

	if (IS_VIRTUAL(grp->addr)) {
		if (!add_u8_16(jgroup, "address", grp->label))
			goto fail;
	} else {
		if (!write_uint16_hex(jgroup, "address", grp->addr))
			goto fail;
	}

	/* Initialize parent group to unassigned address for now*/
	if (!write_uint16_hex(jgroup, "parentAddress", UNASSIGNED_ADDRESS))
		goto fail;

	json_object_array_add(jgroups, jgroup);

	return save_config();

fail:
	json_object_put(jgroup);
	return false;
}

struct l_queue *mesh_db_load_groups(void)
{
	json_object *jgroups;
	struct l_queue *groups;
	int i, sz;

	if (!cfg || !cfg->jcfg)
		return NULL;

	if (!json_object_object_get_ex(cfg->jcfg, "groups", &jgroups)) {
		jgroups = json_object_new_array();
		if (!jgroups)
			return NULL;

		json_object_object_add(cfg->jcfg, "groups", jgroups);
	}

	groups = l_queue_new();

	sz = json_object_array_length(jgroups);

	for (i = 0; i < sz; ++i) {
		json_object *jgroup, *jval;
		struct mesh_group *grp;
		uint16_t addr, addr_len;
		const char *str;

		jgroup = json_object_array_get_idx(jgroups, i);
		if (!jgroup)
			continue;

		if (!json_object_object_get_ex(jgroup, "name", &jval))
			continue;

		str = json_object_get_string(jval);
		if (strlen(str) != 10)
			continue;

		if (sscanf(str + 6, "%04hx", &addr) != 1)
			continue;

		if (!json_object_object_get_ex(jgroup, "address", &jval))
			continue;

		str = json_object_get_string(jval);
		addr_len = strlen(str);
		if (addr_len != 4 && addr_len != 32)
			continue;

		if (addr_len == 32 && !IS_VIRTUAL(addr))
			continue;

		grp = l_new(struct mesh_group, 1);

		if (addr_len == 4)
			sscanf(str, "%04hx", &grp->addr);
		else {
			str2hex(str, 32, grp->label, 16);
			grp->addr = addr;
		}

		l_queue_insert(groups, grp, compare_group_addr, NULL);
	}

	return groups;
}

static json_object *init_elements(uint8_t num_els)
{
	json_object *jelements;
	uint8_t i;

	jelements = json_object_new_array();

	for (i = 0; i < num_els; ++i) {
		json_object *jelement, *jmods;

		jelement = json_object_new_object();

		write_int(jelement, "index", i);
		write_uint16_hex(jelement, "location", DEFAULT_LOCATION);
		jmods = json_object_new_array();
		json_object_object_add(jelement, "models", jmods);

		json_object_array_add(jelements, jelement);
	}

	return jelements;
}

bool mesh_db_add_node(uint8_t uuid[16], uint8_t num_els, uint16_t unicast,
							uint16_t net_idx)
{
	json_object *jnode;
	json_object *jelements, *jnodes, *jnetkeys, *jappkeys;
	char buf[37];

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_uuid(cfg->jcfg, uuid);
	if (jnode) {
		l_error("Node already exists");
		return false;
	}

	jnode = json_object_new_object();
	if (!jnode)
		return false;

	if (!l_uuid_to_string(uuid, buf, sizeof(buf)))
		goto fail;

	if (!add_string(jnode, "UUID", buf))
		goto fail;

	if (!add_string(jnode, "security", "secure"))
		goto fail;

	if (!write_bool(jnode, "excluded", false))
		goto fail;

	if (!write_bool(jnode, "configComplete", false))
		goto fail;

	jelements = init_elements(num_els);

	json_object_object_add(jnode, "elements", jelements);

	jnetkeys = json_object_new_array();
	if (!jnetkeys)
		goto fail;

	json_object_object_add(jnode, "netKeys", jnetkeys);

	if (!add_node_key(jnode, "netKeys", net_idx))
		goto fail;

	jappkeys = json_object_new_array();
	if (!jappkeys)
		goto fail;

	json_object_object_add(jnode, "appKeys", jappkeys);

	if (!write_uint16_hex(jnode, "unicastAddress", unicast))
		goto fail;

	if (!json_object_object_get_ex(cfg->jcfg, "nodes", &jnodes))
		goto fail;

	json_object_array_add(jnodes, jnode);

	return save_config();

fail:
	json_object_put(jnode);
	return false;
}

bool mesh_db_del_node(uint16_t unicast)
{
	json_object *jarray;
	int i, sz;

	if (!json_object_object_get_ex(cfg->jcfg, "nodes", &jarray))
		return false;

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		uint16_t addr;
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "unicastAddress",
								&jval))
			continue;

		str = json_object_get_string(jval);
		if (sscanf(str, "%04hx", &addr) != 1)
			continue;

		if (addr == unicast)
			break;
	}

	if (i == sz)
		return true;

	json_object_array_del_idx(jarray, i, 1);

	return save_config();
}

static json_object *init_model(uint16_t mod_id)
{
	json_object *jmod, *jarray;

	jmod = json_object_new_object();

	if (!write_uint16_hex(jmod, "modelId", mod_id)) {
		json_object_put(jmod);
		return NULL;
	}

	jarray = json_object_new_array();
	json_object_object_add(jmod, "bind", jarray);

	jarray = json_object_new_array();
	json_object_object_add(jmod, "subscribe", jarray);

	return jmod;
}

static json_object *init_vendor_model(uint32_t mod_id)
{
	json_object *jmod, *jarray;

	jmod = json_object_new_object();

	if (!write_uint32_hex(jmod, "modelId", mod_id)) {
		json_object_put(jmod);
		return NULL;
	}

	jarray = json_object_new_array();
	json_object_object_add(jmod, "bind", jarray);

	jarray = json_object_new_array();
	json_object_object_add(jmod, "subscribe", jarray);

	return jmod;
}

bool mesh_db_node_set_composition(uint16_t unicast, uint8_t *data, uint16_t len)
{
	uint16_t features;
	int sz, i = 0;
	json_object *jnode, *jobj, *jelements;
	uint16_t crpl;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(cfg->jcfg, unicast);
	if (!jnode)
		return false;

	/* skip page -- We only support Page Zero */
	data++;
	len--;

	/* If "crpl" property is present, composition is already recorded */
	if (json_object_object_get_ex(jnode, "crpl", &jobj))
		return true;

	if (!write_uint16_hex(jnode, "cid", l_get_le16(&data[0])))
		return false;

	if (!write_uint16_hex(jnode, "pid", l_get_le16(&data[2])))
		return false;

	if (!write_uint16_hex(jnode, "vid", l_get_le16(&data[4])))
		return false;

	crpl = l_get_le16(&data[6]);

	features = l_get_le16(&data[8]);
	data += 10;
	len -= 10;

	jobj = json_object_object_get(jnode, "features");
	if (!jobj) {
		jobj = json_object_new_object();
		json_object_object_add(jnode, "features", jobj);
	}

	if (!(features & FEATURE_RELAY))
		write_int(jobj, "relay", 2);

	if (!(features & FEATURE_FRIEND))
		write_int(jobj, "friend", 2);

	if (!(features & FEATURE_PROXY))
		write_int(jobj, "proxy", 2);

	if (!(features & FEATURE_LPN))
		write_int(jobj, "lowPower", 2);

	jelements = json_object_object_get(jnode, "elements");
	if (!jelements)
		return false;

	sz = json_object_array_length(jelements);

	while (len) {
		json_object *jentry, *jmods;
		uint32_t mod_id;
		uint8_t m, v;

		/* Mismatch in the element count */
		if (i >= sz)
			return false;

		jentry = json_object_array_get_idx(jelements, i);

		write_int(jentry, "index", i);

		if (!write_uint16_hex(jentry, "location", l_get_le16(data)))
			return false;

		data += 2;
		len -= 2;

		m = *data++;
		v = *data++;
		len -= 2;

		jmods = json_object_object_get(jentry, "models");
		if (!jmods) {
			/* For backwards compatibility */
			jmods = json_object_new_array();
			json_object_object_add(jentry, "models", jmods);
		}

		while (len >= 2 && m--) {
			mod_id = l_get_le16(data);

			jobj = init_model(mod_id);
			if (!jobj)
				goto fail;

			json_object_array_add(jmods, jobj);
			data += 2;
			len -= 2;
		}

		while (len >= 4 && v--) {
			jobj = json_object_new_object();
			mod_id = l_get_le16(data + 2);
			mod_id = l_get_le16(data) << 16 | mod_id;

			jobj = init_vendor_model(mod_id);
			if (!jobj)
				goto fail;

			json_object_array_add(jmods, jobj);

			data += 4;
			len -= 4;
		}

		i++;
	}

	/* CRPL is written last. Will be used to check composition's presence */
	if (!write_uint16_hex(jnode, "crpl", crpl))
		goto fail;

	/* Initiate remote's composition from storage */
	if (!load_composition(jnode, unicast))
		goto fail;

	return save_config();

fail:
	/* Reset elements array */
	json_object_object_del(jnode, "elements");
	init_elements(sz);

	return false;
}

bool mesh_db_get_token(uint8_t token[8])
{
	if (!cfg || !cfg->jcfg)
		return false;

	memcpy(token, cfg->token, 8);

	return true;
}

bool mesh_db_get_addr_range(uint16_t *low, uint16_t *high)
{
	json_object *jprov, *jarray, *jobj, *jlow, *jhigh;
	const char *str;

	if (!cfg || !cfg->jcfg)
		return false;

	jarray = json_object_object_get(cfg->jcfg, "provisioners");

	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	/* Assumption: only one provisioner in the system */
	jprov = json_object_array_get_idx(jarray, 0);
	if (!jprov)
		return false;

	if (!json_object_object_get_ex(jprov, "allocatedUnicastRange", &jarray))
		return false;

	/* Assumption: only one contiguous range is specified */
	jobj = json_object_array_get_idx(jarray, 0);
	if (!jobj)
		return false;

	if (!json_object_object_get_ex(jobj, "lowAddress", &jlow) ||
			!json_object_object_get_ex(jobj, "highAddress", &jhigh))
		return false;

	str = json_object_get_string(jlow);
	if (sscanf(str, "%04hx", low) != 1)
		return false;

	str = json_object_get_string(jhigh);
	if (sscanf(str, "%04hx", high) != 1)
		return false;

	return true;
}

/*
 * This is a simplistic implementation of allocated range, where
 * the range is one contiguous chunk of the address space.
 */
static bool add_range(json_object *jobj, const char *keyword, uint16_t low,
								uint16_t high)
{
	json_object *jarray, *jrange;

	jrange = json_object_new_object();

	if (!write_uint16_hex(jrange, "lowAddress", low))
		goto fail;

	if (!write_uint16_hex(jrange, "highAddress", high))
		goto fail;

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_array_add(jarray, jrange);
	json_object_object_add(jobj, keyword, jarray);

	return true;

fail:
	json_object_put(jrange);

	return false;
}

bool mesh_db_add_provisioner(const char *name, uint8_t uuid[16],
				uint16_t unicast_low, uint16_t unicast_high,
					uint16_t group_low, uint16_t group_high)
{
	json_object *jprovs, *jprov, *jscenes;
	char buf[37];

	if (!cfg || !cfg->jcfg)
		return false;

	if (!json_object_object_get_ex(cfg->jcfg, "provisioners", &jprovs))
		return false;

	if (!jprovs || json_object_get_type(jprovs) != json_type_array)
		return false;

	jprov = json_object_new_object();

	if (!add_string(jprov, "provisionerName", name))
		goto fail;

	if (!l_uuid_to_string(uuid, buf, sizeof(buf)))
		goto fail;

	if (!add_string(jprov, "UUID", buf))
		goto fail;

	if (!add_range(jprov, "allocatedUnicastRange", unicast_low,
								unicast_high))
		goto fail;

	if (!add_range(jprov, "allocatedGroupRange", group_low, group_high))
		goto fail;

	/* Scenes are not supported. Just add an empty array */
	jscenes = json_object_new_array();
	if (!jscenes)
		goto fail;

	json_object_object_add(jprov, "allocatedSceneRange", jscenes);

	json_object_array_add(jprovs, jprov);

	return save_config();

fail:
	json_object_put(jprov);
	return false;
}

uint32_t mesh_db_get_iv_index(void)
{
	int ivi;

	if (!cfg || !cfg->jcfg)
		return 0;

	if (!get_int(cfg->jcfg, "ivIndex", &ivi))
		return 0;

	return (uint32_t) ivi;
}

bool mesh_db_set_iv_index(uint32_t ivi)
{
	if (!cfg || !cfg->jcfg)
		return false;

	write_int(cfg->jcfg, "ivIndex", ivi);

	return save_config();
}

static int get_rejected_by_iv_index(json_object *jarray, uint32_t iv_index)
{
	int i, cnt;

	cnt = json_object_array_length(jarray);

	for (i = 0; i < cnt; i++) {
		json_object *jentry;
		int index;

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_int(jentry, "ivIndex", &index))
			continue;

		if (iv_index == (uint32_t)index)
			return i;
	}

	return -1;
}

static bool load_rejected_addresses(json_object *jobj)
{
	json_object *jarray;
	int i, cnt;

	json_object_object_get_ex(jobj, "networkExclusions", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return true;

	cnt = json_object_array_length(jarray);

	for (i = 0; i < cnt; i++) {
		json_object *jaddrs, *jentry, *jval;
		int iv_index, addr_cnt, j;

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_int(jentry, "ivIndex", &iv_index))
			return false;

		if (!json_object_object_get_ex(jentry, "addresses",
								&jaddrs))
			return false;

		addr_cnt = json_object_array_length(jaddrs);

		for (j = 0; j < addr_cnt; j++) {
			const char *str;
			uint16_t unicast;

			jval = json_object_array_get_idx(jaddrs, j);
			str = json_object_get_string(jval);

			if (sscanf(str, "%04hx", &unicast) != 1)
				return false;

			remote_add_rejected_address(unicast, iv_index, false);
		}
	}

	return true;
}

bool mesh_db_add_rejected_addr(uint16_t unicast, uint32_t iv_index)
{
	json_object *jarray, *jobj, *jaddrs, *jstring;
	int idx;
	char buf[5];

	if (!cfg || !cfg->jcfg)
		return false;

	json_object_object_get_ex(cfg->jcfg, "networkExclusions", &jarray);
	if (!jarray) {
		jarray = json_object_new_array();
		json_object_object_add(cfg->jcfg, "networkExclusions", jarray);
	}

	idx = get_rejected_by_iv_index(jarray, iv_index);

	if (idx < 0) {
		jobj = json_object_new_object();

		if (!write_int(jobj, "ivIndex", iv_index))
			goto fail;

		jaddrs = json_object_new_array();
		json_object_object_add(jobj, "addresses", jaddrs);

	} else {
		jobj = json_object_array_get_idx(jarray, idx);
	}

	json_object_object_get_ex(jobj, "addresses", &jaddrs);

	snprintf(buf, 5, "%4.4x", unicast);
	jstring = json_object_new_string(buf);
	if (!jstring)
		goto fail;

	json_object_array_add(jaddrs, jstring);

	if (idx < 0)
		json_object_array_add(jarray, jobj);

	return save_config();

fail:
	json_object_put(jobj);
	return false;
}

bool mesh_db_clear_rejected(uint32_t iv_index)
{
	json_object *jarray;
	int idx;

	if (!cfg || !cfg->jcfg)
		return false;

	json_object_object_get_ex(cfg->jcfg, "networkExclusions", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	idx = get_rejected_by_iv_index(jarray, iv_index);
	if (idx < 0)
		return true;

	json_object_array_del_idx(jarray, idx, 1);

	return save_config();
}

bool mesh_db_create(const char *fname, const uint8_t token[8],
							const char *mesh_name)
{
	json_object *jcfg, *jarray;
	uint8_t uuid[16];
	char buf[37];

	if (cfg)
		return false;

	if (!fname)
		return false;

	jcfg = json_object_new_object();
	if (!jcfg)
		return false;

	cfg = l_new(struct mesh_db, 1);
	cfg->jcfg = jcfg;
	cfg->cfg_fname = l_strdup(fname);
	memcpy(cfg->token, token, 8);

	if (!add_u8_8(jcfg, "token", token))
		goto fail;

	l_uuid_v4(uuid);

	if (!l_uuid_to_string(uuid, buf, sizeof(buf)))
		goto fail;

	if (!add_string(jcfg, "meshUUID", buf))
		goto fail;

	if (mesh_name && !add_string(jcfg, "meshName", mesh_name))
		goto fail;

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "nodes", jarray);

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "provisioners", jarray);

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "netKeys", jarray);

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "appKeys", jarray);

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "networkExclusions", jarray);

	write_int(jcfg, "ivIndex", 0);

	if (!save_config())
		goto fail;

	return true;

fail:
	release_config();

	return false;
}

bool mesh_db_load(const char *fname)
{
	int fd;
	char *str;
	struct stat st;
	ssize_t sz;
	json_object *jcfg;

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		return false;

	if (fstat(fd, &st) == -1) {
		close(fd);
		return false;
	}

	str = (char *) l_new(char, st.st_size + 1);
	if (!str) {
		close(fd);
		return false;
	}

	sz = read(fd, str, st.st_size);
	if (sz != st.st_size) {
		l_error("Failed to read configuration file %s", fname);
		return false;
	}

	jcfg = json_tokener_parse(str);

	close(fd);
	l_free(str);

	if (!jcfg)
		return false;

	cfg = l_new(struct mesh_db, 1);

	cfg->jcfg = jcfg;
	cfg->cfg_fname = l_strdup(fname);

	if (!get_token(jcfg, cfg->token)) {
		l_error("Configuration file missing token");
		goto fail;
	}

	if (!load_keys(jcfg))
		goto fail;

	load_remotes(jcfg);

	load_rejected_addresses(jcfg);

	return true;
fail:
	release_config();

	return false;
}

bool mesh_db_set_device_key(void *expt_cfg, uint16_t unicast, uint8_t key[16])
{
	json_object *jnode;

	if (!expt_cfg)
		return false;

	jnode = get_node_by_unicast(expt_cfg, unicast);
	if (!jnode)
		return false;

	return add_u8_16(jnode, "deviceKey", key);
}

bool mesh_db_set_net_key(void *expt_cfg, uint16_t idx, uint8_t key[16],
					uint8_t *old_key, uint8_t phase)
{
	json_object *jarray, *jkey;

	if (!expt_cfg)
		return false;

	json_object_object_get_ex(expt_cfg, "netKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = get_key_object(jarray, idx);
	if (!jkey)
		return false;

	if (!write_int(jkey, "phase", phase))
		return false;

	if (!add_u8_16(jkey, "key", key))
		return false;

	if (old_key && !(!add_u8_16(jkey, "oldKey", old_key)))
		return false;

	return true;
}


bool mesh_db_set_app_key(void *expt_cfg, uint16_t net_idx, uint16_t app_idx,
					uint8_t key[16], uint8_t *old_key)
{
	json_object *jarray, *jkey;

	if (!expt_cfg)
		return false;

	json_object_object_get_ex(expt_cfg, "appKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = get_key_object(jarray, app_idx);
	if (!jkey)
		return false;

	if (!add_u8_16(jkey, "key", key))
		return false;

	if (old_key && !(!add_u8_16(jkey, "oldKey", old_key)))
		return false;

	return true;
}

void *mesh_db_prepare_export(void)
{
	json_object *export = NULL, *jarray;

	if (!cfg || !cfg->jcfg)
		return false;

	if (json_object_deep_copy(cfg->jcfg, &export, NULL) != 0)
		return NULL;

	/* Delete token */
	json_object_object_del(export, "token");

	/* Delete IV index */
	json_object_object_del(export, "ivIndex");

	/* Scenes are not supported. Just add an empty array */
	jarray = json_object_new_array();
	json_object_object_add(export, "scenes", jarray);

	if (!write_bool(export, "partial", false))
		l_warn("Failed to write\"partial\" property");

	return export;
}

bool mesh_db_finish_export(bool is_error, void *expt_cfg, const char *fname)
{
	FILE *outfile = NULL;
	const char *str, *hdr;
	json_object *jhdr = NULL;
	bool result = false;
	char *pos;

	uint32_t sz;

	if (!expt_cfg)
		return false;

	if (is_error) {
		json_object_put(expt_cfg);
		return true;
	}

	if (!fname)
		goto done;

	outfile = fopen(fname, "w");
	if (!outfile) {
		l_error("Failed to save configuration to %s", fname);
		goto done;
	}

	jhdr = json_object_new_object();
	if (!add_string(jhdr, "$schema", js_schema))
		goto done;

	if (!add_string(jhdr, "id", schema_id))
		goto done;

	if (!add_string(jhdr, "version", schema_version))
		goto done;

	hdr = json_object_to_json_string_ext(jhdr, JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE);

	str = json_object_to_json_string_ext(expt_cfg, JSON_C_TO_STRING_PRETTY |
						JSON_C_TO_STRING_NOSLASHESCAPE);

	if (!hdr || !str)
		goto done;

	/*
	 * Write two strings to the output while stripping closing "}" from the
	 * header string and opening "{" from the config object.
	 */

	pos = strrchr(hdr, '}');
	if (!pos)
		goto done;

	*pos = '\0';

	pos = strrchr(hdr, '"');
	if (!pos)
		goto done;

	pos[1] = ',';

	if (fwrite(hdr, sizeof(char), strlen(hdr), outfile) < strlen(hdr))
		goto done;

	pos = strchr(str, '{');
	if (!pos || pos[1] == '\0')
		goto done;

	pos++;

	sz = strlen(pos);

	if (fwrite(pos, sizeof(char), sz, outfile) < sz)
		goto done;

	result = true;

done:
	if (outfile)
		fclose(outfile);

	json_object_put(expt_cfg);

	if (jhdr)
		json_object_put(jhdr);

	return result;
}
