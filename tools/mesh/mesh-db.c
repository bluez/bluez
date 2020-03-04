/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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
#include <unistd.h>

#include <sys/time.h>

#include <ell/ell.h>
#include <json-c/json.h>

#include "mesh/mesh-defs.h"
#include "mesh/util.h"

#include "tools/mesh/keys.h"
#include "tools/mesh/remote.h"
#include "tools/mesh/cfgcli.h"
#include "tools/mesh/mesh-db.h"

#define KEY_IDX_INVALID NET_IDX_INVALID

struct mesh_db {
	json_object *jcfg;
	char *cfg_fname;
	uint8_t token[8];
	uint8_t pad[12];
	struct timeval write_time;
};

struct mesh_db *cfg;

static json_object *get_node_by_unicast(uint16_t unicast)
{
	json_object *jarray;
	int i, sz;

	if (!json_object_object_get_ex(cfg->jcfg, "nodes", &jarray))
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

static json_object *get_key_object(json_object *jarray, uint16_t idx)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		const char *str;
		uint16_t jidx;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "index", &jval))
			return NULL;

		str = json_object_get_string(jval);
		if (sscanf(str, "%04hx", &jidx) != 1)
			return NULL;

		if (jidx == idx)
			return jentry;
	}

	return NULL;
}

static bool write_int(json_object *jobj, const char *keyword, int val)
{
	json_object *jval;

	json_object_object_del(jobj, keyword);

	jval = json_object_new_int(val);
	if (!jval)
		return false;

	json_object_object_add(jobj, keyword, jval);
	return true;
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

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static json_object *get_node_by_uuid(json_object *jcfg, uint8_t uuid[16])
{
	json_object *jarray = NULL;
	char buf[33];
	int i, sz;

	hex2str(uuid, 16, buf, sizeof(buf));

	json_object_object_get_ex(jcfg, "nodes", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return NULL;

	sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "uuid", &jval))
			return NULL;

		str = json_object_get_string(jval);
		if (strlen(str) != 32)
			continue;

		if (!strcmp(buf, str))
			return jentry;
	}

	return NULL;
}

static bool add_u8_8(json_object *jobj, const uint8_t value[8],
							const char *desc)
{
	json_object *jstring;
	char buf[17];

	hex2str((uint8_t *) value, 8, buf, 17);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static bool add_u8_16(json_object *jobj, const uint8_t value[16],
							const char *desc)
{
	json_object *jstring;
	char buf[33];

	hex2str((uint8_t *) value, 16, buf, 33);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_object_add(jobj, desc, jstring);
	return true;
}

static bool add_string(json_object *jobj, const char *str, const char *desc)
{
	json_object *jstring = json_object_new_string(str);

	if (!jstring)
		return false;

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
	json_object *jkey, *jval;
	const char *str;
	uint16_t idx;

	jkey = json_object_array_get_idx(jarray, i);
	if (!jkey)
		return KEY_IDX_INVALID;

	if (!json_object_object_get_ex(jkey, "index", &jval))
		return KEY_IDX_INVALID;

	str = json_object_get_string(jval);
	if (sscanf(str, "%04hx", &idx) != 1)
		return KEY_IDX_INVALID;

	return idx;
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

		if (!json_object_object_get_ex(jnode, "uuid", &jval))
			continue;

		str = json_object_get_string(jval);
		if (strlen(str) != 32)
			continue;

		str2hex(str, 32, uuid, 16);

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
			key_idx = node_parse_key(jarray, j);

			if (key_idx != KEY_IDX_INVALID)
				remote_add_net_key(unicast, key_idx);
		}

		json_object_object_get_ex(jnode, "appKeys", &jarray);
		if (!jarray || json_object_get_type(jarray) != json_type_array)
			continue;

		key_cnt = json_object_array_length(jarray);

		for (j = 0; j < key_cnt; j++) {
			key_idx = node_parse_key(jarray, j);

			if (key_idx != KEY_IDX_INVALID)
				remote_add_app_key(unicast, key_idx);
		}

		node_count++;

		/* TODO: Add the rest of the configuration */
	}

	if (node_count != sz)
		l_warn("The remote node configuration load is incomplete!");

}

static bool add_app_key(json_object *jobj, uint16_t net_idx, uint16_t app_idx)
{
	json_object *jval, *jkey, *jarray;
	char buf[5];

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = json_object_new_object();

	snprintf(buf, 5, "%4.4x", net_idx);
	jval = json_object_new_string(buf);
	if (!jval)
		goto fail;

	json_object_object_add(jkey, "boundNetKey", jval);

	snprintf(buf, 5, "%4.4x", app_idx);
	jval = json_object_new_string(buf);
	if (!jval)
		goto fail;

	json_object_object_add(jkey, "index", jval);

	json_object_array_add(jarray, jkey);

	return true;
fail:
	json_object_put(jkey);
	return false;
}

static bool add_node_key(json_object *jobj, const char *desc, uint16_t idx)
{
	json_object *jval, *jkey, *jarray;
	char buf[5];

	json_object_object_get_ex(jobj, desc, &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	jkey = json_object_new_object();

	snprintf(buf, 5, "%4.4x", idx);

	jval = json_object_new_string(buf);
	if (!jval) {
		json_object_put(jkey);
		return false;
	}

	json_object_object_add(jkey, "index", jval);
	json_object_array_add(jarray, jkey);

	return mesh_config_save((struct mesh_config *) cfg, true,
								NULL, NULL);
}

bool mesh_db_node_net_key_add(uint16_t unicast, uint16_t idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(unicast);
	if (!jnode)
		return false;

	return add_node_key(jnode, "netKeys", idx);
}

bool mesh_db_node_ttl_set(uint16_t unicast, uint8_t ttl)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(unicast);
	if (!jnode)
		return false;

	if (!write_int(jnode, "defaultTTL", ttl))
		return false;

	return mesh_config_save((struct mesh_config *) cfg, true,
								NULL, NULL);
}

static void jarray_key_del(json_object *jarray, int16_t idx)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jval;
		uint16_t val;
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);

		if (!json_object_object_get_ex(jentry, "index", &jval))
			continue;

		str = json_object_get_string(jval);

		if (sscanf(str, "%04hx", &val) != 1)
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

	return mesh_config_save((struct mesh_config *) cfg, true,
								NULL, NULL);
}

bool mesh_db_node_net_key_del(uint16_t unicast, uint16_t net_idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(unicast);
	if (!jnode)
		return false;

	return delete_key(jnode, "netKeys", net_idx);
}

bool mesh_db_node_app_key_add(uint16_t unicast, uint16_t idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(unicast);
	if (!jnode)
		return false;

	return add_node_key(jnode, "appKeys", idx);
}

bool mesh_db_node_app_key_del(uint16_t unicast, uint16_t idx)
{
	json_object *jnode;

	if (!cfg || !cfg->jcfg)
		return false;

	jnode = get_node_by_unicast(unicast);
	if (!jnode)
		return false;

	return delete_key(jnode, "appKeys", idx);
}

static bool load_keys(json_object *jobj)
{
	json_object *jarray, *jentry, *jval;
	uint16_t net_idx, app_idx;
	int i, key_cnt;

	json_object_object_get_ex(jobj, "netKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	key_cnt = json_object_array_length(jarray);
	if (key_cnt < 0)
		return false;

	for (i = 0; i < key_cnt; ++i) {
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);

		if (!json_object_object_get_ex(jentry, "index", &jval))
			return false;

		str = json_object_get_string(jval);

		if (sscanf(str, "%04hx", &net_idx) != 1)
			return false;

		keys_add_net_key(net_idx);
	}

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	key_cnt = json_object_array_length(jarray);
	if (key_cnt < 0)
		return false;

	for (i = 0; i < key_cnt; ++i) {
		const char *str;

		jentry = json_object_array_get_idx(jarray, i);

		if (!json_object_object_get_ex(jentry, "boundNetKey", &jval))
			return false;

		str = json_object_get_string(jval);

		if (sscanf(str, "%04hx", &net_idx) != 1)
			return false;

		if (!json_object_object_get_ex(jentry, "index", &jval))
			return false;

		str = json_object_get_string(jval);

		if (sscanf(str, "%04hx", &app_idx) != 1)
			return false;
		keys_add_app_key(net_idx, app_idx);
	}

	return true;
}

bool mesh_db_net_key_add(uint16_t net_idx)
{
	json_object *jval, *jkey, *jarray;
	char buf[5];

	if (!cfg || !cfg->jcfg)
		return false;

	json_object_object_get_ex(cfg->jcfg, "netKeys", &jarray);
	if (!jarray || json_object_get_type(jarray) != json_type_array)
		return false;

	if (get_key_object(jarray, net_idx))
		return true;

	jkey = json_object_new_object();

	snprintf(buf, 5, "%4.4x", net_idx);

	jval = json_object_new_string(buf);
	if (!jval)
		goto fail;

	json_object_object_add(jkey, "index", jval);

	jval = json_object_new_int(KEY_REFRESH_PHASE_NONE);
	if (!jval)
		goto fail;

	json_object_object_add(jkey, "phase", jval);
	json_object_array_add(jarray, jkey);

	return mesh_config_save((struct mesh_config *) cfg, true,
								NULL, NULL);
fail:
	json_object_put(jkey);
	return false;
}

bool mesh_db_net_key_del(uint16_t net_idx)
{
	if (!cfg || !cfg->jcfg)
		return false;

	return delete_key(cfg->jcfg, "netKeys", net_idx);
}

bool mesh_db_app_key_add(uint16_t net_idx, uint16_t app_idx)
{
	if (!cfg || !cfg->jcfg)
		return false;

	if (!add_app_key(cfg->jcfg, net_idx, app_idx))
		return false;

	return mesh_config_save((struct mesh_config *) cfg, true,
								NULL, NULL);
}

bool mesh_db_app_key_del(uint16_t app_idx)
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
		if (!add_u8_16(jgroup, grp->label, "address"))
			goto fail;
	} else {
		snprintf(buf, 5, "%4.4x", grp->addr);
		jval = json_object_new_string(buf);
		if (!jval)
			goto fail;
		json_object_object_add(jgroup, "address", jval);
	}

	json_object_array_add(jgroups, jgroup);

	return mesh_config_save((struct mesh_config *) cfg, true, NULL, NULL);

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

bool mesh_db_add_node(uint8_t uuid[16], uint8_t num_els, uint16_t unicast,
							uint16_t net_idx)
{
	json_object *jnode;
	json_object *jelements, *jnodes, *jnetkeys, *jappkeys;
	int i;

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

	if (!add_u8_16(jnode, uuid, "uuid"))
		goto fail;

	jelements = json_object_new_array();
	if (!jelements)
		goto fail;

	for (i = 0; i < num_els; ++i) {
		json_object *jelement = json_object_new_object();

		if (!jelement) {
			json_object_put(jelements);
			goto fail;
		}

		write_int(jelement, "elementIndex", i);
		json_object_array_add(jelements, jelement);
	}

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

	if (!mesh_config_save((struct mesh_config *) cfg, true, NULL, NULL))
		goto fail;

	return true;

fail:
	json_object_put(jnode);
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
	json_object *jlow, *jhigh;
	const char *str;

	if (!cfg || !cfg->jcfg)
		return false;

	if (!json_object_object_get_ex(cfg->jcfg, "low", &jlow) ||
			!json_object_object_get_ex(cfg->jcfg, "high", &jhigh))
		return false;

	str = json_object_get_string(jlow);
	if (sscanf(str, "%04hx", low) != 1)
		return false;

	str = json_object_get_string(jhigh);
	if (sscanf(str, "%04hx", high) != 1)
		return false;

	return true;
}

bool mesh_db_set_addr_range(uint16_t low, uint16_t high)
{
	if (!cfg || !cfg->jcfg)
		return false;

	if (!write_uint16_hex(cfg->jcfg, "low", low))
		return false;

	if (!write_uint16_hex(cfg->jcfg, "high", high))
		return false;

	return mesh_config_save((struct mesh_config *) cfg, true, NULL, NULL);
}

bool mesh_db_create(const char *fname, const uint8_t token[8],
							const char *mesh_name)
{
	json_object *jcfg, *jarray;
	uint8_t uuid[16];

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

	if (!add_u8_8(jcfg, token, "token"))
		goto fail;

	l_getrandom(uuid, 16);

	if (!add_u8_16(jcfg, uuid, "uuid"))
		goto fail;

	if (mesh_name && !add_string(jcfg, mesh_name, "name"))
		goto fail;

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "nodes", jarray);

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "netKeys", jarray);

	jarray = json_object_new_array();
	if (!jarray)
		goto fail;

	json_object_object_add(jcfg, "appKeys", jarray);

	if (!mesh_config_save((struct mesh_config *) cfg, true, NULL, NULL))
		goto fail;

	return true;

fail:
	mesh_config_release((struct mesh_config *)cfg);
	cfg = NULL;

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

	return true;
fail:
	mesh_config_release((struct mesh_config *)cfg);
	cfg = NULL;
	return false;
}
