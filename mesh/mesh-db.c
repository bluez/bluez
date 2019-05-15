/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <ell/ell.h>
#include <json-c/json.h>

#include "mesh/mesh-defs.h"
#include "mesh/util.h"

#include "mesh/mesh-db.h"

#define CHECK_KEY_IDX_RANGE(x) (((x) >= 0) && ((x) <= 4095))

static bool get_int(json_object *jobj, const char *keyword, int *value)
{
	json_object *jvalue;

	if (!json_object_object_get_ex(jobj, keyword, &jvalue))
		return false;

	*value = json_object_get_int(jvalue);
	if (errno == EINVAL)
		return false;

	return true;
}

static bool add_u64_value(json_object *jobject, const char *desc,
					const uint8_t u64[8])
{
	json_object *jstring;
	char hexstr[17];

	hex2str((uint8_t *) u64, 8, hexstr, 17);
	jstring = json_object_new_string(hexstr);
	if (!jstring)
		return false;

	json_object_object_add(jobject, desc, jstring);
	return true;
}

static bool add_key_value(json_object *jobject, const char *desc,
					const uint8_t key[16])
{
	json_object *jstring;
	char hexstr[33];

	hex2str((uint8_t *) key, 16, hexstr, 33);
	jstring = json_object_new_string(hexstr);
	if (!jstring)
		return false;

	json_object_object_add(jobject, desc, jstring);
	return true;
}

static int get_element_index(json_object *jnode, uint16_t ele_addr)
{
	json_object *jvalue, *jelements;
	uint16_t addr, num_ele;
	char *str;

	if (!json_object_object_get_ex(jnode, "unicastAddress", &jvalue))
		return -1;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &addr) != 1)
		return -1;

	if (!json_object_object_get_ex(jnode, "elements", &jelements))
		return -1;

	num_ele = json_object_array_length(jelements);

	if (ele_addr >= addr + num_ele || ele_addr < addr)
		return -1;

	return ele_addr - addr;
}

static json_object *get_element_model(json_object *jnode, int ele_idx,
						uint32_t mod_id, bool vendor)
{
	json_object *jelements, *jelement, *jmodels;
	int i, num_mods;
	size_t len;
	char buf[9];

	if (!vendor)
		snprintf(buf, 5, "%4.4x", (uint16_t)mod_id);
	else
		snprintf(buf, 9, "%8.8x", mod_id);

	if (!json_object_object_get_ex(jnode, "elements", &jelements))
		return NULL;

	jelement = json_object_array_get_idx(jelements, ele_idx);
	if (!jelement)
		return NULL;

	if (!json_object_object_get_ex(jelement, "models", &jmodels))
		return NULL;

	num_mods = json_object_array_length(jmodels);
	if (!num_mods)
		return NULL;

	if (!vendor) {
		snprintf(buf, 5, "%4.4x", mod_id);
		len = 4;
	} else {
		snprintf(buf, 9, "%8.8x", mod_id);
		len = 8;
	}

	for (i = 0; i < num_mods; ++i) {
		json_object *jmodel, *jvalue;
		char *str;

		jmodel = json_object_array_get_idx(jmodels, i);
		if (!json_object_object_get_ex(jmodel, "modelId", &jvalue))
			return NULL;

		str = (char *)json_object_get_string(jvalue);
		if (!str)
			return NULL;

		if (!strncmp(str, buf, len))
			return jmodel;
	}

	return NULL;
}

static bool jarray_has_string(json_object *jarray, char *str, size_t len)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		char *str_entry;

		jentry = json_object_array_get_idx(jarray, i);
		str_entry = (char *)json_object_get_string(jentry);
		if (!str_entry)
			continue;

		if (!strncmp(str, str_entry, len))
			return true;
	}

	return false;
}

static json_object *jarray_string_del(json_object *jarray, char *str,
								size_t len)
{
	int i, sz = json_object_array_length(jarray);
	json_object *jarray_new;

	jarray_new = json_object_new_array();
	if (!jarray_new)
		return NULL;

	for (i = 0; i < sz; ++i) {
		json_object *jentry;
		char *str_entry;

		jentry = json_object_array_get_idx(jarray, i);
		str_entry = (char *)json_object_get_string(jentry);
		if (str_entry && !strncmp(str, str_entry, len))
			continue;

		json_object_get(jentry);
		json_object_array_add(jarray_new, jentry);
	}

	return jarray_new;
}

static json_object *get_key_object(json_object *jarray, uint16_t idx)
{
	int i, sz = json_object_array_length(jarray);

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jvalue;
		uint32_t jidx;

		jentry = json_object_array_get_idx(jarray, i);
		if (!json_object_object_get_ex(jentry, "index", &jvalue))
			return NULL;

		jidx = json_object_get_int(jvalue);

		if (jidx == idx)
			return jentry;
	}

	return NULL;
}

static json_object *jarray_key_del(json_object *jarray, int16_t idx)
{
	json_object *jarray_new;
	int i, sz = json_object_array_length(jarray);

	jarray_new = json_object_new_array();
	if (!jarray_new)
		return NULL;

	for (i = 0; i < sz; ++i) {
		json_object *jentry, *jvalue;

		jentry = json_object_array_get_idx(jarray, i);

		if (json_object_object_get_ex(jentry, "index", &jvalue)) {
			int tmp = json_object_get_int(jvalue);

			if (tmp == idx)
				continue;
		}

		json_object_get(jentry);
		json_object_array_add(jarray_new, jentry);
	}

	return jarray_new;
}

bool mesh_db_read_iv_index(json_object *jobj, uint32_t *idx, bool *update)
{
	int tmp;

	/* IV index */
	if (!get_int(jobj, "IVindex", &tmp))
		return false;

	*idx = (uint32_t) tmp;

	if (!get_int(jobj, "IVupdate", &tmp))
		return false;

	*update = tmp ? true : false;

	return true;
}

bool mesh_db_read_token(json_object *jobj, uint8_t token[8])
{
	json_object *jvalue;
	char *str;

	if (!token)
		return false;

	if (!json_object_object_get_ex(jobj, "token", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (!str2hex(str, strlen(str), token, 8))
		return false;

	return true;
}

bool mesh_db_read_device_key(json_object *jobj, uint8_t key_buf[16])
{
	json_object *jvalue;
	char *str;

	if (!key_buf)
		return false;

	if (!json_object_object_get_ex(jobj, "deviceKey", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (!str2hex(str, strlen(str), key_buf, 16))
		return false;

	return true;
}

bool mesh_db_read_app_keys(json_object *jobj, mesh_db_app_key_cb cb,
							void *user_data)
{
	json_object *jarray;
	int len;
	int i;

	if (!cb)
		return true;

	if (!json_object_object_get_ex(jobj, "appKeys", &jarray))
		return false;

	if (json_object_get_type(jarray) != json_type_array)
		return false;

	len = json_object_array_length(jarray);

	for (i = 0; i < len; ++i) {
		json_object *jtemp, *jvalue;
		int app_idx, net_idx;
		bool key_refresh = false;
		char *str;
		uint8_t key[16];
		uint8_t new_key[16];

		jtemp = json_object_array_get_idx(jarray, i);

		if (!get_int(jtemp, "index", &app_idx))
			return false;

		if (!CHECK_KEY_IDX_RANGE(app_idx))
			return false;

		if (!get_int(jtemp, "boundNetKey", &net_idx))
			return false;

		if (!CHECK_KEY_IDX_RANGE(net_idx))
			return false;

		if (json_object_object_get_ex(jtemp, "oldKey", &jvalue)) {
			str = (char *)json_object_get_string(jvalue);
			if (!str2hex(str, strlen(str), key, 16))
				return false;
			key_refresh = true;
		}

		if (!json_object_object_get_ex(jtemp, "key", &jvalue))
			return false;

		str = (char *)json_object_get_string(jvalue);
		if (!str2hex(str, strlen(str), key_refresh ? new_key : key, 16))
			return false;

		if (!cb((uint16_t)net_idx, (uint16_t) app_idx, key,
				key_refresh ? new_key : NULL, user_data))
			return false;
	}

	return true;
}

bool mesh_db_read_net_keys(json_object *jobj, mesh_db_net_key_cb cb,
								void *user_data)
{
	json_object *jarray;
	int len;
	int i;

	if (!cb)
		return true;

	if (!json_object_object_get_ex(jobj, "netKeys", &jarray))
		return false;

	if (json_object_get_type(jarray) != json_type_array)
		return false;

	len = json_object_array_length(jarray);

	for (i = 0; i < len; ++i) {
		json_object *jtemp, *jvalue;
		int idx;
		char *str;
		bool key_refresh = false;
		int phase;
		uint8_t key[16];
		uint8_t new_key[16];

		jtemp = json_object_array_get_idx(jarray, i);

		if (!get_int(jtemp, "index", &idx))
			return false;

		if (!CHECK_KEY_IDX_RANGE(idx))
			return false;

		if (json_object_object_get_ex(jtemp, "oldKey", &jvalue)) {
			str = (char *)json_object_get_string(jvalue);
			if (!str2hex(str, strlen(str), key, 16))
				return false;
			key_refresh = true;
		}

		if (!json_object_object_get_ex(jtemp, "key", &jvalue))
			return false;

		str = (char *)json_object_get_string(jvalue);
		if (!str2hex(str, strlen(str), key_refresh ? new_key : key, 16))
			return false;

		if (!json_object_object_get_ex(jtemp, "keyRefresh", &jvalue))
			phase = KEY_REFRESH_PHASE_NONE;
		else
			phase = json_object_get_int(jvalue);


		if (!cb((uint16_t)idx, key, key_refresh ? new_key : NULL, phase,
								user_data))
			return false;
	}

	return true;
}

bool mesh_db_net_key_add(json_object *jobj, uint16_t idx,
							const uint8_t key[16])
{
	json_object *jarray = NULL, *jentry = NULL, *jstring;
	char buf[5];

	json_object_object_get_ex(jobj, "netKeys", &jarray);
	if (jarray)
		jentry = get_key_object(jarray, idx);

	/* Do not allow direct overwrite */
	if (jentry)
		return false;

	jentry = json_object_new_object();
	if (!jentry)
		return false;

	snprintf(buf, 5, "%4.4x", idx);
	jstring = json_object_new_string(buf);
	if (!jstring)
		goto fail;

	json_object_object_add(jentry, "index", jstring);

	if (!add_key_value(jentry, "key", key))
		goto fail;

	json_object_object_add(jentry, "keyRefresh",
				json_object_new_int(KEY_REFRESH_PHASE_NONE));

	if (!jarray) {
		jarray = json_object_new_array();
		if (!jarray)
			goto fail;
		json_object_object_add(jobj, "netKeys", jarray);
	}

	json_object_array_add(jarray, jentry);

	return true;
fail:
	if (jentry)
		json_object_put(jentry);

	return false;
}

bool mesh_db_net_key_update(json_object *jobj, uint16_t idx,
							const uint8_t key[16])
{
	json_object *jarray, *jentry, *jstring;
	const char *str;

	if (!json_object_object_get_ex(jobj, "netKeys", &jarray))
		return false;

	jentry = get_key_object(jarray, idx);
	/* Net key must be already recorded */
	if (!jentry)
		return false;

	if (!json_object_object_get_ex(jentry, "key", &jstring))
		return false;

	str = json_object_get_string(jstring);
	jstring = json_object_new_string(str);
	json_object_object_add(jentry, "oldKey", jstring);
	json_object_object_del(jentry, "key");

	if (!add_key_value(jentry, "key", key))
		return false;

	json_object_object_add(jentry, "keyRefresh",
				json_object_new_int(KEY_REFRESH_PHASE_ONE));

	return true;
}

bool mesh_db_net_key_del(json_object *jobj, uint16_t idx)
{
	json_object *jarray, *jarray_new;

	if (!json_object_object_get_ex(jobj, "netKeys", &jarray))
		return true;

	/* Check if matching entry exists */
	if (!get_key_object(jarray, idx))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jobj, "netKeys");
		return true;
	}

	/*
	 * There is no easy way to delete a value from json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_key_del(jarray, idx);
	if (!jarray_new)
		return false;

	json_object_object_del(jobj, "netKeys");
	json_object_object_add(jobj, "netKeys", jarray_new);

	return true;
}

bool mesh_db_write_device_key(json_object *jnode, uint8_t *key)
{
	return add_key_value(jnode, "deviceKey", key);
}

bool mesh_db_write_token(json_object *jnode, uint8_t *token)
{
	return add_u64_value(jnode, "token", token);
}

bool mesh_db_app_key_add(json_object *jobj, uint16_t net_idx, uint16_t app_idx,
							const uint8_t key[16])
{
	json_object *jarray = NULL, *jentry = NULL, *jstring = NULL;
	char buf[5];

	json_object_object_get_ex(jobj, "appKeys", &jarray);
	if (jarray)
		jentry = get_key_object(jarray, app_idx);

	/* Do not allow direct overrwrite */
	if (jentry)
		return false;

	jentry = json_object_new_object();
	if (!jentry)
		return false;

	snprintf(buf, 5, "%4.4x", app_idx);
	jstring = json_object_new_string(buf);
	if (!jstring)
		goto fail;

	json_object_object_add(jentry, "index", jstring);

	snprintf(buf, 5, "%4.4x", net_idx);
	jstring = json_object_new_string(buf);
	if (!jstring)
		goto fail;

	json_object_object_add(jentry, "boundNetKey", jstring);

	if (!add_key_value(jentry, "key", key))
		goto fail;

	if (!jarray) {
		jarray = json_object_new_array();
		if (!jarray)
			goto fail;
		json_object_object_add(jobj, "appKeys", jarray);
	}

	json_object_array_add(jarray, jentry);

	return true;
fail:

	if (jentry)
		json_object_put(jentry);

	return false;
}

bool mesh_db_app_key_update(json_object *jobj, uint16_t app_idx,
							const uint8_t key[16])
{
	json_object *jarray, *jentry = NULL, *jstring = NULL;
	const char *str;

	if (!json_object_object_get_ex(jobj, "appKeys", &jarray))
		return false;

	/* The key entry should exist if the key is updated */
	jentry = get_key_object(jarray, app_idx);
	if (!jentry)
		return false;

	if (!json_object_object_get_ex(jentry, "key", &jstring))
		return false;

	str = json_object_get_string(jstring);
	jstring = json_object_new_string(str);
	json_object_object_add(jentry, "oldKey", jstring);
	json_object_object_del(jentry, "key");

	return add_key_value(jentry, "key", key);
}

bool mesh_db_app_key_del(json_object *jobj, uint16_t net_idx, uint16_t idx)
{
	json_object *jarray, *jarray_new;

	if (!json_object_object_get_ex(jobj, "appKeys", &jarray))
		return true;

	/* Check if matching entry exists */
	if (!get_key_object(jarray, idx))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jobj, "appKeys");
		return true;
	}

	/*
	 * There is no easy way to delete a value from json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_key_del(jarray, idx);
	if (!jarray_new)
		return false;

	json_object_object_del(jobj, "appKeys");
	json_object_object_add(jobj, "appKeys", jarray_new);

	return true;
}

bool mesh_db_model_binding_add(json_object *jnode, uint8_t ele_idx, bool vendor,
				uint32_t mod_id, uint16_t app_idx)
{
	json_object *jmodel, *jstring, *jarray = NULL;
	char buf[5];

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	snprintf(buf, 5, "%4.4x", app_idx);

	json_object_object_get_ex(jmodel, "bind", &jarray);
	if (jarray && jarray_has_string(jarray, buf, 4))
		return true;

	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	if (!jarray) {
		jarray = json_object_new_array();
		if (!jarray) {
			json_object_put(jstring);
			return false;
		}
		json_object_object_add(jmodel, "bind", jarray);
	}

	json_object_array_add(jarray, jstring);

	return true;
}

bool mesh_db_model_binding_del(json_object *jnode, uint8_t ele_idx, bool vendor,
				uint32_t mod_id, uint16_t app_idx)
{
	json_object *jmodel, *jarray, *jarray_new;
	char buf[5];

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	if (!json_object_object_get_ex(jmodel, "bind", &jarray))
		return true;

	snprintf(buf, 5, "%4.4x", app_idx);

	if (!jarray_has_string(jarray, buf, 4))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jmodel, "bind");
		return true;
	}

	/*
	 * There is no easy way to delete a value from json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_string_del(jarray, buf, 4);
	if (!jarray_new)
		return false;

	json_object_object_del(jmodel, "bind");
	json_object_object_add(jmodel, "bind", jarray_new);

	return true;
}

static void free_model(void *data)
{
	struct mesh_db_model *mod = data;

	l_free(mod->bindings);
	l_free(mod->subs);
	l_free(mod->pub);
	l_free(mod);
}

static void free_element(void *data)
{
	struct mesh_db_element *ele = data;

	l_queue_destroy(ele->models, free_model);
	l_free(ele);
}

static bool parse_bindings(json_object *jbindings, struct mesh_db_model *mod)
{
	int cnt;
	int i;

	cnt = json_object_array_length(jbindings);
	if (cnt > 0xffff)
		return false;

	mod->num_bindings = cnt;

	/* Allow empty bindings list */
	if (!cnt)
		return true;

	mod->bindings = l_new(uint16_t, cnt);
	if (!mod->bindings)
		return false;

	for (i = 0; i < cnt; ++i) {
		int idx;
		json_object *jvalue;

		jvalue = json_object_array_get_idx(jbindings, i);
		if (!jvalue)
			return false;

		idx = json_object_get_int(jvalue);
		if (!CHECK_KEY_IDX_RANGE(idx))
			return false;

		mod->bindings[i] = (uint16_t) idx;
	}

	return true;
}

static bool get_key_index(json_object *jobj, const char *keyword,
								uint16_t *index)
{
	int idx;

	if (!get_int(jobj, keyword, &idx))
		return false;

	if (!CHECK_KEY_IDX_RANGE(idx))
		return false;

	*index = (uint16_t) idx;
	return true;
}

static struct mesh_db_pub *parse_model_publication(json_object *jpub)
{
	json_object *jvalue;
	struct mesh_db_pub *pub;
	int len, value;
	char *str;

	if (!json_object_object_get_ex(jpub, "address", &jvalue))
		return NULL;

	str = (char *)json_object_get_string(jvalue);
	len = strlen(str);
	pub = l_new(struct mesh_db_pub, 1);

	switch (len) {
	case 4:
		if (sscanf(str, "%04hx", &pub->addr) != 1)
			goto fail;
		break;
	case 32:
		if (!str2hex(str, len, pub->virt_addr, 16))
			goto fail;
		pub->virt = true;
		break;
	default:
		goto fail;
	}

	if (!get_key_index(jpub, "index", &pub->idx))
		goto fail;

	if (!get_int(jpub, "ttl", &value))
		goto fail;
	pub->ttl = (uint8_t) value;

	if (!get_int(jpub, "period", &value))
		goto fail;
	pub->period = value;

	if (!get_int(jpub, "credentials", &value))
		goto fail;
	pub->credential = (uint8_t) value;

	if (!json_object_object_get_ex(jpub, "retransmit", &jvalue))
		goto fail;

	if (!get_int(jvalue, "count", &value))
		goto fail;
	pub->count = (uint8_t) value;

	if (!get_int(jvalue, "interval", &value))
		goto fail;
	pub->interval = (uint8_t) value;

	return pub;

fail:
	l_free(pub);
	return NULL;
}

static bool parse_model_subscriptions(json_object *jsubs,
						struct mesh_db_model *mod)
{
	struct mesh_db_sub *subs;
	int i, cnt;

	if (json_object_get_type(jsubs) != json_type_array)
		return NULL;

	cnt = json_object_array_length(jsubs);
	/* Allow empty array */
	if (!cnt)
		return true;

	subs = l_new(struct mesh_db_sub, cnt);
	if (!subs)
		return false;

	for (i = 0; i < cnt; ++i) {
		char *str;
		int len;
		json_object *jvalue;

		jvalue = json_object_array_get_idx(jsubs, i);
		if (!jvalue)
			return false;

		str = (char *)json_object_get_string(jvalue);
		len = strlen(str);

		switch (len) {
		case 4:
			if (sscanf(str, "%04hx", &subs[i].src.addr) != 1)
				goto fail;
		break;
		case 32:
			if (!str2hex(str, len, subs[i].src.virt_addr, 16))
				goto fail;
			subs[i].virt = true;
			break;
		default:
			goto fail;
		}
	}

	mod->num_subs = cnt;
	mod->subs = subs;

	return true;
fail:
	l_free(subs);
	return false;
}

static bool parse_models(json_object *jmodels, struct mesh_db_element *ele)
{
	int i, num_models;

	num_models = json_object_array_length(jmodels);
	if (!num_models)
		return true;

	for (i = 0; i < num_models; ++i) {
		json_object *jmodel, *jarray, *jvalue;
		struct mesh_db_model *mod;
		uint32_t id;
		int len;
		char *str;

		jmodel = json_object_array_get_idx(jmodels, i);
		if (!jmodel)
			goto fail;

		mod = l_new(struct mesh_db_model, 1);

		if (!json_object_object_get_ex(jmodel, "modelId", &jvalue))
			goto fail;

		str = (char *)json_object_get_string(jvalue);

		len = strlen(str);

		if (len != 4 && len != 8)
			goto fail;

		if (len == 4) {
			if (sscanf(str, "%04x", &id) != 1)
				goto fail;

			id |= VENDOR_ID_MASK;
		} else if (len == 8) {
			if (sscanf(str, "%08x", &id) != 1)
				goto fail;
		} else
			goto fail;

		mod->id = id;

		if (len == 8)
			mod->vendor = true;

		if (json_object_object_get_ex(jmodel, "bind", &jarray)) {
			if (json_object_get_type(jarray) != json_type_array ||
					!parse_bindings(jarray, mod))
				goto fail;
		}

		if (json_object_object_get_ex(jmodel, "publish", &jvalue)) {
			mod->pub = parse_model_publication(jvalue);
			if (!mod->pub)
				goto fail;
		}

		if (json_object_object_get_ex(jmodel, "subscribe", &jarray)) {
			if (!parse_model_subscriptions(jarray, mod))
				goto fail;
		}

		l_queue_push_tail(ele->models, mod);
	}

	return true;

fail:
	l_queue_destroy(ele->models, free_model);
	return false;
}

static bool parse_elements(json_object *jelements, struct mesh_db_node *node)
{
	int i, num_ele;

	num_ele = json_object_array_length(jelements);
	if (!num_ele)
		/* Allow "empty" nodes */
		return true;

	node->elements = l_queue_new();
	if (!node->elements)
		return false;

	for (i = 0; i < num_ele; ++i) {
		json_object *jelement;
		json_object *jmodels;
		json_object *jvalue;
		struct mesh_db_element *ele;
		int index;
		char *str;

		jelement = json_object_array_get_idx(jelements, i);
		if (!jelement)
			goto fail;

		if (!get_int(jelement, "elementIndex", &index) ||
								index > num_ele)
			goto fail;

		ele = l_new(struct mesh_db_element, 1);
		ele->index = index;
		ele->models = l_queue_new();
		if (!ele->models)
			goto fail;

		if (!json_object_object_get_ex(jelement, "location", &jvalue))
			goto fail;

		str = (char *)json_object_get_string(jvalue);
		if (sscanf(str, "%04hx", &(ele->location)) != 1)
			goto fail;

		if (json_object_object_get_ex(jelement, "models", &jmodels)) {
			if (json_object_get_type(jmodels) != json_type_array ||
						!parse_models(jmodels, ele))
				goto fail;
		}

		l_queue_push_tail(node->elements, ele);
	}

	return true;

fail:
	l_queue_destroy(node->elements, free_element);
	node->elements = NULL;

	return false;
}

static int get_mode(json_object *jvalue)
{
	const char *str;

	str = json_object_get_string(jvalue);
	if (!str)
		return 0xffffffff;

	if (!strncasecmp(str, "disabled", strlen("disabled")))
		return MESH_MODE_DISABLED;

	if (!strncasecmp(str, "enabled", strlen("enabled")))
		return MESH_MODE_ENABLED;

	if (!strncasecmp(str, "unsupported", strlen("unsupported")))
		return MESH_MODE_UNSUPPORTED;

	return 0xffffffff;
}

static void parse_features(json_object *jconfig, struct mesh_db_node *node)
{
	json_object *jvalue, *jrelay;
	int mode, count;
	uint16_t interval;

	if (json_object_object_get_ex(jconfig, "proxy", &jvalue)) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.proxy = mode;
	}

	if (json_object_object_get_ex(jconfig, "friend", &jvalue)) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.friend = mode;
	}

	if (json_object_object_get_ex(jconfig, "lowPower", &jvalue)) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.friend = mode;
	}

	if (json_object_object_get_ex(jconfig, "beacon", &jvalue)) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.beacon = mode;
	}

	if (!json_object_object_get_ex(jconfig, "relay", &jrelay))
		return;

	if (json_object_object_get_ex(jrelay, "mode", &jvalue)) {
		mode = get_mode(jvalue);
		if (mode <= MESH_MODE_UNSUPPORTED)
			node->modes.relay.state = mode;
		else
			return;
	} else
		return;

	if (!json_object_object_get_ex(jrelay, "count", &jvalue))
		return;

	/* TODO: check range */
	count = json_object_get_int(jvalue);
	node->modes.relay.cnt = count;

	if (!json_object_object_get_ex(jrelay, "interval", &jvalue))
		return;

	/* TODO: check range */
	interval = json_object_get_int(jvalue);
	node->modes.relay.interval = interval;
}

static bool parse_composition(json_object *jcomp, struct mesh_db_node *node)
{
	json_object *jvalue;
	char *str;

	/* All the fields in node composition are mandatory */
	if (!json_object_object_get_ex(jcomp, "cid", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->cid) != 1)
		return false;

	if (!json_object_object_get_ex(jcomp, "pid", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->pid) != 1)
		return false;

	if (!json_object_object_get_ex(jcomp, "vid", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->vid) != 1)
		return false;

	if (!json_object_object_get_ex(jcomp, "crpl", &jvalue))
		return false;

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node->crpl) != 1)
		return false;

	return true;
}

bool mesh_db_read_node(json_object *jnode, mesh_db_node_cb cb, void *user_data)
{
	struct mesh_db_node node;
	json_object *jvalue;
	char *str;

	if (!jnode)
		return false;

	if (!cb) {
		l_info("Node read callback is required");
		return false;
	}

	memset(&node, 0, sizeof(node));

	if (!parse_composition(jnode, &node)) {
		l_info("Failed to parse local node composition");
		return false;
	}

	parse_features(jnode, &node);

	if (!json_object_object_get_ex(jnode, "unicastAddress", &jvalue)) {
		l_info("Bad config: Unicast address must be present");
		return false;
	}

	str = (char *)json_object_get_string(jvalue);
	if (sscanf(str, "%04hx", &node.unicast) != 1)
		return false;

	if (json_object_object_get_ex(jnode, "defaultTTL", &jvalue)) {
		int ttl = json_object_get_int(jvalue);

		if (ttl < 0 || ttl == 1 || ttl > DEFAULT_TTL)
			return false;
		node.ttl = (uint8_t) ttl;
	}

	if (json_object_object_get_ex(jnode, "sequenceNumber", &jvalue))
		node.seq_number = json_object_get_int(jvalue);

	if (json_object_object_get_ex(jnode, "elements", &jvalue)) {
		if (json_object_get_type(jvalue) == json_type_array) {
			if (!parse_elements(jvalue, &node))
				return false;
		}
	}

	return cb(&node, user_data);
}

bool mesh_db_write_uint16_hex(json_object *jobj, const char *desc,
								uint16_t value)
{
	json_object *jstring;
	char buf[5];

	if (!jobj)
		return false;

	snprintf(buf, 5, "%4.4x", value);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_object_add(jobj, desc, jstring);
	return true;
}

bool mesh_db_write_uint32_hex(json_object *jobj, const char *desc,
								uint32_t value)
{
	json_object *jstring;
	char buf[9];

	if (!jobj)
		return false;

	snprintf(buf, 9, "%8.8x", value);
	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	json_object_object_add(jobj, desc, jstring);
	return true;
}

bool mesh_db_write_int(json_object *jobj, const char *keyword, int value)
{
	json_object *jvalue;

	if (!jobj)
		return false;

	json_object_object_del(jobj, keyword);

	jvalue = json_object_new_int(value);
	if (!jvalue)
		return false;

	json_object_object_add(jobj, keyword, jvalue);
	return true;
}

bool mesh_db_write_bool(json_object *jobj, const char *keyword, bool value)
{
	json_object *jvalue;

	if (!jobj)
		return false;

	json_object_object_del(jobj, keyword);

	jvalue = json_object_new_boolean(value);
	if (!jvalue)
		return false;

	json_object_object_add(jobj, keyword, jvalue);
	return true;
}

static const char *mode_to_string(int mode)
{
	switch (mode) {
	case MESH_MODE_DISABLED:
		return "disabled";
	case MESH_MODE_ENABLED:
		return "enabled";
	default:
		return "unsupported";
	}
}

bool mesh_db_write_mode(json_object *jobj, const char *keyword, int value)
{
	json_object *jstring;

	if (!jobj)
		return false;

	jstring = json_object_new_string(mode_to_string(value));

	if (!jstring)
		return false;

	json_object_object_add(jobj, keyword, jstring);

	return true;
}

bool mesh_db_write_relay_mode(json_object *jnode, uint8_t mode, uint8_t count,
							uint16_t interval)
{
	json_object *jrelay;

	if (!jnode)
		return false;

	json_object_object_del(jnode, "relay");

	jrelay = json_object_new_object();
	if (!jrelay)
		return false;

	if (!mesh_db_write_mode(jrelay, "mode", mode))
		goto fail;

	if (!mesh_db_write_int(jrelay, "count", count))
		goto fail;

	if (!mesh_db_write_int(jrelay, "interval", interval))
		goto fail;

	json_object_object_add(jnode, "relay", jrelay);

	return true;
fail:
	json_object_put(jrelay);
	return false;
}

bool mesh_db_read_net_transmit(json_object *jobj, uint8_t *cnt,
							uint16_t *interval)
{
	json_object *jretransmit, *jvalue;

	if (!jobj)
		return false;

	if (!json_object_object_get_ex(jobj, "retransmit", &jretransmit))
		return false;

	if (!json_object_object_get_ex(jretransmit, "count", &jvalue))
		return false;

	*cnt = (uint8_t) json_object_get_int(jvalue);

	if (!json_object_object_get_ex(jretransmit, "interval", &jvalue))
		return false;

	*interval = (uint16_t) json_object_get_int(jvalue);

	return true;
}

bool mesh_db_write_net_transmit(json_object *jobj, uint8_t cnt,
							uint16_t interval)
{
	json_object *jretransmit;

	if (!jobj)
		return false;

	json_object_object_del(jobj, "retransmit");

	jretransmit = json_object_new_object();
	if (jretransmit)
		return false;

	if (!mesh_db_write_int(jretransmit, "count", cnt))
		goto fail;

	if (!mesh_db_write_int(jretransmit, "interval", interval))
		goto fail;

	json_object_object_add(jobj, "retransmit", jretransmit);

	return true;
fail:
	json_object_put(jretransmit);
	return false;

}

bool mesh_db_write_iv_index(json_object *jobj, uint32_t idx, bool update)
{
	int tmp = update ? 1 : 0;

	if (!jobj)
		return false;

	if (!mesh_db_write_int(jobj, "IVindex", idx))
		return false;

	if (!mesh_db_write_int(jobj, "IVupdate", tmp))
		return false;

	return true;
}

void mesh_db_remove_property(json_object *jobj, const char *desc)
{
	if (jobj)
		json_object_object_del(jobj, desc);
}

static void add_model(void *a, void *b)
{
	struct mesh_db_model *mod = a;
	json_object *jmodels = b, *jmodel;

	jmodel = json_object_new_object();
	if (!jmodel)
		return;

	if (!mod->vendor)
		mesh_db_write_uint16_hex(jmodel, "modelId",
						(uint16_t) mod->id);
	else
		mesh_db_write_uint32_hex(jmodel, "modelId", mod->id);

	json_object_array_add(jmodels, jmodel);
}

/* Add unprovisioned node (local) */
bool mesh_db_add_node(json_object *jnode, struct mesh_db_node *node) {

	struct mesh_db_modes *modes = &node->modes;
	const struct l_queue_entry *entry;
	json_object *jelements;

	if (!jnode)
		return false;

	/* CID, PID, VID, crpl */
	if (!mesh_db_write_uint16_hex(jnode, "cid", node->cid))
		return false;

	if (!mesh_db_write_uint16_hex(jnode, "pid", node->pid))
		return false;

	if (!mesh_db_write_uint16_hex(jnode, "vid", node->vid))
		return false;

	if (!mesh_db_write_uint16_hex(jnode, "crpl", node->crpl))
		return false;

	/* Features: relay, LPN, friend, proxy*/
	if (!mesh_db_write_relay_mode(jnode, modes->relay.state,
						modes->relay.cnt,
						modes->relay.interval))
		return false;

	if (!mesh_db_write_mode(jnode, "lowPower", modes->lpn))
		return false;

	if (!mesh_db_write_mode(jnode, "friend", modes->friend))
		return false;

	if (!mesh_db_write_mode(jnode, "proxy", modes->proxy))
		return false;

	/* Beaconing state */
	if (!mesh_db_write_mode(jnode, "beacon", modes->beacon))
		return false;

	/* Sequence number */
	json_object_object_add(jnode, "sequenceNumber",
					json_object_new_int(node->seq_number));

	/* Default TTL */
	json_object_object_add(jnode, "defaultTTL",
						json_object_new_int(node->ttl));

	/* Elements */
	jelements = json_object_new_array();
	if (!jelements)
		return false;

	entry = l_queue_get_entries(node->elements);

	for (; entry; entry = entry->next) {
		struct mesh_db_element *ele = entry->data;
		json_object *jelement, *jmodels;

		jelement = json_object_new_object();

		if (!jelement) {
			json_object_put(jelements);
			return false;
		}

		mesh_db_write_int(jelement, "elementIndex", ele->index);
		mesh_db_write_uint16_hex(jelement, "location", ele->location);
		json_object_array_add(jelements, jelement);

		/* Models */
		if (l_queue_isempty(ele->models))
			continue;

		jmodels = json_object_new_array();
		if (!jmodels) {
			json_object_put(jelements);
			return false;
		}

		json_object_object_add(jelement, "models", jmodels);
		l_queue_foreach(ele->models, add_model, jmodels);
	}

	json_object_object_add(jnode, "elements", jelements);

	return true;
}

static void finish_key_refresh(json_object *jobj, uint16_t net_idx)
{
	json_object *jarray;
	int i, len;

	/* Clean up all the bound appkeys */
	if (!json_object_object_get_ex(jobj, "appKeys", &jarray))
		return;

	len = json_object_array_length(jarray);

	for (i = 0; i < len; ++i) {
		json_object *jentry;
		uint16_t idx;

		jentry = json_object_array_get_idx(jarray, i);

		if (!get_key_index(jentry, "boundNetKey", &idx))
			continue;

		if (idx != net_idx)
			continue;

		json_object_object_del(jentry, "oldKey");

		if (!get_key_index(jentry, "index", &idx))
			continue;
	}

}

bool mesh_db_net_key_set_phase(json_object *jobj, uint16_t idx, uint8_t phase)
{
	json_object *jarray, *jentry = NULL;

	if (!jobj)
		return false;

	if (json_object_object_get_ex(jobj, "netKeys", &jarray))
		jentry = get_key_object(jarray, idx);

	if (!jentry)
		return false;

	json_object_object_del(jentry, "keyRefresh");
	json_object_object_add(jentry, "keyRefresh",
					json_object_new_int(phase));

	if (phase == KEY_REFRESH_PHASE_NONE) {
		json_object_object_del(jentry, "oldKey");
		finish_key_refresh(jobj, idx);
	}

	return true;
}

bool mesh_db_model_pub_add(json_object *jnode, uint16_t addr, uint32_t mod_id,
					bool vendor, struct mesh_db_pub *pub)
{
	json_object *jmodel, *jpub, *jretransmit;
	bool res;
	int ele_idx;

	if (!jnode)
		return false;

	ele_idx = get_element_index(jnode, addr);
	if (ele_idx < 0)
		return false;

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	json_object_object_del(jmodel, "publish");

	jpub = json_object_new_object();
	if (!jpub)
		return false;

	if (pub->virt)
		res = add_key_value(jpub, "address", pub->virt_addr);
	else
		res = mesh_db_write_uint16_hex(jpub, "address", pub->addr);

	if (!res)
		goto fail;

	if (!mesh_db_write_uint16_hex(jpub, "index", pub->idx))
		goto fail;

	if (!mesh_db_write_int(jpub, "ttl", pub->ttl))
		goto fail;

	if (!mesh_db_write_int(jpub, "period", pub->period))
		goto fail;

	if (!mesh_db_write_int(jpub, "credentials", pub->credential ? 1 : 0))
		goto fail;

	jretransmit = json_object_new_object();
	if (!jretransmit)
		goto fail;

	if (!mesh_db_write_int(jretransmit, "count", pub->count))
		goto fail;

	if (!mesh_db_write_int(jretransmit, "interval", pub->interval))
		goto fail;

	json_object_object_add(jpub, "retransmit", jretransmit);
	json_object_object_add(jmodel, "publish", jpub);

	return true;
fail:
	json_object_put(jpub);
	return false;
}

static bool delete_model_property(json_object *jnode, uint16_t addr,
			uint32_t mod_id, bool vendor, const char *keyword)
{
	json_object *jmodel;
	int ele_idx;

	ele_idx = get_element_index(jnode, addr);
	if (ele_idx < 0)
		return false;

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	json_object_object_del(jmodel, keyword);

	return true;
}

bool mesh_db_model_pub_del(json_object *jnode, uint16_t addr, uint32_t mod_id,
								bool vendor)
{
	if (!jnode)
		return false;

	return delete_model_property(jnode, addr, mod_id, vendor, "publish");
}

bool mesh_db_model_sub_add(json_object *jnode, uint16_t addr, uint32_t mod_id,
					bool vendor, struct mesh_db_sub *sub)
{
	json_object *jmodel, *jstring, *jarray = NULL;
	int ele_idx, len;
	char buf[33];

	if (!jnode)
		return false;

	ele_idx = get_element_index(jnode, addr);
	if (ele_idx < 0)
		return false;

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	if (!sub->virt) {
		snprintf(buf, 5, "%4.4x", sub->src.addr);
		len = 4;
	} else {
		hex2str(sub->src.virt_addr, 16, buf, 33);
		len = 32;
	}

	json_object_object_get_ex(jmodel, "subscribe", &jarray);
	if (jarray && jarray_has_string(jarray, buf, len))
		return true;

	jstring = json_object_new_string(buf);
	if (!jstring)
		return false;

	if (!jarray) {
		jarray = json_object_new_array();
		if (!jarray) {
			json_object_put(jstring);
			return false;
		}
		json_object_object_add(jmodel, "subscribe", jarray);
	}

	json_object_array_add(jarray, jstring);

	return true;
}

bool mesh_db_model_sub_del(json_object *jnode, uint16_t addr,
			uint32_t mod_id, bool vendor, struct mesh_db_sub *sub)
{
	json_object *jmodel, *jarray, *jarray_new;
	char buf[33];
	int len, ele_idx;

	if (!jnode)
		return false;

	ele_idx = get_element_index(jnode, addr);
	if (ele_idx < 0)
		return false;

	jmodel = get_element_model(jnode, ele_idx, mod_id, vendor);
	if (!jmodel)
		return false;

	if (!json_object_object_get_ex(jmodel, "subscribe", &jarray))
		return true;

	if (!sub->virt) {
		snprintf(buf, 5, "%4.4x", sub->src.addr);
		len = 4;
	} else {
		hex2str(sub->src.virt_addr, 16, buf, 33);
		len = 32;
	}

	if (!jarray_has_string(jarray, buf, len))
		return true;

	if (json_object_array_length(jarray) == 1) {
		json_object_object_del(jmodel, "subscribe");
		return true;
	}

	/*
	 * There is no easy way to delete a value from a json array.
	 * Create a new copy without specified element and
	 * then remove old array.
	 */
	jarray_new = jarray_string_del(jarray, buf, len);
	if (!jarray_new)
		return false;

	json_object_object_del(jmodel, "subscribe");
	json_object_object_add(jmodel, "subscribe", jarray_new);

	return true;
}

bool mesh_db_model_sub_del_all(json_object *jnode, uint16_t addr,
						uint32_t mod_id, bool vendor)
{
	if (!jnode)
		return false;

	return delete_model_property(jnode, addr, mod_id, vendor, "subscribe");
}
