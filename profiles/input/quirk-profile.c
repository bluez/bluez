/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Gamepad Quirk Support
 *
 *  External quirk profile loader. Parses JSON profiles, verifies
 *  HMAC-SHA256 signatures, and creates generic match/apply quirks.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hidp.h"

#include "src/log.h"

#include "quirk.h"
#include "quirk-profile.h"

/* Accessors from src/device.h and src/service.h */
extern struct btd_service *input_device_get_service(
					struct input_device *idev);
extern struct btd_device *btd_service_get_device(
					const struct btd_service *service);
extern uint16_t btd_device_get_vendor(struct btd_device *device);
extern uint16_t btd_device_get_product(struct btd_device *device);
extern bool device_name_known(struct btd_device *device);
extern void device_get_name(struct btd_device *device,
					char *name, size_t len);

#define MAX_EXTERNAL_QUIRKS 32
#define HMAC_KEY_PATH QUIRK_PROFILE_DIR "/.hmac_key"
#define HMAC_KEY_SIZE 32
#define SIG_EXT ".sig"
#define JSON_EXT ".json"

struct external_quirk {
	struct gamepad_quirk base;
	uint16_t vendor_id;
	uint16_t product_id;
	char device_name[248];
	bool match_by_vidpid;
	bool match_by_name;
	uint8_t *rd_data;
	uint16_t rd_size;
	uint16_t parser;
	uint8_t country;
	uint8_t subclass;
};

static struct external_quirk *ext_quirks[MAX_EXTERNAL_QUIRKS + 1];
static int num_ext_quirks;

/*
 * Parse a hex string like "0501 0905" into a byte buffer.
 * Spaces and other whitespace are skipped.
 */
static int parse_hex_descriptor(const char *hex, uint8_t *out, int max)
{
	int len = 0;
	const char *p = hex;
	unsigned int byte;
	char buf[3];

	while (*p && len < max) {
		while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
			p++;
		if (!*p)
			break;
		if (!p[0] || !p[1])
			return -1;

		buf[0] = p[0];
		buf[1] = p[1];
		buf[2] = '\0';
		if (sscanf(buf, "%2x", &byte) != 1)
			return -1;

		out[len++] = (uint8_t)byte;
		p += 2;
	}

	return len;
}

/*
 * Read entire file into malloc'd buffer.
 */
static char *read_file(const char *path, size_t *out_len)
{
	FILE *f;
	long fsize;
	char *buf;

	f = fopen(path, "re");
	if (!f)
		return NULL;

	fseek(f, 0, SEEK_END);
	fsize = ftell(f);
	if (fsize < 0 || fsize > 1024 * 1024) {
		fclose(f);
		return NULL;
	}
	rewind(f);

	buf = malloc(fsize + 1);
	if (!buf) {
		fclose(f);
		return NULL;
	}

	if (fread(buf, 1, fsize, f) != (size_t)fsize) {
		free(buf);
		fclose(f);
		return NULL;
	}
	buf[fsize] = '\0';
	*out_len = fsize;
	fclose(f);
	return buf;
}

/*
 * Compute HMAC-SHA256 using openssl CLI.
 */
static char *hmac_sha256(const uint8_t *key, int key_len,
			 const void *data, size_t data_len)
{
	char key_hex[HMAC_KEY_SIZE * 2 + 1];
	char *cmd;
	char *result = NULL;
	FILE *p, *tmpf;
	int i;
	const char *tmpfile = "/tmp/.bluez_quirk_hmac_input";
	char line[256];
	char *eq, *end;

	for (i = 0; i < key_len; i++)
		snprintf(key_hex + i * 2, 3, "%02x", key[i]);
	key_hex[key_len * 2] = '\0';

	tmpf = fopen(tmpfile, "we");
	if (!tmpf)
		return NULL;

	fwrite(data, 1, data_len, tmpf);
	fclose(tmpf);

	cmd = malloc(strlen(key_hex) + 128);
	if (!cmd) {
		unlink(tmpfile);
		return NULL;
	}

	snprintf(cmd, strlen(key_hex) + 128,
		"openssl dgst -sha256 -hmac '%s' -hex < %s 2>/dev/null",
		key_hex, tmpfile);

	p = popen(cmd, "re");
	free(cmd);
	unlink(tmpfile);

	if (!p)
		return NULL;

	while (fgets(line, sizeof(line), p)) {
		eq = strstr(line, "= ");
		if (eq) {
			eq += 2;
			end = eq + strlen(eq) - 1;
			while (end > eq && (*end == '\n' || *end == '\r'
						|| *end == ' '))
				*end-- = '\0';
			result = strdup(eq);
			break;
		}
	}

	pclose(p);
	return result;
}

/*
 * Verify HMAC signature.
 */
static bool verify_signature(const char *json_path,
			     const uint8_t *hmac_key, int key_len)
{
	char sig_path[1024];
	size_t sig_len, json_len;
	char *sig_hex, *json_data, *expected_sig;
	char *end;
	bool valid;

	snprintf(sig_path, sizeof(sig_path), "%s" SIG_EXT, json_path);

	sig_hex = read_file(sig_path, &sig_len);
	if (!sig_hex) {
		DBG("No signature file: %s", sig_path);
		return false;
	}

	end = sig_hex + strlen(sig_hex) - 1;
	while (end > sig_hex && (*end == '\n' || *end == '\r' || *end == ' '))
		*end-- = '\0';

	json_data = read_file(json_path, &json_len);
	if (!json_data) {
		free(sig_hex);
		return false;
	}

	expected_sig = hmac_sha256(hmac_key, key_len, json_data, json_len);
	free(json_data);

	if (!expected_sig) {
		free(sig_hex);
		return false;
	}

	valid = (strcmp(sig_hex, expected_sig) == 0);

	if (!valid)
		DBG("Signature mismatch for %s", json_path);

	free(sig_hex);
	free(expected_sig);
	return valid;
}

/*
 * Load the HMAC key from disk.
 */
static int load_hmac_key(uint8_t *key, int max_len)
{
	size_t len;
	char *hex;
	int key_len, i;
	char *end;

	hex = read_file(HMAC_KEY_PATH, &len);
	if (!hex)
		return -1;

	end = hex + strlen(hex) - 1;
	while (end > hex && (*end == '\n' || *end == '\r' || *end == ' '))
		*end-- = '\0';

	key_len = len / 2;
	if (key_len > max_len)
		key_len = max_len;

	for (i = 0; i < key_len; i++) {
		unsigned int byte;
		char buf[3];

		buf[0] = hex[i * 2];
		buf[1] = hex[i * 2 + 1];
		buf[2] = '\0';
		if (sscanf(buf, "%2x", &byte) != 1) {
			free(hex);
			return -1;
		}
		key[i] = (uint8_t)byte;
	}

	free(hex);
	return key_len;
}

/* Name storage pool for external quirks */
static char name_pool[MAX_EXTERNAL_QUIRKS][248];

/*
 * Parse a single JSON profile file.
 */
static struct external_quirk *parse_profile(const char *path)
{
	FILE *f;
	json_object *root, *jname, *jmatch, *jdesc, *jtmp, *jpid;
	struct external_quirk *eq;
	const char *name, *desc_hex;
	char *desc_stripped;
	uint16_t parser = 0x0111;
	uint8_t country = 0, subclass = 0;

	f = fopen(path, "re");
	if (!f)
		return NULL;

	root = json_object_from_fd(fileno(f));
	fclose(f);

	if (!root) {
		error("quirk-profile: failed to parse %s", path);
		return NULL;
	}

	if (!json_object_object_get_ex(root, "name", &jname) ||
	    json_object_get_type(jname) != json_type_string) {
		error("quirk-profile: missing 'name' in %s", path);
		goto fail;
	}
	name = json_object_get_string(jname);

	if (!json_object_object_get_ex(root, "match", &jmatch) ||
	    json_object_get_type(jmatch) != json_type_object) {
		error("quirk-profile: missing 'match' in %s", path);
		goto fail;
	}

	if (!json_object_object_get_ex(root, "hid_descriptor", &jdesc) ||
	    json_object_get_type(jdesc) != json_type_string) {
		error("quirk-profile: missing 'hid_descriptor' in %s", path);
		goto fail;
	}
	desc_hex = json_object_get_string(jdesc);

	/* Optional fields */
	if (json_object_object_get_ex(root, "parser_version", &jtmp))
		parser = (uint16_t)strtol(json_object_get_string(jtmp),
						NULL, 16);
	if (json_object_object_get_ex(root, "country", &jtmp))
		country = (uint8_t)json_object_get_int(jtmp);
	if (json_object_object_get_ex(root, "subclass", &jtmp))
		subclass = (uint8_t)json_object_get_int(jtmp);

	eq = calloc(1, sizeof(*eq));
	if (!eq)
		goto fail;

	/* Parse match criteria */
	if (json_object_object_get_ex(jmatch, "vendor_id", &jtmp)) {
		if (json_object_object_get_ex(jmatch, "product_id", &jpid)) {
			eq->vendor_id = (uint16_t)strtol(
				json_object_get_string(jtmp), NULL, 16);
			eq->product_id = (uint16_t)strtol(
				json_object_get_string(jpid), NULL, 16);
			eq->match_by_vidpid = true;
		}
	}

	if (json_object_object_get_ex(jmatch, "device_name", &jtmp)) {
		snprintf(eq->device_name, sizeof(eq->device_name), "%s",
			json_object_get_string(jtmp));
		eq->match_by_name = true;
	}

	if (!eq->match_by_vidpid && !eq->match_by_name) {
		error("quirk-profile: match needs vidpid or device_name in %s",
			path);
		free(eq);
		goto fail;
	}

	/* Parse HID descriptor */
	desc_stripped = strdup(desc_hex);
	if (!desc_stripped) {
		free(eq);
		goto fail;
	}

	eq->rd_data = malloc(QUIRK_MAX_DESCRIPTOR_SIZE);
	if (!eq->rd_data) {
		free(desc_stripped);
		free(eq);
		goto fail;
	}

	eq->rd_size = parse_hex_descriptor(desc_stripped, eq->rd_data,
						QUIRK_MAX_DESCRIPTOR_SIZE);
	free(desc_stripped);

	if (eq->rd_size <= 0 || eq->rd_size > QUIRK_MAX_DESCRIPTOR_SIZE) {
		error("quirk-profile: invalid descriptor in %s", path);
		free(eq->rd_data);
		free(eq);
		goto fail;
	}

	eq->parser = parser;
	eq->country = country;
	eq->subclass = subclass;

	/* Store name */
	if (num_ext_quirks < MAX_EXTERNAL_QUIRKS) {
		snprintf(name_pool[num_ext_quirks], 248, "%s", name);
		eq->base.name = name_pool[num_ext_quirks];
	} else {
		eq->base.name = "external-quirk";
	}

	DBG("quirk-profile: parsed '%s' (%u bytes)", name, eq->rd_size);

	json_object_put(root);
	return eq;

fail:
	json_object_put(root);
	return NULL;
}

/*
 * Generic match: compare VID/PID or device name against stored criteria.
 */
static bool generic_match(struct input_device *idev,
			struct external_quirk *eq)
{
	struct btd_service *service;
	struct btd_device *device;

	if (!idev)
		return false;

	service = input_device_get_service(idev);
	if (!service)
		return false;

	device = btd_service_get_device(service);
	if (!device)
		return false;

	if (eq->match_by_vidpid) {
		uint16_t vid = btd_device_get_vendor(device);
		uint16_t pid = btd_device_get_product(device);
		if (vid != eq->vendor_id || pid != eq->product_id)
			return false;
	}

	if (eq->match_by_name) {
		char name[248];
		if (!device_name_known(device))
			return false;
		device_get_name(device, name, sizeof(name));
		if (strcmp(name, eq->device_name) != 0)
			return false;
	}

	return true;
}

static bool ext_match_wrapper(struct input_device *idev)
{
	int i;

	for (i = 0; ext_quirks[i]; i++) {
		if (generic_match(idev, ext_quirks[i]))
			return true;
	}
	return false;
}

int external_quirk_apply(struct input_device *idev,
			struct hidp_connadd_req *req)
{
	int i;
	struct external_quirk *eq;

	for (i = 0; ext_quirks[i]; i++) {
		eq = ext_quirks[i];
		if (!generic_match(idev, eq))
			continue;

		DBG("Applying external quirk: %s", eq->base.name);

		req->parser = eq->parser;
		req->country = eq->country;
		req->subclass = eq->subclass;
		req->rd_size = eq->rd_size;
		req->rd_data = malloc(req->rd_size);
		if (!req->rd_data)
			return -ENOMEM;

		memcpy(req->rd_data, eq->rd_data, req->rd_size);

		return 0;
	}

	return -1;
}

bool external_quirk_match(struct input_device *idev)
{
	return ext_match_wrapper(idev);
}

int load_external_quirks(const char *dir)
{
	DIR *d;
	struct dirent *ent;
	uint8_t hmac_key[HMAC_KEY_SIZE];
	int key_len, loaded;
	size_t nlen;
	char path[512];
	struct stat st;
	struct external_quirk *eq;

	if (!dir)
		dir = QUIRK_PROFILE_DIR;

	d = opendir(dir);
	if (!d) {
		DBG("quirk-profile: cannot open %s: %s", dir, strerror(errno));
		return 0;
	}

	key_len = load_hmac_key(hmac_key, HMAC_KEY_SIZE);
	if (key_len <= 0)
		DBG("quirk-profile: no HMAC key found");

	loaded = 0;
	num_ext_quirks = 0;

	while ((ent = readdir(d)) != NULL &&
		num_ext_quirks < MAX_EXTERNAL_QUIRKS) {

		nlen = strlen(ent->d_name);
		if (nlen <= strlen(JSON_EXT))
			continue;
		if (strcmp(ent->d_name + nlen - strlen(JSON_EXT), JSON_EXT)
								!= 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

		/* Reject symlinks */
		if (lstat(path, &st) < 0 || S_ISLNK(st.st_mode)) {
			DBG("quirk-profile: skipping symlink %s", path);
			continue;
		}

		/* Verify signature */
		if (key_len > 0 &&
			!verify_signature(path, hmac_key, key_len)) {
			error("quirk-profile: bad signature %s, skipping",
				path);
			continue;
		}

		eq = parse_profile(path);
		if (!eq)
			continue;

		ext_quirks[num_ext_quirks] = eq;
		num_ext_quirks++;
		loaded++;

		DBG("quirk-profile: loaded '%s'", eq->base.name);
	}

	closedir(d);

	if (loaded > 0)
		DBG("quirk-profile: %d external quirk(s) loaded", loaded);

	return loaded;
}

void free_external_quirks(void)
{
	int i;

	for (i = 0; i < num_ext_quirks; i++) {
		if (ext_quirks[i]) {
			free(ext_quirks[i]->rd_data);
			free(ext_quirks[i]);
		}
		ext_quirks[i] = NULL;
	}
	num_ext_quirks = 0;
}
