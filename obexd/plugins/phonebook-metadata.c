// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <glib.h>

#include "obexd/src/log.h"
#include "phonebook.h"
#include "phonebook-metadata.h"

static char *metadata_file;
static GKeyFile *metadata_kf;
static gboolean metadata_dirty;

gboolean metadata_get(const char *group,
					const char *key, uint8_t buf[16])
{
	char *str;
	uint8_t value[16];
	unsigned int i;

	if (!metadata_kf)
		return FALSE;

	str = g_key_file_get_string(metadata_kf, group, key, NULL);
	if (!str || strlen(str) != 32)
		goto failed;

	for (i = 0; i < 16; i++) {
		int high = g_ascii_xdigit_value(str[i * 2]);
		int low = g_ascii_xdigit_value(str[i * 2 + 1]);

		if (high < 0 || low < 0)
			goto failed;

		value[i] = (high << 4) | low;
	}

	memcpy(buf, value, sizeof(value));
	g_free(str);
	return TRUE;

failed:
	g_free(str);
	return FALSE;
}

void metadata_set(const char *group, const char *key,
						const uint8_t buf[16])
{
	char hex[33];
	unsigned int i;

	if (!metadata_file || !metadata_kf)
		return;

	for (i = 0; i < 16; i++)
		sprintf(hex + (i * 2), "%02X", buf[i]);

	g_key_file_set_string(metadata_kf, group, key, hex);
	metadata_dirty = TRUE;
}

void metadata_identifier_update(void)
{
	uint8_t identifier[16];
	unsigned int i;

	if (!metadata_file || !metadata_kf)
		return;

	for (i = 0; i < 16; i += sizeof(uint32_t)) {
		uint32_t value = g_random_int();

		identifier[i] = (value >> 24) & 0xff;
		identifier[i + 1] = (value >> 16) & 0xff;
		identifier[i + 2] = (value >> 8) & 0xff;
		identifier[i + 3] = value & 0xff;
	}

	metadata_set("identifier", "value", identifier);
}

gboolean metadata_save(void)
{
	char *data;
	gsize len;
	GError *gerr = NULL;

	if (!metadata_file || !metadata_kf)
		return FALSE;

	if (!metadata_dirty)
		return TRUE;

	data = g_key_file_to_data(metadata_kf, &len, NULL);

	if (len > 0) {
		if (!g_file_set_contents(metadata_file, data, len, &gerr)) {
			error("Unable to save metadata file: %s",
					gerr->message);
			g_error_free(gerr);
			g_free(data);
			return FALSE;
		}
	}

	g_free(data);
	metadata_dirty = FALSE;

	return TRUE;
}

gboolean metadata_file_open(const char *file)
{
	GError *gerr = NULL;

	if (!file)
		return FALSE;

	metadata_file = g_strdup(file);
	if (!metadata_file)
		return FALSE;

	if (!g_file_test(metadata_file, G_FILE_TEST_EXISTS)) {
		if (!g_file_set_contents(metadata_file, "", 0, &gerr)) {
			error("Unable to create metadata file: %s",
							gerr->message);
			g_error_free(gerr);
			gerr = NULL;
		}
	}

	metadata_kf = g_key_file_new();

	if (metadata_kf && !g_key_file_load_from_file(metadata_kf,
					metadata_file, 0, &gerr)) {
		error("Unable to load metadata file: %s", gerr->message);
		g_error_free(gerr);
		g_key_file_free(metadata_kf);
		metadata_kf = NULL;
		g_free(metadata_file);
		metadata_file = NULL;
		return FALSE;
	}

	metadata_dirty = FALSE;

	return TRUE;
}

gboolean metadata_read(struct phonebook_metadata *metadata)
{
	memset(metadata, 0, sizeof(*metadata));

	if (!metadata_file || !metadata_kf)
		return FALSE;

	/* Values which are not saved are reported as not persistent. */
	if (metadata_dirty)
		return FALSE;

	if (!metadata_get("identifier", "value", metadata->database_identifier))
		DBG("identifier not found in metadata");

	return TRUE;
}

void metadata_file_close(void)
{
	if (metadata_kf) {
		g_key_file_free(metadata_kf);
		metadata_kf = NULL;
	}

	if (metadata_file) {
		g_free(metadata_file);
		metadata_file = NULL;
	}
}
