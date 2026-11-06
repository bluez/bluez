/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  OBEX Server
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 *
 */

#include <stdint.h>

#include <glib.h>

struct phonebook_metadata;

/*
 * Opens and loads the metadata file, creating it when it doesn't exist.
 * The key file is cached internally. Returns FALSE on error.
 */
gboolean metadata_file_open(const char *file);

/* Closes the metadata file and releases cached resources. */
void metadata_file_close(void);

/* Reads metadata and zeroes invalid or unsaved values. */
gboolean metadata_read(const char *folder,
				struct phonebook_metadata *metadata);

/* Stores a hex encoded byte array. */
void metadata_set(const char *group, const char *key,
						const uint8_t buf[16]);

/*
 * Reads a hex encoded byte array. Returns FALSE when the value is
 * missing or invalid.
 */
gboolean metadata_get(const char *group, const char *key, uint8_t buf[16]);

/* Generates and stores a new database identifier. */
void metadata_identifier_update(void);

/*
 * Increments the primary and/or secondary folder version counters.
 * Returns FALSE on missing counters or rollover.
 */
gboolean metadata_folder_version_counter_incr(const char *folder,
						gboolean primary_changed,
						gboolean secondary_changed);

/* Saves the metadata file when it has changes. Returns TRUE on success. */
gboolean metadata_save(void);
