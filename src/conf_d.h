/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025-2026  Valve Corporation
 *
 */

#include <glib.h>

/**
 * confd_process_config:
 *
 * @keyfile: keyfile already initialized and parsed
 *
 * @base_conf_file_path: base config file (e.g. /etc/bluetooth/main.conf,
 * input.conf, network.conf).  The directory to be processed will be same path
 * with ".d" appended.
 *
 * @accept_new_groups: whether to accept groups not appearing in the base config
 * file
 *
 * @accept_new_keys: whether to accept keys not appearing in the base config
 * file
 *
 * @err: error, taken as input to pass back to caller, if any
 *
 * Helper function to process config files in conf.d style dirs (config
 * fragments), overriding values for keys in the base config files (or default
 * config set in code).  For example, for "main.conf" the directory to be
 * processed will be "main.conf.d", in the same basedir as the config file.
 *
 * Within the .d directory, the format of the filename should be
 * '^([0-9][0-9])-([a-zA-Z0-9-_])*\.conf$', that is, starting with "00-" to
 * "99-", ending in ".conf", and with a mix of alphanumeric characters with
 * dashes and underscores in between.  For example:
 * '01-override-general-secureconnections.conf'.
 *
 * Files with a different name scheme will not be considered.  Accepting groups
 * or keys not present in the base config depends on the function arguments.
 * Currently, the callers set it to "NOT accept new groups" but "YES to accept
 * new keys".  This is because the base config files as shipped contain all the
 * groups, but most keys are commented-out, with the default values set in code.
 *
 * The candidate files within the given directory are sorted (with g_strcmp0(),
 * so the ordering will be as with strcmp()).  The configuration in the files
 * being processed later will override previous config, in particular the main
 * config, but also the one from previous files processed, if the Group and Key
 * coincide.
 *
 * For example, consider 'main.conf' that contains the defaults:
 *   [General]
 *   DiscoverableTimeout=0
 *   PairableTimeout=0
 *
 * and there is a file 'main.conf.d/70-default-timeouts-vendor.conf'
 * containing settings for these keys:
 *   [General]
 *   DiscoverableTimeout=30
 *   PairableTimeout=30
 *
 * and another 'main.conf.d/99-default-timeouts-local.conf'
 * containing settings only for 'PairableTimeout':
 *   [General]
 *   PairableTimeout=15
 *
 * What happens is:
 * 1) First, the 'main.conf' is processed as usual;
 * 2) then 'main.conf.d/70-default-timeouts-vendor.conf' is processed,
 *    overriding the two values from the main config file with the given values;
 * 3) and finally 'main.conf.d/99-default-timeouts-local.conf' is processed,
 *    overriding once again only 'PairableTimeout'.
 *
 * The final, effective values are:
 *
 *   DiscoverableTimeout=30
 *   PairableTimeout=15
 *
 **/
void confd_process_config(GKeyFile *keyfile, const gchar *base_conf_file_path,
			  gboolean accept_new_groups, gboolean accept_new_keys,
			  GError **err);
