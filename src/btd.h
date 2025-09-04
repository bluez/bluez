/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#include <stdbool.h>

typedef enum {
	BT_MODE_DUAL,
	BT_MODE_BREDR,
	BT_MODE_LE,
} bt_mode_t;

typedef enum {
	BT_GATT_CACHE_ALWAYS,
	BT_GATT_CACHE_YES,
	BT_GATT_CACHE_NO,
} bt_gatt_cache_t;

enum jw_repairing_t {
	JW_REPAIRING_NEVER,
	JW_REPAIRING_CONFIRM,
	JW_REPAIRING_ALWAYS,
};

enum mps_mode_t {
	MPS_OFF,
	MPS_SINGLE,
	MPS_MULTIPLE,
};

enum sc_mode_t {
	SC_OFF,
	SC_ON,
	SC_ONLY,
};

enum bt_gatt_export_t {
	BT_GATT_EXPORT_OFF,
	BT_GATT_EXPORT_READ_ONLY,
	BT_GATT_EXPORT_READ_WRITE,
};

struct btd_br_defaults {
	uint16_t	page_scan_type;
	uint16_t	page_scan_interval;
	uint16_t	page_scan_win;

	uint16_t	scan_type;
	uint16_t	scan_interval;
	uint16_t	scan_win;

	uint16_t	link_supervision_timeout;
	uint16_t	page_timeout;

	uint16_t	min_sniff_interval;
	uint16_t	max_sniff_interval;
};

struct btd_le_defaults {
	uint8_t		addr_resolution;

	uint16_t	min_adv_interval;
	uint16_t	max_adv_interval;
	uint16_t	adv_rotation_interval;

	uint16_t	scan_interval_autoconnect;
	uint16_t	scan_win_autoconnect;
	uint16_t	scan_interval_suspend;
	uint16_t	scan_win_suspend;
	uint16_t	scan_interval_discovery;
	uint16_t	scan_win_discovery;
	uint16_t	scan_interval_adv_monitor;
	uint16_t	scan_win_adv_monitor;
	uint16_t	scan_interval_connect;
	uint16_t	scan_win_connect;

	uint16_t	min_conn_interval;
	uint16_t	max_conn_interval;
	uint16_t	conn_latency;
	uint16_t	conn_lsto;
	uint16_t	autoconnect_timeout;

	uint16_t	advmon_allowlist_scan_duration;
	uint16_t	advmon_no_filter_scan_duration;
	uint8_t		enable_advmon_interleave_scan;
};

struct btd_defaults {
	uint16_t	num_entries;

	struct btd_br_defaults br;
	struct btd_le_defaults le;
};

struct btd_csis {
	bool    encrypt;
	uint8_t sirk[16];
	uint8_t size;
	uint8_t rank;
};

struct btd_avdtp_opts {
	uint8_t  session_mode;
	uint8_t  stream_mode;
};

struct btd_avrcp_opts {
	bool		volume_without_target;
	bool		volume_category;
};

struct btd_advmon_opts {
	uint8_t		rssi_sampling_period;
};

struct btd_opts {
	char		*name;
	uint32_t	class;
	bool		pairable;
	uint32_t	pairto;
	uint32_t	discovto;
	uint32_t	tmpto;
	uint8_t		privacy;
	bool		device_privacy;
	uint32_t	name_request_retry_delay;
	uint8_t		secure_conn;

	struct btd_defaults defaults;

	bool		reverse_discovery;
	bool		name_resolv;
	bool		debug_keys;
	bool		fast_conn;
	bool		refresh_discovery;
	bool		experimental;
	bool		testing;
	bool		filter_discoverable;
	struct queue	*kernel;

	uint16_t	did_source;
	uint16_t	did_vendor;
	uint16_t	did_product;
	uint16_t	did_version;

	bt_mode_t	mode;
	uint16_t	max_adapters;
	bt_gatt_cache_t gatt_cache;
	uint16_t	gatt_mtu;
	uint8_t		gatt_channels;
	bool		gatt_client;
	enum bt_gatt_export_t gatt_export;
	enum mps_mode_t	mps;

	struct btd_avdtp_opts avdtp;
	struct btd_avrcp_opts avrcp;

	uint8_t		key_size;

	enum jw_repairing_t jw_repairing;

	struct btd_advmon_opts	advmon;

	struct btd_csis csis;
};

extern struct btd_opts btd_opts;

void plugin_init(const char *enable, const char *disable);
void plugin_cleanup(void);

void rfkill_init(void);
void rfkill_exit(void);
int rfkill_get_blocked(uint16_t index);

GKeyFile *btd_get_main_conf(void);
bool btd_kernel_experimental_enabled(const char *uuid);

void btd_exit(void);
