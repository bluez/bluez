/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdint.h>

#define MSFT_SUBCMD_READ_SUPPORTED_FEATURES	0x00

struct msft_cmd_read_supported_features {
	uint8_t subcmd;
} __attribute__((packed));

#define MSFT_MONITOR_BREDR_RSSI			BIT(0)
#define MSFT_MONITOR_LE_RSSI			BIT(1)
#define MSFT_MONITOR_LE_LEGACY_RSSI		BIT(2)
#define MSFT_MONITOR_LE_ADV			BIT(3)
#define MSFT_MONITOR_SSP_VALIDATION		BIT(4)
#define MSFT_MONITOR_LE_ADV_CONTINUOS		BIT(5)

struct msft_rsp_read_supported_features {
	uint8_t  status;
	uint8_t  subcmd;
	uint8_t  features[8];
	uint8_t  evt_prefix_len;
	uint8_t  evt_prefix[];
} __attribute__((packed));

#define MSFT_SUBCMD_MONITOR_RSSI		0x01

struct msft_cmd_monitor_rssi {
	uint8_t  subcmd;
	uint16_t handle;
	int8_t   rssi_high;
	int8_t   rssi_low;
	uint8_t  rssi_low_interval;
	uint8_t  rssi_period;
} __attribute__((packed));

struct msft_rsp_monitor_rssi {
	uint8_t  status;
	uint8_t  subcmd;
} __attribute__((packed));

#define MSFT_SUBCMD_CANCEL_MONITOR_RSSI		0x02

struct msft_cmd_cancel_monitor_rssi {
	uint8_t  subcmd;
	uint16_t handle;
} __attribute__((packed));

struct msft_rsp_cancel_monitor_rssi {
	uint8_t  status;
	uint8_t  subcmd;
} __attribute__((packed));

#define MSFT_SUBCMD_LE_MONITOR_ADV		0x03

#define MSFT_LE_MONITOR_ADV_PATTERN		0x01
struct msft_le_monitor_pattern {
	uint8_t  len;
	uint8_t  type;
	uint8_t  start;
	uint8_t  data[];
} __attribute__((packed));

struct msft_le_monitor_adv_patterns {
	uint8_t num;
	struct msft_le_monitor_pattern data[];
} __attribute__((packed));

#define MSFT_LE_MONITOR_ADV_UUID		0x02
struct msft_le_monitor_adv_uuid {
	uint8_t  type;
	union {
		uint16_t u16;
		uint32_t u32;
		uint8_t  u128[16];
	} value;
} __attribute__((packed));

#define MSFT_LE_MONITOR_ADV_IRK			0x03
struct msft_le_monitor_adv_irk {
	uint8_t  irk[8];
} __attribute__((packed));

#define MSFT_LE_MONITOR_ADV_ADDR		0x04
struct msft_le_monitor_adv_addr {
	uint8_t  type;
	uint8_t  addr[6];
} __attribute__((packed));

struct msft_cmd_le_monitor_adv {
	uint8_t  subcmd;
	int8_t   rssi_high;
	int8_t   rssi_low;
	uint8_t  rssi_low_interval;
	uint8_t  rssi_period;
	uint8_t  type;
	uint8_t  data[];
} __attribute__((packed));

struct msft_rsp_le_monitor_adv {
	uint8_t  status;
	uint8_t  subcmd;
	uint8_t  handle;
} __attribute__((packed));

#define MSFT_SUBCMD_LE_CANCEL_MONITOR_ADV	0x04

struct msft_cmd_le_cancel_monitor_adv {
	uint8_t  subcmd;
	uint8_t  handle;
} __attribute__((packed));

struct msft_rsp_le_cancel_monitor_adv {
	uint8_t  status;
	uint8_t  subcmd;
} __attribute__((packed));

#define MSFT_SUBCMD_LE_MONITOR_ADV_ENABLE	0x05

struct msft_cmd_le_monitor_adv_enable {
	uint8_t  subcmd;
	uint8_t  enable;
} __attribute__((packed));

struct msft_rsp_le_monitor_adv_enable {
	uint8_t  status;
	uint8_t  subcmd;
} __attribute__((packed));

#define MSFT_SUBCMD_READ_ABS_RSSI		0x06

struct msft_cmd_read_abs_rssi {
	uint8_t  subcmd;
	uint16_t handle;
} __attribute__((packed));

struct msft_rsp_read_abs_rssi {
	uint8_t  status;
	uint8_t  subcmd;
	uint16_t handle;
	int8_t  rssi;
} __attribute__((packed));

#define MSFT_SUBEVT_RSSI			0x01

struct msft_evt_rssi {
	uint8_t  subevt;
	uint8_t  status;
	uint16_t handle;
	int8_t  rssi;
} __attribute__((packed));

#define MSFT_SUBEVT_MONITOR_DEVICE		0x02

struct msft_evt_monitor_device {
	uint8_t  subevt;
	uint8_t  addr_type;
	uint8_t  addr[6];
	uint8_t  handle;
	uint8_t  state;
} __attribute__((packed));

struct vendor_ocf;
struct vendor_evt;

const struct vendor_ocf *msft_vendor_ocf(void);
const struct vendor_evt *msft_vendor_evt(void);
