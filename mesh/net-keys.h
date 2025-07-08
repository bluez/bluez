/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

#define BEACON_TYPE_SNB		0x01
#define BEACON_TYPE_MPB		0x02
#define BEACON_LEN_SNB		23
#define BEACON_LEN_MPB		28
#define BEACON_LEN_MAX		BEACON_LEN_MPB
#define KEY_REFRESH		0x01
#define IV_INDEX_UPDATE		0x02
#define NET_MPB_REFRESH_DEFAULT	60

void net_key_cleanup(void);
bool net_key_confirm(uint32_t id, const uint8_t flooding[16]);
bool net_key_retrieve(uint32_t id, uint8_t *flooding);
uint32_t net_key_add(const uint8_t flooding[16]);
uint32_t net_key_frnd_add(uint32_t flooding_id, uint16_t lpn, uint16_t frnd,
					uint16_t lp_cnt, uint16_t fn_cnt);
void net_key_unref(uint32_t id);
uint32_t net_key_decrypt(uint32_t iv_index, const uint8_t *pkt, size_t len,
					uint8_t **plain, size_t *plain_len);
bool net_key_encrypt(uint32_t id, uint32_t iv_index, uint8_t *pkt, size_t len);
uint32_t net_key_network_id(const uint8_t network[8]);
uint32_t net_key_beacon(const uint8_t *data, uint16_t len, uint32_t *ivi,
							bool *ivu, bool *kr);
bool net_key_snb_check(uint32_t id, uint32_t iv_index, bool kr, bool ivu,
								uint64_t cmac);
void net_key_beacon_seen(uint32_t id);
bool net_key_beacon_refresh(uint32_t id, uint32_t iv_index, bool kr, bool ivu,
								bool force);
void net_key_beacon_enable(uint32_t id, bool mpb, uint8_t refresh_count);
void net_key_beacon_disable(uint32_t id, bool mpb);
uint32_t net_key_beacon_last_seen(uint32_t id);
