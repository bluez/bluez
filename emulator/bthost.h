/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright 2023-2024 NXP
 *
 *
 */

#include <stdint.h>
#include <sys/uio.h>

#include "bluetooth/bluetooth.h"

typedef void (*bthost_send_func) (const struct iovec *iov, int iovlen,
							void *user_data);

struct bthost;

struct bthost *bthost_create(void);
void bthost_destroy(struct bthost *bthost);

typedef void (*bthost_ready_cb) (void);
void bthost_notify_ready(struct bthost *bthost, bthost_ready_cb cb);

typedef void (*bthost_debug_func_t)(const char *str, void *user_data);
typedef void (*bthost_destroy_func_t)(void *user_data);
bool bthost_set_debug(struct bthost *bthost, bthost_debug_func_t callback,
			void *user_data, bthost_destroy_func_t destroy);
void bthost_debug(struct bthost *bthost, const char *format, ...)
					__attribute__((format(printf, 2, 3)));

void bthost_set_send_handler(struct bthost *bthost, bthost_send_func handler,
							void *user_data);

void bthost_set_acl_mtu(struct bthost *bthost, uint16_t mtu);
void bthost_set_iso_mtu(struct bthost *bthost, uint16_t mtu);

void bthost_receive_h4(struct bthost *bthost, const void *data, uint16_t len);

typedef void (*bthost_cmd_complete_cb) (uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data);

void bthost_set_cmd_complete_cb(struct bthost *bthost,
				bthost_cmd_complete_cb cb, void *user_data);

typedef uint8_t (*bthost_accept_conn_cb) (uint16_t handle, void *user_data);
typedef void (*bthost_new_conn_cb) (uint16_t handle, void *user_data);

void bthost_set_connect_cb(struct bthost *bthost, bthost_new_conn_cb cb,
							void *user_data);

void bthost_set_sco_cb(struct bthost *bthost, bthost_new_conn_cb cb,
							void *user_data);

void bthost_set_iso_cb(struct bthost *bthost, bthost_accept_conn_cb accept,
				bthost_new_conn_cb cb, void *user_data);

void bthost_hci_connect(struct bthost *bthost, const uint8_t *bdaddr,
							uint8_t addr_type);

void bthost_hci_ext_connect(struct bthost *bthost, const uint8_t *bdaddr,
							uint8_t addr_type);

void bthost_hci_disconnect(struct bthost *bthost, uint16_t handle,
								uint8_t reason);

int bthost_setup_sco(struct bthost *bthost, uint16_t acl_handle,
							uint16_t setting);

typedef void (*bthost_cid_hook_func_t)(const void *data, uint16_t len,
							void *user_data);

void bthost_add_cid_hook(struct bthost *bthost, uint16_t handle, uint16_t cid,
				bthost_cid_hook_func_t func, void *user_data);

typedef void (*bthost_sco_hook_func_t)(const void *data, uint16_t len,
					uint8_t status, void *user_data);

void bthost_add_sco_hook(struct bthost *bthost, uint16_t handle,
				bthost_sco_hook_func_t func, void *user_data,
				bthost_destroy_func_t destroy);

typedef void (*bthost_iso_hook_func_t)(const void *data, uint16_t len,
							void *user_data);

void bthost_add_iso_hook(struct bthost *bthost, uint16_t handle,
				bthost_iso_hook_func_t func, void *user_data,
				bthost_destroy_func_t destroy);

void bthost_send_cid(struct bthost *bthost, uint16_t handle, uint16_t cid,
					const void *data, uint16_t len);
void bthost_send_cid_v(struct bthost *bthost, uint16_t handle, uint16_t cid,
					const struct iovec *iov, int iovcnt);
void bthost_send_sco(struct bthost *bthost, uint16_t handle, uint8_t pkt_status,
			const struct iovec *iov, int iovcnt);
void bthost_send_iso(struct bthost *bthost, uint16_t handle, bool ts,
			uint16_t sn, uint32_t timestamp, uint8_t pkt_status,
			const struct iovec *iov, int iovcnt);

void bthost_disconnect_cid(struct bthost *bthost, uint16_t handle,
								uint16_t cid);

typedef void (*bthost_l2cap_rsp_cb) (uint8_t code, const void *data,
						uint16_t len, void *user_data);

bool bthost_l2cap_req(struct bthost *bthost, uint16_t handle, uint8_t req,
				const void *data, uint16_t len,
				bthost_l2cap_rsp_cb cb, void *user_data);

void bthost_write_scan_enable(struct bthost *bthost, uint8_t scan);

void bthost_set_adv_data(struct bthost *bthost, const uint8_t *data,
								uint8_t len);
void bthost_set_adv_enable(struct bthost *bthost, uint8_t enable);

void bthost_set_ext_adv_data(struct bthost *bthost, const uint8_t *data,
								uint8_t len);
void bthost_set_ext_adv_params(struct bthost *bthost, uint8_t sid);
void bthost_set_ext_adv_enable(struct bthost *bthost, uint8_t enable);
void bthost_set_pa_params(struct bthost *bthost);
void bthost_set_pa_data(struct bthost *bthost, const uint8_t *data,
								uint8_t len);
void bthost_set_past_mode(struct bthost *bthost, uint16_t handle, uint8_t mode);
void bthost_set_base(struct bthost *bthost, const uint8_t *data, uint8_t len);
void bthost_set_pa_enable(struct bthost *bthost, uint8_t enable);
void bthost_past_set_info(struct bthost *bthost, uint16_t handle);
void bthost_create_big(struct bthost *bthost, uint8_t num_bis, uint8_t enc,
				const uint8_t *bcode);
void bthost_terminate_big(struct bthost *bthost, uint8_t reason);
bool bthost_search_ext_adv_addr(struct bthost *bthost, const uint8_t *addr);

void bthost_set_cig_params(struct bthost *bthost, uint8_t cig_id,
				uint8_t cis_id, const struct bt_iso_qos *qos);
void bthost_create_cis(struct bthost *bthost, uint16_t cis_handle,
						uint16_t acl_handle);

void bthost_set_scan_params(struct bthost *bthost, uint8_t scan_type,
				uint8_t addr_type, uint8_t filter_policy);
void bthost_set_scan_enable(struct bthost *bthost, uint8_t enable);

void bthost_write_ssp_mode(struct bthost *bthost, uint8_t mode);

void bthost_write_le_host_supported(struct bthost *bthost, uint8_t mode);

void bthost_request_auth(struct bthost *bthost, uint16_t handle);

void bthost_le_start_encrypt(struct bthost *bthost, uint16_t handle,
							const uint8_t ltk[16]);
typedef void (*bthost_l2cap_connect_cb) (uint16_t handle, uint16_t cid,
							void *user_data);
typedef void (*bthost_l2cap_disconnect_cb) (uint16_t handle, uint16_t cid,
							void *user_data);

void bthost_add_l2cap_server(struct bthost *bthost, uint16_t psm,
				bthost_l2cap_connect_cb func,
				bthost_l2cap_disconnect_cb disconn_func,
				void *user_data);
void bthost_add_l2cap_server_custom(struct bthost *bthost, uint16_t psm,
				uint16_t mtu, uint16_t mps, uint16_t credits,
				bthost_l2cap_connect_cb func,
				bthost_l2cap_disconnect_cb disconn_func,
				void *user_data);

void bthost_set_sc_support(struct bthost *bthost, bool enable);

void bthost_set_pin_code(struct bthost *bthost, const uint8_t *pin,
							uint8_t pin_len);
void bthost_set_io_capability(struct bthost *bthost, uint8_t io_capability);
uint8_t bthost_get_io_capability(struct bthost *bthost);
void bthost_set_auth_req(struct bthost *bthost, uint8_t auth_req);
uint8_t bthost_get_auth_req(struct bthost *bthost);
void bthost_set_reject_user_confirm(struct bthost *bthost, bool reject);
bool bthost_get_reject_user_confirm(struct bthost *bthost);

bool bthost_bredr_capable(struct bthost *bthost);

uint64_t bthost_conn_get_fixed_chan(struct bthost *bthost, uint16_t handle);

typedef void (*bthost_rfcomm_connect_cb) (uint16_t handle, uint16_t cid,
						void *user_data, bool status);

void bthost_add_rfcomm_server(struct bthost *bthost, uint8_t channel,
			bthost_rfcomm_connect_cb func, void *user_data);

bool bthost_connect_rfcomm(struct bthost *bthost, uint16_t handle,
				uint8_t channel, bthost_rfcomm_connect_cb func,
				void *user_data);

typedef void (*bthost_rfcomm_chan_hook_func_t) (const void *data, uint16_t len,
							void *user_data);

void bthost_add_rfcomm_chan_hook(struct bthost *bthost, uint16_t handle,
					uint8_t channel,
					bthost_rfcomm_chan_hook_func_t func,
					void *user_data);

void bthost_send_rfcomm_data(struct bthost *bthost, uint16_t handle,
					uint8_t channel, const void *data,
					uint16_t len);

void bthost_start(struct bthost *bthost);

/* LE SMP support */

void *smp_start(struct bthost *bthost);
void smp_stop(void *smp_data);
void *smp_conn_add(void *smp_data, uint16_t handle,
			const uint8_t *ia, uint8_t ia_type,
			const uint8_t *ra, uint8_t ra_type, bool conn_init);
void smp_conn_del(void *conn_data);
void smp_conn_encrypted(void *conn_data, uint8_t encrypt);
void smp_data(void *conn_data, const void *data, uint16_t len);
void smp_bredr_data(void *conn_data, const void *data, uint16_t len);
int smp_get_ltk(void *smp_data, uint64_t rand, uint16_t ediv, uint8_t *ltk);
void smp_pair(void *conn_data, uint8_t io_cap, uint8_t auth_req);
