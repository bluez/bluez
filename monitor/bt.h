/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>

#define BT_H4_CMD_PKT	0x01
#define BT_H4_ACL_PKT	0x02
#define BT_H4_SCO_PKT	0x03
#define BT_H4_EVT_PKT	0x04

struct bt_hci_cmd_hdr {
	uint16_t opcode;
	uint8_t	 plen;
} __attribute__ ((packed));

struct bt_hci_evt_hdr {
	uint8_t  evt;
	uint8_t  plen;
} __attribute__ ((packed));

#define BT_HCI_CMD_NOP				0x0000

#define BT_HCI_CMD_INQUIRY			0x0401
struct bt_hci_cmd_inquiry {
	uint8_t  lap[3];
	uint8_t  length;
	uint8_t  num_rsp;
} __attribute__ ((packed));

#define BT_HCI_CMD_INQUIRY_CANCEL		0x0402

#define BT_HCI_CMD_CREATE_CONN			0x0405
struct bt_hci_cmd_create_conn {
	uint8_t  bdaddr[6];
	uint16_t pkt_type;
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_mode;
	uint16_t clock_offset;
	uint8_t  role_switch;
} __attribute__ ((packed));

#define BT_HCI_CMD_DISCONNECT			0x0406
struct bt_hci_cmd_disconnect {
	uint16_t handle;
	uint8_t  reason;
} __attribute__ ((packed));

#define BT_HCI_CMD_ADD_SCO_CONN			0x0407
struct bt_hci_cmd_add_sco_conn {
	uint16_t handle;
	uint16_t pkt_type;
} __attribute__ ((packed));

#define BT_HCI_CMD_CREATE_CONN_CANCEL		0x0408
struct bt_hci_cmd_create_conn_cancel {
	uint8_t  bdaddr[6];
} __attribute__ ((packed));

#define BT_HCI_CMD_ACCEPT_CONN_REQUEST		0x0409
struct bt_hci_cmd_accept_conn_request {
	uint8_t  bdaddr[6];
	uint8_t  role;
} __attribute__ ((packed));

#define BT_HCI_CMD_REJECT_CONN_REQUEST		0x040a
struct bt_hci_cmd_reject_conn_request {
	uint8_t  bdaddr[6];
	uint8_t  reason;
} __attribute__ ((packed));

#define BT_HCI_CMD_CHANGE_CONN_PKT_TYPE		0x040f
struct bt_hci_cmd_change_conn_pkt_type {
	uint16_t handle;
	uint16_t pkt_type;
} __attribute__ ((packed));

#define BT_HCI_CMD_REMOTE_NAME_REQUEST		0x0419
struct bt_hci_cmd_remote_name_request {
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_mode;
	uint16_t clock_offset;
} __attribute__ ((packed));

#define BT_HCI_CMD_REMOTE_NAME_REQUEST_CANCEL	0x041a
struct bt_hci_cmd_remote_name_request_cancel {
	uint8_t  bdaddr[6];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_REMOTE_FEATURES		0x041b
struct bt_hci_cmd_read_remote_features {
	uint16_t handle;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_REMOTE_EXT_FEATURES	0x041c
struct bt_hci_cmd_read_remote_ext_features {
	uint16_t handle;
	uint8_t  page;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_REMOTE_VERSION		0x041d
struct bt_hci_cmd_read_remote_version {
	uint16_t handle;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_DEFAULT_LINK_POLICY	0x080e
struct bt_hci_rsp_read_default_link_policy {
	uint8_t  status;
	uint16_t policy;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_DEFAULT_LINK_POLICY	0x080f
struct bt_hci_cmd_write_default_link_policy {
	uint16_t policy;
} __attribute__ ((packed));

#define BT_HCI_CMD_SET_EVENT_MASK		0x0c01
struct bt_hci_cmd_set_event_mask {
	uint8_t  mask[8];
} __attribute__ ((packed));

#define BT_HCI_CMD_RESET			0x0c03

#define BT_HCI_CMD_SET_EVENT_FILTER		0x0c05
struct bt_hci_cmd_set_event_filter {
	uint8_t  type;
	uint8_t  cond_type;
	uint8_t  cond[0];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_STORED_LINK_KEY		0x0c0d
struct bt_hci_cmd_read_stored_link_key {
	uint8_t  bdaddr[6];
	uint8_t  read_all;
} __attribute__ ((packed));
struct bt_hci_rsp_read_stored_link_key {
	uint8_t  status;
	uint16_t max_num_keys;
	uint16_t num_keys;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_STORED_LINK_KEY	0x0c11
struct bt_hci_cmd_write_stored_link_key {
	uint8_t  num_keys;
} __attribute__ ((packed));
struct bt_hci_rsp_write_stored_link_key {
	uint8_t  status;
	uint8_t  num_keys;
} __attribute__ ((packed));

#define BT_HCI_CMD_DELETE_STORED_LINK_KEY	0x0c12
struct bt_hci_cmd_delete_stored_link_key {
	uint8_t  bdaddr[6];
	uint8_t  delete_all;
} __attribute__ ((packed));
struct bt_hci_rsp_delete_stored_link_key {
	uint8_t  status;
	uint16_t num_keys;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_LOCAL_NAME		0x0c13
struct bt_hci_cmd_write_local_name {
	uint8_t  name[248];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_LOCAL_NAME		0x0c14
struct bt_hci_rsp_read_local_name {
	uint8_t  status;
	uint8_t  name[248];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_CONN_ACCEPT_TIMEOUT	0x0c15
struct bt_hci_rsp_read_conn_accept_timeout {
	uint8_t  status;
	uint16_t timeout;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_CONN_ACCEPT_TIMEOUT	0x0c16
struct bt_hci_cmd_write_conn_accept_timeout {
	uint16_t timeout;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_PAGE_TIMEOUT		0x0c17
struct bt_hci_rsp_read_page_timeout {
	uint8_t  status;
	uint16_t timeout;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_PAGE_TIMEOUT		0x0c18
struct bt_hci_cmd_write_page_timeout {
	uint16_t timeout;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_SCAN_ENABLE		0x0c19
struct bt_hci_rsp_read_scan_enable {
	uint8_t  status;
	uint8_t  enable;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_SCAN_ENABLE		0x0c1a
struct bt_hci_cmd_write_scan_enable {
	uint8_t  enable;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_AUTH_ENABLE		0x0c1f
struct bt_hci_rsp_read_auth_enable {
	uint8_t  status;
	uint8_t  enable;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_AUTH_ENABLE		0x0c20
struct bt_hci_cmd_write_auth_enable {
	uint8_t  enable;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_CLASS_OF_DEV		0x0c23
struct bt_hci_rsp_read_class_of_dev {
	uint8_t  status;
	uint8_t  dev_class[3];
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_CLASS_OF_DEV		0x0c24
struct bt_hci_cmd_write_class_of_dev {
	uint8_t  dev_class[3];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_VOICE_SETTING		0x0c25
struct bt_hci_rsp_read_voice_setting {
	uint8_t  status;
	uint16_t setting;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_VOICE_SETTING		0x0c26
struct bt_hci_cmd_write_voice_setting {
	uint16_t setting;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_INQUIRY_MODE		0x0c44
struct bt_hci_rsp_read_inquiry_mode {
	uint8_t  status;
	uint8_t  mode;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_INQUIRY_MODE		0x0c45
struct bt_hci_cmd_write_inquiry_mode {
	uint8_t  mode;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_AFH_ASSESS_MODE		0x0c48
struct bt_hci_rsp_read_afh_assess_mode {
	uint8_t  status;
	uint8_t  mode;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_AFH_ASSESS_MODE	0x0c49
struct bt_hci_cmd_write_afh_assess_mode {
	uint8_t  mode;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_EXT_INQUIRY_RSP		0x0c51
struct bt_hci_rsp_read_ext_inquiry_rsp {
	uint8_t  status;
	uint8_t  fec;
	uint8_t  data[240];
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_EXT_INQUIRY_RSP	0x0c52
struct bt_hci_cmd_write_ext_inquiry_rsp {
	uint8_t  fec;
	uint8_t	 data[240];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_SIMPLE_PAIRING_MODE	0x0c55
struct bt_hci_rsp_read_simple_pairing_mode {
	uint8_t  status;
	uint8_t  mode;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE	0x0c56
struct bt_hci_cmd_write_simple_pairing_mode {
	uint8_t  mode;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_INQUIRY_RSP_TX_POWER	0x0c58
struct bt_hci_rsp_read_inquiry_rsp_tx_power {
	uint8_t  status;
	int8_t   level;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_LE_HOST_SUPPORTED	0x0c6c
struct bt_hci_rsp_read_le_host_supported {
	uint8_t  status;
	uint8_t  supported;
	uint8_t  simultaneous;
} __attribute__ ((packed));

#define BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED	0x0c6d
struct bt_hci_cmd_write_le_host_supported {
	uint8_t  supported;
	uint8_t  simultaneous;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_LOCAL_VERSION		0x1001
struct bt_hci_rsp_read_local_version {
	uint8_t  status;
	uint8_t  hci_ver;
	uint16_t hci_rev;
	uint8_t  lmp_ver;
	uint16_t manufacturer;
	uint16_t lmp_subver;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_LOCAL_COMMANDS		0x1002
struct bt_hci_rsp_read_local_commands {
	uint8_t  status;
	uint8_t  commands[64];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_LOCAL_FEATURES		0x1003
struct bt_hci_rsp_read_local_features {
	uint8_t  status;
	uint8_t  features[8];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_LOCAL_EXT_FEATURES	0x1004
struct bt_hci_cmd_read_local_ext_features {
	uint8_t  page;
} __attribute__ ((packed));
struct bt_hci_rsp_read_local_ext_features {
	uint8_t  status;
	uint8_t  page;
	uint8_t  max_page;
	uint8_t  features[8];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_BUFFER_SIZE		0x1005
struct bt_hci_rsp_read_buffer_size {
	uint8_t  status;
	uint16_t acl_mtu;
	uint8_t  sco_mtu;
	uint16_t acl_max_pkt;
	uint16_t sco_max_pkt;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_COUNTRY_CODE		0x1007
struct bt_hci_rsp_read_country_code {
	uint8_t  status;
	uint8_t  code;
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_BD_ADDR			0x1009
struct bt_hci_rsp_read_bd_addr {
	uint8_t  status;
	uint8_t  bdaddr[6];
} __attribute__ ((packed));

#define BT_HCI_CMD_READ_DATA_BLOCK_SIZE		0x100a
struct bt_hci_rsp_read_data_block_size {
	uint8_t  status;
	uint16_t max_acl_len;
	uint16_t block_len;
	uint16_t num_blocks;
} __attribute__ ((packed));

#define BT_HCI_CMD_LE_SET_EVENT_MASK		0x2001
struct bt_hci_cmd_le_set_event_mask {
	uint8_t  mask[8];
} __attribute__ ((packed));

#define BT_HCI_CMD_LE_READ_BUFFER_SIZE		0x2002
struct bt_hci_rsp_le_read_buffer_size {
	uint8_t  status;
        uint16_t le_mtu;
        uint8_t  le_max_pkt;
} __attribute__ ((packed));

#define BT_HCI_CMD_LE_READ_LOCAL_FEATURES	0x2003
struct bt_hci_rsp_le_read_local_features {
	uint8_t  status;
	uint8_t  features[8];
} __attribute__ ((packed));

#define BT_HCI_CMD_LE_SET_SCAN_PARAMETERS	0x200b
struct bt_hci_cmd_le_set_scan_parameters {
	uint8_t  type;
	uint16_t interval;
	uint16_t window;
	uint8_t  own_addr_type;
	uint8_t  filter_policy;
} __attribute__ ((packed));

#define BT_HCI_CMD_LE_SET_SCAN_ENABLE		0x200c
struct bt_hci_cmd_le_set_scan_enable {
	uint8_t  enable;
	uint8_t  filter_dup;
} __attribute__ ((packed));

#define BT_HCI_CMD_LE_READ_SUPPORTED_STATES	0x201c
struct bt_hci_rsp_le_read_supported_states {
	uint8_t  status;
	uint8_t  states[8];
} __attribute__ ((packed));

#define BT_HCI_EVT_INQUIRY_COMPLETE		0x01
struct bt_hci_evt_inquiry_complete {
	uint8_t  status;
} __attribute__ ((packed));

#define BT_HCI_EVT_INQUIRY_RESULT		0x02
struct bt_hci_evt_inquiry_result {
	uint8_t  num_resp;
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  pscan_mode;
	uint8_t  dev_class[3];
	uint8_t  clock_offset;
} __attribute__ ((packed));

#define BT_HCI_EVT_CONN_COMPLETE		0x03
struct bt_hci_evt_conn_complete {
	uint8_t  status;
	uint16_t handle;
	uint8_t  bdaddr[6];
	uint8_t  link_type;
	uint8_t  encr_mode;
} __attribute__ ((packed));

#define BT_HCI_EVT_CONN_REQUEST			0x04
struct bt_hci_evt_conn_request {
	uint8_t  bdaddr[6];
	uint8_t  dev_class[3];
	uint8_t  link_type;
} __attribute__ ((packed));

#define BT_HCI_EVT_DISCONNECT_COMPLETE		0x05
struct bt_hci_evt_disconnect_complete {
	uint8_t  status;
	uint16_t handle;
	uint8_t  reason;
} __attribute__ ((packed));

#define BT_HCI_EVT_REMOTE_NAME_REQUEST_COMPLETE	0x07
struct bt_hci_evt_remote_name_req_complete {
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint8_t  name[248];
} __attribute__ ((packed));

#define BT_HCI_EVT_REMOTE_FEATURES_COMPLETE	0x0b
struct bt_hci_evt_remote_features_complete {
	uint8_t  status;
	uint16_t handle;
	uint8_t  features[8];
} __attribute__ ((packed));

#define BT_HCI_EVT_REMOTE_VERSION_COMPLETE	0x0c
struct bt_hci_evt_remote_version_complete {
	uint8_t  status;
	uint16_t handle;
	uint8_t  lmp_ver;
	uint16_t manufacturer;
	uint16_t lmp_subver;
} __attribute__ ((packed));

#define BT_HCI_EVT_CMD_COMPLETE			0x0e
struct bt_hci_evt_cmd_complete {
	uint8_t  ncmd;
	uint16_t opcode;
} __attribute__ ((packed));

#define BT_HCI_EVT_CMD_STATUS			0x0f
struct bt_hci_evt_cmd_status {
	uint8_t  status;
	uint8_t  ncmd;
	uint16_t opcode;
} __attribute__ ((packed));

#define BT_HCI_EVT_NUM_COMPLETED_PACKETS	0x13
struct bt_hci_evt_num_completed_packets {
	uint8_t  num_handles;
	uint16_t handle;
	uint16_t count;
} __attribute__ ((packed));

#define BT_HCI_EVT_CONN_PKT_TYPE_CHANGED	0x1d
struct bt_hci_evt_conn_pkt_type_changed {
	uint8_t  status;
	uint16_t handle;
	uint16_t pkt_type;
} __attribute__ ((packed));

#define BT_HCI_EVT_INQUIRY_RESULT_WITH_RSSI	0x22
struct bt_hci_evt_inquiry_result_with_rssi {
	uint8_t  num_resp;
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  dev_class[3];
	uint16_t clock_offset;
	int8_t   rssi;
} __attribute__ ((packed));

#define BT_HCI_EVT_REMOTE_EXT_FEATURES_COMPLETE	0x23
struct bt_hci_evt_remote_ext_features_complete {
	uint8_t  status;
	uint16_t handle;
	uint8_t  page;
	uint8_t  max_page;
	uint8_t  features[8];
} __attribute__ ((packed));

#define BT_HCI_EVT_EXT_INQUIRY_RESULT		0x2f
struct bt_hci_evt_ext_inquiry_result {
	uint8_t  num_resp;
	uint8_t  bdaddr[6];
	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  dev_class[3];
	uint16_t clock_offset;
	int8_t   rssi;
	uint8_t  data[240];
} __attribute__ ((packed));

#define BT_HCI_ERR_SUCCESS			0x00
#define BT_HCI_ERR_UNKNOWN_COMMAND		0x01
#define BT_HCI_ERR_UNKNOWN_CONN_ID		0x02
#define BT_HCI_ERR_HARDWARE_FAILURE		0x03
#define BT_HCI_ERR_PAGE_TIMEOUT			0x04
#define BT_HCI_ERR_INVALID_PARAMETERS		0x12
