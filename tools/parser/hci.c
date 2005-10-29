/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2005  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "parser.h"

static uint16_t manufacturer = DEFAULT_COMPID;

static inline uint16_t get_manufacturer(void)
{
	return (manufacturer == DEFAULT_COMPID ? parser.defcompid : manufacturer);
}

#define EVENT_NUM 47
static char *event_str[EVENT_NUM + 1] = {
	"Unknown",
	"Inquiry Complete",
	"Inquiry Result",
	"Connect Complete",
	"Connect Request",
	"Disconn Complete",
	"Auth Complete",
	"Remote Name Req Complete",
	"Encrypt Change",
	"Change Connection Link Key Complete",
	"Master Link Key Complete",
	"Read Remote Supported Features",
	"Read Remote Ver Info Complete",
	"QoS Setup Complete",
	"Command Complete",
	"Command Status",
	"Hardware Error",
	"Flush Occurred",
	"Role Change",
	"Number of Completed Packets",
	"Mode Change",
	"Return Link Keys",
	"PIN Code Request",
	"Link Key Request",
	"Link Key Notification",
	"Loopback Command",
	"Data Buffer Overflow",
	"Max Slots Change",
	"Read Clock Offset Complete",
	"Connection Packet Type Changed",
	"QoS Violation",
	"Page Scan Mode Change",
	"Page Scan Repetition Mode Change",
	"Flow Specification Complete",
	"Inquiry Result with RSSI",
	"Read Remote Extended Features",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Synchronous Connect Complete",
	"Synchronous Connect Changed",
	"Unknown",
	"Extended Inquiry Result",
};

#define CMD_LINKCTL_NUM 41
static char *cmd_linkctl_str[CMD_LINKCTL_NUM + 1] = {
	"Unknown",
	"Inquiry",
	"Inquiry Cancel",
	"Periodic Inquiry Mode",
	"Exit Periodic Inquiry Mode",
	"Create Connection",
	"Disconnect",
	"Add SCO Connection",
	"Create Connection Cancel",
	"Accept Connection Request",
	"Reject Connection Request",
	"Link Key Request Reply",
	"Link Key Request Negative Reply",
	"PIN Code Request Reply",
	"PIN Code Request Negative Reply",
	"Change Connection Packet Type",
	"Unknown",
	"Authentication Requested",
	"Unknown",
	"Set Connection Encryption",
	"Unknown",
	"Change Connection Link Key",
	"Unknown",
	"Master Link Key",
	"Unknown",
	"Remote Name Request",
	"Remote Name Request Cancel",
	"Read Remote Supported Features",
	"Read Remote Extended Features",
	"Read Remote Version Information",
	"Unknown",
	"Read Clock Offset",
	"Read LMP Handle"
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Setup Synchronous Connection",
	"Accept Synchronous Connection",
	"Reject Synchronous Connection",
};

#define CMD_LINKPOL_NUM 16
static char *cmd_linkpol_str[CMD_LINKPOL_NUM + 1] = {
	"Unknown",
	"Hold Mode",
	"Unknown",
	"Sniff Mode",
	"Exit Sniff Mode",
	"Park State",
	"Exit Park State",
	"QoS Setup",
	"Unknown",
	"Role Discovery",
	"Unknown",
	"Switch Role",
	"Read Link Policy Settings",
	"Write Link Policy Settings",
	"Read Default Link Policy Settings",
	"Write Default Link Policy Settings",
	"Flow Specification",
};

#define CMD_HOSTCTL_NUM 82
static char *cmd_hostctl_str[CMD_HOSTCTL_NUM + 1] = {
	"Unknown",
	"Set Event Mask",
	"Unknown",
	"Reset",
	"Unknown",
	"Set Event Filter",
	"Unknown",
	"Unknown",
	"Flush",
	"Read PIN Type ",
	"Write PIN Type",
	"Create New Unit Key",
	"Unknown",
	"Read Stored Link Key",
	"Unknown",
	"Unknown",
	"Unknown",
	"Write Stored Link Key",
	"Delete Stored Link Key",
	"Write Local Name",
	"Read Local Name",
	"Read Connection Accept Timeout",
	"Write Connection Accept Timeout",
	"Read Page Timeout",
	"Write Page Timeout",
	"Read Scan Enable",
	"Write Scan Enable",
	"Read Page Scan Activity",
	"Write Page Scan Activity",
	"Read Inquiry Scan Activity",
	"Write Inquiry Scan Activity",
	"Read Authentication Enable",
	"Write Authentication Enable",
	"Read Encryption Mode",
	"Write Encryption Mode",
	"Read Class of Device",
	"Write Class of Device",
	"Read Voice Setting",
	"Write Voice Setting",
	"Read Automatic Flush Timeout",
	"Write Automatic Flush Timeout",
	"Read Num Broadcast Retransmissions",
	"Write Num Broadcast Retransmissions",
	"Read Hold Mode Activity ",
	"Write Hold Mode Activity",
	"Read Transmit Power Level",
	"Read Synchronous Flow Control Enable",
	"Write Synchronous Flow Control Enable",
	"Unknown",
	"Set Host Controller To Host Flow Control",
	"Unknown",
	"Host Buffer Size",
	"Unknown",
	"Host Number of Completed Packets",
	"Read Link Supervision Timeout",
	"Write Link Supervision Timeout",
	"Read Number of Supported IAC",
	"Read Current IAC LAP",
	"Write Current IAC LAP",
	"Read Page Scan Period Mode",
	"Write Page Scan Period Mode",
	"Read Page Scan Mode",
	"Write Page Scan Mode",
	"Set AFH Host Channel Classification",
	"Unknown",
	"Unknown",
	"Read Inquiry Scan Type",
	"Write Inquiry Scan Type",
	"Read Inquiry Mode",
	"Write Inquiry Mode",
	"Read Page Scan Type",
	"Write Page Scan Type",
	"Read AFH Channel Assessment Mode",
	"Write AFH Channel Assessment Mode",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Read Extended Inquiry Response",
	"Write Extended Inquiry Response",
};

#define CMD_INFO_NUM 9
static char *cmd_info_str[CMD_INFO_NUM + 1] = {
	"Unknown",
	"Read Local Version Information",
	"Read Local Supported Commands",
	"Read Local Supported Features",
	"Read Local Extended Features",
	"Read Buffer Size",
	"Unknown",
	"Read Country Code",
	"Unknown",
	"Read BD ADDR",
};

#define CMD_STATUS_NUM 7
static char *cmd_status_str[CMD_STATUS_NUM + 1] = {
	"Unknown",
	"Read Failed Contact Counter",
	"Reset Failed Contact Counter",
	"Read Link Quality",
	"Unknown",
	"Read RSSI",
	"Read AFH Channel Map",
	"Read Clock",
};

#define ERROR_CODE_NUM 53
static char *error_code_str[ERROR_CODE_NUM + 1] = {
	"Success",
	"Unknown HCI Command",
	"Unknown Connection Identifier",
	"Hardware Failure",
	"Page Timeout",
	"Authentication Failure",
	"PIN or Key Missing",
	"Memory Capacity Exceeded",
	"Connection Timeout",
	"Connection Limit Exceeded",
	"Synchronous Connection to a Device Exceeded",
	"ACL Connection Already Exists",
	"Command Disallowed",
	"Connection Rejected due to Limited Resources",
	"Connection Rejected due to Security Reasons",
	"Connection Rejected due to Unacceptable BD_ADDR",
	"Connection Accept Timeout Exceeded",
	"Unsupported Feature or Parameter Value",
	"Invalid HCI Command Parameters",
	"Remote User Terminated Connection",
	"Remote Device Terminated Connection due to Low Resources",
	"Remote Device Terminated Connection due to Power Off",
	"Connection Terminated by Local Host",
	"Repeated Attempts",
	"Pairing Not Allowed",
	"Unknown LMP PDU",
	"Unsupported Remote Feature / Unsupported LMP Feature",
	"SCO Offset Rejected",
	"SCO Interval Rejected",
	"SCO Air Mode Rejected",
	"Invalid LMP Parameters",
	"Unspecified Error",
	"Unsupported LMP Parameter Value",
	"Role Change Not Allowed",
	"LMP Response Timeout",
	"LMP Error Transaction Collision",
	"LMP PDU Not Allowed",
	"Encryption Mode Not Acceptable",
	"Link Key Can Not be Changed",
	"Requested QoS Not Supported",
	"Instant Passed",
	"Pairing with Unit Key Not Supported",
	"Different Transaction Collision",
	"Reserved",
	"QoS Unacceptable Parameter",
	"QoS Rejected",
	"Channel Classification Not Supported",
	"Insufficient Security",
	"Parameter out of Mandatory Range",
	"Reserved",
	"Role Switch Pending",
	"Reserved",
	"Reserved Slot Violation",
	"Role Switch Failed",
};

static char *status2str(uint8_t status)
{
	char *str;

	if (status <= ERROR_CODE_NUM)
		str = error_code_str[status];
	else
		str = "Unknown";

	return str;
}

static char *opcode2str(uint16_t opcode)
{
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);
	char *cmd;

	switch (ogf) {
	case OGF_INFO_PARAM:
		if (ocf <= CMD_INFO_NUM)
			cmd = cmd_info_str[ocf];
		else
			cmd = "Unknown";
		break;

	case OGF_HOST_CTL:
		if (ocf <= CMD_HOSTCTL_NUM)
			cmd = cmd_hostctl_str[ocf];
		else
			cmd = "Unknown";
		break;

	case OGF_LINK_CTL:
		if (ocf <= CMD_LINKCTL_NUM)
			cmd = cmd_linkctl_str[ocf];
		else
			cmd = "Unknown";
		break;

	case OGF_LINK_POLICY:
		if (ocf <= CMD_LINKPOL_NUM)
			cmd = cmd_linkpol_str[ocf];
		else
			cmd = "Unknown";
		break;

	case OGF_STATUS_PARAM:
		if (ocf <= CMD_STATUS_NUM)
			cmd = cmd_status_str[ocf];
		else
			cmd = "Unknown";
		break;

	case OGF_TESTING_CMD:
		cmd = "Testing";
		break;

	case OGF_VENDOR_CMD:
		cmd = "Vendor";
		break;

	default:
		cmd = "Unknown";
		break;
	}

	return cmd;
}

static char *role2str(uint8_t role)
{
	switch (role) {
	case 0x00:
		return "Master";
	case 0x01:
		return "Slave";
	default:
		return "Unknown";
	}
}

static char *mode2str(uint8_t mode)
{
	switch (mode) {
	case 0x00:
		return "Active";
	case 0x01:
		return "Hold";
	case 0x02:
		return "Sniff";
	case 0x03:
		return "Park";
	default:
		return "Unknown";
	}
}

static char *airmode2str(uint8_t mode)
{
	switch (mode) {
	case 0x00:
		return "u-law log";
	case 0x01:
		return "A-law log";
	case 0x02:
		return "CVSD";
	case 0x04:
		return "Transparent data";
	default:
		return "Reserved";
	}
}

static inline void generic_command_dump(int level, struct frame *frm)
{
	uint16_t handle = btohs(htons(get_u16(frm)));

	p_indent(level, frm);
	printf("handle %d\n", handle);

	raw_dump(level, frm);
}

static inline void bdaddr_command_dump(int level, struct frame *frm)
{
	bdaddr_t *bdaddr = frm->ptr;
	char addr[18];

	frm->ptr += sizeof(bdaddr_t);
	frm->len -= sizeof(bdaddr_t);

	p_indent(level, frm);
	ba2str(bdaddr, addr);
        printf("bdaddr %s\n", addr);

	raw_dump(level, frm);
}

static inline void inquiry_dump(int level, struct frame *frm)
{
	inquiry_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("lap 0x%2.2x%2.2x%2.2x len %d num %d\n",
		cp->lap[2], cp->lap[1], cp->lap[0], cp->length, cp->num_rsp);
}

static inline void periodic_inquiry_dump(int level, struct frame *frm)
{
	periodic_inquiry_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("max %d min %d lap 0x%2.2x%2.2x%2.2x len %d num %d\n",
		btohs(cp->max_period), btohs(cp->min_period),
		cp->lap[2], cp->lap[1], cp->lap[0], cp->length, cp->num_rsp);
}

static inline void create_conn_dump(int level, struct frame *frm)
{
	create_conn_cp *cp = frm->ptr;
	uint16_t ptype = btohs(cp->pkt_type);
	uint16_t clkoffset = btohs(cp->clock_offset);
	char addr[18], *str;

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	printf("bdaddr %s ptype 0x%4.4x rswitch 0x%2.2x clkoffset 0x%4.4x%s\n",
		addr, ptype, cp->role_switch,
		clkoffset & 0x7fff, clkoffset & 0x8000 ? " (valid)" : "");

	str = hci_ptypetostr(ptype);
	if (str) {
		p_indent(level, frm);
		printf("Packet type: %s\n", str);
		free(str);
	}
}

static inline void disconnect_dump(int level, struct frame *frm)
{
	disconnect_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("handle %d reason 0x%2.2x\n", btohs(cp->handle), cp->reason);

	p_indent(level, frm);
	printf("Reason: %s\n", status2str(cp->reason));
}

static inline void add_sco_dump(int level, struct frame *frm)
{
	add_sco_cp *cp = frm->ptr;
	uint16_t ptype = btohs(cp->pkt_type);
	char *str;

	p_indent(level, frm);
	printf("handle %d ptype 0x%4.4x\n", btohs(cp->handle), ptype);

	str = hci_ptypetostr(ptype);
	if (str) {
		p_indent(level, frm);
		printf("Packet type: %s\n", str);
		free(str);
	}
}

static inline void accept_conn_req_dump(int level, struct frame *frm)
{
	accept_conn_req_cp *cp = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	printf("bdaddr %s role 0x%2.2x\n", addr, cp->role);

	p_indent(level, frm);
	printf("Role: %s\n", role2str(cp->role));
}

static inline void reject_conn_req_dump(int level, struct frame *frm)
{
	reject_conn_req_cp *cp = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	printf("bdaddr %s reason 0x%2.2x\n", addr, cp->reason);

	p_indent(level, frm);
	printf("Reason: %s\n", status2str(cp->reason));
}

static inline void pin_code_reply_dump(int level, struct frame *frm)
{
	pin_code_reply_cp *cp = frm->ptr;
	char addr[18], pin[17];

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	memset(pin, 0, sizeof(pin));
	memcpy(pin, cp->pin_code, cp->pin_len);
	printf("bdaddr %s len %d pin \'%s\'\n", addr, cp->pin_len, pin);
}

static inline void link_key_reply_dump(int level, struct frame *frm)
{
	link_key_reply_cp *cp = frm->ptr;
	char addr[18];
	int i;

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	printf("bdaddr %s key ", addr);
	for (i = 0; i < 16; i++)
		printf("%2.2X", cp->link_key[i]);
	printf("\n");
}

static inline void pin_code_neg_reply_dump(int level, struct frame *frm)
{
	bdaddr_t *bdaddr = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(bdaddr, addr);
	printf("bdaddr %s\n", addr);
}

static inline void set_conn_encrypt_dump(int level, struct frame *frm)
{
	set_conn_encrypt_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("handle %d encrypt 0x%2.2x\n", btohs(cp->handle), cp->encrypt);
}

static inline void remote_name_req_dump(int level, struct frame *frm)
{
	remote_name_req_cp *cp = frm->ptr;
	uint16_t clkoffset = btohs(cp->clock_offset);
	char addr[18];

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	printf("bdaddr %s mode %d clkoffset 0x%4.4x%s\n",
		addr, cp->pscan_rep_mode,
		clkoffset & 0x7fff, clkoffset & 0x8000 ? " (valid)" : "");
}

static inline void master_link_key_dump(int level, struct frame *frm)
{
	master_link_key_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("flag %d\n", cp->key_flag);
}

static inline void read_remote_ext_features_dump(int level, struct frame *frm)
{
	read_remote_ext_features_cp *cp = frm->ptr;

        p_indent(level, frm);
        printf("handle %d page %d\n", btohs(cp->handle), cp->page_num);
}

static inline void write_link_policy_dump(int level, struct frame *frm)
{
	write_link_policy_cp *cp = frm->ptr;
	uint16_t policy = btohs(cp->policy);
	char *str;

	p_indent(level, frm);
	printf("handle %d policy 0x%2.2x\n", btohs(cp->handle), policy);

	str = hci_lptostr(policy);
	if (str) {
		p_indent(level, frm);
		printf("Link policy: %s\n", str);
		free(str);
	}
}

static inline void set_event_mask_dump(int level, struct frame *frm)
{
	set_event_mask_cp *cp = frm->ptr;
	int i;

	p_indent(level, frm);
	printf("Mask: 0x");
	for (i = 0; i < 8; i++)
		printf("%2.2x", cp->mask[i]);
	printf("\n");
}

static inline void set_event_flt_dump(int level, struct frame *frm)
{
	set_event_flt_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("type %d condition %d\n", cp->flt_type, cp->cond_type);

	switch (cp->flt_type) {
	case FLT_CLEAR_ALL:
		printf("Clear all filters\n");
		break;
	case FLT_INQ_RESULT:
		printf("Inquiry result");
		switch (cp->cond_type) {
		case INQ_RESULT_RETURN_ALL:
		case INQ_RESULT_RETURN_CLASS:
		case INQ_RESULT_RETURN_BDADDR:
		default:
			printf("\n");
			break;
		}
		break;
	case FLT_CONN_SETUP:
		printf("Connection setup");
		switch (cp->cond_type) {
		case CONN_SETUP_ALLOW_ALL:
		case CONN_SETUP_ALLOW_CLASS:
		case CONN_SETUP_ALLOW_BDADDR:
		default:
			printf("\n");
			break;
		}
		break;
	}
}

static inline void write_pin_type_dump(int level, struct frame *frm)
{
	write_pin_type_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("type %d\n", cp->pin_type);
}

static inline void request_stored_link_key_dump(int level, struct frame *frm)
{
	read_stored_link_key_cp *cp = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(&cp->bdaddr, addr);
	printf("bdaddr %s all %d\n", addr, cp->read_all);
}

static inline void return_link_keys_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	uint8_t key[16];
	char addr[18];
	int i, n;

	for (n = 0; n < num; n++) {
		ba2str(frm->ptr, addr);
		memcpy(key, frm->ptr + 6, 16);

		p_indent(level, frm);
		printf("bdaddr %s key ", addr);
		for (i = 0; i < 16; i++)
			printf("%2.2X", key[i]);
		printf("\n");

		frm->ptr += 2;
		frm->len -= 2;
	}
}

static inline void change_local_name_dump(int level, struct frame *frm)
{
	change_local_name_cp *cp = frm->ptr;
	char name[249];
	int i;

	memset(name, 0, sizeof(name));
	for (i = 0; i < 248 && cp->name[i]; i++)
		if (isprint(cp->name[i]))
			name[i] = cp->name[i];
		else
			name[i] = '.';

	p_indent(level, frm);
	printf("name \'%s\'\n", name);
}

static inline void write_class_of_dev_dump(int level, struct frame *frm)
{
	write_class_of_dev_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("class 0x%2.2x%2.2x%2.2x\n",
		cp->dev_class[2], cp->dev_class[1], cp->dev_class[0]);
}

static inline void write_voice_setting_dump(int level, struct frame *frm)
{
	write_voice_setting_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("voice setting 0x%4.4x\n", btohs(cp->voice_setting));
}

static inline void write_current_iac_lap_dump(int level, struct frame *frm)
{
	write_current_iac_lap_cp *cp = frm->ptr;
	int i;

	for (i = 0; i < cp->num_current_iac; i++) {
		p_indent(level, frm);
		printf("IAC 0x%2.2x%2.2x%2.2x", cp->lap[i][2], cp->lap[i][1], cp->lap[i][0]);
		if (cp->lap[i][2] == 0x9e && cp->lap[i][1] == 0x8b) {
			switch (cp->lap[i][0]) {
			case 0x00:
				printf(" (Limited Inquiry Access Code)");
				break;
			case 0x33:
				printf(" (General Inquiry Access Code)");
				break;
			}
		}
		printf("\n");
	}
}

static inline void write_scan_enable_dump(int level, struct frame *frm)
{
	uint8_t enable = get_u8(frm);

	p_indent(level, frm);
	printf("enable %d\n", enable);
}

static inline void write_page_timeout_dump(int level, struct frame *frm)
{
	write_page_timeout_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("timeout %d\n", btohs(cp->timeout));
}

static inline void write_page_activity_dump(int level, struct frame *frm)
{
	write_page_activity_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("interval %d window %d\n", btohs(cp->interval), btohs(cp->window));
}

static inline void write_inquiry_scan_type_dump(int level, struct frame *frm)
{
	write_inquiry_scan_type_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("type %d\n", cp->type);
}

static inline void write_inquiry_mode_dump(int level, struct frame *frm)
{
	write_inquiry_mode_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("mode %d\n", cp->mode);
}

static inline void write_link_supervision_timeout_dump(int level, struct frame *frm)
{
	write_link_supervision_timeout_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("handle %d timeout %d\n",
		btohs(cp->handle), btohs(cp->link_sup_to));
}

static inline void write_ext_inquiry_response_dump(int level, struct frame *frm)
{
	write_ext_inquiry_response_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("fec 0x%2.2x\n", cp->fec);

	frm->ptr++;
	frm->len--;

	raw_dump(level, frm);
}

static inline void request_transmit_power_level_dump(int level, struct frame *frm)
{
	read_transmit_power_level_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("handle %d type %d (%s)\n",
		btohs(cp->handle), cp->type,
		cp->type ? "maximum" : "current");
}

static inline void request_local_ext_features_dump(int level, struct frame *frm)
{
	read_local_ext_features_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("page %d\n", cp->page_num);
}

static inline void request_clock_dump(int level, struct frame *frm)
{
	read_clock_cp *cp = frm->ptr;

	p_indent(level, frm);
	printf("handle %d which %d (%s)\n",
		btohs(cp->handle), cp->which_clock,
		cp->which_clock ? "piconet" : "local");
}

static inline void command_dump(int level, struct frame *frm)
{
	hci_command_hdr *hdr = frm->ptr;
	uint16_t opcode = btohs(hdr->opcode);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);

	if (p_filter(FILT_HCI))
		return;

	p_indent(level, frm);

	printf("HCI Command: %s (0x%2.2x|0x%4.4x) plen %d\n", 
		opcode2str(opcode), ogf, ocf, hdr->plen);

	frm->ptr += HCI_COMMAND_HDR_SIZE;
	frm->len -= HCI_COMMAND_HDR_SIZE;

	if (ogf == OGF_VENDOR_CMD && ocf == 0 && get_manufacturer() == 10) {
		csr_dump(level + 1, frm);
		return;
	}

	if (!(parser.flags & DUMP_VERBOSE)) {
		raw_dump(level, frm);
		return;
	}

	switch (ogf) {
	case OGF_LINK_CTL:
		switch (ocf) {
		case OCF_INQUIRY:
			inquiry_dump(level + 1, frm);
			return;
		case OCF_PERIODIC_INQUIRY:
			periodic_inquiry_dump(level + 1, frm);
			return;
		case OCF_INQUIRY_CANCEL:
		case OCF_EXIT_PERIODIC_INQUIRY:
			return;
		case OCF_CREATE_CONN:
			create_conn_dump(level + 1, frm);
			return;
		case OCF_DISCONNECT:
			disconnect_dump(level + 1, frm);
			return;
		case OCF_CREATE_CONN_CANCEL:
		case OCF_REMOTE_NAME_REQ_CANCEL:
		case OCF_ACCEPT_SYNC_CONN_REQ:
			bdaddr_command_dump(level + 1, frm);
			return;
		case OCF_ADD_SCO:
		case OCF_SET_CONN_PTYPE:
			add_sco_dump(level + 1, frm);
			return;
		case OCF_ACCEPT_CONN_REQ:
			accept_conn_req_dump(level + 1, frm);
			return;
		case OCF_REJECT_CONN_REQ:
		case OCF_REJECT_SYNC_CONN_REQ:
			reject_conn_req_dump(level + 1, frm);
			return;
		case OCF_PIN_CODE_REPLY:
			pin_code_reply_dump(level + 1, frm);
			return;
		case OCF_LINK_KEY_REPLY:
			link_key_reply_dump(level + 1, frm);
			return;
		case OCF_PIN_CODE_NEG_REPLY:
		case OCF_LINK_KEY_NEG_REPLY:
			pin_code_neg_reply_dump(level + 1, frm);
			return;
		case OCF_SET_CONN_ENCRYPT:
			set_conn_encrypt_dump(level + 1, frm);
			return;
		case OCF_AUTH_REQUESTED:
		case OCF_CHANGE_CONN_LINK_KEY:
		case OCF_READ_REMOTE_FEATURES:
		case OCF_READ_REMOTE_VERSION:
		case OCF_READ_CLOCK_OFFSET:
		case OCF_READ_LMP_HANDLE:
		case OCF_SETUP_SYNC_CONN:
			generic_command_dump(level + 1, frm);
			return;
		case OCF_MASTER_LINK_KEY:
			master_link_key_dump(level + 1, frm);
			return;
		case OCF_READ_REMOTE_EXT_FEATURES:
			read_remote_ext_features_dump(level + 1, frm);
			return;
		case OCF_REMOTE_NAME_REQ:
			remote_name_req_dump(level + 1, frm);
			return;
		}
		break;

	case OGF_LINK_POLICY:
		switch (ocf) {
		case OCF_EXIT_SNIFF_MODE:
		case OCF_EXIT_PARK_MODE:
		case OCF_ROLE_DISCOVERY:
		case OCF_READ_LINK_POLICY:
			generic_command_dump(level + 1, frm);
			return;
		case OCF_SWITCH_ROLE:
			accept_conn_req_dump(level + 1, frm);
			return;
		case OCF_WRITE_LINK_POLICY:
			write_link_policy_dump(level + 1, frm);
			return;
		}
		break;

	case OGF_HOST_CTL:
		switch (ocf) {
		case OCF_RESET:
		case OCF_CREATE_NEW_UNIT_KEY:
			return;
		case OCF_SET_EVENT_MASK:
			set_event_mask_dump(level + 1, frm);
			return;
		case OCF_SET_EVENT_FLT:
			set_event_flt_dump(level + 1, frm);
			return;
		case OCF_WRITE_PIN_TYPE:
			write_pin_type_dump(level + 1, frm);
			return;
		case OCF_READ_STORED_LINK_KEY:
		case OCF_DELETE_STORED_LINK_KEY:
			request_stored_link_key_dump(level + 1, frm);
			return;
		case OCF_WRITE_STORED_LINK_KEY:
			return_link_keys_dump(level + 1, frm);
			return;
		case OCF_CHANGE_LOCAL_NAME:
			change_local_name_dump(level + 1, frm);
			return;
		case OCF_WRITE_CLASS_OF_DEV:
			write_class_of_dev_dump(level + 1, frm);
			return;
		case OCF_WRITE_VOICE_SETTING:
			write_voice_setting_dump(level + 1, frm);
			return;
		case OCF_WRITE_CURRENT_IAC_LAP:
			write_current_iac_lap_dump(level + 1, frm);
			return;
		case OCF_WRITE_SCAN_ENABLE:
		case OCF_WRITE_AUTH_ENABLE:
			write_scan_enable_dump(level + 1, frm);
			return;
		case OCF_WRITE_CONN_ACCEPT_TIMEOUT:
		case OCF_WRITE_PAGE_TIMEOUT:
			write_page_timeout_dump(level + 1, frm);
			return;
		case OCF_WRITE_PAGE_ACTIVITY:
		case OCF_WRITE_INQ_ACTIVITY:
			write_page_activity_dump(level + 1, frm);
			return;
		case OCF_WRITE_INQUIRY_SCAN_TYPE:
			write_inquiry_scan_type_dump(level + 1, frm);
			return;
		case OCF_WRITE_ENCRYPT_MODE:
		case OCF_WRITE_INQUIRY_MODE:
		case OCF_WRITE_AFH_MODE:
			write_inquiry_mode_dump(level + 1, frm);
			return;
		case OCF_READ_TRANSMIT_POWER_LEVEL:
			request_transmit_power_level_dump(level + 1, frm);
			return;
		case OCF_FLUSH:
		case OCF_READ_LINK_SUPERVISION_TIMEOUT:
			generic_command_dump(level + 1, frm);
			return;
		case OCF_WRITE_LINK_SUPERVISION_TIMEOUT:
			write_link_supervision_timeout_dump(level + 1, frm);
			return;
		case OCF_WRITE_EXT_INQUIRY_RESPONSE:
			write_ext_inquiry_response_dump(level + 1, frm);
			return;
		}
		break;

	case OGF_INFO_PARAM:
		switch (ocf) {
		case OCF_READ_LOCAL_EXT_FEATURES:
			request_local_ext_features_dump(level + 1, frm);
			return;
		}
		break;

	case OGF_STATUS_PARAM:
		switch (ocf) {
		case OCF_READ_LINK_QUALITY:
		case OCF_READ_RSSI:
		case OCF_READ_AFH_MAP:
			generic_command_dump(level + 1, frm);
			return;
		case OCF_READ_CLOCK:
			request_clock_dump(level + 1, frm);
			return;
		}
		break;
	}

	raw_dump(level, frm);
}

static inline void status_response_dump(int level, struct frame *frm)
{
	uint8_t status = get_u8(frm);

	p_indent(level, frm);
	printf("status 0x%2.2x\n", status);

	if (status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(status));
	}

	raw_dump(level, frm);
}

static inline void handle_response_dump(int level, struct frame *frm)
{
	uint16_t handle = btohs(htons(get_u16(frm)));

	p_indent(level, frm);
	printf("handle %d\n", handle);

	raw_dump(level, frm);
}

static inline void bdaddr_response_dump(int level, struct frame *frm)
{
	uint8_t status = get_u8(frm);
	bdaddr_t *bdaddr = frm->ptr;
	char addr[18];

	frm->ptr += sizeof(bdaddr_t);
	frm->len -= sizeof(bdaddr_t);

	p_indent(level, frm);
	ba2str(bdaddr, addr);
	printf("status 0x%2.2x bdaddr %s\n", status, addr);

	if (status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(status));
	}

	raw_dump(level, frm);
}

static inline void generic_response_dump(int level, struct frame *frm)
{
	uint8_t status = get_u8(frm);
	uint16_t handle = btohs(htons(get_u16(frm)));

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d\n", status, handle);

	if (status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(status));
	}

	raw_dump(level, frm);
}

static inline void read_pin_type_dump(int level, struct frame *frm)
{
	read_pin_type_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x type %d\n", rp->status, rp->pin_type);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_stored_link_key_dump(int level, struct frame *frm)
{
	read_stored_link_key_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x max %d num %d\n",
		rp->status, rp->max_keys, rp->num_keys);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void write_stored_link_key_dump(int level, struct frame *frm)
{
	write_stored_link_key_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x written %d\n", rp->status, rp->num_keys);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void delete_stored_link_key_dump(int level, struct frame *frm)
{
	delete_stored_link_key_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x deleted %d\n", rp->status, btohs(rp->num_keys));

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_local_name_dump(int level, struct frame *frm)
{
	read_local_name_rp *rp = frm->ptr;
	char name[249];
	int i;

	memset(name, 0, sizeof(name));
	for (i = 0; i < 248 && rp->name[i]; i++)
		if (isprint(rp->name[i]))
			name[i] = rp->name[i];
		else
			name[i] = '.';

	p_indent(level, frm);
	printf("status 0x%2.2x name \'%s\'\n", rp->status, name);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_class_of_dev_dump(int level, struct frame *frm)
{
	read_class_of_dev_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x class 0x%2.2x%2.2x%2.2x\n", rp->status,
		rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_voice_setting_dump(int level, struct frame *frm)
{
	read_voice_setting_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x voice setting 0x%4.4x\n",
		rp->status, btohs(rp->voice_setting));

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_current_iac_lap_dump(int level, struct frame *frm)
{
	read_current_iac_lap_rp *rp = frm->ptr;
	int i;

	for (i = 0; i < rp->num_current_iac; i++) {
		p_indent(level, frm);
		printf("IAC 0x%2.2x%2.2x%2.2x", rp->lap[i][2], rp->lap[i][1], rp->lap[i][0]);
		if (rp->lap[i][2] == 0x9e && rp->lap[i][1] == 0x8b) {
			switch (rp->lap[i][0]) {
			case 0x00:
				printf(" (Limited Inquiry Access Code)");
				break;
			case 0x33:
				printf(" (General Inquiry Access Code)");
				break;
			}
		}
		printf("\n");
	}
}

static inline void read_scan_enable_dump(int level, struct frame *frm)
{
	uint8_t status = get_u8(frm);
	uint8_t enable = get_u8(frm);

	p_indent(level, frm);
	printf("status 0x%2.2x enable %d\n", status, enable);

	if (status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(status));
	}
}

static inline void read_page_timeout_dump(int level, struct frame *frm)
{
	read_page_timeout_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x timeout %d\n", rp->status, btohs(rp->timeout));

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_page_activity_dump(int level, struct frame *frm)
{
	read_page_activity_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x interval %d window %d\n",
		rp->status, btohs(rp->interval), btohs(rp->window));

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_inquiry_scan_type_dump(int level, struct frame *frm)
{
	read_inquiry_scan_type_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x type %d\n", rp->status, rp->type);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_inquiry_mode_dump(int level, struct frame *frm)
{
	read_inquiry_mode_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x mode %d\n", rp->status, rp->mode);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_link_supervision_timeout_dump(int level, struct frame *frm)
{
	read_link_supervision_timeout_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d timeout %d\n",
		rp->status, btohs(rp->handle), btohs(rp->link_sup_to));

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_transmit_power_level_dump(int level, struct frame *frm)
{
	read_transmit_power_level_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d level %d\n",
		rp->status, btohs(rp->handle), rp->level);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_ext_inquiry_response_dump(int level, struct frame *frm)
{
	read_ext_inquiry_response_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x fec 0x%2.2x\n", rp->status, rp->fec);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		frm->ptr += 2;
		frm->len -= 2;

		raw_dump(level, frm);
	}
}

static inline void read_local_version_dump(int level, struct frame *frm)
{
	read_local_version_rp *rp = frm->ptr;
	uint16_t manufacturer = btohs(rp->manufacturer);

	p_indent(level, frm);
	printf("status 0x%2.2x\n", rp->status);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		p_indent(level, frm);
		printf("HCI Version: %s (0x%x) HCI Revision: 0x%x\n",
			hci_vertostr(rp->hci_ver), rp->hci_ver,
			btohs(rp->hci_rev));
		p_indent(level, frm);
		printf("LMP Version: %s (0x%x) LMP Subversion: 0x%x\n",
			lmp_vertostr(rp->lmp_ver), rp->lmp_ver,
			btohs(rp->lmp_subver));
		p_indent(level, frm);
		printf("Manufacturer: %s (%d)\n",
			bt_compidtostr(manufacturer), manufacturer);
	}
}

static inline void read_local_commands_dump(int level, struct frame *frm)
{
	read_local_commands_rp *rp = frm->ptr;
	int i, max = 0;

	p_indent(level, frm);
	printf("status 0x%2.2x\n", rp->status);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		for (i = 0; i < 64; i++)
			if (rp->commands[i])
				max = i + 1;
		p_indent(level, frm);
		printf("Commands: ");
		for (i = 0; i < (max > 32 ? 32 : max); i++)
			printf("%2.2x", rp->commands[i]);
		printf("\n");
		if (max > 32) {
			p_indent(level, frm);
			printf("          ");
			for (i = 32; i < max; i++)
				printf("%2.2x", rp->commands[i]);
			printf("\n");
		}
	}
}

static inline void read_local_features_dump(int level, struct frame *frm)
{
	read_local_features_rp *rp = frm->ptr;
	int i;

	p_indent(level, frm);
	printf("status 0x%2.2x\n", rp->status);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		p_indent(level, frm);
		printf("Features:");
		for (i = 0; i < 8; i++)
			printf(" 0x%2.2x", rp->features[i]);
		printf("\n");
	}
}

static inline void read_local_ext_features_dump(int level, struct frame *frm)
{
	read_local_ext_features_rp *rp = frm->ptr;
	int i;

	p_indent(level, frm);
	printf("status 0x%2.2x page %d max %d\n",
		rp->status, rp->page_num, rp->max_page_num);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		p_indent(level, frm);
		printf("Features:");
		for (i = 0; i < 8; i++)
			 printf(" 0x%2.2x", rp->features[i]);
		printf("\n");
	}
}

static inline void read_buffer_size_dump(int level, struct frame *frm)
{
	read_buffer_size_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x\n", rp->status);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		p_indent(level, frm);
		printf("ACL MTU %d:%d SCO MTU %d:%d\n",
			btohs(rp->acl_mtu), btohs(rp->acl_max_pkt),
			rp->sco_mtu, btohs(rp->sco_max_pkt));
	}
}

static inline void read_link_quality_dump(int level, struct frame *frm)
{
	read_link_quality_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d lq %d\n",
		rp->status, btohs(rp->handle), rp->link_quality);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_rssi_dump(int level, struct frame *frm)
{
	read_rssi_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d rssi %d\n",
		rp->status, btohs(rp->handle), rp->rssi);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void read_afh_map_dump(int level, struct frame *frm)
{
	read_afh_map_rp *rp = frm->ptr;
	int i;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d mode %d\n",
		rp->status, btohs(rp->handle), rp->mode);

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	} else {
		p_indent(level, frm);
		printf("AFH map: 0x");
		for (i = 0; i < 10; i++)
			printf("%2.2x", rp->map[i]);
		printf("\n");
	}
}

static inline void read_clock_dump(int level, struct frame *frm)
{
	read_clock_rp *rp = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d clock 0x%4.4x accuracy %d\n",
		rp->status, btohs(rp->handle),
		btohl(rp->clock), btohs(rp->accuracy));

	if (rp->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(rp->status));
	}
}

static inline void cmd_complete_dump(int level, struct frame *frm)
{
	evt_cmd_complete *evt = frm->ptr;
	uint16_t opcode = btohs(evt->opcode);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);

	p_indent(level, frm);
	printf("%s (0x%2.2x|0x%4.4x) ncmd %d\n",
		opcode2str(opcode), ogf, ocf, evt->ncmd);

	frm->ptr += EVT_CMD_COMPLETE_SIZE;
	frm->len -= EVT_CMD_COMPLETE_SIZE;

	if (!(parser.flags & DUMP_VERBOSE)) {
		raw_dump(level, frm);
		return;
	}

	switch (ogf) {
	case OGF_LINK_CTL:
		switch (ocf) {
		case OCF_INQUIRY_CANCEL:
		case OCF_PERIODIC_INQUIRY:
		case OCF_EXIT_PERIODIC_INQUIRY:
			status_response_dump(level, frm);
			return;
		case OCF_CREATE_CONN_CANCEL:
		case OCF_REMOTE_NAME_REQ_CANCEL:
		case OCF_PIN_CODE_REPLY:
		case OCF_LINK_KEY_REPLY:
		case OCF_PIN_CODE_NEG_REPLY:
		case OCF_LINK_KEY_NEG_REPLY:
			bdaddr_response_dump(level, frm);
			return;
		}
		break;

	case OGF_LINK_POLICY:
		switch (ocf) {
		case OCF_WRITE_LINK_POLICY:
			generic_response_dump(level, frm);
			return;
		}
		break;

	case OGF_HOST_CTL:
		switch (ocf) {
		case OCF_READ_PIN_TYPE:
			read_pin_type_dump(level, frm);
			return;
		case OCF_READ_STORED_LINK_KEY:
			read_stored_link_key_dump(level, frm);
			return;
		case OCF_WRITE_STORED_LINK_KEY:
			write_stored_link_key_dump(level, frm);
			return;
		case OCF_DELETE_STORED_LINK_KEY:
			delete_stored_link_key_dump(level, frm);
			return;
		case OCF_READ_LOCAL_NAME:
			read_local_name_dump(level, frm);
			return;
		case OCF_READ_CLASS_OF_DEV:
			read_class_of_dev_dump(level, frm);
			return;
		case OCF_READ_VOICE_SETTING:
			read_voice_setting_dump(level, frm);
			return;
		case OCF_READ_CURRENT_IAC_LAP:
			read_current_iac_lap_dump(level, frm);
			return;
		case OCF_READ_SCAN_ENABLE:
		case OCF_READ_AUTH_ENABLE:
			read_scan_enable_dump(level, frm);
			return;
		case OCF_READ_CONN_ACCEPT_TIMEOUT:
		case OCF_READ_PAGE_TIMEOUT:
			read_page_timeout_dump(level, frm);
			return;
		case OCF_READ_PAGE_ACTIVITY:
		case OCF_READ_INQ_ACTIVITY:
			read_page_activity_dump(level, frm);
			return;
		case OCF_READ_INQUIRY_SCAN_TYPE:
			read_inquiry_scan_type_dump(level, frm);
			return;
		case OCF_READ_ENCRYPT_MODE:
		case OCF_READ_INQUIRY_MODE:
		case OCF_READ_AFH_MODE:
			read_inquiry_mode_dump(level, frm);
			return;
		case OCF_READ_LINK_SUPERVISION_TIMEOUT:
			read_link_supervision_timeout_dump(level, frm);
			return;
		case OCF_READ_TRANSMIT_POWER_LEVEL:
			read_transmit_power_level_dump(level, frm);
			return;
		case OCF_READ_EXT_INQUIRY_RESPONSE:
			read_ext_inquiry_response_dump(level, frm);
			return;
		case OCF_FLUSH:
		case OCF_WRITE_LINK_SUPERVISION_TIMEOUT:
			generic_response_dump(level, frm);
			return;
		case OCF_RESET:
		case OCF_SET_EVENT_MASK:
		case OCF_SET_EVENT_FLT:
		case OCF_WRITE_PIN_TYPE:
		case OCF_CREATE_NEW_UNIT_KEY:
		case OCF_CHANGE_LOCAL_NAME:
		case OCF_WRITE_CLASS_OF_DEV:
		case OCF_WRITE_VOICE_SETTING:
		case OCF_WRITE_CURRENT_IAC_LAP:
		case OCF_WRITE_SCAN_ENABLE:
		case OCF_WRITE_AUTH_ENABLE:
		case OCF_WRITE_ENCRYPT_MODE:
		case OCF_WRITE_CONN_ACCEPT_TIMEOUT:
		case OCF_WRITE_PAGE_TIMEOUT:
		case OCF_WRITE_PAGE_ACTIVITY:
		case OCF_WRITE_INQ_ACTIVITY:
		case OCF_WRITE_INQUIRY_SCAN_TYPE:
		case OCF_WRITE_INQUIRY_MODE:
		case OCF_WRITE_AFH_MODE:
		case OCF_SET_AFH_CLASSIFICATION:
		case OCF_WRITE_EXT_INQUIRY_RESPONSE:
			status_response_dump(level, frm);
			return;
		}
		break;

	case OGF_INFO_PARAM:
		switch (ocf) {
		case OCF_READ_LOCAL_VERSION:
			read_local_version_dump(level, frm);
			return;
		case OCF_READ_LOCAL_COMMANDS:
			read_local_commands_dump(level, frm);
			return;
		case OCF_READ_LOCAL_FEATURES:
			read_local_features_dump(level, frm);
			return;
		case OCF_READ_LOCAL_EXT_FEATURES:
			read_local_ext_features_dump(level, frm);
			return;
		case OCF_READ_BUFFER_SIZE:
			read_buffer_size_dump(level, frm);
			return;
		case OCF_READ_BD_ADDR:
			bdaddr_response_dump(level, frm);
			return;
		}
		break;

	case OGF_STATUS_PARAM:
		switch (ocf) {
		case OCF_READ_FAILED_CONTACT_COUNTER:
		case OCF_RESET_FAILED_CONTACT_COUNTER:
			status_response_dump(level, frm);
			return;
		case OCF_READ_LINK_QUALITY:
			read_link_quality_dump(level, frm);
			return;
		case OCF_READ_RSSI:
			read_rssi_dump(level, frm);
			return;
		case OCF_READ_AFH_MAP:
			read_afh_map_dump(level, frm);
			return;
		case OCF_READ_CLOCK:
			read_clock_dump(level, frm);
			return;
		}
		break;
	}

	raw_dump(level, frm);
}

static inline void cmd_status_dump(int level, struct frame *frm)
{
	evt_cmd_status *evt = frm->ptr;
	uint16_t opcode = btohs(evt->opcode);

	p_indent(level, frm);
	printf("%s (0x%2.2x|0x%4.4x) status 0x%2.2x ncmd %d\n",
		opcode2str(opcode),
		cmd_opcode_ogf(opcode), cmd_opcode_ocf(opcode),
		evt->status, evt->ncmd);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void hardware_error_dump(int level, struct frame *frm)
{
	evt_hardware_error *evt = frm->ptr;

	p_indent(level, frm);
	printf("code %d\n", evt->code);
}

static inline void inq_result_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	char addr[18];
	int i;

	for (i = 0; i < num; i++) {
		inquiry_info *info = frm->ptr;

		ba2str(&info->bdaddr, addr);

		p_indent(level, frm);
		printf("bdaddr %s mode %d clkoffset 0x%4.4x class 0x%2.2x%2.2x%2.2x\n",
			addr, info->pscan_rep_mode, btohs(info->clock_offset),
			info->dev_class[2], info->dev_class[1], info->dev_class[0]);

		frm->ptr += INQUIRY_INFO_SIZE;
		frm->len -= INQUIRY_INFO_SIZE;
	}
}

static inline void conn_complete_dump(int level, struct frame *frm)
{
	evt_conn_complete *evt = frm->ptr;
	char addr[18];

	ba2str(&evt->bdaddr, addr);

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d bdaddr %s type %s encrypt 0x%2.2x\n",
		evt->status, btohs(evt->handle), addr,
		evt->link_type == 1 ? "ACL" : "SCO", evt->encr_mode);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void conn_request_dump(int level, struct frame *frm)
{
	evt_conn_request *evt = frm->ptr;
	char addr[18];

	ba2str(&evt->bdaddr, addr);

	p_indent(level, frm);
	printf("bdaddr %s class 0x%2.2x%2.2x%2.2x type %s\n",
		addr, evt->dev_class[2], evt->dev_class[1],
		evt->dev_class[0], evt->link_type == 1 ? "ACL" : "SCO");
}

static inline void disconn_complete_dump(int level, struct frame *frm)
{
	evt_disconn_complete *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d reason 0x%2.2x\n",
		evt->status, btohs(evt->handle), evt->reason);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else if (evt->reason > 0) {
		p_indent(level, frm);
		printf("Reason: %s\n", status2str(evt->reason));
	}
}

static inline void remote_name_req_complete_dump(int level, struct frame *frm)
{
	evt_remote_name_req_complete *evt = frm->ptr;
	char addr[18], name[249];
	int i;

	ba2str(&evt->bdaddr, addr);

	memset(name, 0, sizeof(name));
	for (i = 0; i < 248 && evt->name[i]; i++)
		if (isprint(evt->name[i]))
			name[i] = evt->name[i];
		else
			name[i] = '.';

	p_indent(level, frm);
	printf("status 0x%2.2x bdaddr %s name '%s'\n", evt->status, addr, name);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void master_link_key_complete_dump(int level, struct frame *frm)
{
	evt_master_link_key_complete *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d flag %d\n",
		evt->status, btohs(evt->handle), evt->key_flag);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void encrypt_change_dump(int level, struct frame *frm)
{
	evt_encrypt_change *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d encrypt 0x%2.2x\n",
		evt->status, btohs(evt->handle), evt->encrypt);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void read_remote_features_complete_dump(int level, struct frame *frm)
{
	evt_read_remote_features_complete *evt = frm->ptr;
	int i;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d\n", evt->status, btohs(evt->handle));

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Features:");
		for (i = 0; i < 8; i++)
			printf(" 0x%2.2x", evt->features[i]);
		printf("\n");
	}
}

static inline void read_remote_version_complete_dump(int level, struct frame *frm)
{
	evt_read_remote_version_complete *evt = frm->ptr;
	uint16_t manufacturer = btohs(evt->manufacturer);

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d\n", evt->status, btohs(evt->handle));

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("LMP Version: %s (0x%x) LMP Subversion: 0x%x\n",
			lmp_vertostr(evt->lmp_ver), evt->lmp_ver,
			btohs(evt->lmp_subver));
		p_indent(level, frm);
		printf("Manufacturer: %s (%d)\n",
			bt_compidtostr(manufacturer), manufacturer);
	}
}

static inline void qos_setup_complete_dump(int level, struct frame *frm)
{
	evt_qos_setup_complete *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d flags %d\n",
		evt->status, btohs(evt->handle), evt->flags);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Service type: %d\n", evt->qos.service_type);
		p_indent(level, frm);
		printf("Token rate: %d\n", btohl(evt->qos.token_rate));
		p_indent(level, frm);
		printf("Peak bandwith: %d\n", btohl(evt->qos.peak_bandwidth));
		p_indent(level, frm);
		printf("Latency: %d\n", btohl(evt->qos.latency));
		p_indent(level, frm);
		printf("Delay variation: %d\n", btohl(evt->qos.delay_variation));
	}
}

static inline void role_change_dump(int level, struct frame *frm)
{
	evt_role_change *evt = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(&evt->bdaddr, addr);
	printf("status 0x%2.2x bdaddr %s role 0x%2.2x\n",
		evt->status, addr, evt->role);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Role: %s\n", role2str(evt->role));
	}
}

static inline void num_comp_pkts_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	uint16_t handle, packets;
	int i;

	for (i = 0; i < num; i++) {
		handle = btohs(htons(get_u16(frm)));
		packets = btohs(htons(get_u16(frm)));

		p_indent(level, frm);
		printf("handle %d packets %d\n", handle, packets);
	}
}

static inline void mode_change_dump(int level, struct frame *frm)
{
	evt_mode_change *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d mode 0x%2.2x interval %d\n",
		evt->status, btohs(evt->handle), evt->mode, btohs(evt->interval));

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Mode: %s\n", mode2str(evt->mode));
	}
}

static inline void pin_code_req_dump(int level, struct frame *frm)
{
	evt_pin_code_req *evt = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(&evt->bdaddr, addr);
	printf("bdaddr %s\n", addr);
}

static inline void link_key_notify_dump(int level, struct frame *frm)
{
	evt_link_key_notify *evt = frm->ptr;
	char addr[18];
	int i;

	p_indent(level, frm);
	ba2str(&evt->bdaddr, addr);
	printf("bdaddr %s key ", addr);
	for (i = 0; i < 16; i++)
		printf("%2.2X", evt->link_key[i]);
	printf(" type %d\n", evt->key_type);
}

static inline void max_slots_change_dump(int level, struct frame *frm)
{
	evt_max_slots_change *evt = frm->ptr;

	p_indent(level, frm);
	printf("handle %d slots %d\n", btohs(evt->handle), evt->max_slots);
}

static inline void data_buffer_overflow_dump(int level, struct frame *frm)
{
	evt_data_buffer_overflow *evt = frm->ptr;

	p_indent(level, frm);
	printf("type %s\n", evt->link_type == 1 ? "ACL" : "SCO");
}

static inline void read_clock_offset_complete_dump(int level, struct frame *frm)
{
	evt_read_clock_offset_complete *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d clkoffset 0x%4.4x\n",
		evt->status, btohs(evt->handle), btohs(evt->clock_offset));

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void conn_ptype_changed_dump(int level, struct frame *frm)
{
	evt_conn_ptype_changed *evt = frm->ptr;
	uint16_t ptype = btohs(evt->ptype);
	char *str;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d ptype 0x%4.4x\n",
		evt->status, btohs(evt->handle), ptype);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		str = hci_ptypetostr(ptype);
		if (str) {
			p_indent(level, frm);
			printf("Packet type: %s\n", str);
			free(str);
		}
	}
}

static inline void pscan_rep_mode_change_dump(int level, struct frame *frm)
{
	evt_pscan_rep_mode_change *evt = frm->ptr;
	char addr[18];

	p_indent(level, frm);
	ba2str(&evt->bdaddr, addr);
	printf("bdaddr %s mode %d\n", addr, evt->pscan_rep_mode);
}

static inline void flow_spec_complete_dump(int level, struct frame *frm)
{
	evt_flow_spec_complete *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d flags %d %s\n",
		evt->status, btohs(evt->handle), evt->flags,
		evt->direction == 0 ? "outgoing" : "incoming");

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Service type: %d\n", evt->qos.service_type);
		p_indent(level, frm);
		printf("Token rate: %d\n", btohl(evt->qos.token_rate));
		p_indent(level, frm);
		printf("Peak bandwith: %d\n", btohl(evt->qos.peak_bandwidth));
		p_indent(level, frm);
		printf("Latency: %d\n", btohl(evt->qos.latency));
		p_indent(level, frm);
		printf("Delay variation: %d\n", btohl(evt->qos.delay_variation));
	}
}

static inline void inq_result_with_rssi_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	char addr[18];
	int i;

	if (!num)
		return;

	if (frm->len / num == INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE) {
		for (i = 0; i < num; i++) {
			inquiry_info_with_rssi_and_pscan_mode *info = frm->ptr;

			p_indent(level, frm);

			ba2str(&info->bdaddr, addr);
			printf("bdaddr %s mode %d clkoffset 0x%4.4x class 0x%2.2x%2.2x%2.2x rssi %d\n",
				addr, info->pscan_rep_mode, btohs(info->clock_offset),
				info->dev_class[2], info->dev_class[1], info->dev_class[0], info->rssi);

			frm->ptr += INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE;
			frm->len -= INQUIRY_INFO_WITH_RSSI_AND_PSCAN_MODE_SIZE;
		}
	} else {
		for (i = 0; i < num; i++) {
			inquiry_info_with_rssi *info = frm->ptr;

			p_indent(level, frm);

			ba2str(&info->bdaddr, addr);
			printf("bdaddr %s mode %d clkoffset 0x%4.4x class 0x%2.2x%2.2x%2.2x rssi %d\n",
				addr, info->pscan_rep_mode, btohs(info->clock_offset),
				info->dev_class[2], info->dev_class[1], info->dev_class[0], info->rssi);

			frm->ptr += INQUIRY_INFO_WITH_RSSI_SIZE;
			frm->len -= INQUIRY_INFO_WITH_RSSI_SIZE;
		}
	}
}

static inline void read_remote_ext_features_complete_dump(int level, struct frame *frm)
{
	evt_read_remote_ext_features_complete *evt = frm->ptr;
	int i;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d page %d max %d\n",
		evt->status, btohs(evt->handle),
		evt->page_num, evt->max_page_num);

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Features:");
		for (i = 0; i < 8; i++)
			printf(" 0x%2.2x", evt->features[i]);
		printf("\n");
	}
}

static inline void sync_conn_complete_dump(int level, struct frame *frm)
{
	evt_sync_conn_complete *evt = frm->ptr;
	char addr[18];

	ba2str(&evt->bdaddr, addr);

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d bdaddr %s type %s\n",
		evt->status, btohs(evt->handle), addr,
		evt->link_type == 0 ? "SCO" : "eSCO");

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	} else {
		p_indent(level, frm);
		printf("Air mode: %s\n", airmode2str(evt->air_mode));
	}
}

static inline void sync_conn_changed_dump(int level, struct frame *frm)
{
	evt_sync_conn_changed *evt = frm->ptr;

	p_indent(level, frm);
	printf("status 0x%2.2x handle %d\n",
		evt->status, btohs(evt->handle));

	if (evt->status > 0) {
		p_indent(level, frm);
		printf("Error: %s\n", status2str(evt->status));
	}
}

static inline void extended_inq_result_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	char addr[18];
	int i;

	for (i = 0; i < num; i++) {
		extended_inquiry_info *info = frm->ptr;

		ba2str(&info->bdaddr, addr);

		p_indent(level, frm);
		printf("bdaddr %s mode %d clkoffset 0x%4.4x class 0x%2.2x%2.2x%2.2x rssi %d\n",
			addr, info->pscan_rep_mode, btohs(info->clock_offset),
			info->dev_class[2], info->dev_class[1], info->dev_class[0], info->rssi);

		frm->ptr += INQUIRY_INFO_WITH_RSSI_SIZE;
		frm->len -= INQUIRY_INFO_WITH_RSSI_SIZE;

		raw_dump(level, frm);

		frm->ptr += EXTENDED_INQUIRY_INFO_SIZE - INQUIRY_INFO_WITH_RSSI_SIZE;
		frm->len -= EXTENDED_INQUIRY_INFO_SIZE - INQUIRY_INFO_WITH_RSSI_SIZE;
	}
}

static inline void event_dump(int level, struct frame *frm)
{
	hci_event_hdr *hdr = frm->ptr;
	uint8_t event = hdr->evt;

	if (p_filter(FILT_HCI))
		return;

	p_indent(level, frm);

	if (event <= EVENT_NUM) {
		printf("HCI Event: %s (0x%2.2x) plen %d\n",
			event_str[hdr->evt], hdr->evt, hdr->plen);
	} else if (hdr->evt == EVT_TESTING) {
		printf("HCI Event: Testing (0x%2.2x) plen %d\n", hdr->evt, hdr->plen);
	} else if (hdr->evt == EVT_VENDOR) {
		printf("HCI Event: Vendor (0x%2.2x) plen %d\n", hdr->evt, hdr->plen);
		if (get_manufacturer() == 10) {
			frm->ptr += HCI_EVENT_HDR_SIZE;
			frm->len -= HCI_EVENT_HDR_SIZE;
			csr_dump(level + 1, frm);
			return;
		}
	} else
		printf("HCI Event: code 0x%2.2x plen %d\n", hdr->evt, hdr->plen);

	frm->ptr += HCI_EVENT_HDR_SIZE;
	frm->len -= HCI_EVENT_HDR_SIZE;

	if (event == EVT_CMD_COMPLETE) {
		evt_cmd_complete *cc = frm->ptr;
		if (cc->opcode == cmd_opcode_pack(OGF_INFO_PARAM, OCF_READ_LOCAL_VERSION)) {
			read_local_version_rp *rp = frm->ptr + EVT_CMD_COMPLETE_SIZE;
			manufacturer = rp->manufacturer;
		}
	}

	if (event == EVT_DISCONN_COMPLETE) {
		evt_disconn_complete *evt = frm->ptr;
		l2cap_clear(btohs(evt->handle));
	}

	if (!(parser.flags & DUMP_VERBOSE)) {
		raw_dump(level, frm);
		return;
	}

	switch (event) {
	case EVT_LOOPBACK_COMMAND:
		command_dump(level + 1, frm);
		break;
	case EVT_CMD_COMPLETE:
		cmd_complete_dump(level + 1, frm);
		break;
	case EVT_CMD_STATUS:
		cmd_status_dump(level + 1, frm);
		break;
	case EVT_HARDWARE_ERROR:
		hardware_error_dump(level + 1, frm);
		break;
	case EVT_FLUSH_OCCURRED:
	case EVT_QOS_VIOLATION:
		handle_response_dump(level + 1, frm);
		break;
	case EVT_INQUIRY_COMPLETE:
		status_response_dump(level + 1, frm);
		break;
	case EVT_INQUIRY_RESULT:
		inq_result_dump(level + 1, frm);
		break;
	case EVT_CONN_COMPLETE:
		conn_complete_dump(level + 1, frm);
		break;
	case EVT_CONN_REQUEST:
		conn_request_dump(level + 1, frm);
		break;
	case EVT_DISCONN_COMPLETE:
		disconn_complete_dump(level + 1, frm);
		break;
	case EVT_AUTH_COMPLETE:
	case EVT_CHANGE_CONN_LINK_KEY_COMPLETE:
		generic_response_dump(level + 1, frm);
		break;
	case EVT_MASTER_LINK_KEY_COMPLETE:
		master_link_key_complete_dump(level + 1, frm);
		break;
	case EVT_REMOTE_NAME_REQ_COMPLETE:
		remote_name_req_complete_dump(level + 1, frm);
		break;
	case EVT_ENCRYPT_CHANGE:
		encrypt_change_dump(level + 1, frm);
		break;
	case EVT_READ_REMOTE_FEATURES_COMPLETE:
		read_remote_features_complete_dump(level + 1, frm);
		break;
	case EVT_READ_REMOTE_VERSION_COMPLETE:
		read_remote_version_complete_dump(level + 1, frm);
		break;
	case EVT_QOS_SETUP_COMPLETE:
		qos_setup_complete_dump(level + 1, frm);
		break;
	case EVT_ROLE_CHANGE:
		role_change_dump(level + 1, frm);
		break;
	case EVT_NUM_COMP_PKTS:
		num_comp_pkts_dump(level + 1, frm);
		break;
	case EVT_MODE_CHANGE:
		mode_change_dump(level + 1, frm);
		break;
	case EVT_RETURN_LINK_KEYS:
		return_link_keys_dump(level + 1, frm);
		break;
	case EVT_PIN_CODE_REQ:
	case EVT_LINK_KEY_REQ:
		pin_code_req_dump(level + 1, frm);
		break;
	case EVT_LINK_KEY_NOTIFY:
		link_key_notify_dump(level + 1, frm);
		break;
	case EVT_DATA_BUFFER_OVERFLOW:
		data_buffer_overflow_dump(level + 1, frm);
		break;
	case EVT_MAX_SLOTS_CHANGE:
		max_slots_change_dump(level + 1, frm);
		break;
	case EVT_READ_CLOCK_OFFSET_COMPLETE:
		read_clock_offset_complete_dump(level + 1, frm);
		break;
	case EVT_CONN_PTYPE_CHANGED:
		conn_ptype_changed_dump(level + 1, frm);
		break;
	case EVT_PSCAN_REP_MODE_CHANGE:
		pscan_rep_mode_change_dump(level + 1, frm);
		break;
	case EVT_FLOW_SPEC_COMPLETE:
		flow_spec_complete_dump(level + 1, frm);
		break;
	case EVT_INQUIRY_RESULT_WITH_RSSI:
		inq_result_with_rssi_dump(level + 1, frm);
		break;
	case EVT_READ_REMOTE_EXT_FEATURES_COMPLETE:
		read_remote_ext_features_complete_dump(level + 1, frm);
		break;
	case EVT_SYNC_CONN_COMPLETE:
		sync_conn_complete_dump(level + 1, frm);
		break;
	case EVT_SYNC_CONN_CHANGED:
		sync_conn_changed_dump(level + 1, frm);
		break;
	case EVT_EXTENDED_INQUIRY_RESULT:
		extended_inq_result_dump(level + 1, frm);
		break;
	default:
		raw_dump(level, frm);
		break;
	}
}

static inline void acl_dump(int level, struct frame *frm)
{
	hci_acl_hdr *hdr = (void *) frm->ptr;
	uint16_t handle = btohs(hdr->handle);
	uint16_t dlen = btohs(hdr->dlen);
	uint8_t flags = acl_flags(handle);

	if (!p_filter(FILT_HCI)) {
		p_indent(level, frm);
		printf("ACL data: handle %d flags 0x%2.2x dlen %d\n",
			acl_handle(handle), flags, dlen);
		level++;
	}

	frm->ptr += HCI_ACL_HDR_SIZE;
	frm->len -= HCI_ACL_HDR_SIZE;
	frm->flags  = flags;
	frm->handle = acl_handle(handle);

	if (parser.filter & ~FILT_HCI)
		l2cap_dump(level, frm);
	else
		raw_dump(level, frm);
}

static inline void sco_dump(int level, struct frame *frm)
{
	hci_sco_hdr *hdr = (void *) frm->ptr;
	uint16_t handle = btohs(hdr->handle);

	if (frm->audio_fd > 2)
		write(frm->audio_fd, frm->ptr + HCI_SCO_HDR_SIZE, hdr->dlen);

	if (!p_filter(FILT_SCO)) {
		p_indent(level, frm);
		printf("SCO data: handle %d dlen %d\n",
			acl_handle(handle), hdr->dlen);
		level++;

		frm->ptr += HCI_SCO_HDR_SIZE;
		frm->len -= HCI_SCO_HDR_SIZE;
		raw_dump(level, frm);
	}
}

static inline void vendor_dump(int level, struct frame *frm)
{
	if (p_filter(FILT_HCI))
		return;

	if (frm->dev_id == HCI_DEV_NONE) {
		uint16_t device = btohs(htons(get_u16(frm)));
		uint16_t type = btohs(htons(get_u16(frm)));
		uint16_t plen = btohs(htons(get_u16(frm)));

		p_indent(level, frm);

		printf("System %s: device hci%d type 0x%2.2x plen %d\n",
			frm->in ? "event" : "command", device, type, plen);

		raw_dump(level, frm);
		return;
	}

	if (get_manufacturer() == 12) {
		bpa_dump(level, frm);
		return;
	}

	p_indent(level, frm);
	printf("Vendor data: len %d\n", frm->len);
	raw_dump(level, frm);
}

void hci_dump(int level, struct frame *frm)
{
	uint8_t type = *(uint8_t *)frm->ptr;

	frm->ptr++; frm->len--;

	switch (type) {
	case HCI_COMMAND_PKT:
		command_dump(level, frm);
		break;

	case HCI_EVENT_PKT:
		event_dump(level, frm);
		break;

	case HCI_ACLDATA_PKT:
		acl_dump(level, frm);
		break;

	case HCI_SCODATA_PKT:
		sco_dump(level, frm);
		break;

	case HCI_VENDOR_PKT:
		vendor_dump(level, frm);
		break;

	default:
		if (p_filter(FILT_HCI))
			break;

		p_indent(level, frm);
		printf("Unknown: type 0x%2.2x len %d\n", type, frm->len);
		raw_dump(level, frm);
		break;
	}
}
