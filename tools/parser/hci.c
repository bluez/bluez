/*
 *
 *  Bluetooth packet analyzer - HCI parser
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  $Id$
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "parser.h"

static uint16_t manufacturer = DEFAULT_COMPID;

static inline uint16_t get_manufacturer(void)
{
	return (manufacturer == DEFAULT_COMPID ? parser.defcompid : manufacturer);
}

static char *event_str[] = {
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
	"Synchronous Connect Changed"
};
#define EVENT_NUM 43

static char *cmd_linkctl_str[] = {
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
	"Reject Synchronous Connection"
};
#define CMD_LINKCTL_NUM 42

static char *cmd_linkpol_str[] = {
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
	"Flow Specification"
};
#define CMD_LINKPOL_NUM 16

static char *cmd_hostctl_str[] = {
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
	"Write AFH Channel Assessment Mode"
};
#define CMD_HOSTCTL_NUM 73

static char *cmd_info_str[] = {
	"Unknown",
	"Read Local Version Information",
	"Read Local Supported Commands",
	"Read Local Supported Features",
	"Read Local Extended Features",
	"Read Buffer Size",
	"Unknown",
	"Read Country Code",
	"Unknown",
	"Read BD ADDR"
};
#define CMD_INFO_NUM 9

static char *cmd_status_str[] = {
	"Unknown",
	"Read Failed Contact Counter",
	"Reset Failed Contact Counter",
	"Read Link Quality",
	"Unknown",
	"Read RSSI",
	"Read AFH Channel Map",
	"Read Clock"
};
#define CMD_STATUS_NUM 7

static char *error_code_str[] = {
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
	"Remote User Teminated Connection",
	"Remote Device Terminated Connection due to Low Resources",
	"Remote Device Terminated Connection due to Power Off",
	"Connection Terminated by Local Host",
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
	"Pairing with Unit Key Not Allowed",
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
	"Role Switch Failed"
};
#define ERROR_CODE_NUM 53

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

	switch (ogf) {
	case OGF_HOST_CTL:
		switch (ocf) {
		case OCF_READ_LOCAL_NAME:
		case OCF_READ_PAGE_TIMEOUT:
		case OCF_READ_PAGE_ACTIVITY:
		case OCF_READ_INQ_ACTIVITY:
		case OCF_READ_CLASS_OF_DEV:
		case OCF_READ_VOICE_SETTING:
		case OCF_READ_TRANSMIT_POWER_LEVEL:
		case OCF_READ_LINK_SUPERVISION_TIMEOUT:
		case OCF_READ_CURRENT_IAC_LAP:
		case OCF_SET_AFH_CLASSIFICATION:
		case OCF_READ_INQUIRY_MODE:
		case OCF_READ_AFH_MODE:
			status_response_dump(level, frm);
			break;

		default:
			raw_dump(level, frm);
			break;
		}
		break;

	case OGF_INFO_PARAM:
		switch (ocf) {
		case OCF_READ_LOCAL_VERSION:
		case OCF_READ_LOCAL_FEATURES:
		case OCF_READ_BUFFER_SIZE:
		case OCF_READ_BD_ADDR:
			status_response_dump(level, frm);
			break;

		default:
			raw_dump(level, frm);
			break;
		}
		break;

	case OGF_STATUS_PARAM:
		switch (ocf) {
		case OCF_READ_FAILED_CONTACT_COUNTER:
		case OCF_RESET_FAILED_CONTACT_COUNTER:
		case OCF_READ_LINK_QUALITY:
		case OCF_READ_RSSI:
		case OCF_READ_AFH_MAP:
		case OCF_READ_CLOCK:
			status_response_dump(level, frm);
			break;

		default:
			raw_dump(level, frm);
			break;
		}
		break;

	default:
		raw_dump(level, frm);
		break;
	}
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

static inline void inq_result_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	int i;

	for (i = 0; i < num; i++) {
		inquiry_info *info = frm->ptr;
		char addr[18];

		ba2str(&info->bdaddr, addr);

		p_indent(level, frm);
		printf("bdaddr %s clkoffset 0x%4.4x class 0x%2.2x%2.2x%2.2x\n",
			addr, info->clock_offset, info->dev_class[2],
			info->dev_class[1], info->dev_class[0]);

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

static inline void inq_result_with_rssi_dump(int level, struct frame *frm)
{
	uint8_t num = get_u8(frm);
	int i;

	for (i = 0; i < num; i++) {
		inquiry_info_with_rssi *info = frm->ptr;
		char addr[18];

		p_indent(level, frm);

		ba2str(&info->bdaddr, addr);
		printf("bdaddr %s clkoffset 0x%4.4x class 0x%2.2x%2.2x%2.2x rssi %d\n",
			addr, info->clock_offset, info->dev_class[2],
			info->dev_class[1], info->dev_class[0], info->rssi);

		frm->ptr += INQUIRY_INFO_WITH_RSSI_SIZE;
		frm->len -= INQUIRY_INFO_WITH_RSSI_SIZE;
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

	if (!(parser.flags & DUMP_VERBOSE)) {
		raw_dump(level, frm);
		return;
	}

	switch (event) {
	case EVT_CMD_COMPLETE:
		cmd_complete_dump(level + 1, frm);
		break;

	case EVT_CMD_STATUS:
		cmd_status_dump(level + 1, frm);
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

	case EVT_REMOTE_NAME_REQ_COMPLETE:
		remote_name_req_complete_dump(level + 1, frm);
		break;

	case EVT_ENCRYPT_CHANGE:
		encrypt_change_dump(level + 1, frm);
		break;

	case EVT_INQUIRY_RESULT_WITH_RSSI:
		inq_result_with_rssi_dump(level + 1, frm);
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
