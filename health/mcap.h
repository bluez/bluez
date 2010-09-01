/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#ifndef __MCAP_H
#define __MCAP_H

#ifdef __cplusplus
extern "C" {
#endif

/* maximum transmission unit for channels */
#define MCAP_CC_MTU	48
#define MCAP_DC_MTU	L2CAP_DEFAULT_MTU

/* MCAP Standard Op Codes */
#define MCAP_ERROR_RSP			0x00
#define MCAP_MD_CREATE_MDL_REQ		0x01
#define MCAP_MD_CREATE_MDL_RSP		0x02
#define MCAP_MD_RECONNECT_MDL_REQ	0x03
#define MCAP_MD_RECONNECT_MDL_RSP	0x04
#define MCAP_MD_ABORT_MDL_REQ		0x05
#define MCAP_MD_ABORT_MDL_RSP		0x06
#define MCAP_MD_DELETE_MDL_REQ		0x07
#define MCAP_MD_DELETE_MDL_RSP		0x08

/* MCAP Clock Sync Op Codes */
#define MCAP_MD_SYNC_CAP_REQ		0x11
#define MCAP_MD_SYNC_CAP_RSP		0x12
#define MCAP_MD_SYNC_SET_REQ		0x13
#define MCAP_MD_SYNC_SET_RSP		0x14
#define MCAP_MD_SYNC_INFO_IND		0x15

/* MCAP Response codes */
#define MCAP_SUCCESS			0x00
#define MCAP_INVALID_OP_CODE		0x01
#define MCAP_INVALID_PARAM_VALUE	0x02
#define MCAP_INVALID_MDEP		0x03
#define MCAP_MDEP_BUSY			0x04
#define MCAP_INVALID_MDL		0x05
#define MCAP_MDL_BUSY			0x06
#define MCAP_INVALID_OPERATION		0x07
#define MCAP_RESOURCE_UNAVAILABLE	0x08
#define MCAP_UNSPECIFIED_ERROR		0x09
#define MCAP_REQUEST_NOT_SUPPORTED	0x0A
#define MCAP_CONFIGURATION_REJECTED	0x0B

/* MDL IDs */
#define MCAP_MDLID_RESERVED		0x0000
#define MCAP_MDLID_INITIAL		0x0001
#define MCAP_MDLID_FINAL		0xFEFF
#define MCAP_ALL_MDLIDS			0xFFFF

/*
 * MCAP Response Packet Format
 */

typedef struct {
	uint8_t		op;
	uint8_t		rc;
	uint16_t	mdl;
} __attribute__ ((packed)) mcap_rsp;

#ifdef __cplusplus
}
#endif

#endif /* __MCAP_H */
