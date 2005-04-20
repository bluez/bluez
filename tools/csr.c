/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2005  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "csr.h"

static struct {
	uint16_t id;
	char *str;
} csr_map[] = {
	{   66, "HCI 9.8"	},
	{   97, "HCI 10.3"	},
	{  101, "HCI 10.5"	},
	{  111,	"HCI 11.0"	},
	{  112,	"HCI 11.1"	},
	{  114,	"HCI 11.2"	},
	{  115,	"HCI 11.3"	},
	{  117,	"HCI 12.0"	},
	{  119,	"HCI 12.1"	},
	{  133,	"HCI 12.2"	},
	{  134,	"HCI 12.3"	},
	{  162,	"HCI 12.4"	},
	{  165,	"HCI 12.5"	},
	{  169,	"HCI 12.6"	},
	{  188,	"HCI 12.7"	},
	{  218,	"HCI 12.8"	},
	{  283,	"HCI 12.9"	},
	{  203,	"HCI 13.2"	},
	{  204,	"HCI 13.2"	},
	{  210,	"HCI 13.3"	},
	{  211,	"HCI 13.3"	},
	{  213,	"HCI 13.4"	},
	{  214,	"HCI 13.4"	},
	{  225,	"HCI 13.5"	},
	{  226,	"HCI 13.5"	},
	{  237,	"HCI 13.6"	},
	{  238,	"HCI 13.6"	},
	{  242,	"HCI 14.0"	},
	{  243,	"HCI 14.0"	},
	{  244,	"HCI 14.0"	},
	{  245,	"HCI 14.0"	},
	{  254,	"HCI 13.7"	},
	{  255,	"HCI 13.7"	},
	{  264,	"HCI 14.1"	},
	{  265,	"HCI 14.1"	},
	{  267,	"HCI 14.2"	},
	{  268,	"HCI 14.2"	},
	{  272,	"HCI 14.3"	},
	{  273,	"HCI 14.3"	},
	{  274,	"HCI 13.8"	},
	{  275,	"HCI 13.8"	},
	{  286,	"HCI 13.9"	},
	{  287,	"HCI 13.9"	},
	{  309,	"HCI 13.10"	},
	{  310,	"HCI 13.10"	},
	{  313,	"HCI 14.4"	},
	{  314,	"HCI 14.4"	},
	{  323,	"HCI 14.5"	},
	{  324,	"HCI 14.5"	},
	{  336,	"HCI 14.6"	},
	{  337,	"HCI 14.6"	},
	{  351,	"HCI 13.11"	},
	{  352,	"HCI 13.11"	},
	{  362,	"HCI 15.0"	},
	{  363,	"HCI 15.0"	},
	{  364,	"HCI 15.0"	},
	{  365,	"HCI 15.0"	},
	{  373,	"HCI 14.7"	},
	{  374,	"HCI 14.7"	},
	{  379,	"HCI 15.1"	},
	{  380,	"HCI 15.1"	},
	{  381,	"HCI 15.1"	},
	{  382,	"HCI 15.1"	},
	{  392,	"HCI 15.2"	},
	{  393,	"HCI 15.2"	},
	{  394,	"HCI 15.2"	},
	{  395,	"HCI 15.2"	},
	{  436,	"HCI 16.0"	},
	{  437,	"HCI 16.0"	},
	{  438,	"HCI 16.0"	},
	{  439,	"HCI 16.0"	},
	{  443,	"HCI 15.3"	},
	{  444,	"HCI 15.3"	},
	{  465,	"HCI 16.1"	},
	{  466,	"HCI 16.1"	},
	{  467,	"HCI 16.1"	},
	{  468,	"HCI 16.1"	},
	{  487,	"HCI 14.8"	},
	{  488,	"HCI 14.8"	},
	{  492,	"HCI 16.2"	},
	{  493,	"HCI 16.2"	},
	{  495,	"HCI 16.2"	},
	{  496,	"HCI 16.2"	},
	{  502,	"HCI 16.1.1"	},
	{  503,	"HCI 16.1.1"	},
	{  504,	"HCI 16.1.1"	},
	{  505,	"HCI 16.1.1"	},
	{  506,	"HCI 16.1.2"	},
	{  507,	"HCI 16.1.2"	},
	{  508,	"HCI 16.1.2"	},
	{  509,	"HCI 16.1.2"	},
	{  516,	"HCI 16.3"	},
	{  517,	"HCI 16.3"	},
	{  518,	"HCI 16.3"	},
	{  519,	"HCI 16.3"	},
	{  523,	"HCI 16.4"	},
	{  524,	"HCI 16.4"	},
	{  525,	"HCI 16.4"	},
	{  526,	"HCI 16.4"	},
	{  553,	"HCI 15.3"	},
	{  554,	"HCI 15.3"	},
	{  562,	"HCI 16.5"	},
	{  563,	"HCI 16.5"	},
	{  564,	"HCI 16.5"	},
	{  565,	"HCI 16.5"	},
	{  593,	"HCI 17.0"	},
	{  594,	"HCI 17.0"	},
	{  595,	"HCI 17.0"	},
	{  599,	"HCI 17.0"	},
	{  600,	"HCI 17.0"	},
	{  608,	"HCI 13.10.1"	},
	{  609,	"HCI 13.10.1"	},
	{  613,	"HCI 17.1"	},
	{  614,	"HCI 17.1"	},
	{  615,	"HCI 17.1"	},
	{  616,	"HCI 17.1"	},
	{  618,	"HCI 17.1"	},
	{  624,	"HCI 17.2"	},
	{  625,	"HCI 17.2"	},
	{  626,	"HCI 17.2"	},
	{  627,	"HCI 17.2"	},
	{  637,	"HCI 16.6"	},
	{  638,	"HCI 16.6"	},
	{  639,	"HCI 16.6"	},
	{  640,	"HCI 16.6"	},
	{  642,	"HCI 13.10.2"	},
	{  643,	"HCI 13.10.2"	},
	{  644,	"HCI 13.10.3"	},
	{  645,	"HCI 13.10.3"	},
	{  668,	"HCI 13.10.4"	},
	{  669,	"HCI 13.10.4"	},
	{  681,	"HCI 16.7"	},
	{  682,	"HCI 16.7"	},
	{  683,	"HCI 16.7"	},
	{  684,	"HCI 16.7"	},
	{  704,	"HCI 16.8"	},
	{  718,	"HCI 16.4.1"	},
	{  719,	"HCI 16.4.1"	},
	{  720,	"HCI 16.4.1"	},
	{  721,	"HCI 16.4.1"	},
	{  722,	"HCI 16.7.1"	},
	{  723,	"HCI 16.7.1"	},
	{  724,	"HCI 16.7.1"	},
	{  725,	"HCI 16.7.1"	},
	{  731,	"HCI 16.7.2"	},
	{  732,	"HCI 16.7.2"	},
	{  733,	"HCI 16.7.2"	},
	{  734,	"HCI 16.7.2"	},
	{  735,	"HCI 16.4.2"	},
	{  736,	"HCI 16.4.2"	},
	{  737,	"HCI 16.4.2"	},
	{  738,	"HCI 16.4.2"	},
	{  750,	"HCI 16.7.3"	},
	{  751,	"HCI 16.7.3"	},
	{  752,	"HCI 16.7.3"	},
	{  753,	"HCI 16.7.3"	},
	{  760,	"HCI 16.7.4"	},
	{  761,	"HCI 16.7.4"	},
	{  762,	"HCI 16.7.4"	},
	{  763,	"HCI 16.7.4"	},
	{  770,	"HCI 16.9"	},
	{  771,	"HCI 16.9"	},
	{  772,	"HCI 16.9"	},
	{  773,	"HCI 16.9"	},
	{  774,	"HCI 17.3"	},
	{  775,	"HCI 17.3"	},
	{  776,	"HCI 17.3"	},
	{  777,	"HCI 17.3"	},
	{  781,	"HCI 16.7.5"	},
	{  786,	"HCI 16.10"	},
	{  787,	"HCI 16.10"	},
	{  788,	"HCI 16.10"	},
	{  789,	"HCI 16.10"	},
	{  791,	"HCI 16.4.3"	},
	{  792,	"HCI 16.4.3"	},
	{  793,	"HCI 16.4.3"	},
	{  794,	"HCI 16.4.3"	},
	{  798,	"HCI 16.11"	},
	{  799,	"HCI 16.11"	},
	{  800,	"HCI 16.11"	},
	{  801,	"HCI 16.11"	},
	{  806,	"HCI 16.7.5"	},
	{  807,	"HCI 16.12"	},
	{  808,	"HCI 16.12"	},
	{  809,	"HCI 16.12"	},
	{  810,	"HCI 16.12"	},
	{  817,	"HCI 16.13"	},
	{  818,	"HCI 16.13"	},
	{  819,	"HCI 16.13"	},
	{  820,	"HCI 16.13"	},
	{  823,	"HCI 13.10.5"	},
	{  824,	"HCI 13.10.5"	},
	{  826,	"HCI 16.14"	},
	{  827,	"HCI 16.14"	},
	{  828,	"HCI 16.14"	},
	{  829,	"HCI 16.14"	},
	{  843,	"HCI 17.3.1"	},
	{  856,	"HCI 17.3.2"	},
	{  857,	"HCI 17.3.2"	},
	{  858,	"HCI 17.3.2"	},
	{ 1120, "HCI 17.11"	},
	{ 1168, "HCI 18.1"	},
	{ 1169, "HCI 18.1"	},
	{ 1241, "HCI 18.x"	},
	{ 1298, "HCI 18.2"	},
	{ 1354, "HCI 18.2"	},
	{ 1392, "HCI 18.2"	},
	{ 1393, "HCI 18.2"	},
	{ 1501, "HCI 18.2"	},
	{ 1503, "HCI 18.2"	},
	{ 1504, "HCI 18.2"	},
	{ 1505, "HCI 18.2"	},
	{ 1506, "HCI 18.2"	},
	{ 1520, "HCI 18.2"	},
	{ 1586, "HCI 18.2"	},
	{ 1591, "HCI 18.2"	},
	{ 1592, "HCI 18.2"	},
	{ 1733, "HCI 18.3"	},
	{ 1734, "HCI 18.3"	},
	{ 1735, "HCI 18.3"	},
	{ 1737, "HCI 18.3"	},
	{ 1915, "HCI 19.2"	},
	{ 1916, "HCI 19.2"	},
	{ 1958, "HCI 19.2"	},
	{ 1981, "HCI 19.2"	},
	{ 1989, "HCI 18.4"	},
	{  195, "Sniff 1 (2001-11-27)"	},
	{  220, "Sniff 2 (2002-01-03)"	},
	{  269, "Sniff 3 (2002-02-22)"	},
	{  270, "Sniff 4 (2002-02-26)"	},
	{  284, "Sniff 5 (2002-03-12)"	},
	{  292, "Sniff 6 (2002-03-20)"	},
	{  305, "Sniff 7 (2002-04-12)"	},
	{  306, "Sniff 8 (2002-04-12)"	},
	{  343, "Sniff 9 (2002-05-02)"	},
	{  346, "Sniff 10 (2002-05-03)"	},
	{  355, "Sniff 11 (2002-05-16)" },
	{  256, "Sniff 11 (2002-05-16)"	},
	{  390, "Sniff 12 (2002-06-26)"	},
	{  450, "Sniff 13 (2002-08-16)"	},
	{  451, "Sniff 13 (2002-08-16)"	},
	{  533, "Sniff 14 (2002-10-11)"	},
	{  580, "Sniff 15 (2002-11-14)"	},
	{  623, "Sniff 16 (2002-12-12)"	},
	{  678, "Sniff 17 (2003-01-29)"	},
	{  847, "Sniff 18 (2003-04-17)"	},
	{  876, "Sniff 19 (2003-06-10)"	},
	{  997, "Sniff 22 (2003-09-05)"	},
	{ 1027, "Sniff 23 (2003-10-03)"	},
	{ 1029, "Sniff 24 (2003-10-03)"	},
	{ 1112, "Sniff 25 (2003-12-03)"	},
	{ 1113, "Sniff 25 (2003-12-03)"	},
	{ 1133, "Sniff 26 (2003-12-18)"	},
	{ 1134, "Sniff 26 (2003-12-18)"	},
	{ 1223, "Sniff 27 (2004-03-08)"	},
	{ 1224, "Sniff 27 (2004-03-08)"	},
	{ 1319, "Sniff 31 (2004-04-22)"	},
	{ 1320, "Sniff 31 (2004-04-22)"	},
	{ 1427, "Sniff 34 (2004-06-16)"	},
	{ 1508, "Sniff 35 (2004-07-19)"	},
	{ 1509, "Sniff 35 (2004-07-19)"	},
	{ 1587, "Sniff 36 (2004-08-18)"	},
	{ 1588, "Sniff 36 (2004-08-18)"	},
	{ 1641, "Sniff 37 (2004-09-16)"	},
	{ 1642, "Sniff 37 (2004-09-16)"	},
	{ 1699, "Sniff 38 (2004-10-07)"	},
	{ 1700, "Sniff 38 (2004-10-07)"	},
	{ 1752, "Sniff 39 (2004-11-02)"	},
	{ 1753, "Sniff 39 (2004-11-02)"	},
	{ 1759, "Sniff 40 (2004-11-03)"	},
	{ 1760, "Sniff 40 (2004-11-03)"	},
	{ 1761, "Sniff 40 (2004-11-03)"	},
	{    0, }
};

char *csr_buildidtostr(uint16_t id)
{
	static char str[12];
	int i;

	for (i = 0; csr_map[i].id; i++)
		if (csr_map[i].id == id)
			return csr_map[i].str;

	snprintf(str, 11, "Build %d", id);
	return str;
}

char *csr_chipvertostr(uint16_t ver, uint16_t rev)
{
	switch (ver) {
	case 0x00:
		return "BlueCore01a";
	case 0x01:
		if (rev == 0x64)
			return "BlueCore01b (ES)";
		else
			return "BlueCore01b";
	case 0x02:
		switch (rev) {
		case 0x89:
			return "BlueCore02-External (ES2)";
		case 0x8a:
			return "BlueCore02-External";
		case 0x28:
			return "BlueCore02-ROM/Audio/Flash";
		default:
			return "BlueCore02";
		}
	case 0x03:
		switch (rev) {
		case 0x43:
			return "BlueCore3-MM";
		case 0x15:
			return "BlueCore3-ROM";
		case 0xe2:
			return "BlueCore3-Flash";
		case 0x26:
			return "BlueCore4-External";
		case 0x30:
			return "BlueCore4-ROM";
		default:
			return "BlueCore3 or BlueCore4";
		}
	default:
		return "Unknown";
	}
}

char *csr_pskeytostr(uint16_t pskey)
{
	switch (pskey) {
	case CSR_PSKEY_HOSTIO_MAP_SCO_PCM:
		return "Map SCO over PCM";
	case CSR_PSKEY_UART_BAUDRATE:
		return "UART Baud rate";
	case CSR_PSKEY_HOST_INTERFACE:
		return "Host interface";
	case CSR_PSKEY_USB_VENDOR_ID:
		return "USB vendor identifier";
	case CSR_PSKEY_USB_PRODUCT_ID:
		return "USB product identifier";
	case CSR_PSKEY_USB_DFU_PRODUCT_ID:
		return "USB DFU product ID";
	case CSR_PSKEY_INITIAL_BOOTMODE:
		return "Initial device bootmode";
	default:
		return "Unknown";
	}
}

int csr_read_varid_uint16(int dd, uint16_t seqnum, uint16_t varid, uint16_t *value)
{
	unsigned char cmd[] = { 0x00, 0x00, 0x09, 0x00,
				seqnum & 0xff, seqnum >> 8, varid & 0xff, varid >> 8, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	unsigned char cp[254], rp[254];
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp[0] = 0xc2;
	memcpy(cp + 1, cmd, sizeof(cmd));

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = 0x00;
	rq.event  = EVT_VENDOR;
	rq.cparam = cp;
	rq.clen   = sizeof(cmd) + 1;
	rq.rparam = rp;
	rq.rlen   = sizeof(rp);

	if (hci_send_req(dd, &rq, 2000) < 0)
		return -1;

	if (rp[0] != 0xc2) {
		errno = EIO;
		return -1;
	}

	if ((rp[9] + (rp[10] << 8)) != 0) {
		errno = ENXIO;
		return -1;
	}

	*value = rp[11] + (rp[12] << 8);

	return 0;
}

int csr_read_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t *value)
{
	unsigned char cmd[] = { 0x00, 0x00, 0x09, 0x00,
				seqnum & 0xff, seqnum >> 8, 0x03, 0x70, 0x00, 0x00,
				pskey & 0xff, pskey >> 8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

	unsigned char cp[254], rp[254];
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp[0] = 0xc2;
	memcpy(cp + 1, cmd, sizeof(cmd));

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = 0x00;
	rq.event  = EVT_VENDOR;
	rq.cparam = cp;
	rq.clen   = sizeof(cmd) + 1;
	rq.rparam = rp;
	rq.rlen   = sizeof(rp);

	if (hci_send_req(dd, &rq, 2000) < 0)
		return -1;

	if (rp[0] != 0xc2) {
		errno = EIO;
		return -1;
	}

	if ((rp[9] + (rp[10] << 8)) != 0) {
		errno = ENXIO;
		return -1;
	}

	*value = rp[17] + (rp[18] << 8);

	return 0;
}

int csr_write_pskey_uint16(int dd, uint16_t seqnum, uint16_t pskey, uint16_t value)
{
	unsigned char cmd[] = { 0x02, 0x00, 0x09, 0x00,
				seqnum & 0xff, seqnum >> 8, 0x03, 0x70, 0x00, 0x00,
				pskey & 0xff, pskey >> 8, 0x01, 0x00, 0x00, 0x00,
				value & 0xff, value >> 8 };

	unsigned char cp[254], rp[254];
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp[0] = 0xc2;
	memcpy(cp + 1, cmd, sizeof(cmd));

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = 0x00;
	rq.event  = EVT_VENDOR;
	rq.cparam = cp;
	rq.clen   = sizeof(cmd) + 1;
	rq.rparam = rp;
	rq.rlen   = sizeof(rp);

	if (hci_send_req(dd, &rq, 2000) < 0)
		return -1;

	if (rp[0] != 0xc2) {
		errno = EIO;
		return -1;
	}

	if ((rp[9] + (rp[10] << 8)) != 0) {
		errno = ENXIO;
		return -1;
	}

	return 0;
}
