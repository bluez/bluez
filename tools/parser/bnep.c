/*
 *
 *  Bluetooth packet analyzer - BNEP parser
 *
 *  Copyright (C) 2002-2003  Takashi Sasai <sasai@sm.sony.co.jp>
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "parser.h"

#define PAYLOAD_RAW_DUMP

/* BNEP Type */
#define BNEP_GENERAL_ETHERNET			0x00
#define BNEP_CONTROL				0x01
#define BNEP_COMPRESSED_ETHERNET		0x02
#define BNEP_COMPRESSED_ETHERNET_SOURCE_ONLY	0x03
#define BNEP_COMPRESSED_ETHERNET_DEST_ONLY	0x04

/* BNEP Control Packet Type */
#define BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD	0x00
#define BNEP_SETUP_CONNECTION_REQUEST_MSG	0x01
#define BNEP_SETUP_CONNECTION_RESPONSE_MSG	0x02
#define BNEP_FILTER_NET_TYPE_SET_MSG		0x03
#define BNEP_FILTER_NET_TYPE_RESPONSE_MSG	0x04
#define BNEP_FILTER_MULT_ADDR_SET_MSG		0x05
#define BNEP_FILTER_MULT_ADDR_RESPONSE_MSG	0x06

/* BNEP Extension Type */
#define BNEP_EXTENSION_CONTROL			0x00

static char *get_macaddr(struct frame *frm)
{
	static char str[20];
	unsigned char *buf = frm->ptr;

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
	frm->ptr += 6;
	frm->len -= 6;
	return str;
}

static void bnep_control(int level, struct frame *frm, int header_length)
{
	uint8_t uuid_size;
	int i, length;
	char *s;
	uint32_t uuid = 0;
	uint8_t type = get_u8(frm);

	p_indent(++level, frm);
	switch (type) {
	case BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD:
		printf("Not Understood(0x%02x) type 0x%02x\n", type, get_u8(frm));
		break;

	case BNEP_SETUP_CONNECTION_REQUEST_MSG:
		uuid_size = get_u8(frm);
		printf("Setup Req(0x%02x) size 0x%02x ", type, uuid_size);
		switch (uuid_size) {
		case 2:
			uuid = get_u16(frm);
			printf("dst 0x%x", uuid);
			if ((s = get_uuid_name(uuid)) != 0)
				printf("(%s)", s);
			uuid = get_u16(frm);
			printf(" src 0x%x", uuid);
			if ((s = get_uuid_name(uuid)) != 0)
				printf("(%s)", s);
			printf("\n");
			break;
		case 4:
			uuid = get_u32(frm);
			printf("dst 0x%x", uuid);
			if ((s = get_uuid_name(uuid)) != 0)
				printf("(%s)", s);
			uuid = get_u32(frm);
			printf(" src 0x%x", uuid);
			if ((s = get_uuid_name(uuid)) != 0)
				printf("(%s)", s);
			printf("\n");
			break;
		case 16:
			uuid = get_u32(frm);
			printf("dst 0x%x", uuid);
			if ((s = get_uuid_name(uuid)) != 0)
				printf("(%s)", s);
			frm->ptr += 12;
			frm->len -= 12;
			uuid = get_u32(frm);
			printf(" src 0x%x", uuid);
			if ((s = get_uuid_name(uuid)) != 0)
				printf("(%s)", s);
			printf("\n");
			frm->ptr += 12;
			frm->len -= 12;
			break;
		default:
			frm->ptr += (uuid_size * 2);
			frm->len -= (uuid_size * 2);
			break;
		}
		break;

	case BNEP_SETUP_CONNECTION_RESPONSE_MSG:
		printf("Setup Rsp(0x%02x) res 0x%04x\n", type, get_u16(frm));
		break;

	case BNEP_FILTER_NET_TYPE_SET_MSG:
		length = get_u16(frm);
		printf("Filter NetType Set(0x%02x) len 0x%04x\n", type, length);
		for (i = 0; i < length / 4; i++) {
			p_indent(level + 1, frm);
			printf("0x%04x - ", get_u16(frm));
			printf("0x%04x\n", get_u16(frm));
		}
		break;

	case BNEP_FILTER_NET_TYPE_RESPONSE_MSG:
		printf("Filter NetType Rsp(0x%02x) res 0x%04x\n", type, get_u16(frm));
		break;

	case BNEP_FILTER_MULT_ADDR_SET_MSG:
		length = get_u16(frm);
		printf("Filter MultAddr Set(0x%02x) len 0x%04x\n", type, length);
		for (i = 0; i < length / 12; i++) {
			p_indent(level + 1, frm);
			printf("%s - ", get_macaddr(frm));
			printf("%s\n", get_macaddr(frm));
		}
		break;

	case BNEP_FILTER_MULT_ADDR_RESPONSE_MSG:
		printf("Filter MultAddr Rsp(0x%02x) res 0x%04x\n", type, get_u16(frm));
		break;

	default:
		printf("Unknown control type(0x%02x)\n", type);
		raw_ndump(level + 1, frm, header_length - 1);
		frm->ptr += header_length - 1;
		frm->len -= header_length - 1;
		return;
	}
}

static void bnep_eval_extension(int level, struct frame *frm)
{
	uint8_t type = get_u8(frm);
	int extension = type & 0x80;
	uint8_t length = get_u8(frm);

	p_indent(level, frm);
	switch (type & 0x7f) {
	case BNEP_EXTENSION_CONTROL:
		printf("Ext Control(0x%02x|%s) len 0x%02x\n", type & 0x7f, extension ? "1" : "0", length);
		bnep_control(level, frm, length);
		break;

	default:
		printf("Ext Unknown(0x%02x|%s) len 0x%02x\n", type & 0x7f, extension ? "1" : "0", length);
		raw_ndump(level + 1, frm, length);
		frm->ptr += length;
		frm->len -= length;
	}

	if (extension) {
		bnep_eval_extension(level, frm);
	}
}

#ifndef PAYLOAD_RAW_DUMP

static void arp_dump(int level, struct frame *frm)
{
	int i;
	struct ether_arp *arp = (struct ether_arp *) frm->ptr;

	printf("Src ");
	for (i = 0; i < 5; i++)
		printf("%02x:", arp->arp_sha[i]);
	printf("%02x", arp->arp_sha[5]);
	printf("(%s) ", inet_ntoa(*(struct in_addr *) &arp->arp_spa));
	printf("Tgt ");
	for (i = 0; i < 5; i++)
		printf("%02x:", arp->arp_tha[i]);
	printf("%02x", arp->arp_tha[5]);
	printf("(%s)\n", inet_ntoa(*(struct in_addr *) &arp->arp_tpa));
	frm->ptr += sizeof(struct ether_arp);
	frm->len -= sizeof(struct ether_arp);
	raw_dump(level, frm);		// not needed.
}

static void ip_dump(int level, struct frame *frm)
{
	struct ip *ip = (struct ip *) (frm->ptr);
	int len = ip->ip_hl << 2;
	frm->ptr += len;
	frm->len -= len;

	printf("src %s ", inet_ntoa(*(struct in_addr *) &(ip->ip_src)));
	printf("dst %s\n", inet_ntoa(*(struct in_addr *) &(ip->ip_dst)));
	p_indent(++level, frm);

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("TCP:\n");
		raw_dump(level, frm);
		break;

	case IPPROTO_UDP:
		printf("UDP:\n");
		raw_dump(level, frm);
		break;

	case IPPROTO_ICMP:
		printf("ICMP:\n");
		raw_dump(level, frm);
		break;

	default:
		printf("Unknown Protocol: 0x%02x\n", ip->ip_p);
		raw_dump(level, frm);
	}
}

#endif

void bnep_dump(int level, struct frame *frm)
{
	uint8_t type = get_u8(frm);
	uint16_t proto = 0x0000;
	int extension = type & 0x80;

	p_indent(level, frm);

	switch (type & 0x7f) {
	case BNEP_CONTROL:
		printf("BNEP: Control(0x%02x|%s)\n", type & 0x7f, extension ? "1" : "0");
		bnep_control(level, frm, -1);
		break;

	case BNEP_COMPRESSED_ETHERNET:
		printf("BNEP: Compressed(0x%02x|%s)\n", type & 0x7f, extension ? "1" : "0");
		p_indent(++level, frm);
		proto = get_u16(frm);
		printf("[proto 0x%04x]\n", proto);
		break;

	case BNEP_GENERAL_ETHERNET:
		printf("BNEP: General ethernet(0x%02x|%s)\n", type & 0x7f, extension ? "1" : "0");
		p_indent(++level, frm);
		printf("dst %s ", get_macaddr(frm));
		printf("src %s ", get_macaddr(frm));
		proto = get_u16(frm);
		printf("[proto 0x%04x]\n", proto);
		break;

	case BNEP_COMPRESSED_ETHERNET_DEST_ONLY:
		printf("BNEP: Compressed DestOnly(0x%02x|%s)\n", type & 0x7f, extension ? "1" : "0");
		p_indent(++level, frm);
		printf("dst %s ", get_macaddr(frm));
		proto = get_u16(frm);
		printf("[proto 0x%04x]\n", proto);
		break;

	case BNEP_COMPRESSED_ETHERNET_SOURCE_ONLY:
		printf("BNEP: Compressed SrcOnly(0x%02x|%s)\n", type & 0x7f, extension ? "1" : "0");
		p_indent(++level, frm);
		printf("src %s ", get_macaddr(frm));
		proto = get_u16(frm);
		printf("[proto 0x%04x]\n", proto);
		break;

	default:
		printf("(Unknown packet type)\n");
		return;
	}

	/* Extension info */
	if (extension)
		bnep_eval_extension(++level, frm);

	/* Control packet => No payload info */
	if ((type & 0x7f) == BNEP_CONTROL)
		return;

	if (proto == 0x8100) { /* 802.1p */
		p_indent(level, frm);
		printf("802.1p Header: 0x%04x ", get_u16(frm));
		proto = get_u16(frm);
		printf("[proto 0x%04x]\n", proto);
	}

#ifdef PAYLOAD_RAW_DUMP
	raw_dump(level, frm);
#else
	switch (proto) {
	case ETHERTYPE_ARP:
		p_indent(++level, frm);
		printf("ARP: ");
		arp_dump(level, frm);
		break;

	case ETHERTYPE_REVARP:
		p_indent(++level, frm);
		printf("RARP: ");
		arp_dump(level, frm);
		break;

	case ETHERTYPE_IP:
		p_indent(++level, frm);
		printf("IP: ");
		ip_dump(level, frm);
		break;

	default:
		raw_dump(level, frm);
	}
#endif
}
