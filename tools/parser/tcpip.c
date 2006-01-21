/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "parser.h"

void arp_dump(int level, struct frame *frm)
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

void ip_dump(int level, struct frame *frm)
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
