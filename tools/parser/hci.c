/* 
	HCIDump - HCI packet analyzer	
	Copyright (C) 2000-2001 Maxim Krasnyansky <maxk@qualcomm.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as
	published by the Free Software Foundation;

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
	IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
	OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
	RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
	NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
	USE OR PERFORMANCE OF THIS SOFTWARE.

	ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
	TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/

/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

#include "parser.h"

static inline void command_dump(void *ptr, int len)
{
	hci_command_hdr *hdr = ptr;
	__u16 opcode = __le16_to_cpu(hdr->opcode);

	ptr += HCI_COMMAND_HDR_SIZE;
	len -= HCI_COMMAND_HDR_SIZE;

	printf("Command: ogf 0x%x ocf 0x%x plen %d\n",
		cmd_opcode_ogf(opcode), cmd_opcode_ocf(opcode), hdr->plen);
	raw_dump(1, ptr, len);
}

static inline void event_dump(void *ptr, int len)
{
	hci_event_hdr *hdr = ptr;
	
	ptr += HCI_EVENT_HDR_SIZE;
	len -= HCI_EVENT_HDR_SIZE;

	printf("Event: code 0x%2.2x plen %d\n", hdr->evt, hdr->plen);
	raw_dump(1, ptr, len);
}

static inline void acl_dump(void *ptr, int len)
{
	hci_acl_hdr *hdr = ptr;
	__u16 handle = __le16_to_cpu(hdr->handle);
	__u16 dlen = __le16_to_cpu(hdr->dlen);

	printf("ACL data: handle 0x%x flags 0x%x dlen %d\n",
		acl_handle(handle), acl_flags(handle), dlen);
	
	ptr += HCI_ACL_HDR_SIZE;
	len -= HCI_ACL_HDR_SIZE;
	l2cap_dump(1, ptr, len, acl_flags(handle));
}

void hci_dump(int level, __u8 *data, int len)
{
	unsigned char *ptr = data;
	__u8 type;

	type = *ptr++; len--;
	
	switch (type) {
	case HCI_COMMAND_PKT:
		command_dump(ptr, len);
		break;

	case HCI_EVENT_PKT:
		event_dump(ptr, len);
		break;

	case HCI_ACLDATA_PKT:
		acl_dump(ptr, len);
		break;

	default:
		printf("Unknown: type 0x%2.2x len %d\n", type, len);
		raw_dump(1, ptr, len);
		break;
	}
}
