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
#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <string.h>

#include <asm/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

/* Default options */
int snap_len  = 1 + HCI_ACL_HDR_SIZE + L2CAP_HDR_SIZE + 40;
int dump_type = 0;

void usage(void)
{
	printf("HCIDump - HCI packet analyzer ver %s\n", VERSION);
	printf("Usage:\n");
	printf("\thcidump <-i hciX> [-h]\n");
}

void raw_dump(char *pref, unsigned char *buf, int len)
{
	register char *ptr;
	register int i;
	char line[100];

	if (!dump_type)
		return;

	ptr = line; *ptr = 0; 
	for (i=0; i<len; i++) {
		ptr += sprintf(ptr, " %2.2X", buf[i]);
		if (i && !((i+1)%20)) {
			printf("%s%s\n", pref, line);
			ptr = line; *ptr = 0;
		}
	}
	if (line[0])
		printf("%s%s\n", pref, line);
}

static inline void command_dump(void *ptr, int len)
{
	hci_command_hdr *hdr = ptr;
	__u16 opcode = __le16_to_cpu(hdr->opcode);

	ptr += HCI_COMMAND_HDR_SIZE;
	len -= HCI_COMMAND_HDR_SIZE;

	printf("Command: ogf 0x%x ocf 0x%x plen %d\n", 
		cmd_opcode_ogf(opcode), cmd_opcode_ocf(opcode), hdr->plen);
	raw_dump(" ", ptr, len);
}

static inline void event_dump(void *ptr, int len)
{
	hci_event_hdr *hdr = ptr;
	
	ptr += HCI_EVENT_HDR_SIZE;
	len -= HCI_EVENT_HDR_SIZE;

	printf("Event: code 0x%2.2x plen %d\n", hdr->evt, hdr->plen);
	raw_dump(" ", ptr, len);
}

static inline void l2cap_dump(void *ptr, int len)
{
	l2cap_hdr *hdr = ptr;
	__u16 dlen = __le16_to_cpu(hdr->len);
	__u16 cid  = __le16_to_cpu(hdr->cid);

	ptr += L2CAP_HDR_SIZE;
	len -= L2CAP_HDR_SIZE;

	if (cid == 0x1) {
		l2cap_cmd_hdr *hdr = ptr;
		__u16 len = __le16_to_cpu(hdr->len);

		ptr += L2CAP_CMD_HDR_SIZE;
		len -= L2CAP_CMD_HDR_SIZE;

		printf("  L2CAP signaling: code 0x%2.2x ident %d len %d\n", 
				hdr->code, hdr->ident, len);
		raw_dump(" ", ptr, len);
	} else {
		printf("  L2CAP data: cid 0x%x len %d\n", cid, dlen);
		raw_dump(" ", ptr, len);
	}
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
	l2cap_dump(ptr, len);
}

static inline void analyze(int type, unsigned char *ptr, int len)
{
	switch( type ){
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
			printf("Unknown: type 0x%2.2x len %d\n", 
					(__u8) type, len);

			raw_dump("  ", ptr, len);
			break;
	}
}

void process_frames(int dev, int fd)
{
	char data[HCI_MAX_FRAME_SIZE], ctrl[100], *ptr;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec  iv;
	int len, type, in;

	if (snap_len > sizeof(data))
		snap_len = sizeof(data);
	else if (snap_len < 20)
		snap_len = 20;	

	printf("device: hci%d snap_len: %d filter: none\n", dev, snap_len); 

	while (1) {
		iv.iov_base = data;
		iv.iov_len  = snap_len;

		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof(ctrl);

		if( (len = recvmsg(fd, &msg, 0)) < 0 ){
			perror("Receive failed");
			exit(1);
		}

		/* Process control message */
		in = 0;
		cmsg = CMSG_FIRSTHDR(&msg);
		while( cmsg ){
			switch(cmsg->cmsg_type){
				case HCI_CMSG_DIR:
					in = *((int *)CMSG_DATA(cmsg));
					break;
			}
			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}

		ptr = data;
		type = *ptr++; len--;

		/* Print data direction */
		printf("%c ", (in ? '>' : '<')); 

		analyze(type, ptr, len);

		fflush(stdout);
	}
}

extern int optind,opterr,optopt;
extern char *optarg;

int main(int argc, char *argv[])
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	int s, opt, dev;

	dev = 0;
	while( (opt=getopt(argc, argv,"i:s:h")) != EOF ) {
		switch(opt) {
			case 'i':
				dev = atoi(optarg+3);
				break;

			case 'h':
				dump_type = 1;
				break;

			case 's':
				snap_len = atoi(optarg);
				break;

			default:
				usage();
				exit(1);
		}
	}

	/* Create HCI socket */
	if( (s=socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0 ) {
		perror("Can't create HCI socket");
		exit(1);
	}
	
	opt = 1;
	if( setsockopt(s, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0 ) {
		perror("Can't enable data direction info");
		exit(1);
	}

	/* Setup filter */
	flt.type_mask  = ~0;      // All packet types
	flt.event_mask[0] = ~0L;  // All events
	flt.event_mask[1] = ~0L;
	if (setsockopt(s, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		perror("Can't set HCI filter");
		exit(1);
	}

	/* Bind socket to the HCI device */
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = dev;
	if( bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		printf("Can't attach to device hci%d. %s(%d)\n", 
					dev, strerror(errno), errno);
		exit(1);
	}

	printf("HCIDump - HCI packet analyzer ver %s.\n", VERSION);

	process_frames(dev, s);	

	close(s);
	return 0;
}
