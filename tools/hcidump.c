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

#include "parser.h"

/* Default options */
int snap_len  = 1 + HCI_ACL_HDR_SIZE + L2CAP_HDR_SIZE + 40;

void usage(void)
{
	printf("HCIDump - HCI packet analyzer ver %s\n", VERSION);
	printf("Usage:\n");
	printf("\thcidump <-i hciX> [-h]\n");
}

void process_frames(int dev, int fd)
{
	char *data, *ctrl;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec  iv;
	int len, in;

	if (snap_len < 20)
		snap_len = 20;	

	if (!(data = malloc(snap_len))) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	if (!(ctrl = malloc(100))) {
		perror("Can't allocate control buffer");
		exit(1);
	}
	
	printf("device: hci%d snap_len: %d filter: none\n", dev, snap_len); 

	while (1) {
		iv.iov_base = data;
		iv.iov_len  = snap_len;

		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = 100;

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

		/* Print data direction */
		printf("%c ", (in ? '>' : '<')); 

		parse(data, len);

		fflush(stdout);
	}
}

int main(int argc, char *argv[])
{
	extern int optind, opterr, optopt;
	extern char *optarg;
	struct sockaddr_hci addr;
	struct hci_filter flt;
	int s, opt, dev;
	long flags;	

	dev = 0;
	flags = 0;
	
	while ((opt=getopt(argc, argv,"i:s:ha")) != EOF) {
		switch(opt) {
		case 'i':
			dev = atoi(optarg+3);
			break;

		case 'h':
			flags |= DUMP_HEX;
			break;

		case 'a':
			flags |= DUMP_ASCII;
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

	init_parser(flags);
	process_frames(dev, s);	

	close(s);
	return 0;
}
