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

#define HEXDUMP		0
#define ANALYZE		1

/* Default options */
int action = ANALYZE;

char * hci_pkt_type[] = {
	"Unknown ",
	"Command ",
	"ACL Data",
	"SCO Data",
	"Event   "
};

void usage(void)
{
	printf("HCIDump - HCI packet analyzer ver %s\n", VERSION);
	printf("Usage:\n");
	printf("\thcidump <-i hciX> [-h]\n");
}

void hex_dump(char *pref, unsigned char *buf, int len)
{
	register char *ptr;
	register int i;
	char line[100];

	ptr = line; *ptr = 0; 
	for(i=0; i<len; i++ ){
		ptr += sprintf(ptr, " %2.2X", buf[i]);
		if( i && !((i+1)%20) ){
			printf("%s%s\n", pref, line);
			ptr = line; *ptr = 0;
		}
	}
	if( line[0] )
		printf("%s%s\n", pref, line);
}

void inline event_dump(void *ptr, int len)
{
	hci_event_hdr *hdr = ptr;
	printf("  code: 0x%x plen: %d\n", hdr->evt, hdr->plen);
}

void analyze(int type, unsigned char *ptr, int len)
{
	switch( type ){
		case HCI_EVENT_PKT:
			event_dump(ptr, len);
			break;
	}
}

extern int optind,opterr,optopt;
extern char *optarg;

int main(int argc, char *argv[])
{
	char data[4096], ctrl[100], *ptr;
	int s, len, type, opt, dev, in;
	struct sockaddr_hci addr;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec  iv;

	dev = 0;
	while( (opt=getopt(argc, argv,"i:h")) != EOF ) {
		switch(opt) {
			case 'i':
				dev = atoi(optarg+3);
				break;

			case 'h':
				action = HEXDUMP;
				break;

			case 'a':
				action = ANALYZE;
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

	/* Bind socket to the HCI device */
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = dev;
	if( bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 ) {
		printf("Can't attach to device hci%d. %s(%d)\n", dev, strerror(errno), errno);
		exit(1);
	}

	printf("HCIDump version %s\n", VERSION);

	while( 1 ) {
		iv.iov_base = data;
		iv.iov_len  = sizeof(data);

		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof(ctrl);

		if( (len = recvmsg(s, &msg, 0)) < 0 ){
			perror("Receive failed");
			exit(1);
		}

		/* Process controll message */
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
		if( type < 0 || type > 4 )
			type = 0;

		printf("%c %s(0x%2.2x), len %d\n", 
			(in ? '>' : '<'), hci_pkt_type[type], (__u8)type, len);

		switch( action ){
			case ANALYZE:
				analyze(type, ptr, len);
				break;

			case HEXDUMP:
				hex_dump("  ", ptr, len);
				break;
		}

		fflush(stdout);
	}
}
