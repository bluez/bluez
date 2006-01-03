/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <malloc.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

/* Defaults */
static bdaddr_t bdaddr;
static int size    = 44;
static int ident   = 200;
static int delay   = 1;
static int count   = -1;
static int timeout = 10;

/* Stats */
static int sent_pkt = 0;
static int recv_pkt = 0;

static float tv2fl(struct timeval tv)
{
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

static void stat(int sig)
{
	int loss = sent_pkt ? (float)((sent_pkt-recv_pkt)/(sent_pkt/100.0)) : 0;
	printf("%d sent, %d received, %d%% loss\n", sent_pkt, recv_pkt, loss);
	exit(0);
}

static void ping(char *svr)
{
	struct sigaction sa;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	unsigned char *buf;
	char str[18];
	int i, sk, lost;
	uint8_t id;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stat;
	sigaction(SIGINT, &sa, NULL);

	buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	if (!buf) {
		perror("Can't allocate buffer");
		exit(1);
	}

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		free(buf);
		exit(1);
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		close(sk);
		free(buf);
		exit(1);
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't connect");
		close(sk);
		free(buf);
		exit(1);
	}

	/* Get local address */
	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	if (getsockname(sk, (struct sockaddr *) &addr, &optlen) < 0) {
		perror("Can't get local address");
		close(sk);
		free(buf);
		exit(1);
	}

	ba2str(&addr.l2_bdaddr, str);
	printf("Ping: %s from %s (data size %d) ...\n", svr, str, size);

	/* Initialize buffer */
	for (i = 0; i < size; i++)
		buf[L2CAP_CMD_HDR_SIZE + i] = (i % 40) + 'A';

	id = ident;

	while (count == -1 || count-- > 0) {
		struct timeval tv_send, tv_recv, tv_diff;
		l2cap_cmd_hdr *cmd = (l2cap_cmd_hdr *) buf;

		/* Build command header */
		cmd->code  = L2CAP_ECHO_REQ;
		cmd->ident = id;
		cmd->len   = htobs(size);

		gettimeofday(&tv_send, NULL);

		/* Send Echo Request */
		if (send(sk, buf, L2CAP_CMD_HDR_SIZE + size, 0) <= 0) {
			perror("Send failed");
			exit(1);
		}

		/* Wait for Echo Response */
		lost = 0;
		while (1) {
			struct pollfd pf[1];
			int err;

			pf[0].fd = sk;
			pf[0].events = POLLIN;

			if ((err = poll(pf, 1, timeout * 1000)) < 0) {
				perror("Poll failed");
				exit(1);
			}

			if (!err) {
				lost = 1;
				break;
			}

			if ((err = recv(sk, buf, L2CAP_CMD_HDR_SIZE + size, 0)) < 0) {
				perror("Recv failed");
				exit(1);
			}

			if (!err){
				printf("Disconnected\n");
				exit(1);
			}

			cmd->len = btohs(cmd->len);

			/* Check for our id */
			if (cmd->ident != id)
				continue;

			/* Check type */
			if (cmd->code == L2CAP_ECHO_RSP)
				break;
			if (cmd->code == L2CAP_COMMAND_REJ) {
				printf("Peer doesn't support Echo packets\n");
				exit(1);
			}

		}
		sent_pkt++;

		if (!lost) {
			recv_pkt++;

			gettimeofday(&tv_recv, NULL);
			timersub(&tv_recv, &tv_send, &tv_diff);

			printf("%d bytes from %s id %d time %.2fms\n", cmd->len, svr, id - ident, tv2fl(tv_diff));

			if (delay)
				sleep(delay);
		} else {
			printf("no response from %s: id %d\n", svr, id - ident);
		}

		if (++id > 254)
			id = ident;
	}
	stat(0);
}

static void usage(void)
{
	printf("l2ping - L2CAP ping\n");
	printf("Usage:\n");
	printf("\tl2ping [-i device] [-s size] [-c count] [-t timeout] [-f] <bdaddr>\n");
}

int main(int argc, char *argv[])
{
	int opt;

	/* Default options */
	bacpy(&bdaddr, BDADDR_ANY);

	while ((opt=getopt(argc,argv,"i:s:c:t:f")) != EOF) {
		switch(opt) {
		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;

		case 'f':
			/* Kinda flood ping */
			delay = 0;
			break;

		case 'c':
			count = atoi(optarg);
			break;

		case 't':
			timeout = atoi(optarg);
			break;

		case 's':
			size = atoi(optarg);
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (!(argc - optind)) {
		usage();
		exit(1);
	}

	ping(argv[optind]);

	return 0;
}
