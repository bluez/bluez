/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <syslog.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/rfcomm.h>

/* Test modes */
enum {
	SEND,
	RECV,
	RECONNECT,
	MULTY,
	DUMP,
	CONNECT,
	CRECV,
	LSEND
};

static unsigned char *buf;

/* Default data size */
static long data_size = 127;
static long num_frames = -1;

/* Default addr and channel */
static bdaddr_t bdaddr;
static uint8_t channel = 10;

static int master = 0;
static int auth = 0;
static int encrypt = 0;
static int secure = 0;
static int socktype = SOCK_STREAM;
static int linger = 0;

static float tv2fl(struct timeval tv)
{
	return (float)tv.tv_sec + (float)(tv.tv_usec/1000000.0);
}

static int do_connect(char *svr)
{
	struct sockaddr_rc addr;
	struct rfcomm_conninfo conn;
	socklen_t optlen;
	int sk;

	/* Create socket */
	sk = socket(PF_BLUETOOTH, socktype, BTPROTO_RFCOMM);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
							strerror(errno), errno);
		return -1;
	}

	/* Enable SO_LINGER */
	if (linger) {
		struct linger l = { .l_onoff = 1, .l_linger = linger };

		if (setsockopt(sk, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) < 0) {
			syslog(LOG_ERR, "Can't enable SO_LINGER: %s (%d)",
							strerror(errno), errno);
			goto error;
		}
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	str2ba(svr, &addr.rc_bdaddr);
	addr.rc_channel = channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't connect: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Get connection information */
	memset(&conn, 0, sizeof(conn));
	optlen = sizeof(conn);

	if (getsockopt(sk, SOL_RFCOMM, RFCOMM_CONNINFO, &conn, &optlen) < 0) {
		syslog(LOG_ERR, "Can't get RFCOMM connection information: %s (%d)",
							strerror(errno), errno);
		//goto error;
	}

	syslog(LOG_INFO, "Connected [handle %d, class 0x%02x%02x%02x]",
		conn.hci_handle,
		conn.dev_class[2], conn.dev_class[1], conn.dev_class[0]);

	return sk;

error:
	close(sk);
	return -1;
}

static void do_listen(void (*handler)(int sk))
{
	struct sockaddr_rc addr;
	struct rfcomm_conninfo conn;
	socklen_t optlen;
	int sk, nsk, opt;
	char ba[18];

	/* Create socket */
	sk = socket(PF_BLUETOOTH, socktype, BTPROTO_RFCOMM);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	/* Bind to local address */
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &bdaddr);
	addr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Set link mode */
	opt = 0;
	if (master)
		opt |= RFCOMM_LM_MASTER;
	if (auth)
		opt |= RFCOMM_LM_AUTH;
	if (encrypt)
		opt |= RFCOMM_LM_ENCRYPT;
	if (secure)
		opt |= RFCOMM_LM_SECURE;

	if (opt && setsockopt(sk, SOL_RFCOMM, RFCOMM_LM, &opt, sizeof(opt)) < 0) {
		syslog(LOG_ERR, "Can't set RFCOMM link mode: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Listen for connections */
	if (listen(sk, 10)) {
		syslog(LOG_ERR,"Can not listen on the socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	syslog(LOG_INFO,"Waiting for connection on channel %d ...", channel);

	while(1) {
		memset(&addr, 0, sizeof(addr));
		optlen = sizeof(addr);

		nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
		if (nsk < 0) {
			syslog(LOG_ERR,"Accept failed: %s (%d)",
							strerror(errno), errno);
			goto error;
		}
		if (fork()) {
			/* Parent */
			close(nsk);
			continue;
		}
		/* Child */
		close(sk);

		/* Get connection information */
		memset(&conn, 0, sizeof(conn));
		optlen = sizeof(conn);

		if (getsockopt(nsk, SOL_RFCOMM, RFCOMM_CONNINFO, &conn, &optlen) < 0) {
			syslog(LOG_ERR, "Can't get RFCOMM connection information: %s (%d)",
							strerror(errno), errno);
			//close(nsk);
			//goto error;
		}

		ba2str(&addr.rc_bdaddr, ba);
		syslog(LOG_INFO, "Connect from %s [handle %d, class 0x%02x%02x%02x]",
			ba, conn.hci_handle,
			conn.dev_class[2], conn.dev_class[1], conn.dev_class[0]);

		/* Enable SO_LINGER */
		if (linger) {
			struct linger l = { .l_onoff = 1, .l_linger = linger };

			if (setsockopt(nsk, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) < 0) {
				syslog(LOG_ERR, "Can't enable SO_LINGER: %s (%d)",
							strerror(errno), errno);
				close(nsk);
				goto error;
			}
		}

		handler(nsk);

		syslog(LOG_INFO, "Disconnect: %m");
		exit(0);
	}

	return;

error:
	close(sk);
	exit(1);
}

static void dump_mode(int sk)
{
	int len;

	syslog(LOG_INFO, "Receiving ...");
	while ((len = read(sk, buf, data_size)) > 0)
		syslog(LOG_INFO, "Recevied %d bytes", len);
}

static void recv_mode(int sk)
{
	struct timeval tv_beg,tv_end,tv_diff;
	long total;
	uint32_t seq;

	syslog(LOG_INFO,"Receiving ...");

	seq = 0;
	while (1) {
		gettimeofday(&tv_beg,NULL);
		total = 0;
		while (total < data_size) {
			//uint32_t sq;
			//uint16_t l;
			int r;

			if ((r = recv(sk, buf, data_size, 0)) <= 0) {
				if (r < 0)
					syslog(LOG_ERR, "Read failed: %s (%d)",
							strerror(errno), errno);
				return;	
			}
#if 0
			/* Check sequence */
			sq = btohl(*(uint32_t *) buf);
			if (seq != sq) {
				syslog(LOG_INFO, "seq missmatch: %d -> %d", seq, sq);
				seq = sq;
			}
			seq++;
			
			/* Check length */
			l = btohs(*(uint16_t *) (buf + 4));
			if (r != l) {
				syslog(LOG_INFO, "size missmatch: %d -> %d", r, l);
				continue;
			}
			
			/* Verify data */	
			for (i = 6; i < r; i++) {
				if (buf[i] != 0x7f)
					syslog(LOG_INFO, "data missmatch: byte %d 0x%2.2x", i, buf[i]);
			}
#endif
			total += r;
		}
		gettimeofday(&tv_end,NULL);

		timersub(&tv_end,&tv_beg,&tv_diff);

		syslog(LOG_INFO,"%ld bytes in %.2f sec, %.2f kB/s", total,
			tv2fl(tv_diff), (float)(total / tv2fl(tv_diff) ) / 1024.0);
	}
}

static void send_mode(int sk)
{
	uint32_t seq;
	int i;

	syslog(LOG_INFO,"Sending ...");

	for (i = 6; i < data_size; i++)
		buf[i] = 0x7f;

	seq = 0;
	while ((num_frames == -1) || (num_frames-- > 0)) {
		*(uint32_t *) buf = htobl(seq);
		*(uint16_t *) (buf + 4) = htobs(data_size);
		seq++;
		
		if (send(sk, buf, data_size, 0) <= 0) {
			syslog(LOG_ERR, "Send failed: %s (%d)",
							strerror(errno), errno);
			exit(1);
		}
	}

	syslog(LOG_INFO, "Closing channel ...");
	if (shutdown(sk, SHUT_RDWR) < 0)
		syslog(LOG_INFO, "Close failed: %m");
	else
		syslog(LOG_INFO, "Done");
}

static void reconnect_mode(char *svr)
{
	while(1) {
		int sk = do_connect(svr);
		close(sk);
	}
}

static void multi_connect_mode(char *svr)
{
	while (1) {
		int i, sk;

		for (i = 0; i < 10; i++) {
			if (fork()) continue;

			/* Child */
			sk = do_connect(svr);
			usleep(500);
			close(sk);
			exit(0);
		}

		sleep(2);
	}
}

static void usage(void)
{
	printf("rctest - RFCOMM testing\n"
		"Usage:\n");
	printf("\trctest <mode> [options] [bdaddr]\n");
	printf("Modes:\n"
		"\t-r listen and receive\n"
		"\t-w listen and send\n"
		"\t-d listen and dump incoming data\n"
		"\t-s connect and send\n"
		"\t-u connect and receive\n"
		"\t-n connect and be silent\n"
		"\t-c connect, disconnect, connect, ...\n"
		"\t-m multiple connects\n");

	printf("Options:\n"
		"\t[-b bytes] [-i device] [-P channel]\n"
		"\t[-L seconds] enabled SO_LINGER option\n"
		"\t[-N num] number of frames to send\n"
		"\t[-A] request authentication\n"
		"\t[-E] request encryption\n"
		"\t[-S] secure connection\n"
		"\t[-M] become master\n");
}

int main(int argc ,char *argv[])
{
	struct sigaction sa;
	int opt, sk, mode = RECV, need_addr = 0;

	bacpy(&bdaddr, BDADDR_ANY);

	while ((opt=getopt(argc,argv,"rdscuwmnb:i:P:N:MAESL:")) != EOF) {
		switch (opt) {
		case 'r':
			mode = RECV;
			break;

		case 's':
			mode = SEND;
			need_addr = 1;
			break;

		case 'w':
			mode = LSEND;
			break;

		case 'u':
			mode = CRECV;
			need_addr = 1;
			break;

		case 'd':
			mode = DUMP;
			break;

		case 'c':
			mode = RECONNECT;
			need_addr = 1;
			break;

		case 'n':
			mode = CONNECT;
			need_addr = 1;
			break;

		case 'm':
			mode = MULTY;
			need_addr = 1;
			break;

		case 'b':
			data_size = atoi(optarg);
			break;

		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;

		case 'P':
			channel = atoi(optarg);
			break;

		case 'M':
			master = 1;
			break;

		case 'A':
			auth = 1;
			break;

		case 'E':
			encrypt = 1;
			break;

		case 'S':
			secure = 1;
			break;

		case 'L':
			linger = atoi(optarg);
			break;

		case 'N':
			num_frames = atoi(optarg);
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (need_addr && !(argc - optind)) {
		usage();
		exit(1);
	}

	if (!(buf = malloc(data_size))) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags   = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	openlog("rctest", LOG_PERROR | LOG_PID, LOG_LOCAL0);

	switch (mode) {
		case RECV:
			do_listen(recv_mode);
			break;

		case CRECV:
			sk = do_connect(argv[optind]);
			if (sk < 0)
				exit(1);
			recv_mode(sk);
			break;

		case DUMP:
			do_listen(dump_mode);
			break;

		case SEND:
			sk = do_connect(argv[optind]);
			if (sk < 0)
				exit(1);
			send_mode(sk);
			break;

		case LSEND:
			do_listen(send_mode);
			break;

		case RECONNECT:
			reconnect_mode(argv[optind]);
			break;

		case MULTY:
			multi_connect_mode(argv[optind]);
			break;

		case CONNECT:
			sk = do_connect(argv[optind]);
			if (sk < 0)
				exit(1);
			dump_mode(sk);
			break;
	}

	syslog(LOG_INFO, "Exit");

	closelog();

	return 0;
}
