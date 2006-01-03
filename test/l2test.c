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
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <syslog.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#define NIBBLE_TO_ASCII(c)  ((c) < 0x0a ? (c) + 0x30 : (c) + 0x57)

/* Test modes */
enum {
	SEND,
	RECV,
	RECONNECT,
	MULTY,
	DUMP,
	CONNECT,
	CRECV,
	LSEND,
	SENDDUMP,
	LSENDDUMP
};

static unsigned char *buf;

/* Default mtu */
static int imtu = 672;
static int omtu = 0;

/* Default data size */
static long data_size = -1;

/* Default addr and psm */
static bdaddr_t bdaddr;
static unsigned short psm = 10;

/* Default number of frames to send (-1 = infinite) */
static int num_frames = -1;

static int flowctl = 0;
static int master = 0;
static int auth = 0;
static int encrypt = 0;
static int secure = 0;
static int socktype = SOCK_SEQPACKET;
static int linger = 0;
static int reliable = 0;

static float tv2fl(struct timeval tv)
{
	return (float)tv.tv_sec + (float)(tv.tv_usec/1000000.0);
}

static char *ltoh(unsigned long c, char* s)
{
	int c1;

	c1     = (c >> 28) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = (c >> 24) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = (c >> 20) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = (c >> 16) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = (c >> 12) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = (c >>  8) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = (c >>  4) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = c & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	*s     = 0;
	return s;
}

static char *ctoh(char c, char* s)
{
	char c1;

	c1     = (c >> 4) & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	c1     = c & 0x0f;
	*(s++) = NIBBLE_TO_ASCII (c1);
	*s     = 0;
	return s;
}

static void hexdump(unsigned char *s, unsigned long l)
{
	char bfr[80];
	char *pb;
	unsigned long i, n = 0;

	if (l == 0)
		return;

	while (n < l) {
		pb = bfr;
		pb = ltoh (n, pb);
		*(pb++) = ':';
		*(pb++) = ' ';
		for (i = 0; i < 16; i++) {
			if (n + i >= l) {
				*(pb++) = ' ';
				*(pb++) = ' ';
			} else
				pb = ctoh (*(s + i), pb);
			*(pb++) = ' ';
		}
		*(pb++) = ' ';
		for (i = 0; i < 16; i++) {
			if (n + i >= l)
				break;
			else
				*(pb++) = (isprint (*(s + i)) ? *(s + i) : '.');
		}
		*pb = 0;
		n += 16;
		s += 16;
		puts(bfr);
	}
}

static int do_connect(char *svr)
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	struct l2cap_conninfo conn;
	socklen_t optlen;
	int sk, opt;

	/* Create socket */
	sk = socket(PF_BLUETOOTH, socktype, BTPROTO_L2CAP);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
							strerror(errno), errno);
		return -1;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Get default options */
	memset(&opts, 0, sizeof(opts));
	optlen = sizeof(opts);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) < 0) {
		syslog(LOG_ERR, "Can't get default L2CAP options: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Set new options */
	opts.omtu = omtu;
	opts.imtu = imtu;
	if (flowctl)
		opts.mode = 2;

	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts)) < 0) {
		syslog(LOG_ERR, "Can't set L2CAP options: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Enable SO_LINGER */
	if (linger) {
		struct linger l = { .l_onoff = 1, .l_linger = linger };

		if (setsockopt(sk, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) < 0) {
			syslog(LOG_ERR, "Can't enable SO_LINGER: %s (%d)",
							strerror(errno), errno);
			return -1;
		}
	}

	/* Set link mode */
	opt = 0;
	if (reliable)
		opt |= L2CAP_LM_RELIABLE;

	if (setsockopt(sk, SOL_L2CAP, L2CAP_LM, &opt, sizeof(opt)) < 0) {
		syslog(LOG_ERR, "Can't set L2CAP link mode: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);
	addr.l2_psm = htobs(psm);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0 ) {
		syslog(LOG_ERR, "Can't connect: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Get current options */
	memset(&opts, 0, sizeof(opts));
	optlen = sizeof(opts);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) < 0) {
		syslog(LOG_ERR, "Can't get L2CAP options: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Get connection information */
	memset(&conn, 0, sizeof(conn));
	optlen = sizeof(conn);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_CONNINFO, &conn, &optlen) < 0) {
		syslog(LOG_ERR, "Can't get L2CAP connection information: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	syslog(LOG_INFO, "Connected [imtu %d, omtu %d, flush_to %d, "
				"mode %d, handle %d, class 0x%02x%02x%02x]",
		opts.imtu, opts.omtu, opts.flush_to, opts.mode, conn.hci_handle,
		conn.dev_class[2], conn.dev_class[1], conn.dev_class[0]);

	if (data_size > opts.omtu)
		data_size = opts.omtu;

	return sk;

error:
	close(sk);
	return -1;
}

static void do_listen(void (*handler)(int sk))
{
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	struct l2cap_conninfo conn;
	socklen_t optlen;
	int sk, nsk, opt;
	char ba[18];

	/* Create socket */
	sk = socket(PF_BLUETOOTH, socktype, BTPROTO_L2CAP);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
							strerror(errno), errno);
		exit(1);
	}

	/* Bind to local address */
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);
	addr.l2_psm = htobs(psm);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Set link mode */
	opt = 0;
	if (reliable)
		opt |= L2CAP_LM_RELIABLE;
	if (master)
		opt |= L2CAP_LM_MASTER;
	if (auth)
		opt |= L2CAP_LM_AUTH;
	if (encrypt)
		opt |= L2CAP_LM_ENCRYPT;
	if (secure)
		opt |= L2CAP_LM_SECURE;

	if (opt && setsockopt(sk, SOL_L2CAP, L2CAP_LM, &opt, sizeof(opt)) < 0) {
		syslog(LOG_ERR, "Can't set L2CAP link mode: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Get default options */
	memset(&opts, 0, sizeof(opts));
	optlen = sizeof(opts);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) < 0) {
		syslog(LOG_ERR, "Can't get default L2CAP options: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	/* Set new options */
	opts.imtu = imtu;
	if (flowctl)
		opts.mode = 2;

	if (setsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts)) < 0) {
		syslog(LOG_ERR, "Can't set L2CAP options: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	if (socktype == SOCK_DGRAM) {
		handler(sk);
		return;
	}

	/* Listen for connections */
	if (listen(sk, 10)) {
		syslog(LOG_ERR, "Can not listen on the socket: %s (%d)",
							strerror(errno), errno);
		goto error;
	}

	syslog(LOG_INFO, "Waiting for connection on psm %d ...", psm);

	while(1) {
		memset(&addr, 0, sizeof(addr));
		optlen = sizeof(addr);

		nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
		if (nsk < 0) {
			syslog(LOG_ERR, "Accept failed: %s (%d)",
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

		/* Get current options */
		memset(&opts, 0, sizeof(opts));
		optlen = sizeof(opts);

		if (getsockopt(nsk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) < 0) {
			syslog(LOG_ERR, "Can't get L2CAP options: %s (%d)",
							strerror(errno), errno);
			close(nsk);
			goto error;
		}

		/* Get connection information */
		memset(&conn, 0, sizeof(conn));
		optlen = sizeof(conn);

		if (getsockopt(nsk, SOL_L2CAP, L2CAP_CONNINFO, &conn, &optlen) < 0) {
			syslog(LOG_ERR, "Can't get L2CAP connection information: %s (%d)",
							strerror(errno), errno);
			close(nsk);
			goto error;
		}

		ba2str(&addr.l2_bdaddr, ba);
		syslog(LOG_INFO, "Connect from %s [imtu %d, omtu %d, flush_to %d, "
					"mode %d, handle %d, class 0x%02x%02x%02x]",
			ba, opts.imtu, opts.omtu, opts.flush_to, opts.mode, conn.hci_handle,
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
	socklen_t optlen;
	int opt, len;

	syslog(LOG_INFO, "Receiving ...");
	while (1) {
		fd_set rset;

		FD_ZERO(&rset);
		FD_SET(sk, &rset);

		if (select(sk + 1, &rset, NULL, NULL, NULL) < 0)
			return;

		if (!FD_ISSET(sk, &rset))
			continue;

		len = read(sk, buf, data_size);
		if (len <= 0) {
			if (len < 0) {
				if (reliable && (errno == ECOMM)) {
					syslog(LOG_INFO, "L2CAP Error ECOMM - clearing error and continuing.");
					optlen = sizeof(opt);
					if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &opt, &optlen) < 0) {
						syslog(LOG_ERR, "Couldn't getsockopt(SO_ERROR): %s (%d)",
							strerror(errno), errno);
						return;
					}
					continue;
				} else {
					syslog(LOG_ERR, "Read error: %s(%d)",
							strerror(errno), errno);
				}
			}
			return;
		}

		syslog(LOG_INFO, "Recevied %d bytes", len);
		hexdump(buf, len);
	}
}

static void recv_mode(int sk)
{
	struct timeval tv_beg, tv_end, tv_diff;
	struct pollfd p;
	long total;
	uint32_t seq;
	socklen_t optlen;
	int opt;

	syslog(LOG_INFO,"Receiving ...");

	p.fd = sk;
	p.events = POLLIN | POLLERR | POLLHUP;

	seq = 0;
	while (1) {
		gettimeofday(&tv_beg, NULL);
		total = 0;
		while (total < data_size) {
			uint32_t sq;
			uint16_t l;
			int i, len;

			p.revents = 0;
			if (poll(&p, 1, -1) <= 0)
				return;

			if (p.revents & (POLLERR | POLLHUP))
				return;

			len = recv(sk, buf, data_size, 0);
			if (len < 0) {
				if (reliable && (errno == ECOMM)) {
					syslog(LOG_INFO, "L2CAP Error ECOMM - clearing error and continuing.\n");
					optlen = sizeof(opt);
					if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &opt, &optlen) < 0) {
						syslog(LOG_ERR, "Couldn't getsockopt(SO_ERROR): %s (%d)",
							strerror(errno), errno);
						return;
					}
					continue;
				} else {
					syslog(LOG_ERR, "Read failed: %s (%d)",
						strerror(errno), errno);
				}
			}

			if (len < 6)
				break;

			/* Check sequence */
			sq = btohl(*(uint32_t *) buf);
			if (seq != sq) {
				syslog(LOG_INFO, "seq missmatch: %d -> %d", seq, sq);
				seq = sq;
			}
			seq++;

			/* Check length */
			l = btohs(*(uint16_t *) (buf + 4));
			if (len != l) {
				syslog(LOG_INFO, "size missmatch: %d -> %d", len, l);
				continue;
			}

			/* Verify data */
			for (i = 6; i < len; i++) {
				if (buf[i] != 0x7f)
					syslog(LOG_INFO, "data missmatch: byte %d 0x%2.2x", i, buf[i]);
			}

			total += len;
		}
		gettimeofday(&tv_end, NULL);

		timersub(&tv_end, &tv_beg, &tv_diff);

		syslog(LOG_INFO,"%ld bytes in %.2f sec, %.2f kB/s", total,
			tv2fl(tv_diff), (float)(total / tv2fl(tv_diff) ) / 1024.0);
	}
}

static void send_mode(int sk)
{
	uint32_t seq;
	int i, len;

	syslog(LOG_INFO, "Sending ...");

	for (i = 6; i < data_size; i++)
		buf[i] = 0x7f;

	seq = 0;
	while ((num_frames == -1) || (num_frames-- > 0)) {
		*(uint32_t *) buf = htobl(seq);
		*(uint16_t *) (buf + 4) = htobs(data_size);
		seq++;

		len = send(sk, buf, data_size, 0);
		if (len < 0 || len != data_size) {
			syslog(LOG_ERR, "Send failed: %s (%d)", strerror(errno), errno);
			exit(1);
		}
	}

	syslog(LOG_INFO, "Closing channel ...");
	if (shutdown(sk, SHUT_RDWR) < 0)
		syslog(LOG_INFO, "Close failed: %m");
	else
		syslog(LOG_INFO, "Done");
}

static void senddump_mode(int sk)
{
	uint32_t seq;
	int i;

	syslog(LOG_INFO, "Sending ...");

	for (i = 6; i < data_size; i++)
		buf[i] = 0x7f;

	seq = 0;
	while ((num_frames == -1) || (num_frames-- > 0)) {
		*(uint32_t *) buf = htobl(seq);
		*(uint16_t *) (buf + 4) = htobs(data_size);
		seq++;

		if (send(sk, buf, data_size, 0) <= 0) {
			syslog(LOG_ERR, "Send failed: %s (%d)", strerror(errno), errno);
			exit(1);
		}
	}

	dump_mode(sk);
}

static void reconnect_mode(char *svr)
{
	while (1) {
		int sk = do_connect(svr);
		close(sk);
	}
}

static void connect_mode(char *svr)
{
	struct pollfd p;
	int sk;

	if ((sk = do_connect(svr)) < 0)
		exit(1);

	p.fd = sk;
	p.events = POLLERR | POLLHUP;

	while (1) {
		p.revents = 0;
		if (poll(&p, 1, 100))
			break;
	}

	syslog(LOG_INFO, "Disconnected");

	close(sk);
}

static void multi_connect_mode(char *svr)
{
	while (1) {
		int i, s;
		for (i = 0; i < 10; i++) {
			if (fork()) continue;

			/* Child */
			s = do_connect(svr);
			usleep(500);
			close(s);
			exit(0);
		}
		sleep(2);
	}
}

static void usage(void)
{
	printf("l2test - L2CAP testing\n"
		"Usage:\n");
	printf("\tl2test <mode> [options] [bdaddr]\n");
	printf("Modes:\n"
		"\t-r listen and receive\n"
		"\t-w listen and send\n"
		"\t-d listen and dump incoming data\n"
		"\t-x listen, then send, then dump incoming data\n"
		"\t-s connect and send\n"
		"\t-u connect and receive\n"
		"\t-n connect and be silent\n"
		"\t-y connect, then send, then dump incoming data\n"
		"\t-c connect, disconnect, connect, ...\n"
		"\t-m multiple connects\n");

	printf("Options:\n"
		"\t[-b bytes] [-i device] [-P psm]\n"
		"\t[-I imtu] [-O omtu]\n"
		"\t[-N num] send num frames (default = infinite)\n"
		"\t[-L seconds] enable SO_LINGER\n"
		"\t[-R] reliable mode\n"
		"\t[-D] use connectionless channel (datagram)\n"
		"\t[-F] enable flow control\n"
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

	while ((opt=getopt(argc,argv,"rdscuwmnxyb:i:P:I:O:N:L:RDFAESM")) != EOF) {
		switch(opt) {
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

		case 'x':
			mode = LSENDDUMP;
			break;

		case 'y':
			mode = SENDDUMP;
			break;

		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;

		case 'P':
			psm = atoi(optarg);
			break;

		case 'I':
			imtu = atoi(optarg);
			break;

		case 'O':
			omtu = atoi(optarg);
			break;

		case 'L':
			linger = atoi(optarg);
			break;

		case 'R':
			reliable = 1;
			break;

		case 'M':
			master = 1;
			break;

		case 'F':
			flowctl = 1;
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

		case 'D':
			socktype = SOCK_DGRAM;
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

	if (data_size < 0) {
		data_size = 48;
		if (imtu > data_size)
			data_size = imtu;
		if (omtu > data_size)
			data_size = omtu;
	}

	if (!(buf = malloc(data_size))) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags   = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	openlog("l2test", LOG_PERROR | LOG_PID, LOG_LOCAL0);

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
			connect_mode(argv[optind]);
			break;

		case SENDDUMP:
			sk = do_connect(argv[optind]);
			if (sk < 0)
				exit(1);
			senddump_mode(sk);
			break;

		case LSENDDUMP:
			do_listen(senddump_mode);
			break;
	}

	syslog(LOG_INFO, "Exit");

	closelog();

	return 0;
}
