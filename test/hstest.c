/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>

static volatile int terminate = 0;

static void sig_term(int sig) {
	terminate = 1;
}

static int rfcomm_connect(bdaddr_t *src, bdaddr_t *dst, uint8_t channel)
{
	struct sockaddr_rc addr;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);
	addr.rc_channel = 0;
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 ){
		close(s);
		return -1;
	}

	return s;
}

static int sco_connect(bdaddr_t *src, bdaddr_t *dst, uint16_t *handle, uint16_t *mtu)
{
	struct sockaddr_sco addr;
	struct sco_conninfo conn;
	struct sco_options opts;
	socklen_t size;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO)) < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, src);

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, dst);

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0 ){
		close(s);
		return -1;
	}

	memset(&conn, 0, sizeof(conn));
	size = sizeof(conn);

	if (getsockopt(s, SOL_SCO, SCO_CONNINFO, &conn, &size) < 0) {
		close(s);
		return -1;
	}

	memset(&opts, 0, sizeof(opts));
	size = sizeof(opts);

	if (getsockopt(s, SOL_SCO, SCO_OPTIONS, &opts, &size) < 0) {
		close(s);
		return -1;
	}

	if (handle)
		*handle = conn.hci_handle;

	if (mtu)
		*mtu = opts.mtu;

	return s;
}

static void usage(void)
{
	printf("Usage:\n"
		"\thstest play   <file> <bdaddr> [channel]\n"
		"\thstest record <file> <bdaddr> [channel]\n");
}

#define PLAY	1
#define RECORD	2

int main(int argc, char *argv[])
{
	struct sigaction sa;

	fd_set rfds;
	struct timeval timeout;
	unsigned char buf[2048], *p;
	int maxfd, sel, rlen, wlen;

	bdaddr_t local;
	bdaddr_t bdaddr;
	uint8_t channel;

	char *filename;
	mode_t filemode;
	int mode = 0;
	int dd, rd, sd, fd;
	uint16_t sco_handle, sco_mtu, vs;

	switch (argc) {
	case 4:
		str2ba(argv[3], &bdaddr);
		channel = 6;
		break;
	case 5:
		str2ba(argv[3], &bdaddr);
		channel = atoi(argv[4]);
		break;
	default:
		usage();
		exit(-1);
	}

	if (strncmp(argv[1], "play", 4) == 0) {
		mode = PLAY;
		filemode = O_RDONLY;
	} else if (strncmp(argv[1], "rec", 3) == 0) {
		mode = RECORD;
		filemode = O_WRONLY | O_CREAT | O_TRUNC;
	} else {
		usage();
		exit(-1);
	}

	filename = argv[2];

	hci_devba(0, &local);
	dd = hci_open_dev(0);
	hci_read_voice_setting(dd, &vs, 1000);
	vs = htobs(vs);
	fprintf(stderr, "Voice setting: 0x%04x\n", vs);
	close(dd);
	if (vs != 0x0060) {
		fprintf(stderr, "The voice setting must be 0x0060\n");
		return -1;
	}

	if (strcmp(filename, "-") == 0) {
		switch (mode) {
		case PLAY:
			fd = 0;
			break;
		case RECORD:
			fd = 1;
			break;
		default:
			return -1;
		}
	} else {
		if ((fd = open(filename, filemode)) < 0) {
			perror("Can't open input/output file");
			return -1;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	if ((rd = rfcomm_connect(&local, &bdaddr, channel)) < 0) {
		perror("Can't connect RFCOMM channel");
		return -1;
	}

	fprintf(stderr, "RFCOMM channel connected\n");

	if ((sd = sco_connect(&local, &bdaddr, &sco_handle, &sco_mtu)) < 0) {
		perror("Can't connect SCO audio channel");
		close(rd);
		return -1;
	}

	fprintf(stderr, "SCO audio channel connected (handle %d, mtu %d)\n", sco_handle, sco_mtu);

	if (mode == RECORD) {
		if (write(rd, "RING\r\n", 6) < 0)
			return -errno;
	}

	maxfd = (rd > sd) ? rd : sd;

	while (!terminate) {

		FD_ZERO(&rfds);
		FD_SET(rd, &rfds);
		FD_SET(sd, &rfds);

		timeout.tv_sec = 0;
		timeout.tv_usec = 10000;

		if ((sel = select(maxfd + 1, &rfds, NULL, NULL, &timeout)) > 0) {

			if (FD_ISSET(rd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(rd, buf, sizeof(buf));
				if (rlen > 0) {
					fprintf(stderr, "%s\n", buf);
					wlen = write(rd, "OK\r\n", 4);
				}
			}

			if (FD_ISSET(sd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				rlen = read(sd, buf, sizeof(buf));
				if (rlen > 0)
					switch (mode) {
					case PLAY:
						rlen = read(fd, buf, rlen);

						wlen = 0;
						p = buf;
						while (rlen > sco_mtu) {
						        wlen += write(sd, p, sco_mtu);
						        rlen -= sco_mtu;
						        p += sco_mtu;
						}
						wlen += write(sd, p, rlen);
						break;
					case RECORD:
						wlen = write(fd, buf, rlen);
						break;
					default:
						break;
					}
			}

		}

	}

	close(sd);
	sleep(5);
	close(rd);

	close(fd);

	return 0;
}
