/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

extern int optind, opterr, optopt;
extern char *optarg;

/* IO cancelation */
static volatile sig_atomic_t __io_canceled;

static inline void io_init(void)
{
	__io_canceled = 0;
}

static inline void io_cancel(void)
{
	__io_canceled = 1;
}

/* Signal functions */
static void sig_hup(int sig)
{
	return;
}

static void sig_term(int sig)
{
	syslog(LOG_INFO, "Closing RFCOMM channel");
	io_cancel();
}

/* Read exactly len bytes (Signal safe)*/
static inline int read_n(int fd, char *buf, int len)
{
	register int t = 0, w;

	while (!__io_canceled && len > 0) {
		if ((w = read(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w;
		buf += w;
		t += w;
	}

	return t;
}

/* Write exactly len bytes (Signal safe)*/
static inline int write_n(int fd, char *buf, int len)
{
	register int t = 0, w;

	while (!__io_canceled && len > 0) {
		if ((w = write(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w;
		buf += w;
		t += w;
	}

	return t;
}

/* Create the RFCOMM connection */
static int create_connection(bdaddr_t *bdaddr, uint8_t channel)
{
	struct sockaddr_rc remote_addr, local_addr;
	int fd, err;

	if ((fd = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0)
		return fd;

	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.rc_family = AF_BLUETOOTH;
	bacpy(&local_addr.rc_bdaddr, BDADDR_ANY);
	if ((err = bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr))) < 0) {
		close(fd);
		return err;
	}

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.rc_family = AF_BLUETOOTH;
	bacpy(&remote_addr.rc_bdaddr, bdaddr);
	remote_addr.rc_channel = channel;
	if ((err = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr))) < 0) {
		close(fd);
		return err;
	}

	syslog(LOG_INFO, "RFCOMM channel %d connected", channel);

	return fd;
}

/* Process the data from socket and pseudo tty */
static int process_data(int fd)
{
	struct pollfd p[2];
	char buf[1024];
	int err, r;

	p[0].fd = 0;
	p[0].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
	
	p[1].fd = fd;
	p[1].events = POLLIN | POLLERR | POLLHUP | POLLNVAL;

	err = 0;

	while (!__io_canceled) {
		p[0].revents = 0;
		p[1].revents = 0;
		
		err = poll(p, 2, -1);
		if (err < 0)
			break;

		err = 0;

		if (p[0].revents) {
			if (p[0].revents & (POLLERR | POLLHUP | POLLNVAL))
			  break;
			r = read(0, buf, sizeof(buf));
			if (r < 0) {
				if (errno != EINTR && errno != EAGAIN) {
					err = r;
					break;
				}
			}

			err = write_n(fd, buf, r);
			if (err < 0)
				break;
		}

		if (p[1].revents) {
			if (p[1].revents & (POLLERR | POLLHUP | POLLNVAL))
				break;
			r = read(fd, buf, sizeof(buf));
			if (r < 0) {
				if (errno != EINTR && errno != EAGAIN) {
					err = r;
					break;
				}
			}

			err = write_n(1, buf, r);
			if (err < 0)
				break;
		}
	}

	return err;
}

static void usage(void)
{
	printf("Usage:\tppporc <bdaddr> [channel]\n");
}

int main(int argc, char** argv)
{
	struct sigaction sa;
	int fd, err, opt;

	bdaddr_t bdaddr;
	uint8_t channel;

	/* Parse command line options */
	while ((opt = getopt(argc, argv, "h")) != EOF) {
		switch(opt) {
		case 'h':
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		str2ba(argv[0], &bdaddr);
		channel = 1;
		break;
	case 2:
		str2ba(argv[0], &bdaddr);
		channel = atoi(argv[1]);
		break;
	default:
		usage();
		exit(0);
	}

	/* Initialize syslog */
	openlog("ppporc", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "PPP over RFCOMM");

	/* Initialize signals */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	syslog(LOG_INFO, "Connecting to %s", argv[0]);

	if ((fd = create_connection(&bdaddr, channel)) < 0) {
		syslog(LOG_ERR, "Can't connect to remote device (%s)", strerror(errno));
		return fd;
	}

	err = process_data(fd);

	close(fd);

	return err;
}
