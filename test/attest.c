/*
 *
 *  Programm for testing AT commands over Bluetooth RFCOMM
 *
 *  Copyright (C) 2001-2002  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>



static int at_command(int fd, char *cmd, int to)
{
	fd_set rfds;
	struct timeval timeout;
	unsigned char buf[1024];
	int sel, len, i, n;

	write(fd, cmd, strlen(cmd));

	for (i = 0; i < 100; i++) {

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		timeout.tv_sec = 0;
		timeout.tv_usec = to;

		if ((sel = select(fd + 1, &rfds, NULL, NULL, &timeout)) > 0) {

			if (FD_ISSET(fd, &rfds)) {
				memset(buf, 0, sizeof(buf));
				len = read(fd, buf, sizeof(buf));
				for (n = 0; n < len; n++)
					printf("%c", buf[n]);
				if (strstr(buf, "\r\nOK") != NULL)
					break;
				if (strstr(buf, "\r\nERROR") != NULL)
					break;
				if (strstr(buf, "\r\nCONNECT") != NULL)
					break;
			}

		}

	}

	return 0;
}


static int open_device(char *device)
{
	int fd;
	struct termios ti;

	if ((fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK)) < 0) {
		printf("Can't open serial port. %s (%d)\n", strerror(errno), errno);
		return -1;
	}

	tcflush(fd, TCIOFLUSH);

	/* Switch tty to RAW mode */
	cfmakeraw(&ti);
	tcsetattr(fd, TCSANOW, &ti);

	return fd;
}


static int open_socket(bdaddr_t *bdaddr, uint8_t channel)
{
	struct sockaddr_rc remote_addr, local_addr;
	int s;

	if ((s = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)) < 0) {
		printf("Can't create socket. %s (%d)\n", strerror(errno), errno);
		return -1;
        }

	memset(&local_addr, 0, sizeof(local_addr));
	local_addr.rc_family = AF_BLUETOOTH;
	bacpy(&local_addr.rc_bdaddr, BDADDR_ANY);
	if (bind(s, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
		printf("Can't bind socket. %s (%d)\n", strerror(errno), errno);
		close(s);
		return -1;
	}

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.rc_family = AF_BLUETOOTH;
	bacpy(&remote_addr.rc_bdaddr, bdaddr);
	remote_addr.rc_channel = channel;
	if (connect(s, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) < 0) {
		printf("Can't connect. %s (%d)\n", strerror(errno), errno);
		close(s);
		return -1;
	}

	return s;
}


static void usage(void)
{
	printf("Usage:\n\tattest <device> | <bdaddr> [channel]\n");
}


int main(int argc, char *argv[])
{
	int fd;

	bdaddr_t bdaddr;
	uint8_t channel;

	switch (argc) {
	case 2:
		str2ba(argv[1], &bdaddr);
		channel = 1;
		break;
	case 3:
		str2ba(argv[1], &bdaddr);
		channel = atoi(argv[2]);
		break;
	default:
		usage();
		exit(-1);
	}

	if (bacmp(BDADDR_ANY, &bdaddr)) {
		printf("Connecting to %s on channel %d\n", argv[1], channel);
		fd = open_socket(&bdaddr, channel);
	} else {
		printf("Opening device %s\n", argv[1]);
		fd = open_device(argv[1]);
	}

	if (fd < 0)
		exit(-2);

	at_command(fd, "ATZ\r\n", 10000);
	at_command(fd, "AT+CPBS=\"ME\"\r\n", 10000);
	at_command(fd, "AT+CPBR=1,100\r\n", 100000);

	close(fd);

	return 0;
}
