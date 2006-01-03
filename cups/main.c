/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <string.h>
#include <signal.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

extern int sdp_search_spp(sdp_session_t *sdp, uint8_t *channel);
extern int sdp_search_hcrp(sdp_session_t *sdp, unsigned short *ctrl_psm, unsigned short *data_psm);

extern int spp_print(bdaddr_t *src, bdaddr_t *dst, uint8_t channel, int fd, int copies);
extern int hcrp_print(bdaddr_t *src, bdaddr_t *dst, unsigned short ctrl_psm, unsigned short data_psm, int fd, int copies);

/*
 *  Usage: printer-uri job-id user title copies options [file]
 *
 */

int main(int argc, char *argv[])
{
	sdp_session_t *sdp;
	bdaddr_t bdaddr;
	unsigned short ctrl_psm, data_psm;
	uint8_t channel, b[6];
	char *ptr, str[3], device[18], service[12];
	int i, err, fd, copies, proto;

	/* Make sure status messages are not buffered */
	setbuf(stderr, NULL);

	/* Ignore SIGPIPE signals */
#ifdef HAVE_SIGSET
	sigset(SIGPIPE, SIG_IGN);
#elif defined(HAVE_SIGACTION)
	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);
#else
	signal(SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGSET */

	if (argc == 1) {
		puts("network bluetooth \"Unknown\" \"Bluetooth printer\"");
		return 0;
	}

	if (argc < 6 || argc > 7) {
		fprintf(stderr, "Usage: bluetooth job-id user title copies options [file]\n");
		return 1;
	}

	if (argc == 6) {
		fd = 0;
		copies = 1;
	} else {
		if ((fd = open(argv[6], O_RDONLY)) < 0) {
			perror("ERROR: Unable to open print file");
			return 1;
		}
		copies = atoi(argv[4]);
	}

	if (strncasecmp(argv[0], "bluetooth://", 12)) {
		fprintf(stderr, "ERROR: No device URI found\n");
		return 1;
	}

	ptr = argv[0] + 12;
	for (i = 0; i < 6; i++) {
		strncpy(str, ptr, 2);
		b[i] = (uint8_t) strtol(str, NULL, 16);
		ptr += 2;
	}
	sprintf(device, "%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X",
		b[0], b[1], b[2], b[3], b[4], b[5]);

	str2ba(device, &bdaddr);

	ptr = strchr(ptr, '/');
	if (ptr) {
		strncpy(service, ptr + 1, 12);

		if (!strncasecmp(ptr + 1, "spp", 3))
			proto = 1;
		else if (!strncasecmp(ptr + 1, "hcrp", 4))
			proto = 2;
		else
			proto = 0;
	} else {
		strcpy(service, "auto");
		proto = 0;
	}

	fprintf(stderr, "DEBUG: %s device %s service %s fd %d copies %d\n",
			argv[0], device, service, fd, copies);

	sdp = sdp_connect(BDADDR_ANY, &bdaddr, SDP_RETRY_IF_BUSY);
	if (!sdp) {
		fprintf(stderr, "ERROR: Can't open Bluetooth connection\n");
		return 1;
	}

	switch (proto) {
	case 1:
		err = sdp_search_spp(sdp, &channel);
		break;
	case 2:
		err = sdp_search_hcrp(sdp, &ctrl_psm, &data_psm);
		break;
	default:
		proto = 2;
		err = sdp_search_hcrp(sdp, &ctrl_psm, &data_psm);
		if (err) {
			proto = 1;
			err = sdp_search_spp(sdp, &channel);
		}
		break;
	}

	sdp_close(sdp);

	if (err) {
		fprintf(stderr, "ERROR: Can't get service information\n");
		return 1;
	}

	switch (proto) {
	case 1:
		err = spp_print(BDADDR_ANY, &bdaddr, channel, fd, copies);
		break;
	case 2:
		err = hcrp_print(BDADDR_ANY, &bdaddr, ctrl_psm, data_psm, fd, copies);
		break;
	default:
		err = 1;
		fprintf(stderr, "ERROR: Unsupported protocol\n");
		break;
	}

	if (fd != 0)
		close(fd);

	if (!err)
		fprintf(stderr, "INFO: Ready to print\n");

	return err;
}
