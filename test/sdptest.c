/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

static volatile sig_atomic_t __io_finished = 0;

static void callback(uint8_t type, uint16_t status,
				uint8_t *rsp, size_t size, void *udata)
{
	unsigned int i;

	for (i = 0; i < size; i++) {
		printf("%02x ", rsp[i]);
		if ((i + 1) % 8 == 0)
			printf(" ");
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");

	__io_finished = 1;
}

static void cmd_search(bdaddr_t *src, bdaddr_t *dst)
{
	sdp_session_t *session;
	sdp_list_t *search, *attrids;
	uint32_t range = 0x0000ffff;
	uuid_t uuid;

	session = sdp_connect(src, dst, 0);
	if (!session) {
		perror("Can't connect to SDP service");
		exit(1);
	}

	sdp_set_notify(session, callback, NULL);

	sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);

	search = sdp_list_append(NULL, &uuid);

	attrids = sdp_list_append(NULL, &range);

	//sdp_service_search_attr_async(session, search,
	//				SDP_ATTR_REQ_RANGE, attrids);

	sdp_service_search_async(session, search, 0xffff);

	sdp_list_free(attrids, NULL);

	sdp_list_free(search, NULL);

	while (!__io_finished)
		sdp_process(session);

	sdp_close(session);
}

static void usage(void)
{
	printf("sdptest - Utility for SDP testing\n\n");
	printf("Usage:\n"
		"\tsdptest [-i <dev>] <bdaddr>\n");
}

static struct option main_options[] = {
	{ "device",	1, 0, 'i' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	bdaddr_t src, dst;
	int opt;

	bacpy(&src, BDADDR_ANY);

	while ((opt=getopt_long(argc, argv, "+i:h", main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &src);
			else
				str2ba(optarg, &dst);
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		exit(1);
	}

	str2ba(argv[0], &dst);

	cmd_search(&src, &dst);

	return 0;
}
