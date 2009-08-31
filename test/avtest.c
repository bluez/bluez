/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#define AVDTP_PKT_TYPE_SINGLE		0x00

#define AVDTP_MSG_TYPE_COMMAND		0x00
#define AVDTP_MSG_TYPE_ACCEPT		0x02
#define AVDTP_MSG_TYPE_REJECT		0x03

#define AVDTP_DISCOVER			0x01
#define AVDTP_GET_CAPABILITIES		0x02
#define AVDTP_SET_CONFIGURATION		0x03
#define AVDTP_GET_CONFIGURATION		0x04

#define AVDTP_SEP_TYPE_SOURCE		0x00
#define AVDTP_SEP_TYPE_SINK		0x01

#define AVDTP_MEDIA_TYPE_AUDIO		0x00
#define AVDTP_MEDIA_TYPE_VIDEO		0x01
#define AVDTP_MEDIA_TYPE_MULTIMEDIA	0x02

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avdtp_header {
	uint8_t message_type:2;
	uint8_t packet_type:2;
	uint8_t transaction:4;
	uint8_t signal_id:6;
	uint8_t rfa0:2;
} __attribute__ ((packed));

struct seid_info {
	uint8_t rfa0:1;
	uint8_t inuse:1;
	uint8_t seid:6;
	uint8_t rfa2:3;
	uint8_t type:1;
	uint8_t media_type:4;
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avdtp_header {
	uint8_t transaction:4;
	uint8_t packet_type:2;
	uint8_t message_type:2;
	uint8_t rfa0:2;
	uint8_t signal_id:6;
} __attribute__ ((packed));

struct seid_info {
	uint8_t seid:6;
	uint8_t inuse:1;
	uint8_t rfa0:1;
	uint8_t media_type:4;
	uint8_t type:1;
	uint8_t rfa2:3;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

static void dump_header(struct avdtp_header *hdr)
{
	printf("TL %d PT %d MT %d SI %d\n", hdr->transaction,
			hdr->packet_type, hdr->message_type, hdr->signal_id);
}

static void dump_buffer(const unsigned char *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		printf("%02x ", buf[i]);
	printf("\n");
}

static void process_sigchan(int sk, unsigned char reject)
{
	unsigned char buf[672];
	ssize_t len;

	while (1) {
		struct avdtp_header *hdr = (void *) buf;

		len = read(sk, buf, sizeof(buf));
		if (len <= 0) {
			perror("Read failed");
			break;
		}

		dump_buffer(buf, len);
		dump_header(hdr);

		if (hdr->packet_type != AVDTP_PKT_TYPE_SINGLE) {
			fprintf(stderr, "Only single packets are supported\n");
			break;
		}

		if (hdr->message_type != AVDTP_MSG_TYPE_COMMAND) {
			fprintf(stderr, "Ignoring non-command messages\n");
			continue;
		}

		switch (hdr->signal_id) {
		case AVDTP_DISCOVER:
			if (reject == AVDTP_DISCOVER) {
				hdr->message_type = AVDTP_MSG_TYPE_REJECT;
				buf[2] = 0x29; /* Unsupported configuration */
				printf("Rejecting discover command\n");
				len = write(sk, buf, 3);
			} else {
				struct seid_info *sei = (void *) (buf + 2);
				hdr->message_type = AVDTP_MSG_TYPE_ACCEPT;
				buf[2] = 0x00;
				buf[3] = 0x00;
				sei->seid = 0x01;
				sei->type = AVDTP_SEP_TYPE_SINK;
				sei->media_type = AVDTP_MEDIA_TYPE_AUDIO;
				printf("Accepting discover command\n");
				len = write(sk, buf, 4);
			}
			break;

		case AVDTP_GET_CAPABILITIES:
			if (reject == AVDTP_GET_CAPABILITIES) {
				hdr->message_type = AVDTP_MSG_TYPE_REJECT;
				buf[2] = 0x29; /* Unsupported configuration */
				printf("Rejecting get capabilties command\n");
				len = write(sk, buf, 3);
			} else {
				hdr->message_type = AVDTP_MSG_TYPE_ACCEPT;
				buf[2] = 0x01;	/* Media transport category */
				buf[3] = 0x00;
				buf[4] = 0x07;	/* Media codec category */
				buf[5] = 0x06;
				buf[6] = 0x00;	/* Media type audio */
				buf[7] = 0x00;	/* Codec SBC */
				buf[8] = 0x22;	/* 44.1 kHz, stereo */
				buf[9] = 0x15;	/* 16 blocks, 8 subbands */
				buf[10] = 0x02;
				buf[11] = 0x33;
				printf("Accepting get capabilities command\n");
				len = write(sk, buf, 12);
			}
			break;

		default:
			buf[1] = 0x00;
			printf("Unknown command\n");
			len = write(sk, buf, 2);
			break;
		}
	}
}

static void do_listen(const bdaddr_t *src, unsigned char reject)
{
	struct sockaddr_l2 addr;
	socklen_t optlen;
	int sk, nsk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);
	addr.l2_psm = htobs(25);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	if (listen(sk, 10)) {
		perror("Can't listen on the socket");
		goto error;
	}

	while (1) {
		memset(&addr, 0, sizeof(addr));
		optlen = sizeof(addr);

		nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
		if (nsk < 0) {
			perror("Accept failed");
			continue;
		}

		process_sigchan(nsk, reject);

		close(nsk);
	}

error:
	close(sk);
}

static void usage()
{
	printf("avtest - Audio/Video testing ver %s\n", VERSION);
	printf("Usage:\n"
		"\tavtest [options]\n");
	printf("Options:\n"
		"\t--reject <command>\tReject command\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ "reject",	1, 0, 'r' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	unsigned char reject = 0x00;
	bdaddr_t src, dst;
	int opt;

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	while ((opt = getopt_long(argc, argv, "+i:r:h",
						main_options, NULL)) != EOF) {
		switch (opt) {
		case 'i':
			if (!strncmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &src);
			else
				str2ba(optarg, &src);
			break;

		case 'r':
			if (!strncmp(optarg, "discov", 6))
				reject = AVDTP_DISCOVER;
			else if (!strncmp(optarg, "capa", 4))
				reject = AVDTP_GET_CAPABILITIES;
			else if (!strncmp(optarg, "getcapa", 7))
				reject = AVDTP_GET_CAPABILITIES;
			else if (!strncmp(optarg, "setconf", 7))
				reject = AVDTP_SET_CONFIGURATION;
			else if (!strncmp(optarg, "getconf", 7))
				reject = AVDTP_GET_CONFIGURATION;
			else
				reject = atoi(optarg);
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	do_listen(&src, reject);

	return 0;
}
