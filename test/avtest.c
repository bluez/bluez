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
#define AVDTP_RECONFIGURE		0x05
#define AVDTP_OPEN			0x06

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

static const unsigned char media_transport[] = {
		0x01,	/* Media transport category */
		0x00,
		0x07,	/* Media codec category */
		0x06,
		0x00,	/* Media type audio */
		0x00,	/* Codec SBC */
		0x22,	/* 44.1 kHz, stereo */
		0x15,	/* 16 blocks, 8 subbands */
		0x02,
		0x33,
};

static int media_sock = -1;

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
				memcpy(&buf[2], media_transport,
						sizeof(media_transport));
				printf("Accepting get capabilities command\n");
				len = write(sk, buf,
						2 + sizeof(media_transport));
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

static int do_connect(const bdaddr_t *src, const bdaddr_t *dst)
{
	struct sockaddr_l2 addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, dst);
	addr.l2_psm = htobs(25);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		perror("Unable to connect");
		goto error;
	}

	return sk;

error:
	close(sk);
	return -1;
}

static void do_send(int sk, const bdaddr_t *src, const bdaddr_t *dst,
				unsigned char cmd, int invalid, int preconf)
{
	unsigned char buf[672];
	struct avdtp_header *hdr = (void *) buf;
	ssize_t len;

	memset(buf, 0, sizeof(buf));

	switch (cmd) {
	case AVDTP_DISCOVER:
		if (invalid)
			hdr->message_type = 0x01;
		else
			hdr->message_type = AVDTP_MSG_TYPE_COMMAND;
		hdr->packet_type = AVDTP_PKT_TYPE_SINGLE;
		hdr->signal_id = AVDTP_DISCOVER;
		len = write(sk, buf, 2);
		break;

	case AVDTP_GET_CAPABILITIES:
		hdr->message_type = AVDTP_MSG_TYPE_COMMAND;
		hdr->packet_type = AVDTP_PKT_TYPE_SINGLE;
		hdr->signal_id = AVDTP_GET_CAPABILITIES;
		buf[2] = 1 << 2; /* SEID 1 */
		len = write(sk, buf, invalid ? 2 : 3);
		break;

	case AVDTP_SET_CONFIGURATION:
		if (invalid)
			do_send(sk, src, dst, cmd, 0, 0);
		hdr->message_type = AVDTP_MSG_TYPE_COMMAND;
		hdr->packet_type = AVDTP_PKT_TYPE_SINGLE;
		hdr->signal_id = AVDTP_SET_CONFIGURATION;
		buf[2] = 1 << 2; /* ACP SEID */
		buf[3] = 1 << 2; /* INT SEID */
		memcpy(&buf[4], media_transport, sizeof(media_transport));
		len = write(sk, buf, 4 + sizeof(media_transport));
		break;

	case AVDTP_GET_CONFIGURATION:
		if (preconf)
			do_send(sk, src, dst, AVDTP_SET_CONFIGURATION, 0, 0);
		hdr->message_type = AVDTP_MSG_TYPE_COMMAND;
		hdr->packet_type = AVDTP_PKT_TYPE_SINGLE;
		hdr->signal_id = AVDTP_GET_CONFIGURATION;
		if (invalid)
			buf[2] = 13 << 2; /* Invalid ACP SEID */
		else
			buf[2] = 1 << 2; /* Valid ACP SEID */
		len = write(sk, buf, 3);
		break;

	case AVDTP_OPEN:
		if (preconf)
			do_send(sk, src, dst, AVDTP_SET_CONFIGURATION, 0, 0);
		hdr->message_type = AVDTP_MSG_TYPE_COMMAND;
		hdr->packet_type = AVDTP_PKT_TYPE_SINGLE;
		hdr->signal_id = AVDTP_OPEN;
		buf[2] = 1 << 2; /* ACP SEID */
		len = write(sk, buf, 3);
		break;
	}

	len = read(sk, buf, sizeof(buf));

	dump_buffer(buf, len);
	dump_header(hdr);

	if (cmd == AVDTP_OPEN)
		media_sock = do_connect(src, dst);
}

static void usage()
{
	printf("avtest - Audio/Video testing ver %s\n", VERSION);
	printf("Usage:\n"
		"\tavtest [options] [remote address]\n");
	printf("Options:\n"
		"\t--reject <command>\tReject command\n"
		"\t--send <command>\tSend command\n"
		"\t--invalid <command>\tSend invalid command\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ "reject",	1, 0, 'r' },
	{ "send",	1, 0, 's' },
	{ "invalid",	1, 0, 'f' },
	{ "preconf",	0, 0, 'c' },
	{ 0, 0, 0, 0 }
};

static unsigned char parse_cmd(const char *arg)
{
	if (!strncmp(arg, "discov", 6))
		return AVDTP_DISCOVER;
	else if (!strncmp(arg, "capa", 4))
		return AVDTP_GET_CAPABILITIES;
	else if (!strncmp(arg, "getcapa", 7))
		return AVDTP_GET_CAPABILITIES;
	else if (!strncmp(arg, "setconf", 7))
		return AVDTP_SET_CONFIGURATION;
	else if (!strncmp(arg, "getconf", 7))
		return AVDTP_GET_CONFIGURATION;
	else if (!strncmp(arg, "open", 4))
		return AVDTP_OPEN;
	else
		return atoi(arg);
}

enum {
	MODE_NONE, MODE_REJECT, MODE_SEND,
};

int main(int argc, char *argv[])
{
	unsigned char cmd = 0x00;
	bdaddr_t src, dst;
	int opt, mode = MODE_NONE, sk, invalid = 0, preconf = 0;

	bacpy(&src, BDADDR_ANY);
	bacpy(&dst, BDADDR_ANY);

	while ((opt = getopt_long(argc, argv, "+i:r:s:f:hc",
						main_options, NULL)) != EOF) {
		switch (opt) {
		case 'i':
			if (!strncmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &src);
			else
				str2ba(optarg, &src);
			break;

		case 'r':
			mode = MODE_REJECT;
			cmd = parse_cmd(optarg);
			break;

		case 'f':
			invalid = 1;
			/* Intentionally missing break */

		case 's':
			mode = MODE_SEND;
			cmd = parse_cmd(optarg);
			break;

		case 'c':
			preconf = 1;
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	if (argv[optind])
		str2ba(argv[optind], &dst);

	switch (mode) {
	case MODE_REJECT:
		do_listen(&src, cmd);
		break;
	case MODE_SEND:
		sk = do_connect(&src, &dst);
		if (sk < 0)
			exit(1);
		do_send(sk, &src, &dst, cmd, invalid, preconf);
		if (media_sock >= 0)
			close(media_sock);
		close(sk);
		break;
	default:
		fprintf(stderr, "No operating mode specified!\n");
		exit(1);
	}

	return 0;
}
