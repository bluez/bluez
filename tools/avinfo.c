/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#define AVDTP_PSM			25

/* Commands */
#define AVDTP_DISCOVER			0x01
#define AVDTP_GET_CAPABILITIES		0x02

#define AVDTP_PKT_TYPE_SINGLE		0x00

#define AVDTP_MSG_TYPE_COMMAND		0x00

/* SEP capability categories */
#define AVDTP_MEDIA_TRANSPORT		0x01
#define AVDTP_REPORTING			0x02
#define AVDTP_RECOVERY			0x03
#define AVDTP_CONTENT_PROTECTION	0x04
#define AVDTP_HEADER_COMPRESSION	0x05
#define AVDTP_MULTIPLEXING		0x06
#define AVDTP_MEDIA_CODEC		0x07

/* SEP types definitions */
#define AVDTP_SEP_TYPE_SOURCE		0x00
#define AVDTP_SEP_TYPE_SINK		0x01

/* Media types definitions */
#define AVDTP_MEDIA_TYPE_AUDIO		0x00
#define AVDTP_MEDIA_TYPE_VIDEO		0x01
#define AVDTP_MEDIA_TYPE_MULTIMEDIA	0x02

#define A2DP_CODEC_SBC			0x00
#define A2DP_CODEC_MPEG12		0x01
#define A2DP_CODEC_MPEG24		0x02
#define A2DP_CODEC_ATRAC		0x03

#define SBC_SAMPLING_FREQ_16000		(1 << 3)
#define SBC_SAMPLING_FREQ_32000		(1 << 2)
#define SBC_SAMPLING_FREQ_44100		(1 << 1)
#define SBC_SAMPLING_FREQ_48000		(1 << 0)

#define SBC_CHANNEL_MODE_MONO		(1 << 3)
#define SBC_CHANNEL_MODE_DUAL_CHANNEL	(1 << 2)
#define SBC_CHANNEL_MODE_STEREO		(1 << 1)
#define SBC_CHANNEL_MODE_JOINT_STEREO	(1 << 0)

#define SBC_BLOCK_LENGTH_4		(1 << 3)
#define SBC_BLOCK_LENGTH_8		(1 << 2)
#define SBC_BLOCK_LENGTH_12		(1 << 1)
#define SBC_BLOCK_LENGTH_16		(1 << 0)

#define SBC_SUBBANDS_4			(1 << 1)
#define SBC_SUBBANDS_8			(1 << 0)

#define SBC_ALLOCATION_SNR		(1 << 1)
#define SBC_ALLOCATION_LOUDNESS		(1 << 0)

#define MPEG_CHANNEL_MODE_MONO		(1 << 3)
#define MPEG_CHANNEL_MODE_DUAL_CHANNEL	(1 << 2)
#define MPEG_CHANNEL_MODE_STEREO	(1 << 1)
#define MPEG_CHANNEL_MODE_JOINT_STEREO	(1 << 0)

#define MPEG_LAYER_MP1			(1 << 2)
#define MPEG_LAYER_MP2			(1 << 1)
#define MPEG_LAYER_MP3			(1 << 0)

#define MPEG_SAMPLING_FREQ_16000	(1 << 5)
#define MPEG_SAMPLING_FREQ_22050	(1 << 4)
#define MPEG_SAMPLING_FREQ_24000	(1 << 3)
#define MPEG_SAMPLING_FREQ_32000	(1 << 2)
#define MPEG_SAMPLING_FREQ_44100	(1 << 1)
#define MPEG_SAMPLING_FREQ_48000	(1 << 0)

#define MPEG_BIT_RATE_VBR		0x8000
#define MPEG_BIT_RATE_320000		0x4000
#define MPEG_BIT_RATE_256000		0x2000
#define MPEG_BIT_RATE_224000		0x1000
#define MPEG_BIT_RATE_192000		0x0800
#define MPEG_BIT_RATE_160000		0x0400
#define MPEG_BIT_RATE_128000		0x0200
#define MPEG_BIT_RATE_112000		0x0100
#define MPEG_BIT_RATE_96000		0x0080
#define MPEG_BIT_RATE_80000		0x0040
#define MPEG_BIT_RATE_64000		0x0020
#define MPEG_BIT_RATE_56000		0x0010
#define MPEG_BIT_RATE_48000		0x0008
#define MPEG_BIT_RATE_40000		0x0004
#define MPEG_BIT_RATE_32000		0x0002
#define MPEG_BIT_RATE_FREE		0x0001

struct avdtp_service_capability {
	uint8_t category;
	uint8_t length;
	uint8_t data[0];
} __attribute__ ((packed));

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

struct seid_req {
	struct avdtp_header header;
	uint8_t rfa0:2;
	uint8_t acp_seid:6;
} __attribute__ ((packed));

struct avdtp_media_codec_capability {
	uint8_t rfa0:4;
	uint8_t media_type:4;
	uint8_t media_codec_type;
	uint8_t data[0];
} __attribute__ ((packed));

struct sbc_codec_cap {
	struct avdtp_media_codec_capability cap;
	uint8_t channel_mode:4;
	uint8_t frequency:4;
	uint8_t allocation_method:2;
	uint8_t subbands:2;
	uint8_t block_length:4;
	uint8_t min_bitpool;
	uint8_t max_bitpool;
} __attribute__ ((packed));

struct mpeg_codec_cap {
	struct avdtp_media_codec_capability cap;
	uint8_t channel_mode:4;
	uint8_t crc:1;
	uint8_t layer:3;
	uint8_t frequency:6;
	uint8_t mpf:1;
	uint8_t rfa:1;
	uint16_t bitrate;
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

struct seid_req {
	struct avdtp_header header;
	uint8_t acp_seid:6;
	uint8_t rfa0:2;
} __attribute__ ((packed));

struct avdtp_media_codec_capability {
	uint8_t media_type:4;
	uint8_t rfa0:4;
	uint8_t media_codec_type;
	uint8_t data[0];
} __attribute__ ((packed));

struct sbc_codec_cap {
	struct avdtp_media_codec_capability cap;
	uint8_t frequency:4;
	uint8_t channel_mode:4;
	uint8_t block_length:4;
	uint8_t subbands:2;
	uint8_t allocation_method:2;
	uint8_t min_bitpool;
	uint8_t max_bitpool;
} __attribute__ ((packed));

struct mpeg_codec_cap {
	struct avdtp_media_codec_capability cap;
	uint8_t layer:3;
	uint8_t crc:1;
	uint8_t channel_mode:4;
	uint8_t rfa:1;
	uint8_t mpf:1;
	uint8_t frequency:6;
	uint16_t bitrate;
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

struct discover_resp {
	struct avdtp_header header;
	struct seid_info seps[0];
} __attribute__ ((packed));

struct getcap_resp {
	struct avdtp_header header;
	uint8_t caps[0];
} __attribute__ ((packed));


static void print_mpeg12(struct mpeg_codec_cap *mpeg)
{
	printf("\tMedia Codec: MPEG12\n\t\tChannel Modes: ");

	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_MONO)
		printf("Mono ");
	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_DUAL_CHANNEL)
		printf("DualChannel ");
	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_STEREO)
		printf("Stereo ");
	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_JOINT_STEREO)
		printf("JointStereo");

	printf("\n\t\tFrequencies: ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_16000)
		printf("16Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_22050)
		printf("22.05Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_24000)
		printf("24Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_32000)
		printf("32Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_44100)
		printf("44.1Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_48000)
		printf("48Khz ");

	printf("\n\t\tCRC: %s", mpeg->crc ? "Yes" : "No");

	printf("\n\t\tLayer: ");
	if (mpeg->layer & MPEG_LAYER_MP1)
		printf("1 ");
	if (mpeg->layer & MPEG_LAYER_MP2)
		printf("2 ");
	if (mpeg->layer & MPEG_LAYER_MP3)
		printf("3 ");

	printf("\n\t\tBit Rate: ");
	if (mpeg->bitrate & MPEG_BIT_RATE_FREE)
		printf("Free format");
	else {
		if (mpeg->bitrate & MPEG_BIT_RATE_32000)
			printf("32kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_40000)
			printf("40kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_48000)
			printf("48kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_56000)
			printf("56kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_64000)
			printf("64kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_80000)
			printf("80kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_96000)
			printf("96kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_112000)
			printf("112kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_128000)
			printf("128kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_160000)
			printf("160kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_192000)
			printf("192kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_224000)
			printf("224kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_256000)
			printf("256kbps ");
		if (mpeg->bitrate & MPEG_BIT_RATE_320000)
			printf("320kbps ");
	}

	printf("\n\t\tVBR: %s", mpeg->bitrate & MPEG_BIT_RATE_VBR ? "Yes" :
		"No");

	printf("\n\t\tPayload Format: ");
	if (mpeg->mpf)
		printf("RFC-2250 RFC-3119\n");
	else
		printf("RFC-2250\n");
}

static void print_sbc(struct sbc_codec_cap *sbc)
{
	printf("\tMedia Codec: SBC\n\t\tChannel Modes: ");

	if (sbc->channel_mode & SBC_CHANNEL_MODE_MONO)
		printf("Mono ");
	if (sbc->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL)
		printf("DualChannel ");
	if (sbc->channel_mode & SBC_CHANNEL_MODE_STEREO)
		printf("Stereo ");
	if (sbc->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO)
		printf("JointStereo");

	printf("\n\t\tFrequencies: ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_16000)
		printf("16Khz ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_32000)
		printf("32Khz ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_44100)
		printf("44.1Khz ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_48000)
		printf("48Khz ");

	printf("\n\t\tSubbands: ");
	if (sbc->allocation_method & SBC_SUBBANDS_4)
		printf("4 ");
	if (sbc->allocation_method & SBC_SUBBANDS_8)
		printf("8");

	printf("\n\t\tBlocks: ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_4)
		printf("4 ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_8)
		printf("8 ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_12)
		printf("12 ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_16)
		printf("16 ");

	printf("\n\t\tBitpool Range: %d-%d\n",
				sbc->min_bitpool, sbc->max_bitpool);
}

static void print_media_codec(struct avdtp_media_codec_capability *cap)
{
	switch (cap->media_codec_type) {
	case A2DP_CODEC_SBC:
		print_sbc((void *) cap);
		break;
	case A2DP_CODEC_MPEG12:
		print_mpeg12((void *) cap);
		break;
	default:
		printf("\tMedia Codec: Unknown\n");
	}
}

static void print_caps(void *data, int size)
{
	int processed;

	for (processed = 0; processed + 2 < size;) {
		struct avdtp_service_capability *cap;

		cap = data;

		if (processed + 2 + cap->length > size) {
			printf("Invalid capability data in getcap resp\n");
			break;
		}

		switch (cap->category) {
		case AVDTP_MEDIA_TRANSPORT:
		case AVDTP_REPORTING:
		case AVDTP_RECOVERY:
		case AVDTP_CONTENT_PROTECTION:
		case AVDTP_MULTIPLEXING:
			/* FIXME: Add proper functions */
			break;
		case AVDTP_MEDIA_CODEC:
			print_media_codec((void *) cap->data);
			break;
		}

		processed += 2 + cap->length;
		data += 2 + cap->length;
	}
}

static void init_request(struct avdtp_header *header, int request_id)
{
	static int transaction = 0;

	header->packet_type = AVDTP_PKT_TYPE_SINGLE;
	header->message_type = AVDTP_MSG_TYPE_COMMAND;
	header->transaction = transaction;
	header->signal_id = request_id;

	/* clear rfa bits */
	header->rfa0 = 0;

	transaction = (transaction + 1) % 16;
}

static ssize_t avdtp_send(int sk, void *data, int len)
{
	ssize_t ret;

	ret = send(sk, data, len, 0);

	if (ret < 0)
		ret = -errno;
	else if (ret != len)
		ret = -EIO;

	if (ret < 0) {
		printf("Unable to send message: %s (%zd)\n",
						strerror(-ret), -ret);
		return ret;
	}

	return ret;
}

static ssize_t avdtp_receive(int sk, void *data, int len)
{
	ssize_t ret;

	ret = recv(sk, data, len, 0);

	if (ret < 0) {
		printf("Unable to receive message: %s (%d)\n",
						strerror(errno), errno);
		return -errno;
	}

	return ret;
}

static ssize_t avdtp_get_caps(int sk, int seid)
{
	struct seid_req req;
	char buffer[1024];
	struct getcap_resp *caps = (void *) buffer;
	ssize_t ret;

	memset(&req, 0, sizeof(req));
	init_request(&req.header, AVDTP_GET_CAPABILITIES);
	req.acp_seid = seid;

	ret = avdtp_send(sk, &req, sizeof(req));
	if (ret < 0)
		return ret;

	memset(&buffer, 0, sizeof(buffer));
	ret = avdtp_receive(sk, caps, sizeof(buffer));
	if (ret < 0)
		return ret;

	if ((size_t) ret < (sizeof(struct getcap_resp) + 4 +
			sizeof(struct avdtp_media_codec_capability))) {
		printf("Invalid capabilities\n");
		return -1;
	}

	print_caps(caps, ret);

	return 0;
}

static ssize_t avdtp_discover(int sk)
{
	struct avdtp_header req;
	char buffer[256];
	struct discover_resp *discover = (void *) buffer;
	int seps, i;
	ssize_t ret;

	memset(&req, 0, sizeof(req));
	init_request(&req, AVDTP_DISCOVER);

	ret = avdtp_send(sk, &req, sizeof(req));
	if (ret < 0)
		return ret;

	memset(&buffer, 0, sizeof(buffer));
	ret = avdtp_receive(sk, discover, sizeof(buffer));
	if (ret < 0)
		return ret;

	seps = (ret - sizeof(struct avdtp_header)) / sizeof(struct seid_info);
	for (i = 0; i < seps; i++) {
		const char *type, *media;

		switch (discover->seps[i].type) {
		case AVDTP_SEP_TYPE_SOURCE:
			type = "Source";
			break;
		case AVDTP_SEP_TYPE_SINK:
			type = "Sink";
			break;
		default:
			type = "Invalid";
		}

		switch (discover->seps[i].media_type) {
		case AVDTP_MEDIA_TYPE_AUDIO:
			media = "Audio";
			break;
		case AVDTP_MEDIA_TYPE_VIDEO:
			media = "Video";
			break;
		case AVDTP_MEDIA_TYPE_MULTIMEDIA:
			media = "Multimedia";
			break;
		default:
			media = "Invalid";
		}

		printf("Stream End-Point #%d: %s %s %s\n",
					discover->seps[i].seid, media, type,
					discover->seps[i].inuse ? "*" : "");

		avdtp_get_caps(sk, discover->seps[i].seid);
	}

	return 0;
}

static int l2cap_connect(bdaddr_t *src, bdaddr_t *dst)
{
	struct sockaddr_l2 l2a;
	int sk;

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, src);

	sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		printf("Cannot create L2CAP socket. %s(%d)\n", strerror(errno),
				errno);
		return -errno;
	}

	if (bind(sk, (struct sockaddr *) &l2a, sizeof(l2a)) < 0) {
		printf("Bind failed. %s (%d)\n", strerror(errno), errno);
		return -errno;
	}

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, dst);
	l2a.l2_psm = htobs(AVDTP_PSM);

	if (connect(sk, (struct sockaddr *) &l2a, sizeof(l2a)) < 0) {
		printf("Connect failed. %s(%d)\n", strerror(errno), errno);
		return -errno;
	}

	return sk;
}

static void usage()
{
	printf("avinfo - Audio/Video Info Tool ver %s\n", VERSION);
	printf("Usage:\n"
		"\tavinfo [options] <remote address>\n");
	printf("Options:\n"
		"\t-h\t\tDisplay help\n"
		"\t-i\t\tSpecify source interface\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	bdaddr_t src, dst;
	int opt, sk, dev_id;

	if (argc < 2) {
		usage();
		exit(0);
	}

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0)) {
		printf("Cannot find any local adapter\n");
		exit(-1);
	}

	while ((opt = getopt_long(argc, argv, "+i:h", main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			if (!strncmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &src);
			else
				str2ba(optarg, &src);
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	printf("Connecting ... \n");

	if (bachk(argv[optind]) < 0) {
		printf("Invalid argument\n");
		exit(1);
	}

	str2ba(argv[optind], &dst);
	sk = l2cap_connect(&src, &dst);
	if (sk < 0)
		exit(1);

	if (avdtp_discover(sk) < 0)
		exit(1);

	return 0;
}
