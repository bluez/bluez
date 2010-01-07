/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) library
 *
 *  Copyright (C) 2008-2010  Nokia Corporation
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <libgen.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
struct sbc_frame_hdr {
	uint8_t syncword:8;		/* Sync word */
	uint8_t subbands:1;		/* Subbands */
	uint8_t allocation_method:1;	/* Allocation method */
	uint8_t channel_mode:2;		/* Channel mode */
	uint8_t blocks:2;		/* Blocks */
	uint8_t sampling_frequency:2;	/* Sampling frequency */
	uint8_t bitpool:8;		/* Bitpool */
	uint8_t crc_check:8;		/* CRC check */
} __attribute__ ((packed));
#elif __BYTE_ORDER == __BIG_ENDIAN
struct sbc_frame_hdr {
	uint8_t syncword:8;		/* Sync word */
	uint8_t sampling_frequency:2;	/* Sampling frequency */
	uint8_t blocks:2;		/* Blocks */
	uint8_t channel_mode:2;		/* Channel mode */
	uint8_t allocation_method:1;	/* Allocation method */
	uint8_t subbands:1;		/* Subbands */
	uint8_t bitpool:8;		/* Bitpool */
	uint8_t crc_check:8;		/* CRC check */
} __attribute__ ((packed));
#else
#error "Unknown byte order"
#endif

static int calc_frame_len(struct sbc_frame_hdr *hdr)
{
	int tmp, nrof_subbands, nrof_blocks;

	nrof_subbands = (hdr->subbands + 1) * 4;
	nrof_blocks = (hdr->blocks + 1) * 4;

	switch (hdr->channel_mode) {
	case 0x00:
		nrof_subbands /= 2;
		tmp = nrof_blocks * hdr->bitpool;
		break;
	case 0x01:
		tmp = nrof_blocks * hdr->bitpool * 2;
		break;
	case 0x02:
		tmp = nrof_blocks * hdr->bitpool;
		break;
	case 0x03:
		tmp = nrof_blocks * hdr->bitpool + nrof_subbands;
		break;
	default:
		return 0;
	}

	return (nrof_subbands + ((tmp + 7) / 8));
}

static double calc_bit_rate(struct sbc_frame_hdr *hdr)
{
	int nrof_subbands, nrof_blocks;
	double f;

	nrof_subbands = (hdr->subbands + 1) * 4;
	nrof_blocks = (hdr->blocks + 1) * 4;

	switch (hdr->sampling_frequency) {
	case 0:
		f = 16;
		break;
	case 1:
		f = 32;
		break;
	case 2:
		f = 44.1;
		break;
	case 3:
		f = 48;
		break;
	default:
		return 0;
	}

	return ((8 * (calc_frame_len(hdr) + 4) * f) /
			(nrof_subbands * nrof_blocks));
}

static char *freq2str(uint8_t freq)
{
	switch (freq) {
	case 0:
		return "16 kHz";
	case 1:
		return "32 kHz";
	case 2:
		return "44.1 kHz";
	case 3:
		return "48 kHz";
	default:
		return "Unknown";
	}
}

static char *mode2str(uint8_t mode)
{
	switch (mode) {
	case 0:
		return "Mono";
	case 1:
		return "Dual Channel";
	case 2:
		return "Stereo";
	case 3:
		return "Joint Stereo";
	default:
		return "Unknown";
	}
}

static ssize_t __read(int fd, void *buf, size_t count)
{
	ssize_t len, pos = 0;

	while (count > 0) {
		len = read(fd, buf + pos, count);
		if (len <= 0)
			return len;

		count -= len;
		pos   += len;
	}

	return pos;
}

#define SIZE 32

static int analyze_file(char *filename)
{
	struct sbc_frame_hdr hdr;
	unsigned char buf[64];
	double rate;
	int bitpool[SIZE], frame_len[SIZE];
	int subbands, blocks, freq, mode, method;
	int n, p1, p2, fd, size, num;
	ssize_t len;
	unsigned int count;

	if (strcmp(filename, "-")) {
		printf("Filename\t\t%s\n", basename(filename));

		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			perror("Can't open file");
			return -1;
		}
	} else
		fd = fileno(stdin);

	len = __read(fd, &hdr, sizeof(hdr));
	if (len != sizeof(hdr) || hdr.syncword != 0x9c) {
		fprintf(stderr, "Not a SBC audio file\n");
		return -1;
	}

	subbands = (hdr.subbands + 1) * 4;
	blocks = (hdr.blocks + 1) * 4;
	freq = hdr.sampling_frequency;
	mode = hdr.channel_mode;
	method = hdr.allocation_method;

	count = calc_frame_len(&hdr);

	bitpool[0] = hdr.bitpool;
	frame_len[0] = count + 4;

	for (n = 1; n < SIZE; n++) {
		bitpool[n] = 0;
		frame_len[n] = 0;
	}

	if (lseek(fd, 0, SEEK_SET) < 0) {
		num = 1;
		rate = calc_bit_rate(&hdr);
		while (count) {
			size = count > sizeof(buf) ? sizeof(buf) : count;
			len = __read(fd, buf, size);
			if (len < 0)
				break;
			count -= len;
		}
	} else {
		num = 0;
		rate = 0;
	}

	while (1) {
		len = __read(fd, &hdr, sizeof(hdr));
		if (len < 0) {
			fprintf(stderr, "Unable to read frame header"
					" (error %d)\n", errno);
			break;
		}

		if (len == 0)
			break;

		if ((size_t) len < sizeof(hdr) || hdr.syncword != 0x9c) {
			fprintf(stderr, "Corrupted SBC stream "
					"(len %zd syncword 0x%02x)\n",
					len, hdr.syncword);
			break;
		}

		count = calc_frame_len(&hdr);
		len = count + 4;

		p1 = -1;
		p2 = -1;
		for (n = 0; n < SIZE; n++) {
			if (p1 < 0 && (bitpool[n] == 0 || bitpool[n] == hdr.bitpool))
				p1 = n;
			if (p2 < 0 && (frame_len[n] == 0 || frame_len[n] == len))
				p2 = n;
		}
		if (p1 >= 0)
			bitpool[p1] = hdr.bitpool;
		if (p2 >= 0)
			frame_len[p2] = len;

		while (count) {
			size = count > sizeof(buf) ? sizeof(buf) : count;

			len = __read(fd, buf, size);
			if (len != size) {
				fprintf(stderr, "Unable to read frame data "
						"(error %d)\n", errno);
				break;
			}

			count -= len;
		}

		rate += calc_bit_rate(&hdr);
		num++;
	}

	printf("Subbands\t\t%d\n", subbands);
	printf("Block length\t\t%d\n", blocks);
	printf("Sampling frequency\t%s\n", freq2str(freq));
	printf("Channel mode\t\t%s\n", mode2str(hdr.channel_mode));
	printf("Allocation method\t%s\n", method ? "SNR" : "Loudness");
	printf("Bitpool\t\t\t%d", bitpool[0]);
	for (n = 1; n < SIZE; n++)
		if (bitpool[n] > 0)
			printf(", %d", bitpool[n]);
	printf("\n");
	printf("Number of frames\t%d\n", num);
	printf("Frame length\t\t%d", frame_len[0]);
	for (n = 1; n < SIZE; n++)
		if (frame_len[n] > 0)
			printf(", %d", frame_len[n]);
	printf(" Bytes\n");
	if (num > 0)
		printf("Bit rate\t\t%.3f kbps\n", rate / num);

	if (fd > fileno(stderr))
		close(fd);

	printf("\n");

	return 0;
}

int main(int argc, char *argv[])
{
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: sbcinfo <file>\n");
		exit(1);
	}

	for (i = 0; i < argc - 1; i++)
		if (analyze_file(argv[i + 1]) < 0)
			exit(1);

	return 0;
}
