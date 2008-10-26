/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) encoder
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <getopt.h>
#include <sys/stat.h>

#include "sbc.h"
#include "formats.h"

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

static ssize_t __write(int fd, const void *buf, size_t count)
{
	ssize_t len, pos = 0;

	while (count > 0) {
		len = write(fd, buf + pos, count);
		if (len <= 0)
			return len;

		count -= len;
		pos   += len;
	}

	return pos;
}

static void encode(char *filename, int subbands, int bitpool, int joint)
{
	struct au_header *au_hdr;
	unsigned char input[2048], output[2048];
	sbc_t sbc;
	int fd, len, size, count, encoded;

	if (strcmp(filename, "-")) {
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Can't open file %s: %s\n",
						filename, strerror(errno));
			return;
		}
	} else
		fd = fileno(stdin);

	len = __read(fd, input, sizeof(input));
	if (len < sizeof(*au_hdr)) {
		if (fd > fileno(stderr))
			fprintf(stderr, "Can't read header from file %s: %s\n",
						filename, strerror(errno));
		else
			perror("Can't read audio header");
		goto done;
	}

	au_hdr = (struct au_header *) input;

	if (au_hdr->magic != AU_MAGIC ||
			BE_INT(au_hdr->hdr_size) > 128 ||
			BE_INT(au_hdr->hdr_size) < 24 ||
			BE_INT(au_hdr->encoding) != AU_FMT_LIN16) {
		fprintf(stderr, "Data is not in Sun/NeXT audio S16_BE format\n");
		goto done;
	}

	sbc_init(&sbc, 0L);

	switch (BE_INT(au_hdr->sample_rate)) {
	case 16000:
		sbc.frequency = SBC_FREQ_16000;
		break;
	case 32000:
		sbc.frequency = SBC_FREQ_32000;
		break;
	case 44100:
		sbc.frequency = SBC_FREQ_44100;
		break;
	case 48000:
		sbc.frequency = SBC_FREQ_48000;
		break;
	}

	sbc.subbands = subbands == 4 ? SBC_SB_4 : SBC_SB_8;

	if (BE_INT(au_hdr->channels) == 1)
		sbc.mode = SBC_MODE_MONO;
	else if (joint)
		sbc.mode = SBC_MODE_JOINT_STEREO;
	else
		sbc.mode = SBC_MODE_STEREO;

	sbc.endian = SBC_BE;
	count = BE_INT(au_hdr->data_size);
	size = len - BE_INT(au_hdr->hdr_size);
	memmove(input, input + BE_INT(au_hdr->hdr_size), size);

	sbc.bitpool = bitpool;

	while (1) {
		if (size < sizeof(input)) {
			len = __read(fd, input + size, sizeof(input) - size);
			if (len == 0 && size == 0)
				break;

			if (len < 0) {
				perror("Can't read audio data");
				break;
			}

			size += len;
		}

		len = sbc_encode(&sbc, input, size,
					output, sizeof(output), &encoded);
		if (len < size)
			memmove(input, input + len, size - len);

		size -= len;

		len = __write(fileno(stdout), output, encoded);
		if (len == 0)
			break;

		if (len < 0 || len != encoded) {
			perror("Can't write SBC output");
			break;
		}
	}

	sbc_finish(&sbc);

done:
	if (fd > fileno(stderr))
		close(fd);
}

static void usage(void)
{
	printf("SBC encoder utility ver %s\n", VERSION);
	printf("Copyright (c) 2004-2008  Marcel Holtmann\n\n");

	printf("Usage:\n"
		"\tsbcenc [options] file(s)\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\t-v, --verbose        Verbose mode\n"
		"\t-s, --subbands       Number of subbands to use (4 or 8)\n"
		"\t-b, --bitpool        Bitpool value (default is 32)\n"
		"\t-j, --joint          Joint stereo\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "verbose",	0, 0, 'v' },
	{ "subbands",	1, 0, 's' },
	{ "bitpool",	1, 0, 'b' },
	{ "joint",	0, 0, 'j' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int i, opt, verbose = 0, subbands = 8, bitpool = 32, joint = 0;

	while ((opt = getopt_long(argc, argv, "+hvs:b:j", main_options, NULL)) != -1) {
		switch(opt) {
		case 'h':
			usage();
			exit(0);

		case 'v':
			verbose = 1;
			break;

		case 's':
			subbands = atoi(optarg);
			if (subbands != 8 && subbands != 4) {
				fprintf(stderr, "Invalid subbands %d!\n",
						subbands);
				exit(1);
			}
			break;

		case 'b':
			bitpool = atoi(optarg);
			break;

		case 'j':
			joint = 1;
			break;

		default:
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		exit(1);
	}

	for (i = 0; i < argc; i++)
		encode(argv[i], subbands, bitpool, joint);

	return 0;
}
