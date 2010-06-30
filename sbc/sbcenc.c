/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) encoder
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
#include <getopt.h>
#include <sys/stat.h>

#include "sbc.h"
#include "formats.h"

static int verbose = 0;

#define BUF_SIZE 32768
static unsigned char input[BUF_SIZE], output[BUF_SIZE + BUF_SIZE / 4];

static void encode(char *filename, int subbands, int bitpool, int joint,
					int dualchannel, int snr, int blocks)
{
	struct au_header au_hdr;
	sbc_t sbc;
	int fd, size, srate, codesize, nframes;
	ssize_t encoded;
	ssize_t len;

	if (sizeof(au_hdr) != 24) {
		/* Sanity check just in case */
		fprintf(stderr, "FIXME: sizeof(au_hdr) != 24\n");
		return;
	}

	if (strcmp(filename, "-")) {
		fd = open(filename, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Can't open file %s: %s\n",
						filename, strerror(errno));
			return;
		}
	} else
		fd = fileno(stdin);

	len = read(fd, &au_hdr, sizeof(au_hdr));
	if (len < (ssize_t) sizeof(au_hdr)) {
		if (fd > fileno(stderr))
			fprintf(stderr, "Can't read header from file %s: %s\n",
						filename, strerror(errno));
		else
			perror("Can't read audio header");
		goto done;
	}

	if (au_hdr.magic != AU_MAGIC ||
			BE_INT(au_hdr.hdr_size) > 128 ||
			BE_INT(au_hdr.hdr_size) < sizeof(au_hdr) ||
			BE_INT(au_hdr.encoding) != AU_FMT_LIN16) {
		fprintf(stderr, "Not in Sun/NeXT audio S16_BE format\n");
		goto done;
	}

	sbc_init(&sbc, 0L);

	switch (BE_INT(au_hdr.sample_rate)) {
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

	srate = BE_INT(au_hdr.sample_rate);

	sbc.subbands = subbands == 4 ? SBC_SB_4 : SBC_SB_8;

	if (BE_INT(au_hdr.channels) == 1) {
		sbc.mode = SBC_MODE_MONO;
		if (joint || dualchannel) {
			fprintf(stderr, "Audio is mono but joint or "
				"dualchannel mode has been specified\n");
			goto done;
		}
	} else if (joint && !dualchannel)
		sbc.mode = SBC_MODE_JOINT_STEREO;
	else if (!joint && dualchannel)
		sbc.mode = SBC_MODE_DUAL_CHANNEL;
	else if (!joint && !dualchannel)
		sbc.mode = SBC_MODE_STEREO;
	else {
		fprintf(stderr, "Both joint and dualchannel mode have been "
								"specified\n");
		goto done;
	}

	sbc.endian = SBC_BE;
	/* Skip extra bytes of the header if any */
	if (read(fd, input, BE_INT(au_hdr.hdr_size) - len) < 0)
		goto done;

	sbc.bitpool = bitpool;
	sbc.allocation = snr ? SBC_AM_SNR : SBC_AM_LOUDNESS;
	sbc.blocks = blocks == 4 ? SBC_BLK_4 :
			blocks == 8 ? SBC_BLK_8 :
				blocks == 12 ? SBC_BLK_12 : SBC_BLK_16;

	if (verbose) {
		fprintf(stderr, "encoding %s with rate %d, %d blocks, "
			"%d subbands, %d bits, allocation method %s, "
							"and mode %s\n",
			filename, srate, blocks, subbands, bitpool,
			sbc.allocation == SBC_AM_SNR ? "SNR" : "LOUDNESS",
			sbc.mode == SBC_MODE_MONO ? "MONO" :
					sbc.mode == SBC_MODE_STEREO ?
						"STEREO" : "JOINTSTEREO");
	}

	codesize = sbc_get_codesize(&sbc);
	nframes = sizeof(input) / codesize;
	while (1) {
		unsigned char *inp, *outp;
		/* read data for up to 'nframes' frames of input data */
		size = read(fd, input, codesize * nframes);
		if (size < 0) {
			/* Something really bad happened */
			perror("Can't read audio data");
			break;
		}
		if (size < codesize) {
			/* Not enough data for encoding even a single frame */
			break;
		}
		/* encode all the data from the input buffer in a loop */
		inp = input;
		outp = output;
		while (size >= codesize) {
			len = sbc_encode(&sbc, inp, codesize,
				outp, sizeof(output) - (outp - output),
				&encoded);
			if (len != codesize || encoded <= 0) {
				fprintf(stderr,
					"sbc_encode fail, len=%zd, encoded=%lu\n",
					len, (unsigned long) encoded);
				break;
			}
			size -= len;
			inp += len;
			outp += encoded;
		}
		len = write(fileno(stdout), output, outp - output);
		if (len != outp - output) {
			perror("Can't write SBC output");
			break;
		}
		if (size != 0) {
			/*
			 * sbc_encode failure has been detected earlier or end
			 * of file reached (have trailing partial data which is
			 * insufficient to encode SBC frame)
			 */
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
	printf("Copyright (c) 2004-2010  Marcel Holtmann\n\n");

	printf("Usage:\n"
		"\tsbcenc [options] file(s)\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\t-v, --verbose        Verbose mode\n"
		"\t-s, --subbands       Number of subbands to use (4 or 8)\n"
		"\t-b, --bitpool        Bitpool value (default is 32)\n"
		"\t-j, --joint          Joint stereo\n"
		"\t-d, --dualchannel    Dual channel\n"
		"\t-S, --snr            Use SNR mode (default is loudness)\n"
		"\t-B, --blocks         Number of blocks (4, 8, 12 or 16)\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "verbose",	0, 0, 'v' },
	{ "subbands",	1, 0, 's' },
	{ "bitpool",	1, 0, 'b' },
	{ "joint",	0, 0, 'j' },
	{ "dualchannel",0, 0, 'd' },
	{ "snr",	0, 0, 'S' },
	{ "blocks",	1, 0, 'B' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	int i, opt, subbands = 8, bitpool = 32, joint = 0, dualchannel = 0;
	int snr = 0, blocks = 16;

	while ((opt = getopt_long(argc, argv, "+hvs:b:jdSB:",
						main_options, NULL)) != -1) {
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
				fprintf(stderr, "Invalid subbands\n");
				exit(1);
			}
			break;

		case 'b':
			bitpool = atoi(optarg);
			break;

		case 'j':
			joint = 1;
			break;

		case 'd':
			dualchannel = 1;
			break;

		case 'S':
			snr = 1;
			break;

		case 'B':
			blocks = atoi(optarg);
			if (blocks != 16 && blocks != 12 &&
						blocks != 8 && blocks != 4) {
				fprintf(stderr, "Invalid blocks\n");
				exit(1);
			}
			break;

		default:
			usage();
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
		encode(argv[i], subbands, bitpool, joint, dualchannel,
								snr, blocks);

	return 0;
}
