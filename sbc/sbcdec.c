/*
 *
 *  Bluetooth low-complexity, subband codec (SBC) decoder
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
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/soundcard.h>

#include "sbc.h"
#include "formats.h"

#define BUF_SIZE 8192

static int verbose = 0;

static void decode(char *filename, char *output, int tofile)
{
	unsigned char buf[BUF_SIZE], *stream;
	struct stat st;
	sbc_t sbc;
	int fd, ad, pos, streamlen, framelen, count;
	size_t len;
	int format = AFMT_S16_BE, frequency, channels;
	ssize_t written;

	if (stat(filename, &st) < 0) {
		fprintf(stderr, "Can't get size of file %s: %s\n",
						filename, strerror(errno));
		return;
	}

	stream = malloc(st.st_size);

	if (!stream) {
		fprintf(stderr, "Can't allocate memory for %s: %s\n",
						filename, strerror(errno));
		return;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Can't open file %s: %s\n",
						filename, strerror(errno));
		goto free;
	}

	if (read(fd, stream, st.st_size) != st.st_size) {
		fprintf(stderr, "Can't read content of %s: %s\n",
						filename, strerror(errno));
		close(fd);
		goto free;
	}

	close(fd);

	pos = 0;
	streamlen = st.st_size;

	if (tofile)
		ad = open(output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	else
		ad = open(output, O_WRONLY, 0);

	if (ad < 0) {
		fprintf(stderr, "Can't open output %s: %s\n",
						output, strerror(errno));
		goto free;
	}

	sbc_init(&sbc, 0L);
	sbc.endian = SBC_BE;

	framelen = sbc_decode(&sbc, stream, streamlen, buf, sizeof(buf), &len);
	channels = sbc.mode == SBC_MODE_MONO ? 1 : 2;
	switch (sbc.frequency) {
	case SBC_FREQ_16000:
		frequency = 16000;
		break;

	case SBC_FREQ_32000:
		frequency = 32000;
		break;

	case SBC_FREQ_44100:
		frequency = 44100;
		break;

	case SBC_FREQ_48000:
		frequency = 48000;
		break;
	default:
		frequency = 0;
	}

	if (verbose) {
		fprintf(stderr,"decoding %s with rate %d, %d subbands, "
			"%d bits, allocation method %s and mode %s\n",
			filename, frequency, sbc.subbands * 4 + 4, sbc.bitpool,
			sbc.allocation == SBC_AM_SNR ? "SNR" : "LOUDNESS",
			sbc.mode == SBC_MODE_MONO ? "MONO" :
					sbc.mode == SBC_MODE_STEREO ?
						"STEREO" : "JOINTSTEREO");
	}

	if (tofile) {
		struct au_header au_hdr;

		au_hdr.magic       = AU_MAGIC;
		au_hdr.hdr_size    = BE_INT(24);
		au_hdr.data_size   = BE_INT(0);
		au_hdr.encoding    = BE_INT(AU_FMT_LIN16);
		au_hdr.sample_rate = BE_INT(frequency);
		au_hdr.channels    = BE_INT(channels);

		written = write(ad, &au_hdr, sizeof(au_hdr));
		if (written < (ssize_t) sizeof(au_hdr)) {
			fprintf(stderr, "Failed to write header\n");
			goto close;
		}
	} else {
		if (ioctl(ad, SNDCTL_DSP_SETFMT, &format) < 0) {
			fprintf(stderr, "Can't set audio format on %s: %s\n",
						output, strerror(errno));
			goto close;
		}

		if (ioctl(ad, SNDCTL_DSP_CHANNELS, &channels) < 0) {
			fprintf(stderr, "Can't set number of channels on %s: %s\n",
						output, strerror(errno));
			goto close;
		}

		if (ioctl(ad, SNDCTL_DSP_SPEED, &frequency) < 0) {
			fprintf(stderr, "Can't set audio rate on %s: %s\n",
						output, strerror(errno));
			goto close;
		}
	}

	count = len;

	while (framelen > 0) {
		/* we have completed an sbc_decode at this point sbc.len is the
		 * length of the frame we just decoded count is the number of
		 * decoded bytes yet to be written */

		if (count + len >= BUF_SIZE) {
			/* buffer is too full to stuff decoded audio in so it
			 * must be written to the device */
			written = write(ad, buf, count);
			if (written > 0)
				count -= written;
		}

		/* sanity check */
		if (count + len >= BUF_SIZE) {
			fprintf(stderr,
				"buffer size of %d is too small for decoded"
				" data (%lu)\n", BUF_SIZE, (unsigned long) (len + count));
			exit(1);
		}

		/* push the pointer in the file forward to the next bit to be
		 * decoded tell the decoder to decode up to the remaining
		 * length of the file (!) */
		pos += framelen;
		framelen = sbc_decode(&sbc, stream + pos, streamlen - pos,
					buf + count, sizeof(buf) - count, &len);

		/* increase the count */
		count += len;
	}

	if (count > 0) {
		written = write(ad, buf, count);
		if (written > 0)
			count -= written;
	}

close:
	sbc_finish(&sbc);

	close(ad);

free:
	free(stream);
}

static void usage(void)
{
	printf("SBC decoder utility ver %s\n", VERSION);
	printf("Copyright (c) 2004-2010  Marcel Holtmann\n\n");

	printf("Usage:\n"
		"\tsbcdec [options] file(s)\n"
		"\n");

	printf("Options:\n"
		"\t-h, --help           Display help\n"
		"\t-v, --verbose        Verbose mode\n"
		"\t-d, --device <dsp>   Sound device\n"
		"\t-f, --file <file>    Decode to a file\n"
		"\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'd' },
	{ "verbose",	0, 0, 'v' },
	{ "file",	1, 0, 'f' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	char *output = NULL;
	int i, opt, tofile = 0;

	while ((opt = getopt_long(argc, argv, "+hvd:f:",
						main_options, NULL)) != -1) {
		switch(opt) {
		case 'h':
			usage();
			exit(0);

		case 'v':
			verbose = 1;
			break;

		case 'd':
			free(output);
			output = strdup(optarg);
			tofile = 0;
			break;

		case 'f' :
			free(output);
			output = strdup(optarg);
			tofile = 1;
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
		decode(argv[i], output ? output : "/dev/dsp", tofile);

	free(output);

	return 0;
}
