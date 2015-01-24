/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2013  Intel Corporation
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>

static ssize_t process_record(int fd, const char *line, uint16_t *upper_addr)
{
	const char *ptr = line + 1;
	char str[3];
	size_t len;
	uint8_t *buf;
	uint32_t addr;
	uint8_t sum = 0;
	int n = 0;

	if (line[0] != ':') {
		fprintf(stderr, "Invalid record start code (%c)\n", line[0]);
		return -EINVAL;
	}

	len = strlen(line);
	if (len < 11) {
		fprintf(stderr, "Record information is too short\n");
		return -EILSEQ;
	}

	buf = malloc((len / 2) + 3);
	if (!buf) {
		fprintf(stderr, "Failed to allocate memory for record data\n");
		return -ENOMEM;
	}

	while (1) {
		str[0] = *ptr++;
		str[1] = *ptr++;
		str[2] = '\0';

		buf[3 + n] = strtol(str, NULL, 16);

		if (*ptr == '\r' || *ptr == '\n')
			break;

		sum += buf[3 + n++];
	}

	sum = 0x100 - (sum & 0xff);

	if (n < 4 || buf[3] + 4 != n) {
		fprintf(stderr, "Record length is not matching data\n");
		free(buf);
		return -EILSEQ;
	}

	if (buf[3 + n] != sum) {
		fprintf(stderr, "Checksum mismatch\n");
		free(buf);
		return -EILSEQ;
	}

	switch (buf[6]) {
	case 0x00:
		addr = (*upper_addr << 16) + (buf[4] << 8) + buf[5];

		buf[0] = 0x4c;
		buf[1] = 0xfc;
		buf[2] = n;

		buf[3] = (addr & 0x000000ff);
		buf[4] = (addr & 0x0000ff00) >> 8;
		buf[5] = (addr & 0x00ff0000) >> 16;
		buf[6] = (addr & 0xff000000) >> 24;

		if (write(fd, buf, n + 3) < 0) {
			perror("Failed to write data record");
			free(buf);
			return -errno;
		}
		break;
	case 0x01:
		buf[0] = 0x4e;
		buf[1] = 0xfc;
		buf[2] = 0x04;

		buf[3] = 0xff;
		buf[4] = 0xff;
		buf[5] = 0xff;
		buf[6] = 0xff;

		if (write(fd, buf, 7) < 0) {
			perror("Failed to write end record");
			free(buf);
			return -errno;
		}
		break;
	case 0x04:
		*upper_addr = (buf[7] << 8) + buf[8];
		break;
	default:
		fprintf(stderr, "Unsupported record type (%02X)\n", buf[3]);
		free(buf);
		return -EILSEQ;
	}

	free(buf);

	return len;
}

static void convert_file(const char *input_path, const char *output_path)
{
	uint16_t upper_addr = 0x0000;
	size_t line_size = 1024;
	char line_buffer[line_size];
	char *path;
	const char *ptr;
	FILE *fp;
	struct stat st;
	off_t cur = 0;
	int fd;

	if (output_path) {
		path = strdup(output_path);
		if (!path) {
			perror("Failed to allocate string");
			return;
		}
	} else {
		ptr = strrchr(input_path, '.');
		if (ptr) {
			path = malloc(ptr - input_path + 6);
			if (!path) {
				perror("Failed to allocate string");
				return;
			}
			strncpy(path, input_path, ptr - input_path);
			strcpy(path + (ptr - input_path), ".hcd");
		} else {
			if (asprintf(&path, "%s.hcd", input_path) < 0) {
				perror("Failed to allocate string");
				return;
			}
		}
	}

	printf("Converting %s to %s\n", input_path, path);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	free(path);

	if (fd < 0) {
		perror("Failed to create output file");
		return;
	}

	if (stat(input_path, &st) < 0) {
		fprintf(stderr, "Failed get file size\n");
		close(fd);
		return;
	}

	if (st.st_size == 0) {
		fprintf(stderr, "Empty file\n");
		close(fd);
		return;
	}

	fp = fopen(input_path, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open input file\n");
		close(fd);
		return;
	}

	while (1) {
		char *str;
		ssize_t len;

		str = fgets(line_buffer, line_size - 1, fp);
		if (!str)
			break;

		len = process_record(fd, str, &upper_addr);
		if (len < 0)
			goto done;

		cur += len;
	}

	if (cur != st.st_size) {
		fprintf(stderr, "Data length does not match file length\n");
		goto done;
	}

done:
	fclose(fp);

	close(fd);
}

static void usage(void)
{
	printf("Broadcom Bluetooth firmware converter\n"
		"Usage:\n");
	printf("\thex2hcd [options] <file>\n");
	printf("Options:\n"
		"\t-o, --output <file>    Provide firmware output file\n"
		"\t-h, --help             Show help options\n");
}

static const struct option main_options[] = {
	{ "output",  required_argument, NULL, 'o' },
	{ "version", no_argument,       NULL, 'v' },
	{ "help",    no_argument,       NULL, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	const char *output_path = NULL;
	int i;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "o:vh", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'o':
			output_path = optarg;
			break;
		case 'v':
			printf("%s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			return EXIT_FAILURE;
		}
	}

	if (argc - optind < 1) {
		fprintf(stderr, "No input firmware files provided\n");
		return EXIT_FAILURE;
	}

	if (output_path && argc - optind > 1) {
		fprintf(stderr, "Only single input firmware supported\n");
		return EXIT_FAILURE;
	}

	for (i = optind; i < argc; i++)
		convert_file(argv[i], output_path);

	return EXIT_SUCCESS;
}
