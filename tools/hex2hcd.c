/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Canonical
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define RBUF_SIZE	640

static unsigned int asc_to_int(char a)
{
	if (a >= 'A')
		return (a - 'A') + 10;
	else
		return a - '0';
}

static unsigned int hex_to_int(const char *h)
{
	return asc_to_int(*h) * 0x10 + asc_to_int(*(h + 1));
}

static unsigned int lhex_to_int(const char *h)
{
	return hex_to_int(h) * 0x100 + hex_to_int(h + 2);
}

static int check_sum(const char *str, int len)
{
	unsigned int sum, cal;
	int i;
	sum = hex_to_int(str + len - 2);
	for (cal = 0, i = 1; i < len - 2; i += 2)
		cal += hex_to_int(str + i);
	cal = 0x100 - (cal & 0xFF);
	return sum == cal;
}

static int check_hex_line(const char *str, unsigned int len)
{
	if ((str[0] != ':') || (len < 11) || !check_sum(str, len) ||
			(hex_to_int(str + 1) * 2 + 11 != len))
		return 0;
	return 1;
}

int main(int argc, char *argv[])
{
	unsigned int i, addr = 0;
	FILE *ifp, *ofp;
	char *rbuf;
	ssize_t len;
	size_t buflen;

	if (argc != 3) {
		printf("Usage: %s <input hex file> <output file>\n", argv[0]);
		return 0;
	}

	ifp = fopen(argv[1], "r");
	ofp = fopen(argv[2], "w");
	if ((ifp == NULL) || (ofp == NULL)) {
		puts("failed to open file.");
		return -EIO;
	}

	rbuf = NULL;
	while ((len = getline(&rbuf, &buflen, ifp)) > 0) {
		int type;
		char obuf[7];
		unsigned int dest_addr;
		while ((rbuf[len - 1] == '\r') || (rbuf[len - 1] == '\n'))
			len--;
		printf("%d, %s\n", (int)len, rbuf);
		if (!check_hex_line(rbuf, len))
			break;
		type = hex_to_int(rbuf + 7);
		switch (type) {
			case 4:
				addr = lhex_to_int(rbuf + 9) * 0x10000;
				printf("bump addr to 0x%08X\n", addr);
				break;
			case 0:
				dest_addr = addr + lhex_to_int(rbuf + 3);
				obuf[0] = 0x4c;
				obuf[1] = 0xfc;
				obuf[2] = hex_to_int(rbuf + 1) + 4;
				obuf[3] = dest_addr;
				obuf[4] = dest_addr >> 8;
				obuf[5] = dest_addr >> 16;
				obuf[6] = dest_addr >> 24;
				if (fwrite(obuf, 7, 1, ofp) != 1)
					goto output_err;
				for (i = 0; i < hex_to_int(rbuf + 1); i++) {
					obuf[0] = hex_to_int(rbuf + 9 + i * 2);
					if (fwrite(obuf, 1, 1, ofp) != 1)
						goto output_err;
				}
				break;
			case 1:
				if (fwrite("\x4e\xfc\x04\xff\xff\xff\xff", 7, 1, ofp) != 1)
					goto output_err;
				goto end;
			default:
				return -EINVAL;
		}
	}

	puts("hex file formatting error");
	return -EINVAL;

output_err:
	puts("error on writing output file");
	return -EIO;

end:
	return 0;
}

