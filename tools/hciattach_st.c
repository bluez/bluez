/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdint.h>
#include <string.h>

static int debug = 0;

static int do_command(int fd, uint8_t ogf, uint16_t ocf,
			uint8_t *cparam, int clen, uint8_t *rparam, int rlen)
{
	//uint16_t opcode = (uint16_t) ((ocf & 0x03ff) | (ogf << 10));
	unsigned char cp[254], rp[254];
	int len, size, offset = 3;

	cp[0] = 0x01;
	cp[1] = ocf & 0xff;
	cp[2] = ogf << 2 | ocf >> 8;
	cp[3] = clen;

	if (clen > 0)
		memcpy(cp + 4, cparam, clen);

	if (debug) {
		int i;
		printf("[<");
		for (i = 0; i < clen + 4; i++)
			printf(" %02x", cp[i]);
		printf("]\n");
	}

	if (write(fd, cp, clen + 4) < 0)
		return -1;

	do {
		if (read(fd, rp, 1) < 1)
			return -1;
	} while (rp[0] != 0x04);

	if (read(fd, rp + 1, 2) < 2)
		return -1;

	do {
		len = read(fd, rp + offset, sizeof(rp) - offset);
		offset += len;
	} while (offset < rp[2] + 3);

	if (debug) {
		int i;
		printf("[>");
		for (i = 0; i < offset; i++)
			printf(" %02x", rp[i]);
		printf("]\n");
	}

	if (rp[0] != 0x04) {
		errno = EIO;
		return -1;
	}

	switch (rp[1]) {
	case 0x0e:	/* command complete */
		if (rp[6] != 0x00)
			return -ENXIO;
		offset = 3 + 4;
		size = rp[2] - 4;
		break;
	case 0x0f:	/* command status */
		/* fall through */
	default:
		offset = 3;
		size = rp[2];
		break;
	}

	if (!rparam || rlen < size)
		return -ENXIO;

	memcpy(rparam, rp + offset, size);

	return size;
}

int stlc2500_init(int fd)
{
	unsigned char cmd[16];
	unsigned char buf[254];
	int len;

	len = do_command(fd, 0x04, 0x0001, NULL, 0, buf, sizeof(buf));

	printf("Patch: STLC2500_R%d_%02d_*.ptc\n", buf[2], buf[1]);

	len = do_command(fd, 0xff, 0x000f, NULL, 0, buf, sizeof(buf));

	printf("%s\n", buf);

	cmd[0] = 0xfe;
	cmd[1] = 0x06;
	cmd[2] = 0xba;
	cmd[3] = 0xab;
	cmd[4] = 0x00;
	cmd[5] = 0xe1;
	cmd[6] = 0x80;
	cmd[7] = 0x00;

	len = do_command(fd, 0xff, 0x0022, cmd, 8, buf, sizeof(buf));

	len = do_command(fd, 0x03, 0x0003, NULL, 0, buf, sizeof(buf));

	return 0;
}
