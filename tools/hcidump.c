/*
 *
 *  Bluetooth packet analyzer - HCIdump
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2004  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "parser.h"
#include "sdp.h"

#define SNAP_LEN HCI_MAX_FRAME_SIZE

/* Modes */
enum {
	PARSE,
	READ,
	WRITE
};

/* Default options */
static int  device;
static int  snap_len = SNAP_LEN;
static int  defpsm = 0;
static int  mode = PARSE;
static long flags;
static long filter;
static char *dump_file;

struct dump_hdr {
	uint16_t	len;
	uint8_t		in;
	uint8_t		pad;
	uint32_t	ts_sec;
	uint32_t	ts_usec;
} __attribute__ ((packed));
#define DUMP_HDR_SIZE (sizeof(struct dump_hdr))

static inline int read_n(int fd, char *buf, int len)
{
	register int t = 0, w;

	while (len > 0) {
		if ((w = read(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}

static inline int write_n(int fd, char *buf, int len)
{
	register int t = 0, w;

	while (len > 0) {
		if ((w = write(fd, buf, len)) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}

static void process_frames(int dev, int sock, int file)
{
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec  iv;
	struct dump_hdr *dh;
	struct frame frm;
	char *buf, *ctrl;

	if (snap_len < SNAP_LEN)
		snap_len = SNAP_LEN;

	if (!(buf = malloc(snap_len + DUMP_HDR_SIZE))) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	dh = (void *) buf;
	frm.data = buf + DUMP_HDR_SIZE;

	if (!(ctrl = malloc(100))) {
		perror("Can't allocate control buffer");
		exit(1);
	}

	printf("device: hci%d snap_len: %d filter: 0x%lx\n", 
		dev, snap_len, filter); 

	memset(&msg, 0, sizeof(msg));

	while (1) {
		iv.iov_base = frm.data;
		iv.iov_len  = snap_len;

		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = 100;

		if ((frm.data_len = recvmsg(sock, &msg, 0)) < 0) {
			perror("Receive failed");
			exit(1);
		}

		/* Process control message */
		frm.in = 0;
		cmsg = CMSG_FIRSTHDR(&msg);
		while (cmsg) {
			switch (cmsg->cmsg_type) {
			case HCI_CMSG_DIR:
				frm.in = *((int *)CMSG_DATA(cmsg));
				break;
			case HCI_CMSG_TSTAMP:
				frm.ts = *((struct timeval *)CMSG_DATA(cmsg));
				break;
			}
			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}

		frm.ptr = frm.data;
		frm.len = frm.data_len;

		switch (mode) {
		case WRITE:
			/* Save dump */
			dh->len = htobs(frm.data_len);
			dh->in  = frm.in;
			dh->ts_sec  = htobl(frm.ts.tv_sec);
			dh->ts_usec = htobl(frm.ts.tv_usec);
			if (write_n(file, buf, frm.data_len + DUMP_HDR_SIZE) < 0) {
				perror("Write error");
				exit(1);
			}
			break;

		default:
			/* Parse and print */
			parse(&frm);
			break;
		}
	}
}

static void read_dump(int file)
{
	struct dump_hdr dh;
	struct frame frm;
	int err;

	if (!(frm.data = malloc(HCI_MAX_FRAME_SIZE))) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	while (1) {
		if ((err = read_n(file, (void *) &dh, DUMP_HDR_SIZE)) < 0)
			goto failed;
		if (!err) return;

		frm.data_len = btohs(dh.len);

		if ((err = read_n(file, frm.data, frm.data_len)) < 0)
			goto failed;
		if (!err) return;

		frm.ptr = frm.data;
		frm.len = frm.data_len;
		frm.in  = dh.in;
		frm.ts.tv_sec  = btohl(dh.ts_sec);
		frm.ts.tv_usec = btohl(dh.ts_usec);

		parse(&frm);
	}

failed:
	perror("Read failed");
	exit(1);
}

static int open_file(char *file, int mode)
{
	int f, flags;

	if (mode == WRITE)
		flags = O_WRONLY | O_CREAT | O_APPEND;
	else
		flags = O_RDONLY;

	if ((f = open(file, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
		perror("Can't open output file");
		exit(1);
	}
	return f;
}

static int open_socket(int dev)
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	int sk, opt;

	/* Create HCI socket */
	if ((sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't create HCI socket");
		exit(1);
	}

	opt = 1;
	if (setsockopt(sk, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
		perror("Can't enable data direction info");
		exit(1);
	}

	opt = 1;
	if (setsockopt(sk, SOL_HCI, HCI_TIME_STAMP, &opt, sizeof(opt)) < 0) {
		perror("Can't enable time stamp");
		exit(1);
	}

	/* Setup filter */
	hci_filter_clear(&flt);
	hci_filter_all_ptypes(&flt);
	hci_filter_all_events(&flt);
	if (setsockopt(sk, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		perror("Can't set HCI filter");
		exit(1);
	}

	/* Bind socket to the HCI device */
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = dev;
	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("Can't attach to device hci%d. %s(%d)\n", 
					dev, strerror(errno), errno);
		exit(1);
	}

	return sk;
}

static struct {
	char *name;
	int  flag;
} filters[] = {
	{ "hci",	FILT_HCI	},
	{ "sco",	FILT_SCO	},
	{ "l2cap",	FILT_L2CAP	},
	{ "rfcomm",	FILT_RFCOMM	},
	{ "sdp",	FILT_SDP	},
	{ "bnep",	FILT_BNEP	},
	{ "cmtp",	FILT_CMTP	},
	{ "hidp",	FILT_HIDP	},
	{ "hcrp",	FILT_HCRP	},
	{ "avdtp",	FILT_AVDTP	},
	{ "capi",	FILT_CAPI	},
	{ 0 }
};

static void parse_filter(int argc, char **argv)
{
	int i,n;

	for (i = 0; i < argc; i++) {
		for (n = 0; filters[n].name; n++) {
			if (!strcmp(filters[n].name, argv[i])) {
				filter |= filters[n].flag;
				break;
			}
		}
	}
}

static void usage(void)
{
	printf(
	"Usage: hcidump [OPTION...] [filter]\n"
	"  -i, --device=hci_dev       HCI device\n"
	"  -s, --snap-len=len         Snap len (in bytes)\n"
	"  -p, --psm=psm              Default PSM\n"
	"  -w, --save-dump=file       Save dump to a file\n"
	"  -r, --read-dump=file       Read dump from a file\n"
	"  -t, --ts                   Display time stamps\n"
	"  -a, --ascii                Dump data in ascii\n"
	"  -x, --hex                  Dump data in hex\n"
	"  -X, --ext                  Dump data in hex and ascii\n"
	"  -R, --raw                  Raw mode\n"
	"  -C, --cmtp=psm             PSM for CMTP\n"
	"  -H, --hcrp=psm             PSM for HCRP\n"
	"  -?, --help                 Give this help list\n"
	"      --usage                Give a short usage message\n"
	);
}

static struct option main_options[] = {
	{ "device",	1, 0, 'i' },
	{ "snap-len",	1, 0, 's' },
	{ "psm",	1, 0, 'p' },
	{ "save-dump",	1, 0, 'w' },
	{ "read-dump",	1, 0, 'r' },
	{ "ts",		0, 0, 't' },
	{ "ascii",	0, 0, 'a' },
	{ "hex",	0, 0, 'x' },
	{ "ext",	0, 0, 'X' },
	{ "raw",	0, 0, 'R' },
	{ "cmtp",	1, 0, 'C' },
	{ "hcrp",	1, 0, 'H' },
	{ "help",	0, 0, 'h' },
	{ 0 }
};

int main(int argc, char *argv[])
{
	int opt;

	printf("HCIDump - HCI packet analyzer ver %s\n", VERSION);

	while ((opt=getopt_long(argc, argv, "i:s:p:w:r:taxXRC:H:h", main_options, NULL)) != -1) {
		switch(opt) {
		case 'i':
			device = atoi(optarg + 3);
			break;

		case 's': 
			snap_len = atoi(optarg);
			break;

		case 'p': 
			defpsm = atoi(optarg);
			break;

		case 'w':
			mode = WRITE;
			dump_file = strdup(optarg);
			break;

		case 'r':
			mode = READ;
			dump_file = strdup(optarg);
			break;

		case 't': 
			flags |= DUMP_TSTAMP;
			break;

		case 'a': 
			flags |= DUMP_ASCII;
			break;

		case 'x':
			flags |= DUMP_HEX;
			break;

		case 'X':
			flags |= DUMP_EXT;
			break;

		case 'R': 
			flags |= DUMP_RAW;
			break;

		case 'C': 
			set_proto(0, atoi(optarg), SDP_UUID_CMTP);
			break;

		case 'H':
			set_proto(0, atoi(optarg), SDP_UUID_HARDCOPY_CONTROL_CHANNEL);
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc > 0)
		parse_filter(argc, argv);

	/* Default settings */
	if (!filter)
		filter = ~0L;

	switch (mode) {
	case PARSE:
		init_parser(flags, filter, defpsm);
		process_frames(device, open_socket(device), -1);
		break;

	case WRITE:
		process_frames(device, open_socket(device), open_file(dump_file, mode));
		break;

	case READ:
		init_parser(flags, filter, defpsm);
		read_dump(open_file(dump_file, mode));
		break;
	}

	return 0;
}
