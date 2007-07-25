/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "parser.h"
#include "sdp.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t ntoh64(uint64_t n)
{
	uint64_t h;
	uint64_t tmp = ntohl(n & 0x00000000ffffffff);
	h = ntohl(n >> 32);
	h |= tmp << 32;
	return h;
}
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ntoh64(x) (x)
#else
#error "Unknown byte order"
#endif
#define hton64(x) ntoh64(x)

#define SNAP_LEN 	HCI_MAX_FRAME_SIZE
#define DEFAULT_PORT	"10839";

/* Modes */
enum {
	PARSE,
	READ,
	WRITE,
	RECEIVE,
	SEND,
	SERVER,
	PPPDUMP,
	AUDIO
};

/* Default options */
static int  snap_len = SNAP_LEN;
static int  mode = PARSE;
static int  permcheck = 1;
static int  noappend = 0;
static char *dump_file = NULL;
static char *pppdump_file = NULL;
static char *audio_file = NULL;
static char *dump_addr;
static char *dump_port = DEFAULT_PORT;
static int af = AF_UNSPEC;

struct hcidump_hdr {
	uint16_t	len;
	uint8_t		in;
	uint8_t		pad;
	uint32_t	ts_sec;
	uint32_t	ts_usec;
} __attribute__ ((packed));
#define HCIDUMP_HDR_SIZE (sizeof(struct hcidump_hdr))

struct btsnoop_hdr {
	uint8_t		id[8];		/* Identification Pattern */
	uint32_t	version;	/* Version Number = 1 */
	uint32_t	type;		/* Datalink Type */
} __attribute__ ((packed));
#define BTSNOOP_HDR_SIZE (sizeof(struct btsnoop_hdr))

struct btsnoop_pkt {
	uint32_t	size;		/* Original Length */
	uint32_t	len;		/* Included Length */
	uint32_t	flags;		/* Packet Flags */
	uint32_t	drops;		/* Cumulative Drops */
	uint64_t	ts;		/* Timestamp microseconds */
	uint8_t		data[0];	/* Packet Data */
} __attribute__ ((packed));
#define BTSNOOP_PKT_SIZE (sizeof(struct btsnoop_pkt))

static uint8_t btsnoop_id[] = { 0x62, 0x74, 0x73, 0x6e, 0x6f, 0x6f, 0x70, 0x00 };

static uint32_t btsnoop_version = 0;
static uint32_t btsnoop_type = 0;

struct pktlog_hdr {
	uint32_t	len;
	uint64_t	ts;
	uint8_t		type;
} __attribute__ ((packed));
#define PKTLOG_HDR_SIZE (sizeof(struct pktlog_hdr))

static inline int read_n(int fd, char *buf, int len)
{
	int t = 0, w;

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
	int t = 0, w;

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

static void process_frames(int dev, int sock, int fd, unsigned long flags)
{
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec  iv;
	struct hcidump_hdr *dh;
	struct btsnoop_pkt *dp;
	struct frame frm;
	char *buf, *ctrl;
	int len, hdr_size = HCIDUMP_HDR_SIZE;

	if (snap_len < SNAP_LEN)
		snap_len = SNAP_LEN;

	if (flags & DUMP_BTSNOOP)
		hdr_size = BTSNOOP_PKT_SIZE;

	buf = malloc(snap_len + hdr_size);
	if (!buf) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	dh = (void *) buf;
	dp = (void *) buf;
	frm.data = buf + hdr_size;

	ctrl = malloc(100);
	if (!ctrl) {
		perror("Can't allocate control buffer");
		exit(1);
	}

	if (dev == HCI_DEV_NONE)
		printf("system: ");
	else
		printf("device: hci%d ", dev);

	printf("snap_len: %d filter: 0x%lx\n", snap_len, parser.filter);

	memset(&msg, 0, sizeof(msg));

	while (1) {
		iv.iov_base = frm.data;
		iv.iov_len  = snap_len;

		msg.msg_iov = &iv;
		msg.msg_iovlen = 1;
		msg.msg_control = ctrl;
		msg.msg_controllen = 100;

		len = recvmsg(sock, &msg, 0);
		if (len < 0) {
			perror("Receive failed");
			if (mode == SERVER)
				return;
			else
				exit(1);
		}

		/* Process control message */
		frm.data_len = len;
		frm.dev_id = dev;
		frm.in = 0;
		frm.pppdump_fd = parser.pppdump_fd;
		frm.audio_fd   = parser.audio_fd;

		cmsg = CMSG_FIRSTHDR(&msg);
		while (cmsg) {
			switch (cmsg->cmsg_type) {
			case HCI_CMSG_DIR:
				frm.in = *((int *) CMSG_DATA(cmsg));
				break;
			case HCI_CMSG_TSTAMP:
				frm.ts = *((struct timeval *) CMSG_DATA(cmsg));
				break;
			}
			cmsg = CMSG_NXTHDR(&msg, cmsg);
		}

		frm.ptr = frm.data;
		frm.len = frm.data_len;

		switch (mode) {
		case WRITE:
		case SEND:
		case SERVER:
			/* Save or send dump */
			if (flags & DUMP_BTSNOOP) {
				uint64_t ts;
				uint8_t pkt_type = ((uint8_t *) frm.data)[0];
				dp->size = htonl(frm.data_len);
				dp->len  = dp->size;
				dp->flags = ntohl(frm.in & 0x01);
				dp->drops = 0;
				ts = (frm.ts.tv_sec - 946684800ll) * 1000000ll + frm.ts.tv_usec;
				dp->ts = hton64(ts + 0x00E03AB44A676000ll);
				if (pkt_type == HCI_COMMAND_PKT ||
						pkt_type == HCI_EVENT_PKT)
					dp->flags |= ntohl(0x02);
			} else {
				dh->len = htobs(frm.data_len);
				dh->in  = frm.in;
				dh->ts_sec  = htobl(frm.ts.tv_sec);
				dh->ts_usec = htobl(frm.ts.tv_usec);
			}

			if (write_n(fd, buf, frm.data_len + hdr_size) < 0) {
				perror("Write error");
				if (mode == SERVER)
					return;
				else
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

static void read_dump(int fd)
{
	struct hcidump_hdr dh;
	struct btsnoop_pkt dp;
	struct pktlog_hdr ph;
	struct frame frm;
	uint8_t pkt_type;
	int err;

	frm.data = malloc(HCI_MAX_FRAME_SIZE);
	if (!frm.data) {
		perror("Can't allocate data buffer");
		exit(1);
	}

	while (1) {
		if (parser.flags & DUMP_PKTLOG)
			err = read_n(fd, (void *) &ph, PKTLOG_HDR_SIZE);
		else if (parser.flags & DUMP_BTSNOOP)
			err = read_n(fd, (void *) &dp, BTSNOOP_PKT_SIZE);
		else
			err = read_n(fd, (void *) &dh, HCIDUMP_HDR_SIZE);

		if (err < 0)
			goto failed;
		if (!err)
			return;

		if (parser.flags & DUMP_PKTLOG) {
			switch (ph.type) {
			case 0x00:
				((uint8_t *) frm.data)[0] = HCI_COMMAND_PKT;
				frm.in = 0;
				break;
			case 0x01:
				((uint8_t *) frm.data)[0] = HCI_EVENT_PKT;
				frm.in = 1;
				break;
			case 0x02:
				((uint8_t *) frm.data)[0] = HCI_ACLDATA_PKT;
				frm.in = 0;
				break;
			case 0x03:
				((uint8_t *) frm.data)[0] = HCI_ACLDATA_PKT;
				frm.in = 1;
				break;
			default:
				lseek(fd, ntohl(ph.len) - 9, SEEK_CUR);
				continue;
			}

			frm.data_len = ntohl(ph.len) - 8;
			err = read_n(fd, frm.data + 1, frm.data_len - 1);
		} else if (parser.flags & DUMP_BTSNOOP) {
			switch (btsnoop_type) {
			case 1001:
				if (ntohl(dp.flags) & 0x02) {
					if (ntohl(dp.flags) & 0x01)
						pkt_type = HCI_EVENT_PKT;
					else
						pkt_type = HCI_COMMAND_PKT;
				} else
					pkt_type = HCI_ACLDATA_PKT;

				((uint8_t *) frm.data)[0] = pkt_type;

				frm.data_len = ntohl(dp.len) + 1;
				err = read_n(fd, frm.data + 1, frm.data_len - 1);
				break;

			case 1002:
				frm.data_len = ntohl(dp.len);
				err = read_n(fd, frm.data, frm.data_len);
				break;
			}
		} else {
			frm.data_len = btohs(dh.len);
			err = read_n(fd, frm.data, frm.data_len);
		}

		if (err < 0)
			goto failed;
		if (!err)
			return;

		frm.ptr = frm.data;
		frm.len = frm.data_len;

		if (parser.flags & DUMP_PKTLOG) {
			uint64_t ts;
			ts = ntoh64(ph.ts);
			frm.ts.tv_sec = ts >> 32;
			frm.ts.tv_usec = ts & 0xffffffff;
		} else if (parser.flags & DUMP_BTSNOOP) {
			uint64_t ts;
			frm.in = ntohl(dp.flags) & 0x01;
			ts = ntoh64(dp.ts) - 0x00E03AB44A676000ll;
			frm.ts.tv_sec = (ts / 1000000ll) + 946684800ll;
			frm.ts.tv_usec = ts % 1000000ll;
		} else {
			frm.in = dh.in;
			frm.ts.tv_sec  = btohl(dh.ts_sec);
			frm.ts.tv_usec = btohl(dh.ts_usec);
		}

		parse(&frm);
	}

failed:
	perror("Read failed");
	exit(1);
}

static int open_file(char *file, int mode, unsigned long flags)
{
	unsigned char buf[BTSNOOP_HDR_SIZE];
	struct btsnoop_hdr *hdr = (struct btsnoop_hdr *) buf;
	int fd, len, open_flags;

	if (mode == WRITE || mode == PPPDUMP || mode == AUDIO) {
		if (noappend || flags & DUMP_BTSNOOP)
			open_flags = O_WRONLY | O_CREAT | O_TRUNC;
		else
			open_flags = O_WRONLY | O_CREAT | O_APPEND;
	} else
		open_flags = O_RDONLY;

	fd = open(file, open_flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		perror("Can't open dump file");
		exit(1);
	}

	if (mode == READ) {
		len = read(fd, buf, BTSNOOP_HDR_SIZE);
		if (len != BTSNOOP_HDR_SIZE) {
			lseek(fd, 0, SEEK_SET);
			return fd;
		}

		if (!memcmp(hdr->id, btsnoop_id, sizeof(btsnoop_id))) {
			parser.flags |= DUMP_BTSNOOP;

			btsnoop_version = ntohl(hdr->version);
			btsnoop_type = ntohl(hdr->type);

			printf("btsnoop version: %d datalink type: %d\n",
						btsnoop_version, btsnoop_type);

			if (btsnoop_version != 1) {
				fprintf(stderr, "Unsupported BTSnoop version\n");
				exit(1);
			}

			if (btsnoop_type != 1001 && btsnoop_type != 1002) {
				fprintf(stderr, "Unsupported BTSnoop datalink type\n");
				exit(1);
			}
		} else {
			if (buf[0] == 0x00 && buf[1] == 0x00) {
				parser.flags |= DUMP_PKTLOG;
				printf("packet logger data format\n");
			}

			parser.flags &= ~DUMP_BTSNOOP;
			lseek(fd, 0, SEEK_SET);
			return fd;
		}
	} else {
		if (flags & DUMP_BTSNOOP) {
			btsnoop_version = 1;
			btsnoop_type = 1002;

			memcpy(hdr->id, btsnoop_id, sizeof(btsnoop_id));
			hdr->version = htonl(btsnoop_version);
			hdr->type = htonl(btsnoop_type);

			printf("btsnoop version: %d datalink type: %d\n",
						btsnoop_version, btsnoop_type);

			len = write(fd, buf, BTSNOOP_HDR_SIZE);
			if (len < 0) {
				perror("Can't create dump header");
				exit(1);
			}

			if (len != BTSNOOP_HDR_SIZE) {
				fprintf(stderr, "Header size mismatch\n");
				exit(1);
			}
		}
	}

	return fd;
}

static int open_socket(int dev, unsigned long flags)
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	struct hci_dev_info di;
	int sk, dd, opt;

	if (permcheck && dev != HCI_DEV_NONE) {
		dd = hci_open_dev(dev);
		if (dd < 0) {
			perror("Can't open device");
			exit(1);
		}

		if (hci_devinfo(dev, &di) < 0) {
			perror("Can't get device info");
			exit(1);
		}

		opt = hci_test_bit(HCI_RAW, &di.flags);
		if (ioctl(dd, HCISETRAW, opt) < 0) {
			if (errno == EACCES) {
				perror("Can't access device");
				exit(1);
			}
		}

		hci_close_dev(dd);
	}

	/* Create HCI socket */
	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0) {
		perror("Can't create raw socket");
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
		perror("Can't set filter");
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

static int open_connection(char *addr, char *port)
{
	struct sockaddr_storage ss;
	struct addrinfo hints, *res0, *res;
	int sk = -1, opt = 1;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	
	if (getaddrinfo(addr, port, &hints, &res0))
		if(getaddrinfo(NULL, port, &hints, &res0)) {
			perror("getaddrinfo");
			exit(1);
		}
	
	for (res = res0; res; res = res->ai_next) {
		sk = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sk < 0) {
			if (res->ai_next)
				continue;

			perror("Can't create socket");
			freeaddrinfo(res0);
			exit(1);
		}

		setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		
		memcpy(&ss, res->ai_addr, res->ai_addrlen);

		switch(ss.ss_family) {
		case AF_INET:
			((struct sockaddr_in *) &ss)->sin_addr.s_addr = htonl(INADDR_ANY);
			((struct sockaddr_in *) &ss)->sin_port = 0;
			break;
		case AF_INET6:
			memcpy(&((struct sockaddr_in6 *) &ss)->sin6_addr, &in6addr_any, sizeof(in6addr_any));
			((struct sockaddr_in6 *) &ss)->sin6_port = 0;
			break;
		}

		if (bind(sk, (struct sockaddr *) &ss, sizeof(ss)) < 0) {
			perror("Can't bind socket");
			close(sk);
			freeaddrinfo(res0);
			exit(1);
		}
		
		if (connect(sk, res->ai_addr, res->ai_addrlen) < 0) {
			perror("Can't connect socket");
			close(sk);
			freeaddrinfo(res0);
			exit(1);
		}
	}

	freeaddrinfo(res0);

	return sk;
}

static int wait_connection(char *addr, char *port)
{
	char hname[100], hport[10];
	struct sockaddr_storage ss;
	struct addrinfo hints, *res0, *res;
	socklen_t len;
	int sk = -1, nsk, opt = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	if (getaddrinfo(addr, port, &hints, &res0))
		if (getaddrinfo(NULL, port, &hints, &res0)) {
			perror("getaddrinfo");
			exit(1);
		}
 	
	for (res = res0; res; res = res->ai_next) {
		sk = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sk < 0) {
			if (res->ai_next)
				continue;

			perror("Can't create socket");
 			freeaddrinfo(res0);
			exit(1);
		}

		setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

		if (bind(sk, res->ai_addr, res->ai_addrlen) < 0) {
			if(res->ai_next) {
				close(sk);
				continue;
			}

			perror("Can't bind socket");
			close(sk);
			freeaddrinfo(res0);
			exit(1);
 		}

		getnameinfo(res->ai_addr, res->ai_addrlen, hname, sizeof(hname),
					hport, sizeof(hport), NI_NUMERICSERV);
		printf("device: %s:%s snap_len: %d filter: 0x%lx\n",
					hname, port, snap_len, parser.filter);
		if (listen(sk, 1) < 0) {
			if (res->ai_next) {
				close(sk);
				continue;
			}

			perror("Can't listen on socket");
			close(sk);
			freeaddrinfo(res0);
			exit(1);
		}
	}

	freeaddrinfo(res0);

	len = sizeof(ss);
	nsk = accept(sk, (struct sockaddr *) &ss, &len);
	if (nsk < 0) {
		perror("Can't accept new socket");
		close(sk);
		freeaddrinfo(res0);
		exit(1);
	}

	getnameinfo((struct sockaddr *) &ss, sizeof(ss),
					hname, sizeof(hname), NULL, 0, 0);

	printf("device: %s snap_len: %d filter: 0x%lx\n",
					hname, snap_len, parser.filter);

	close(sk);

	return nsk;
}

static int run_server(int dev, char *addr, char *port, unsigned long flags)
{
	int dd, sk;

	dd = open_socket(dev, flags);
	if (dd < 0)
		return dd;

	close(dd);

	flags &= ~DUMP_BTSNOOP;

	while (1) {
		sk = wait_connection(addr, port);
		if (sk < 0)
			continue;

		dd = open_socket(dev, flags);
		if (dd < 0) {
			close(sk);
			continue;
		}

		process_frames(dev, dd, sk, flags);

		close(dd);
		close(sk);
	}

	return 0;
}

static struct {
	char *name;
	int  flag;
} filters[] = {
	{ "lmp",	FILT_LMP	},
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
	{ "avctp",	FILT_AVCTP	},
	{ "obex",	FILT_OBEX	},
	{ "capi",	FILT_CAPI	},
	{ "ppp",	FILT_PPP	},
	{ "csr",	FILT_CSR	},
	{ "dga",	FILT_DGA	},
	{ 0 }
};

static unsigned long parse_filter(int argc, char **argv)
{
	unsigned long filter = 0;
	int i,n;

	for (i = 0; i < argc; i++) {
		for (n = 0; filters[n].name; n++) {
			if (!strcasecmp(filters[n].name, argv[i])) {
				filter |= filters[n].flag;
				break;
			}
		}
	}

	return filter;
}

static void usage(void)
{
	printf(
	"Usage: hcidump [OPTION...] [filter]\n"
	"  -i, --device=hci_dev       HCI device\n"
	"  -l, --snap-len=len         Snap len (in bytes)\n"
	"  -p, --psm=psm              Default PSM\n"
	"  -m, --manufacturer=compid  Default manufacturer\n"
	"  -w, --save-dump=file       Save dump to a file\n"
	"  -r, --read-dump=file       Read dump from a file\n"
	"  -s, --send-dump=host       Send dump to a host\n"
	"  -n, --recv-dump=host       Receive dump on a host\n"
	"  -d, --wait-dump=host       Wait on a host and send\n"
	"  -t, --ts                   Display time stamps\n"
	"  -a, --ascii                Dump data in ascii\n"
	"  -x, --hex                  Dump data in hex\n"
	"  -X, --ext                  Dump data in hex and ascii\n"
	"  -R, --raw                  Dump raw data\n"
	"  -C, --cmtp=psm             PSM for CMTP\n"
	"  -H, --hcrp=psm             PSM for HCRP\n"
	"  -O, --obex=channel         Channel for OBEX\n"
	"  -P, --ppp=channel          Channel for PPP\n"
	"  -D, --pppdump=file         Extract PPP traffic\n"
	"  -A, --audio=file           Extract SCO audio data\n"
	"  -B, --btsnoop              Use BTSnoop file format\n"
	"  -V, --verbose              Verbose decoding\n"
	"  -Y, --novendor             No vendor commands or events\n"
	"  -N, --noappend             No appending to existing files\n"
	"  -4, --ipv4                 Use IPv4 as transport\n"
	"  -6  --ipv6                 Use IPv6 as transport\n"
	"  -h, --help                 Give this help list\n"
	"      --usage                Give a short usage message\n"
	);
}

static struct option main_options[] = {
	{ "device",		1, 0, 'i' },
	{ "snap-len",		1, 0, 'l' },
	{ "psm",		1, 0, 'p' },
	{ "manufacturer",	1, 0, 'm' },
	{ "save-dump",		1, 0, 'w' },
	{ "read-dump",		1, 0, 'r' },
	{ "send-dump",		1, 0, 's' },
	{ "recv-dump",		1, 0, 'n' },
	{ "wait-dump",		1, 0, 'd' },
	{ "timestamp",		0, 0, 't' },
	{ "ascii",		0, 0, 'a' },
	{ "hex",		0, 0, 'x' },
	{ "ext",		0, 0, 'X' },
	{ "raw",		0, 0, 'R' },
	{ "cmtp",		1, 0, 'C' },
	{ "hcrp",		1, 0, 'H' },
	{ "obex",		1, 0, 'O' },
	{ "ppp",		1, 0, 'P' },
	{ "pppdump",		1, 0, 'D' },
	{ "audio",		1, 0, 'A' },
	{ "btsnoop",		0, 0, 'B' },
	{ "verbose",		0, 0, 'V' },
	{ "novendor",		0, 0, 'Y' },
	{ "nopermcheck",	0, 0, 'Z' },
	{ "noappend",		0, 0, 'N' },
	{ "ipv4",		0, 0, '4' },
	{ "ipv6",		0, 0, '6' },
	{ "help",		0, 0, 'h' },
	{ 0 }
};

int main(int argc, char *argv[])
{
	unsigned long flags = 0;
	unsigned long filter = 0;
	int device = 0;
	int defpsm = 0;
	int defcompid = DEFAULT_COMPID;
	int opt, pppdump_fd = -1, audio_fd = -1;

	printf("HCI sniffer - Bluetooth packet analyzer ver %s\n", VERSION);

	while ((opt=getopt_long(argc, argv, "i:l:p:m:w:r:s:n:d:taxXRC:H:O:P:D:A:BVYZN46h", main_options, NULL)) != -1) {
		switch(opt) {
		case 'i':
			if (strcasecmp(optarg, "none") && strcasecmp(optarg, "system"))
				device = atoi(optarg + 3);
			else
				device = HCI_DEV_NONE;
			break;

		case 'l': 
			snap_len = atoi(optarg);
			break;

		case 'p': 
			defpsm = atoi(optarg);
			break;

		case 'm':
			defcompid = atoi(optarg);
			break;

		case 'w':
			mode = WRITE;
			dump_file = strdup(optarg);
			break;

		case 'r':
			mode = READ;
			dump_file = strdup(optarg);
			break;

		case 's':
			mode = SEND;
			dump_addr = optarg;
			break;

		case 'n':
			mode = RECEIVE;
			dump_addr = optarg;
			break;

		case 'd':
			mode = SERVER;
			dump_addr = optarg;
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
			set_proto(0, atoi(optarg), 0, SDP_UUID_CMTP);
			break;

		case 'H':
			set_proto(0, atoi(optarg), 0, SDP_UUID_HARDCOPY_CONTROL_CHANNEL);
			break;

		case 'O':
			set_proto(0, 0, atoi(optarg), SDP_UUID_OBEX);
			break;

		case 'P':
			set_proto(0, 0, atoi(optarg), SDP_UUID_LAN_ACCESS_PPP);
			break;

		case 'D':
			pppdump_file = strdup(optarg);
			break;

		case 'A':
			audio_file = strdup(optarg);
			break;

		case 'B':
			flags |= DUMP_BTSNOOP;
			break;

		case 'V':
			flags |= DUMP_VERBOSE;
			break;

		case 'Y':
			flags |= DUMP_NOVENDOR;
			break;

		case 'Z':
			permcheck = 0;
			break;

		case 'N':
			noappend = 1;
			break;

		case '4':
			af = AF_INET;
			break;

		case '6':
			af = AF_INET6;
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
		filter = parse_filter(argc, argv);

	/* Default settings */
	if (!filter)
		filter = ~0L;

	if (pppdump_file)
		pppdump_fd = open_file(pppdump_file, PPPDUMP, flags);

	if (audio_file)
		audio_fd = open_file(audio_file, AUDIO, flags);

	switch (mode) {
	case PARSE:
		init_parser(flags, filter, defpsm, defcompid, pppdump_fd, audio_fd);
		process_frames(device, open_socket(device, flags), -1, flags);
		break;

	case READ:
		init_parser(flags, filter, defpsm, defcompid, pppdump_fd, audio_fd);
		read_dump(open_file(dump_file, mode, flags));
		break;

	case WRITE:
		process_frames(device, open_socket(device, flags),
				open_file(dump_file, mode, flags), flags);
		break;

	case RECEIVE:
		init_parser(flags, filter, defpsm, defcompid, pppdump_fd, audio_fd);
		read_dump(wait_connection(dump_addr, dump_port));
		break;

	case SEND:
		process_frames(device, open_socket(device, flags),
				open_connection(dump_addr, dump_port), flags);
		break;

	case SERVER:
		init_parser(flags, filter, defpsm, defcompid, pppdump_fd, audio_fd);
		run_server(device, dump_addr, dump_port, flags);
		break;
	}

	return 0;
}
