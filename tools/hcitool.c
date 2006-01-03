/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "textfile.h"
#include "oui.h"

#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)

static void usage(void);

static int dev_info(int s, int dev_id, long arg)
{
	struct hci_dev_info di = { dev_id: dev_id };
	char addr[18];

	if (ioctl(s, HCIGETDEVINFO, (void *) &di))
		return 0;

	ba2str(&di.bdaddr, addr);
	printf("\t%s\t%s\n", di.name, addr);
	return 0;
}

static int conn_list(int s, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int id = arg;
	int i;

	if (id != -1 && dev_id != id)
		return 0;

	if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
		perror("Can't allocate memory");
		exit(1);
	}
	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(s, HCIGETCONNLIST, (void *) cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i = 0; i < cl->conn_num; i++, ci++) {
		char addr[18];
		ba2str(&ci->bdaddr, addr);
		printf("\t%s %s %s handle %d state %d lm %s\n",
			ci->out ? "<" : ">",
			ci->type == ACL_LINK ? "ACL" : "SCO",
			addr, ci->handle, ci->state,
			hci_lmtostr(ci->link_mode));
	}

	return 0;
}

static int find_conn(int s, int dev_id, long arg)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int i;

	if (!(cl = malloc(10 * sizeof(*ci) + sizeof(*cl)))) {
		perror("Can't allocate memory");
		exit(1);
	}
	cl->dev_id = dev_id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(s, HCIGETCONNLIST, (void *) cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i = 0; i < cl->conn_num; i++, ci++)
		if (!bacmp((bdaddr_t *) arg, &ci->bdaddr))
			return 1;

	return 0;
}

static void hex_dump(char *pref, int width, unsigned char *buf, int len)
{
	register int i,n;

	for (i = 0, n = 1; i < len; i++, n++) {
		if (n == 1)
			printf("%s", pref);
		printf("%2.2X ", buf[i]);
		if (n == width) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}

static char *get_minor_device_name(int major, int minor)
{
	switch (major) {
	case 0:	/* misc */
		return "";
	case 1:	/* computer */
		switch(minor) {
		case 0:
			return "Uncategorized";
		case 1:
			return "Desktop workstation";
		case 2:
			return "Server";
		case 3:
			return "Laptop";
		case 4:
			return "Handheld";
		case 5:
			return "Palm";
		case 6:
			return "Wearable";
		}
		break;
	case 2:	/* phone */
		switch(minor) {
		case 0:
			return "Uncategorized";
		case 1:
			return "Cellular";
		case 2:
			return "Cordless";
		case 3:
			return "Smart phone";
		case 4:
			return "Wired modem or voice gateway";
		case 5:
			return "Common ISDN Access";
		case 6:
			return "Sim Card Reader";
		}
		break;
	case 3:	/* lan access */
		if (minor == 0)
			return "Uncategorized";
		switch(minor / 8) {
		case 0:
			return "Fully available";
		case 1:
			return "1-17% utilized";
		case 2:
			return "17-33% utilized";
		case 3:
			return "33-50% utilized";
		case 4:
			return "50-67% utilized";
		case 5:
			return "67-83% utilized";
		case 6:
			return "83-99% utilized";
		case 7:
			return "No service available";
		}
		break;
	case 4:	/* audio/video */
		switch(minor) {
		case 0:
			return "Uncategorized";
		case 1:
			return "Device conforms to the Headset profile";
		case 2:
			return "Hands-free";
			/* 3 is reserved */
		case 4:
			return "Microphone";
		case 5:
			return "Loudspeaker";
		case 6:
			return "Headphones";
		case 7:
			return "Portable Audio";
		case 8:
			return "Car Audio";
		case 9:
			return "Set-top box";
		case 10:
			return "HiFi Audio Device";
		case 11:
			return "VCR";
		case 12:
			return "Video Camera";
		case 13:
			return "Camcorder";
		case 14:
			return "Video Monitor";
		case 15:
			return "Video Display and Loudspeaker";
		case 16:
			return "Video Conferencing";
			/* 17 is reserved */
		case 18:
			return "Gaming/Toy";
		}
		break;
	case 5:	/* peripheral */
		switch(minor) {
		case 16:
			return "Keyboard";
		case 32:
			return "Pointing device";
		case 48:
			return "Combo keyboard/pointing device";
		}
		break;
	case 6:	/* imaging */
		if (minor & 4)
			return "Display";
		if (minor & 8)
			return "Camera";
		if (minor & 16)
			return "Scanner";
		if (minor & 32)
			return "Printer";
		break;
	case 63:	/* uncategorised */
		return "";
	}
	return "Unknown (reserved) minor device class";
}

static char *major_classes[] = {
	"Miscellaneous", "Computer", "Phone", "LAN Access",
	"Audio/Video", "Peripheral", "Imaging", "Uncategorized"
};

static char *get_device_name(const bdaddr_t *local, const bdaddr_t *peer)
{
	char filename[PATH_MAX + 1], addr[18];

	ba2str(local, addr);
	snprintf(filename, PATH_MAX, "%s/%s/names", STORAGEDIR, addr);

	ba2str(peer, addr);
	return textfile_get(filename, addr);
}

/* Display local devices */

static struct option dev_options[] = {
	{ "help",	0, 0, 'h' },
	{0, 0, 0, 0 }
};

static char *dev_help =
	"Usage:\n"
	"\tdev\n";

static void cmd_dev(int dev_id, int argc, char **argv)
{
	int opt;
	for_each_opt(opt, dev_options, NULL) {
		switch (opt) {
		default:
			printf(dev_help);
			return;
		}
	}

	printf("Devices:\n");
	hci_for_each_dev(HCI_UP, dev_info, 0);
}

/* Inquiry */

static struct option inq_options[] = {
	{ "help",	0, 0, 'h' },
	{ "length",	1, 0, 'l' },
	{ "numrsp",	1, 0, 'n' },
	{ "iac",	1, 0, 'i' },
	{ "flush",	0, 0, 'f' },
	{ 0, 0, 0, 0 }
};

static char *inq_help =
	"Usage:\n"
	"\tinq [--length=N] maximum inquiry duration in 1.28 s units\n"
	"\t    [--numrsp=N] specify maximum number of inquiry responses\n"
	"\t    [--iac=lap]  specify the inquiry access code\n"
	"\t    [--flush]    flush the inquiry cache\n";

static void cmd_inq(int dev_id, int argc, char **argv)
{
	inquiry_info *info = NULL;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int num_rsp, length, flags;
	char addr[18];
	int i, l, opt;

	length  = 8;	/* ~10 seconds */
	num_rsp = 0;
	flags   = 0;

	for_each_opt(opt, inq_options, NULL) {
		switch (opt) {
		case 'l':
			length = atoi(optarg);
			break;

		case 'n':
			num_rsp = atoi(optarg);
			break;

		case 'i':
			l = strtoul(optarg, 0, 16);
			if (!strcasecmp(optarg, "giac")) {
				l = 0x9e8b33;
			} else if (!strcasecmp(optarg, "liac")) {
				l = 0x9e8b00;
			} if (l < 0x9e8b00 || l > 0x9e8b3f) {
				printf("Invalid access code 0x%x\n", l);
				exit(1);
			}
			lap[0] = (l & 0xff);
			lap[1] = (l >> 8) & 0xff;
			lap[2] = (l >> 16) & 0xff;
			break;

		case 'f':
			flags |= IREQ_CACHE_FLUSH;
			break;

		default:
			printf(inq_help);
			return;
		}
	}

	printf("Inquiring ...\n");
	num_rsp = hci_inquiry(dev_id, length, num_rsp, lap, &info, flags);
	if (num_rsp < 0) {
		perror("Inquiry failed.");
		exit(1);
	}

	for (i = 0; i < num_rsp; i++) {
		ba2str(&(info+i)->bdaddr, addr);
		printf("\t%s\tclock offset: 0x%4.4x\tclass: 0x%2.2x%2.2x%2.2x\n",
			addr, btohs((info+i)->clock_offset),
			(info+i)->dev_class[2],
			(info+i)->dev_class[1],
			(info+i)->dev_class[0]);
	}

	bt_free(info);
}

/* Device scanning */

static struct option scan_options[] = {
	{ "help",	0, 0, 'h' },
	{ "length",	1, 0, 'l' },
	{ "numrsp",	1, 0, 'n' },
	{ "iac",	1, 0, 'i' },
	{ "flush",	0, 0, 'f' },
	{ "class",	0, 0, 'C' },
	{ "info",	0, 0, 'I' },
	{ "oui",	0, 0, 'O' },
	{ "all",	0, 0, 'A' },
	{ "ext",	0, 0, 'A' },
	{ 0, 0, 0, 0 }
};

static char *scan_help =
	"Usage:\n"
	"\tscan [--length=N] [--numrsp=N] [--iac=lap] [--flush] [--class] [--info] [--oui]\n";

static void cmd_scan(int dev_id, int argc, char **argv)
{
	inquiry_info *info = NULL;
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int num_rsp, length, flags;
	uint8_t cls[3], features[8];
	uint16_t handle;
	char addr[18], name[249], oui[9], *comp, *tmp;
	struct hci_version version;
	struct hci_dev_info di;
	struct hci_conn_info_req *cr;
	int extcls = 0, extinf = 0, extoui = 0;
	int i, n, l, opt, dd, cc, nc;

	length  = 8;	/* ~10 seconds */
	num_rsp = 0;
	flags   = 0;

	for_each_opt(opt, scan_options, NULL) {
		switch (opt) {
		case 'l':
			length = atoi(optarg);
			break;

		case 'n':
			num_rsp = atoi(optarg);
			break;

		case 'i':
			l = strtoul(optarg, 0, 16);
			if (!strcasecmp(optarg, "giac")) {
				l = 0x9e8b33;
			} else if (!strcasecmp(optarg, "liac")) {
				l = 0x9e8b00;
			} else if (l < 0x9e8b00 || l > 0x9e8b3f) {
				printf("Invalid access code 0x%x\n", l);
				exit(1);
			}
			lap[0] = (l & 0xff);
			lap[1] = (l >> 8) & 0xff;
			lap[2] = (l >> 16) & 0xff;
			break;

		case 'f':
			flags |= IREQ_CACHE_FLUSH;
			break;

		case 'C':
			extcls = 1;
			break;

		case 'I':
			extinf = 1;
			break;

		case 'O':
			extoui = 1;
			break;

		case 'A':
			extcls = 1;
			extinf = 1;
			extoui = 1;
			break;

		default:
			printf(scan_help);
			return;
		}
	}

	if (dev_id < 0) {
		dev_id = hci_get_route(NULL);
		if (dev_id < 0) {
			perror("Device is not available");
			exit(1);
		}
	}

	if (hci_devinfo(dev_id, &di) < 0) {
		perror("Can't get device info");
		exit(1);
	}

	printf("Scanning ...\n");
	num_rsp = hci_inquiry(dev_id, length, num_rsp, lap, &info, flags);
	if (num_rsp < 0) {
		perror("Inquiry failed");
		exit(1);
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		free(info);
		exit(1);
	}

	if (extcls || extinf || extoui)
		printf("\n");

	for (i = 0; i < num_rsp; i++) {
		memset(name, 0, sizeof(name));
		tmp = get_device_name(&di.bdaddr, &(info+i)->bdaddr);
		if (tmp) {
			strncpy(name, tmp, 249);
			free(tmp);
			nc = 1;
		} else
			nc = 0;

		if (!extcls && !extinf && !extoui) {
			ba2str(&(info+i)->bdaddr, addr);

			if (nc) {
				printf("\t%s\t%s\n", addr, name);
				continue;
			}

			if (hci_read_remote_name_with_clock_offset(dd,
					&(info+i)->bdaddr,
					(info+i)->pscan_rep_mode,
					(info+i)->clock_offset | 0x8000,
					sizeof(name), name, 100000) < 0)
				strcpy(name, "n/a");

			for (n = 0; n < 248 && name[n]; n++)
				if (!isprint(name[n]))
					name[n] = '.';
			name[248] = '\0';

			printf("\t%s\t%s\n", addr, name);
			continue;
		}

		ba2str(&(info+i)->bdaddr, addr);
		printf("BD Address:\t%s [mode %d, clkoffset 0x%4.4x]\n", addr,
			(info+i)->pscan_rep_mode, btohs((info+i)->clock_offset));

		if (extoui) {
			ba2oui(&(info+i)->bdaddr, oui);
			comp = ouitocomp(oui);
			if (comp) {
				printf("OUI company:\t%s (%s)\n", comp, oui);
				free(comp);
			}
		}

		cc = 0;

		if (extinf) {
			cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
			if (cr) {
				bacpy(&cr->bdaddr, &(info+i)->bdaddr);
				cr->type = ACL_LINK;
				if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
					handle = 0;
					cc = 1;
				} else {
					handle = htobs(cr->conn_info->handle);
					cc = 0;
				}
				free(cr);
			}

			if (cc) {
				if (hci_create_connection(dd, &(info+i)->bdaddr,
						htobs(di.pkt_type & ACL_PTYPE_MASK),
						(info+i)->clock_offset | 0x8000,
						0x01, &handle, 25000) < 0) {
					handle = 0;
					cc = 0;
				}
			}
		}

		if (handle > 0 || !nc) {
			if (hci_read_remote_name_with_clock_offset(dd,
					&(info+i)->bdaddr,
					(info+i)->pscan_rep_mode,
					(info+i)->clock_offset | 0x8000,
					sizeof(name), name, 100000) < 0) {
				if (!nc)
					strcpy(name, "n/a");
			} else {
				for (n = 0; n < 248 && name[n]; n++)
					if (!isprint(name[n]))
						name[n] = '.';
				name[248] = '\0';
				nc = 0;
			}
		}

		if (strlen(name) > 0)
			printf("Device name:\t%s%s\n", name, nc ? " [cached]" : "");

		if (extcls) {
			memcpy(cls, (info+i)->dev_class, 3);
			printf("Device class:\t");
			if ((cls[1] & 0x1f) > sizeof(*major_classes))
				printf("Invalid");
			else
				printf("%s, %s", major_classes[cls[1] & 0x1f],
					get_minor_device_name(cls[1] & 0x1f, cls[0] >> 2));
			printf(" (0x%2.2x%2.2x%2.2x)\n", cls[2], cls[1], cls[0]);
		}

		if (extinf && handle > 0) {
			if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
				char *ver = lmp_vertostr(version.lmp_ver);
				printf("Manufacturer:\t%s (%d)\n",
					bt_compidtostr(version.manufacturer),
					version.manufacturer);
				printf("LMP version:\t%s (0x%x) [subver 0x%x]\n",
					ver ? ver : "n/a",
					version.lmp_ver, version.lmp_subver);
				if (ver)
					bt_free(ver);
			}

			if (hci_read_remote_features(dd, handle, features, 20000) == 0) {
				char *tmp = lmp_featurestostr(features, "\t\t", 63);
				printf("LMP features:\t0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x"
					" 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n",
					features[0], features[1],
					features[2], features[3],
					features[4], features[5],
					features[6], features[7]);
				printf("%s\n", tmp);
				bt_free(tmp);
			}

			if (cc) {
				usleep(10000);
				hci_disconnect(dd, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
			}
		}

		printf("\n");
	}

	close(dd);
	bt_free(info);
}

/* Remote name */

static struct option name_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *name_help =
	"Usage:\n"
	"\tname <bdaddr>\n";

static void cmd_name(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	char name[248];
	int opt, dd;

	for_each_opt(opt, name_options, NULL) {
		switch (opt) {
		default:
			printf(name_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(name_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_get_route(&bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Device is not available.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	if (hci_read_remote_name(dd, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("%s\n", name);

	close(dd);
}

/* Info about remote device */

static struct option info_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *info_help =
	"Usage:\n"
	"\tinfo <bdaddr>\n";

static void cmd_info(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint16_t handle;
	uint8_t max_page, features[8];
	char name[249], oui[9], *comp;
	struct hci_version version;
	struct hci_dev_info di;
	struct hci_conn_info_req *cr;
	int opt, dd, cc = 0;

	for_each_opt(opt, info_options, NULL) {
		switch (opt) {
		default:
			printf(info_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(info_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0)
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);

	if (dev_id < 0)
		dev_id = hci_get_route(&bdaddr);

	if (dev_id < 0) {
		fprintf(stderr, "Device is not available or not connected.\n");
		exit(1);
	}

	if (hci_devinfo(dev_id, &di) < 0) {
		perror("Can't get device info");
		exit(1);
	}

	printf("Requesting information ...\n");

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't get connection info");
		close(dd);
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		if (hci_create_connection(dd, &bdaddr,
					htobs(di.pkt_type & ACL_PTYPE_MASK),
					0, 0x01, &handle, 25000) < 0) {
			perror("Can't create connection");
			close(dd);
			exit(1);
		}
		cc = 1;
	} else
		handle = htobs(cr->conn_info->handle);

	printf("\tBD Address:  %s\n", argv[0]);

	ba2oui(&bdaddr, oui);
	comp = ouitocomp(oui);
	if (comp) {
		printf("\tOUI Company: %s (%s)\n", comp, oui);
		free(comp);
	}

	if (hci_read_remote_name(dd, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("\tDevice Name: %s\n", name);

	if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
		char *ver = lmp_vertostr(version.lmp_ver);
		printf("\tLMP Version: %s (0x%x) LMP Subversion: 0x%x\n"
			"\tManufacturer: %s (%d)\n",
			ver ? ver : "n/a",
			version.lmp_ver,
			version.lmp_subver,
			bt_compidtostr(version.manufacturer),
			version.manufacturer);
		if (ver)
			bt_free(ver);
	}

	if (hci_read_remote_features(dd, handle, features, 20000) == 0) {
		char *tmp = lmp_featurestostr(features, "\t\t", 63);
		printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n%s\n",
			features[0], features[1], features[2], features[3],
			features[4], features[5], features[6], features[7], tmp);
		bt_free(tmp);
	}

	if (features[7] & LMP_EXT_FEAT) {
		if (hci_read_remote_ext_features(dd, handle, 0, &max_page, features, 20000) == 0)
			if (max_page > 0)
				printf("\tExtended features: %d pages\n", max_page);
	}

	if (cc) {
		usleep(10000);
		hci_disconnect(dd, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
	}

	close(dd);
}

/* Send arbitrary HCI commands */

static struct option cmd_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *cmd_help =
	"Usage:\n"
	"\tcmd <ogf> <ocf> [parameters]\n"
	"Example:\n"
	"\tcmd 0x03 0x0013 0x41 0x42 0x43 0x44\n";

static void cmd_cmd(int dev_id, int argc, char **argv)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	struct hci_filter flt;
	hci_event_hdr *hdr;
	int i, opt, len, dd;
	uint16_t ocf;
	uint8_t ogf;

	for_each_opt(opt, cmd_options, NULL) {
		switch (opt) {
		default:
			printf(cmd_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		printf(cmd_help);
		return;
	}

	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	errno = 0;
	ogf = strtol(argv[0], NULL, 16);
	ocf = strtol(argv[1], NULL, 16);
	if (errno == ERANGE || (ogf > 0x3f) || (ocf > 0x3ff)) {
		printf(cmd_help);
		return;
	}

	for (i = 2, len = 0; i < argc && len < sizeof(buf); i++, len++)
		*ptr++ = (uint8_t) strtol(argv[i], NULL, 16);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("Device open failed");
		exit(EXIT_FAILURE);
	}

	/* Setup filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_all_events(&flt);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		perror("HCI filter setup failed");
		exit(EXIT_FAILURE);
	}

	printf("< HCI Command: ogf 0x%02x, ocf 0x%04x, plen %d\n", ogf, ocf, len);
	hex_dump("  ", 20, buf, len); fflush(stdout);

	if (hci_send_cmd(dd, ogf, ocf, len, buf) < 0) {
		perror("Send failed");
		exit(EXIT_FAILURE);
	}

	len = read(dd, buf, sizeof(buf));
	if (len < 0) {
		perror("Read failed");
		exit(EXIT_FAILURE);
	}

	hdr = (void *)(buf + 1);
	ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
	len -= (1 + HCI_EVENT_HDR_SIZE);

	printf("> HCI Event: 0x%02x plen %d\n", hdr->evt, hdr->plen);
	hex_dump("  ", 20, ptr, len); fflush(stdout);

	hci_close_dev(dd);
}

/* Display active connections */

static struct option con_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *con_help =
	"Usage:\n"
	"\tcon\n";

static void cmd_con(int dev_id, int argc, char **argv)
{
	int opt;

	for_each_opt(opt, con_options, NULL) {
		switch (opt) {
		default:
			printf(con_help);
			return;
		}
	}

	printf("Connections:\n");
	hci_for_each_dev(HCI_UP, conn_list, dev_id);
}

/* Create connection */

static struct option cc_options[] = {
	{ "help",	0, 0, 'h' },
	{ "role",	1, 0, 'r' },
	{ "ptype",	1, 0, 'p' },
	{ 0, 0, 0, 0 }
};

static char *cc_help =
	"Usage:\n"
	"\tcc [--role=m|s] [--ptype=pkt_types] <bdaddr>\n"
	"Example:\n"
	"\tcc --ptype=dm1,dh3,dh5 01:02:03:04:05:06\n"
	"\tcc --role=m 01:02:03:04:05:06\n";

static void cmd_cc(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint16_t handle;
	uint8_t role;
	unsigned int ptype;
	int dd, opt;

	role = 0x01;
	ptype = HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5;

	for_each_opt(opt, cc_options, NULL) {
		switch (opt) {
		case 'p':
			hci_strtoptype(optarg, &ptype);
			break;

		case 'r':
			role = optarg[0] == 'm' ? 0 : 1;
			break;

		default:
			printf(cc_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(cc_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_get_route(&bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Device is not available.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	if (hci_create_connection(dd, &bdaddr, htobs(ptype),
				htobs(0x0000), role, &handle, 25000) < 0)
		perror("Can't create connection");
	hci_close_dev(dd);
}

/* Close connection */

static struct option dc_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *dc_help =
	"Usage:\n"
	"\tdc <bdaddr>\n";

static void cmd_dc(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int opt, dd;

	for_each_opt(opt, dc_options, NULL) {
		switch (opt) {
		default:
			printf(dc_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(dc_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_disconnect(dd, htobs(cr->conn_info->handle),
				HCI_OE_USER_ENDED_CONNECTION, 10000) < 0)
		perror("Disconnect failed");

	close(dd);
	free(cr);
}

/* Role switch */

static struct option sr_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *sr_help =
	"Usage:\n"
	"\tsr <bdaddr> <role>\n";

static void cmd_sr(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint8_t role;
	int opt, dd;

	for_each_opt(opt, sr_options, NULL) {
		switch (opt) {
		default:
			printf(sr_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		printf(sr_help);
		return;
	}

	str2ba(argv[0], &bdaddr);
	switch (argv[1][0]) {
	case 'm':
		role = 0;
		break;
	case 's':
		role = 1;
		break;
	default:
		role = atoi(argv[1]);
		break;
	}

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	if (hci_switch_role(dd, &bdaddr, role, 10000) < 0) {
		perror("Switch role request failed");
		exit(1);
	}

	close(dd);
}

/* Read RSSI */

static struct option rssi_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *rssi_help =
	"Usage:\n"
	"\trssi <bdaddr>\n";

static void cmd_rssi(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int8_t rssi;
	int opt, dd;

	for_each_opt(opt, rssi_options, NULL) {
		switch (opt) {
		default:
			printf(rssi_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(rssi_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_read_rssi(dd, htobs(cr->conn_info->handle), &rssi, 1000) < 0) {
		perror("Read RSSI failed");
		exit(1);
	}

	printf("RSSI return value: %d\n", rssi);

	close(dd);
	free(cr);
}

/* Get link quality */

static struct option lq_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *lq_help =
	"Usage:\n"
	"\tlq <bdaddr>\n";

static void cmd_lq(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint8_t lq;
	int opt, dd;

	for_each_opt(opt, lq_options, NULL) {
		switch (opt) {
		default:
			printf(lq_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(lq_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_read_link_quality(dd, htobs(cr->conn_info->handle), &lq, 1000) < 0) {
		perror("HCI read_link_quality request failed");
		exit(1);
	}

	printf("Link quality: %d\n", lq);

	close(dd);
	free(cr);
}

/* Get transmit power level */

static struct option tpl_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *tpl_help =
	"Usage:\n"
	"\ttpl <bdaddr> [type]\n";

static void cmd_tpl(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint8_t type;
	int8_t level;
	int opt, dd;

	for_each_opt(opt, tpl_options, NULL) {
		switch (opt) {
		default:
			printf(tpl_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(tpl_help);
		return;
	}

	str2ba(argv[0], &bdaddr);
	type = (argc > 1) ? atoi(argv[1]) : 0;

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_read_transmit_power_level(dd, htobs(cr->conn_info->handle), type, &level, 1000) < 0) {
		perror("HCI read transmit power level request failed");
		exit(1);
	}

	printf("%s transmit power level: %d\n",
		(type == 0) ? "Current" : "Maximum", level);

	close(dd);
	free(cr);
}

/* Get AFH channel map */

static struct option afh_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *afh_help =
	"Usage:\n"
	"\tafh <bdaddr>\n";

static void cmd_afh(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint16_t handle;
	uint8_t mode, map[10];
	int opt, dd;

	for_each_opt(opt, afh_options, NULL) {
		switch (opt) {
		default:
			printf(afh_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(afh_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	handle = htobs(cr->conn_info->handle);

	if (hci_read_afh_map(dd, handle, &mode, map, 1000) < 0) {
		perror("HCI read AFH map request failed");
		exit(1);
	}

	if (mode == 0x01) {
		int i;
		printf("AFH map: 0x");
		for (i = 0; i < 10; i++)
			printf("%02x", map[i]);
		printf("\n");
	} else
		printf("AFH disabled\n");

	close(dd);
	free(cr);
}

/* Set connection packet type */

static struct option cpt_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *cpt_help =
	"Usage:\n"
	"\tcpt <bdaddr> <packet_types>\n";

static void cmd_cpt(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	struct hci_request rq;
	set_conn_ptype_cp cp;
	evt_conn_ptype_changed rp;
	bdaddr_t bdaddr;
	unsigned int ptype;
	int dd, opt;

	for_each_opt(opt, cpt_options, NULL) {
		switch (opt) {
		default:
			printf(cpt_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		printf(cpt_help);
		return;
	}

	str2ba(argv[0], &bdaddr);
	hci_strtoptype(argv[1], &ptype);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	cp.handle   = htobs(cr->conn_info->handle);
	cp.pkt_type = ptype;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_SET_CONN_PTYPE;
	rq.cparam = &cp;
	rq.clen   = SET_CONN_PTYPE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CONN_PTYPE_CHANGED_SIZE;
	rq.event  = EVT_CONN_PTYPE_CHANGED;

	if (hci_send_req(dd, &rq, 100) < 0) {
		perror("Packet type change failed");
		exit(1);
	}

	close(dd);
	free(cr);
}

/* Get/Set link supervision timeout */

static struct option lst_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *lst_help =
	"Usage:\n"
	"\tlst <bdaddr> [new value in slots]\n";

static void cmd_lst(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint16_t timeout;
	int opt, dd;

	for_each_opt(opt, lst_options, NULL) {
		switch (opt) {
		default:
			printf(lst_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(lst_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (argc == 1) {
		if (hci_read_link_supervision_timeout(dd, htobs(cr->conn_info->handle), &timeout, 1000) < 0) {
			perror("HCI read_link_supervision_timeout request failed");
			exit(1);
		}

		timeout = btohs(timeout);

		if (timeout)
			printf("Link supervision timeout: %u slots (%.2f msec)\n",
				timeout, (float) timeout * 0.625);
		else
			printf("Link supervision timeout never expires\n");
	} else {
		timeout = btohs(strtol(argv[1], NULL, 10));

		if (hci_write_link_supervision_timeout(dd, htobs(cr->conn_info->handle), timeout, 1000) < 0) {
			perror("HCI write_link_supervision_timeout request failed");
			exit(1);
		}
	}

	close(dd);
	free(cr);
}

/* Request authentication */

static struct option auth_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *auth_help =
	"Usage:\n"
	"\tauth <bdaddr>\n";

static void cmd_auth(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int opt, dd;

	for_each_opt(opt, auth_options, NULL) {
		switch (opt) {
		default:
			printf(auth_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(auth_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_authenticate_link(dd, htobs(cr->conn_info->handle), 25000) < 0) {
		perror("HCI authentication request failed");
		exit(1);
	}

	close(dd);
	free(cr);
}

/* Activate encryption */

static struct option enc_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *enc_help =
	"Usage:\n"
	"\tenc <bdaddr> [encrypt enable]\n";

static void cmd_enc(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint8_t encrypt;
	int opt, dd;

	for_each_opt(opt, enc_options, NULL) {
		switch (opt) {
		default:
			printf(enc_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(enc_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	encrypt = (argc > 1) ? atoi(argv[1]) : 1;

	if (hci_encrypt_link(dd, htobs(cr->conn_info->handle), encrypt, 25000) < 0) {
		perror("HCI set encryption request failed");
		exit(1);
	}

	close(dd);
	free(cr);
}

/* Change connection link key */

static struct option key_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *key_help =
	"Usage:\n"
	"\tkey <bdaddr>\n";

static void cmd_key(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int opt, dd;

	for_each_opt(opt, key_options, NULL) {
		switch (opt) {
		default:
			printf(key_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(key_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_change_link_key(dd, htobs(cr->conn_info->handle), 25000) < 0) {
		perror("Changing link key failed");
		exit(1);
	}

	close(dd);
	free(cr);
}

/* Read clock offset */

static struct option clkoff_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *clkoff_help =
	"Usage:\n"
	"\tclkoff <bdaddr>\n";

static void cmd_clkoff(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint16_t offset;
	int opt, dd;

	for_each_opt(opt, clkoff_options, NULL) {
		switch (opt) {
		default:
			printf(clkoff_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1) {
		printf(clkoff_help);
		return;
	}

	str2ba(argv[0], &bdaddr);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr) {
		perror("Can't allocate memory");
		exit(1);
	}

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}

	if (hci_read_clock_offset(dd, htobs(cr->conn_info->handle), &offset, 1000) < 0) {
		perror("Reading clock offset failed");
		exit(1);
	}

	printf("Clock offset: 0x%4.4x\n", btohs(offset));

	close(dd);
	free(cr);
}

/* Read clock */

static struct option clock_options[] = {
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

static char *clock_help =
	"Usage:\n"
	"\tclock [bdaddr] [which clock]\n";

static void cmd_clock(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	uint8_t which;
	uint32_t handle, clock;
	uint16_t accuracy;
	int opt, dd;

	for_each_opt(opt, clock_options, NULL) {
		switch (opt) {
		default:
			printf(clock_help);
			return;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 0)
		str2ba(argv[0], &bdaddr);
	else
		bacpy(&bdaddr, BDADDR_ANY);

	if (!bacmp(&bdaddr, BDADDR_ANY))
		dev_id = hci_get_route(NULL);

	if (dev_id < 0) {
		dev_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Not connected.\n");
			exit(1);
		}
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	if (bacmp(&bdaddr, BDADDR_ANY)) {
		cr = malloc(sizeof(*cr) + sizeof(struct hci_conn_info));
		if (!cr) {
			perror("Can't allocate memory");
			exit(1);
		}

		bacpy(&cr->bdaddr, &bdaddr);
		cr->type = ACL_LINK;
		if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
			perror("Get connection info failed");
			free(cr);
			exit(1);
		}

		handle = htobs(cr->conn_info->handle);
		which = (argc > 1) ? atoi(argv[1]) : 0x01;

		free(cr);
	} else {
		handle = 0x00;
		which = 0x00;
	}

	if (hci_read_clock(dd, handle, which, &clock, &accuracy, 1000) < 0) {
		perror("Reading clock failed");
		exit(1);
	}

	accuracy = btohs(accuracy);

	printf("Clock:    0x%4.4x\n", btohl(clock));
	printf("Accuracy: %.2f msec\n", (float) accuracy * 0.3125);

	close(dd);
}

static struct {
	char *cmd;
	void (*func)(int dev_id, int argc, char **argv);
	char *doc;
} command[] = {
	{ "dev",    cmd_dev,    "Display local devices"                },
	{ "inq",    cmd_inq,    "Inquire remote devices"               },
	{ "scan",   cmd_scan,   "Scan for remote devices"              },
	{ "name",   cmd_name,   "Get name from remote device"          },
	{ "info",   cmd_info,   "Get information from remote device"   },
	{ "cmd",    cmd_cmd,    "Submit arbitrary HCI commands"        },
	{ "con",    cmd_con,    "Display active connections"           },
	{ "cc",     cmd_cc,     "Create connection to remote device"   },
	{ "dc",     cmd_dc,     "Disconnect from remote device"        },
	{ "sr",     cmd_sr,     "Switch master/slave role"             },
	{ "cpt",    cmd_cpt,    "Change connection packet type"        },
	{ "rssi",   cmd_rssi,   "Display connection RSSI"              },
	{ "lq",     cmd_lq,     "Display link quality"                 },
	{ "tpl",    cmd_tpl,    "Display transmit power level"         },
	{ "afh",    cmd_afh,    "Display AFH channel map"              },
	{ "lst",    cmd_lst,    "Set/display link supervision timeout" },
	{ "auth",   cmd_auth,   "Request authentication"               },
	{ "enc",    cmd_enc,    "Set connection encryption"            },
	{ "key",    cmd_key,    "Change connection link key"           },
	{ "clkoff", cmd_clkoff, "Read clock offset"                    },
	{ "clock",  cmd_clock,  "Read local or remote clock"           },
	{ NULL, NULL, 0 }
};

static void usage(void)
{
	int i;

	printf("hcitool - HCI Tool ver %s\n", VERSION);
	printf("Usage:\n"
		"\thcitool [options] <command> [command parameters]\n");
	printf("Options:\n"
		"\t--help\tDisplay help\n"
		"\t-i dev\tHCI device\n");
	printf("Commands:\n");
	for (i = 0; command[i].cmd; i++)
		printf("\t%-4s\t%s\n", command[i].cmd,
		command[i].doc);
	printf("\n"
		"For more information on the usage of each command use:\n"
		"\thcitool <command> --help\n" );
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "device",	1, 0, 'i' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	int opt, i, dev_id = -1;
	bdaddr_t ba;

	while ((opt=getopt_long(argc, argv, "+i:h", main_options, NULL)) != -1) {
		switch (opt) {
		case 'i':
			dev_id = hci_devid(optarg);
			if (dev_id < 0) {
				perror("Invalid device");
				exit(1);
			}
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

	if (argc < 1) {
		usage();
		exit(0);
	}

	if (dev_id != -1 && hci_devba(dev_id, &ba) < 0) {
		perror("Device is not available");
		exit(1);
	}

	for (i = 0; command[i].cmd; i++) {
		if (strncmp(command[i].cmd, argv[0], 3))
			continue;
		command[i].func(dev_id, argc, argv);
		break;
	}
	return 0;
}
