/* 
	BlueZ - Bluetooth protocol stack for Linux
	Copyright (C) 2000-2001 Qualcomm Incorporated

	Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as
	published by the Free Software Foundation;

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
	IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
	OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
	RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
	NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
	USE OR PERFORMANCE OF THIS SOFTWARE.

	ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
	TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/

/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#include <termios.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <netinet/in.h>

#include <bluetooth.h>
#include <hci.h>
#include <hci_lib.h>

extern int optind,opterr,optopt;
extern char *optarg;

#define for_each_opt(opt, long, short) while ((opt=getopt_long(argc, argv, short ? short:"+", long, NULL)) != -1)

static void usage(void);

static int dev_info(int s, int dev_id, long arg)
{
	struct hci_dev_info di = {dev_id: dev_id};
	bdaddr_t bdaddr;
	if (ioctl(s, HCIGETDEVINFO, (void*) &di))
		return 0;
	
	baswap(&bdaddr, &di.bdaddr);
	printf("\t%s\t%s\n", di.name, batostr(&bdaddr));
	return 0;
}

static int rev_info(int s, int dev_id, long arg)
{
	struct hci_version ver;
	int id = arg;
	int dd;

	struct hci_request rq;
	unsigned char buf[102];

	if (id != -1 && dev_id != id)
		return 0;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		printf("Can't open device hci%d. %s(%d)\n", dev_id, strerror(errno), errno);
		return -1;
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		printf("Can't read version info hci%d. %s(%d)\n",
			dev_id, strerror(errno), errno);
		return -1;
	}

	printf("hci%d:", dev_id);
	switch (ver.manufacturer) {
	case 0:
		memset(&rq, 0, sizeof(rq));
		rq.ogf = 0x3f;
		rq.ocf = 0x000f;
		rq.cparam = NULL;
		rq.clen = 0;
		rq.rparam = &buf;
		rq.rlen = sizeof(buf);

		if (hci_send_req(dd, &rq, 1000) < 0) {
			printf("\n Can't read revision info. %s(%d)\n",
				strerror(errno), errno);
			return -1;
		}

		printf("%s\n", buf + 1);
		break;
	default:
		printf("\n Manufacturer not supported\n");
		break;
	}
	printf("\n");
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

	if (ioctl(s, HCIGETCONNLIST, (void*)cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i=0; i < cl->conn_num; i++, ci++) {
		bdaddr_t bdaddr;
		baswap(&bdaddr, &ci->bdaddr);
		printf("\t%s %s %s handle %d state %d lm %s\n",
			ci->out ? "<" : ">",
			ci->type == ACL_LINK ? "ACL" : "SCO",
			batostr(&bdaddr), ci->handle, ci->state,
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

	if (ioctl(s, HCIGETCONNLIST, (void*)cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i=0; i < cl->conn_num; i++, ci++)
		if (!bacmp((bdaddr_t *)arg, &ci->bdaddr))
			return 1;
	return 0;
}

static void hex_dump(char *pref, int width, unsigned char *buf, int len)
{
	register int i,n;

	for (i=0, n=1; i<len; i++, n++) {
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

/* Display local devices */

static struct option dev_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *dev_help = 
	"Usage:\n"
	"\tdev\n";

static void cmd_dev(int dev_id, int argc, char **argv)
{
	int opt;
	for_each_opt(opt, dev_options, NULL) {
		switch(opt) {
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
	{"help",    0,0, 'h'},
	{"length",  1,0, 'l'},
	{"numrsp",  1,0, 'n'},
	{"flush",   0,0, 'f'},
	{0, 0, 0, 0}
};

static char *inq_help = 
	"Usage:\n"
	"\tinq [--length=N] maximum inquiry duration in 1.28 s units\n"
        "\t    [--numrsp=N] specify maximum number of inquiry responses\n"
        "\t    [--flush]    flush the inquiry cache\n";

static void cmd_inq(int dev_id, int argc, char **argv)
{
	int num_rsp, length, flags;
	inquiry_info *info = NULL;
	bdaddr_t bdaddr;
	int i, opt;

	length  = 8;  /* ~10 seconds */
	num_rsp = 10;
	flags = 0;

	for_each_opt(opt, inq_options, NULL) {
		switch(opt) {
		case 'l':
			length = atoi(optarg);
			break;
		
		case 'n':
			num_rsp = atoi(optarg);
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
	num_rsp = hci_inquiry(dev_id, length, num_rsp, NULL, &info, flags);
	if (num_rsp < 0) {
		perror("Inquiry failed.");
		exit(1);
	}

	for (i = 0; i < num_rsp; i++) {
		baswap(&bdaddr, &(info+i)->bdaddr);
		printf("\t%s\tclock offset: 0x%4.4x\tclass: 0x%2.2x%2.2x%2.2x\n",
			batostr(&bdaddr), (info+i)->clock_offset,
			(info+i)->dev_class[2], 
			(info+i)->dev_class[1], 
			(info+i)->dev_class[0]);
	}
	free(info);
}

/* Device scanning */

static struct option scan_options[] = {
	{"help",    0,0, 'h'},
	{"length",  1,0, 'l'},
	{"numrsp",  1,0, 'n'},
	{"flush",   0,0, 'f'},
	{0, 0, 0, 0}
};

static char *scan_help = 
	"Usage:\n"
	"\tscan [--length=N] [--numrsp=N] [--flush]\n";

static void cmd_scan(int dev_id, int argc, char **argv)
{
	inquiry_info *info = NULL;
	int num_rsp, length, flags;
	bdaddr_t bdaddr;
	char name[248];
	int i, opt, dd;

	length  = 8;  /* ~10 seconds */
	num_rsp = 10;
	flags = 0;

	for_each_opt(opt, scan_options, NULL) {
		switch(opt) {
		case 'l':
			length = atoi(optarg);
			break;
		
		case 'n':
			num_rsp = atoi(optarg);
			break;

		case 'f':
			flags |= IREQ_CACHE_FLUSH;
			break;

		default:
			printf(scan_help);
			return;
		}
	}

	printf("Scanning ...\n");
	num_rsp = hci_inquiry(dev_id, length, num_rsp, NULL, &info, flags);
	if (num_rsp < 0) {
		perror("Inquiry failed.");
		exit(1);
	}

	for (i = 0; i < num_rsp; i++) {
		dd = hci_open_dev(dev_id);
		memset(name, 0, sizeof(name));
		if (hci_remote_name(dd, &(info+i)->bdaddr, sizeof(name), name, 100000) < 0)
			strcpy(name, "n/a");
		close(dd);
		baswap(&bdaddr, &(info+i)->bdaddr);
                printf("\t%s\t%s\n", batostr(&bdaddr), name);
	}
	free(info);
}

/* Remote name */

static struct option name_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
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
		switch(opt) {
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

	baswap(&bdaddr, strtoba(argv[0]));

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

	if (hci_remote_name(dd, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("%s\n", name);

	close(dd);

}

/* Info about remote device */

static struct option info_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *info_help = 
	"Usage:\n"
	"\tinfo <bdaddr>\n";

static void cmd_info(int dev_id, int argc, char **argv)
{
	bdaddr_t bdaddr;
	uint16_t handle;
	char name[248];
	unsigned char features[8];
	struct hci_version version;
	int opt, dd;

	for_each_opt(opt, info_options, NULL) {
		switch(opt) {
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

	baswap(&bdaddr, strtoba(argv[0]));

	if (dev_id < 0) {
		dev_id = hci_get_route(&bdaddr);
		if (dev_id < 0) {
			fprintf(stderr, "Device is not available.\n");
			exit(1);
		}
	}

	printf("Requesting information ...\n");

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		perror("HCI device open failed");
		exit(1);
	}

	printf("\tBD Address:  %s\n", argv[0]);

	if (hci_create_connection(dd, &bdaddr, 0x0008 | 0x0010, 0, 0, &handle, 25000) < 0) {
		close(dd);
		exit(1);
	}

	if (hci_remote_name(dd, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("\tDevice Name: %s\n", name);

	if (hci_read_remote_version(dd, handle, &version, 20000) == 0) {
		printf("\tLMP Version: %s (0x%x) LMP Subversion: 0x%x\n"
			"\tManufacturer: %s (%d)\n",
			lmp_vertostr(version.lmp_ver), version.lmp_ver, version.lmp_subver, 
			bt_compidtostr(version.manufacturer), version.manufacturer);
	}

	if (hci_read_remote_features(dd, handle, features, 20000) == 0) {
		printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n%s\n",
				features[0], features[1], features[2], features[3],
				lmp_featurestostr(features, "\t\t", 3));
	}

	hci_disconnect(dd, handle, 0x13, 10000);

	close(dd);
}

/* Send arbitrary HCI commands */

static struct option cmd_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *cmd_help = 
	"Usage:\n"
	"\tcmd <ogf> <ocf> [parameters]\n"
	"Example:\n"
	"\tcmd 0x03 0x0013 0x41 0x42 0x43 0x44\n";

static void cmd_cmd(int dev_id, int argc, char **argv)
{
	char buf[HCI_MAX_EVENT_SIZE], *ptr = buf;
	struct hci_filter flt;
	hci_event_hdr *hdr;
	int i, opt, len, dd;
	uint16_t ocf;
	uint8_t  ogf;

	for_each_opt(opt, cmd_options, NULL) {
		switch(opt) {
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
	return;
}

/* Display revision info */

static struct option rev_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *rev_help = 
	"Usage:\n"
	"\trev\n";

static void cmd_rev(int dev_id, int argc, char **argv)
{
	int opt;

	for_each_opt(opt, rev_options, NULL) {
		switch(opt) {
		default:
			printf(rev_help);
			return;
		}
	}
	hci_for_each_dev(HCI_UP, rev_info, dev_id);
}

/* Display active connections */

static struct option con_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *con_help = 
	"Usage:\n"
	"\tcon\n";

static void cmd_con(int dev_id, int argc, char **argv)
{
	int opt;

	for_each_opt(opt, con_options, NULL) {
		switch(opt) {
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
	{"help",    0,0, 'h'},
	{"role",    1,0, 'r'},
	{"ptype",   1,0, 'p'},
	{0, 0, 0, 0}
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
	int opt, ptype, dd;
	uint16_t handle;
	uint8_t role;

	role = 0;
	ptype = HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5;

	for_each_opt(opt, cc_options, NULL) {
		switch(opt) {
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

	hci_create_connection(dd, &bdaddr, ptype, 0, role, &handle, 1000);
	hci_close_dev(dd);
}

/* Close connection */

static struct option dc_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
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
		switch(opt) {
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
        if (!cr)
                return;

        bacpy(&cr->bdaddr, &bdaddr);
        cr->type = ACL_LINK;
        if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
                exit(1);
        }

	hci_disconnect(dd, cr->conn_info->handle, 0x13, 100);

	close(dd);
	free(cr);
}

/* Read RSSI */

static struct option rssi_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *rssi_help = 
	"Usage:\n"
	"\trssi <bdaddr>\n";

static void cmd_rssi(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	struct hci_request rq;	
	read_rssi_rp rp;
	bdaddr_t bdaddr;
	int opt, dd;

	for_each_opt(opt, rssi_options, NULL) {
		switch(opt) {
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
	if (!cr)
        	return;

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}
	
	memset(&rq, 0, sizeof(rq));	
	rq.ogf = OGF_STATUS_PARAM;
	rq.ocf = OCF_READ_RSSI;
	rq.cparam = &cr->conn_info->handle;
	rq.clen = 2;
	rq.rparam = &rp;
	rq.rlen = READ_RSSI_RP_SIZE;
	
	if (hci_send_req(dd, &rq, 100) < 0) {
		perror("Read RSSI failed");
		exit(1);
	}

	if (rp.status) {
		printf("Read RSSI returned (error) status 0x%2.2X\n", rp.status);
		exit(1);
	}
	printf("\tRSSI return value: %d\n", rp.rssi);
	
	close(dd);
	free(cr);
}

/* Set connection packet type */

static struct option cpt_options[] = {
	{"help",    0,0, 'h'},
	{0, 0, 0, 0}
};

static char *cpt_help = 
	"Usage:\n"
	"\tcpt <bdaddr> <packet_types>\n";

static void cmd_cpt(int dev_id, int argc, char **argv)
{
	struct hci_conn_info_req *cr;
	struct hci_request rq;
	set_conn_ptype_cp  cp;
	bdaddr_t bdaddr;
	int opt, dd, ptype;

	for_each_opt(opt, cpt_options, NULL) {
		switch(opt) {
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
	if (!cr)
        	return;

	bacpy(&cr->bdaddr, &bdaddr);
	cr->type = ACL_LINK;
	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		perror("Get connection info failed");
		exit(1);
	}
	
	cp.handle   = cr->conn_info->handle;
	cp.pkt_type = ptype;

	memset(&rq, 0, sizeof(rq));	
	rq.ogf = OGF_STATUS_PARAM;
	rq.ocf = OCF_READ_RSSI;
	rq.cparam = &cp;
	rq.clen   = SET_CONN_PTYPE_CP_SIZE;
	
	if (hci_send_req(dd, &rq, 100) < 0) {
		perror("Packet type change failed");
		exit(1);
	}

	close(dd);
	free(cr);
}


struct {
	char *cmd;
	void (*func)(int dev_id, int argc, char **argv);
	char *doc;
} command[] = {
	{ "dev",  cmd_dev,  "Display local devices"              },
	{ "rev",  cmd_rev,  "Display revison information"        },
	{ "inq",  cmd_inq,  "Inquire remote devices"             },
	{ "scan", cmd_scan, "Scan for remote devices"            },
	{ "name", cmd_name, "Get name from remote device"        },
	{ "info", cmd_info, "Get information from remote device" },
	{ "cmd",  cmd_cmd,  "Submit arbitrary HCI commands"      },
	{ "con",  cmd_con,  "Display active connections"         },
	{ "cc",   cmd_cc,   "Create connection to remote device" },
	{ "dc",	  cmd_dc,   "Disconnect from remote device"      },
	{ "cpt",  cmd_cpt,  "Change connection packet type"      },
	{ "rssi", cmd_rssi, "Display connection RSSI"            },
	{ NULL, NULL, 0}
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
	for (i=0; command[i].cmd; i++)
		printf("\t%-4s\t%s\n", command[i].cmd,
		command[i].doc);
	printf("\n"
		"For more information on the usage of each command use:\n"
		"\thcitool <command> --help\n" );
}

static struct option main_options[] = {
	{"help",        0,0, 'h'},
	{"device",      1,0, 'i'},
	{0, 0, 0, 0}
};

int main(int argc, char **argv)
{
	int opt, i, dev_id = -1;
	bdaddr_t ba;

	while ((opt=getopt_long(argc, argv, "+i:h", main_options, NULL)) != -1) {
		switch(opt) {
		case 'i':
			dev_id = atoi(optarg + 3);
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

	for (i=0; command[i].cmd; i++) {
		if (strncmp(command[i].cmd, argv[0], 3))
			continue;
		command[i].func(dev_id, argc, argv);
		break;
	}
	return 0;
}
