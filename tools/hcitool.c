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

#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <bluetooth.h>
#include <hci.h>
#include <hci_lib.h>

extern int optind,opterr,optopt;
extern char *optarg;

static int ctl;

static int for_each_dev(int flag, int(*func)(int d, long arg), long arg)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t));
	if (!dl) {
		perror("Can't allocate memory");
		return -1;
	}
	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, (void*)dl)) {
		perror("Can't get device list");
		return -1;
	}
	
	if (!dl->dev_num)
		return -1;

	for (i=0; i < dl->dev_num; i++, dr++) {
		if (dr->dev_opt & (1<<flag)) {
			if (!func || func(dr->dev_id, arg))
				return dr->dev_id;
		}
	}
	return -1;
}

static int other_bdaddr(int dev_id, long arg)
{
	struct hci_dev_info di = {dev_id: dev_id};
	if (ioctl(ctl, HCIGETDEVINFO, (void*) &di))
		return 0;
	return bacmp((bdaddr_t *)arg, &di.bdaddr);
}

static int get_route(bdaddr_t *bdaddr)
{
	if (bdaddr)
		return for_each_dev(HCI_UP, other_bdaddr, (long) bdaddr);
	else
		return for_each_dev(HCI_UP, NULL, 0);
}

static int dev_info(int dev_id, long arg)
{
	struct hci_dev_info di = {dev_id: dev_id};
	bdaddr_t bdaddr;
	if (ioctl(ctl, HCIGETDEVINFO, (void*) &di))
		return 0;
	
	baswap(&bdaddr, &di.bdaddr);
	printf("\t%s\t%s\n", di.name, batostr(&bdaddr));
	return 0;
}

static int rev_info(int dev_id, long arg)
{
	struct hci_version ver;
	int dd;

	struct hci_request rq;
	unsigned char buf[102];


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

static int conn_list(int dev_id, long arg)
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

	if (ioctl(ctl, HCIGETCONNLIST, (void*)cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i=0; i < cl->conn_num; i++, ci++) {
		bdaddr_t bdaddr;
		baswap(&bdaddr, &ci->bdaddr);
		printf("\t%s %s %s handle %d state %d lm %s\n",
			ci->out ? "<" : ">",
			ci->type == ACL_LINK ? "ACL" : "SCO",
			batostr(&bdaddr), ci->handle,
		     	ci->state,
			hci_lmtostr(ci->link_mode));
	}
	return 0;
}

static int find_conn(int dev_id, long arg)
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

	if (ioctl(ctl, HCIGETCONNLIST, (void*)cl)) {
		perror("Can't get connection list");
		exit(1);
	}

	for (i=0; i < cl->conn_num; i++, ci++)
		if (!bacmp((bdaddr_t *)arg, &ci->bdaddr))
			return 1;
	return 0;
}

static void cmd_dev(int dev_id, char **opt, int nopt)
{
	printf("Devices:\n");
	for_each_dev(HCI_UP, dev_info, 0);	
}

static void cmd_inq(int dev_id, char **opt, int nopt)
{
	inquiry_info *info;
	int i, num_rsp = 0, length, flags;
	bdaddr_t bdaddr;
	
	if (dev_id < 0)
		dev_id = get_route(NULL);
	
	if (nopt >= 1)
		length = atoi(opt[0]);
	else
		length = 8; /* ~ 10 seconds */

	flags = 0;
	if (nopt >= 2)
		flags |= !strncasecmp("f", opt[1], 1) ? IREQ_CACHE_FLUSH : 0;
		
	printf("Inquiring ...\n");
	info = hci_inquiry(dev_id, length, &num_rsp, NULL, flags);

	if (!info) {
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

static void cmd_scan(int dev_id, char **opt, int nopt)
{
	inquiry_info *info;
	int i, num_rsp = 0, length, flags;
	bdaddr_t bdaddr;
	int dd;
	char name[248];

	if (dev_id < 0)
		dev_id = get_route(NULL);

	if (nopt >= 1)
		length = atoi(opt[0]);
	else
		length = 8; /* ~ 10 seconds */

	flags = 0;
	if (nopt >= 2)
		flags |= !strncasecmp("f", opt[1], 1) ? IREQ_CACHE_FLUSH : 0;

	printf("Scanning ...\n");
	info = hci_inquiry(dev_id, length, &num_rsp, NULL, flags);

	if (!info) {
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

static void cmd_rev(int dev_id, char **opt, int nopt)
{
        if (dev_id < 0)
                for_each_dev(HCI_UP, rev_info, 0);
        else
                rev_info(dev_id, 0);
}

static void cmd_con(int dev_id, char **opt, int nopt)
{
	printf("Connections:\n");
	if (dev_id < 0)
		for_each_dev(HCI_UP, conn_list, 0);
	else
		conn_list(dev_id, 0);
}

static void cmd_cc(int dev_id, char **opt, int nopt)
{
	bdaddr_t bdaddr;
	int ptype, dd;
	uint16_t handle;
	uint8_t role;

	if (nopt < 1)
		return;

	baswap(&bdaddr, strtoba(opt[0]));

	if (dev_id < 0) {
		dev_id = get_route(&bdaddr);
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

	if (nopt >= 2)
		hci_strtoptype(opt[1], &ptype);
	else
		ptype = HCI_DM1 | HCI_DM3 | HCI_DM5 | HCI_DH1 | HCI_DH3 | HCI_DH5;

	if (nopt >= 3)
		role = !strncasecmp("m", opt[2], 1) ? 0 : 1;
	else
		role = 0;
	
	hci_create_connection(dd, &bdaddr, ptype, 0, role, &handle, 1000);

	hci_close_dev(dd);
}

static void cmd_dc(int dev_id, char **opt, int nopt)
{
	struct hci_conn_info_req *cr;
	bdaddr_t bdaddr;
	int dd;

	if (nopt < 1)
		return;

	baswap(&bdaddr, strtoba(*opt));

	if (dev_id < 0) {
		dev_id = for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
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

struct {
	char *cmd;
	void (*func)(int dev_id, char **opt, int nopt);
	char *opt;
	char *doc;
} command[] = {
	{ "dev",  cmd_dev,  0,          "Display local devices"       },
	{ "rev",  cmd_rev,  0,          "Display revison information" },
	{ "inq",  cmd_inq,  "[length] [flush]", "Inquire remote devices"     },
	{ "scan", cmd_scan, "[length] [flush]", "Scan for remote devices"     },
	{ "con",  cmd_con,  0,          "Display active connections" },
	{ "cc",   cmd_cc,   "<bdaddr> [pkt type] [role]", "Create connection to remote device" },
	{ "dc",	  cmd_dc,   "<bdaddr>", "Disconnect from remote device" },
	{ NULL, NULL, 0}
};

static void usage(void)
{
	int i;

	printf("hcitool - HCI Tool\n");
	printf("Usage:\n"
		"\thcitool [-i hciX] [command]\n");
	printf("Commands:\n");
	for (i=0; command[i].cmd; i++)
		printf("\t%-4s %-20s\t%s\n", command[i].cmd,
		command[i].opt ? command[i].opt : " ",
		command[i].doc);
}

int main(int argc, char *argv[], char *env[])
{
	int opt, i, dev_id = -1;
	char *dev;

	while ((opt=getopt(argc, argv, "i:h")) != EOF) {
		switch(opt) {
		case 'i':
			dev    = strdup(optarg);
			dev_id = atoi(dev + 3);
			break;

		case 'h':
		default:
			usage();
			exit(0);
		}
	}

	if (argc - optind < 1) {
		usage();
		exit(0);
	}

	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		exit(1);
	}

	for (i=0; command[i].cmd; i++) {
		if (strncmp(command[i].cmd, argv[optind], 3)) 
			continue;
		optind++;
		command[i].func(dev_id, argv + optind, argc - optind);
		break;
	}

	close(ctl);
	return 0;
}
