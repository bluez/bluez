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

static struct hci_dev_info di;
static int all;

void print_dev_hdr(struct hci_dev_info *di);
void print_dev_info(int ctl, struct hci_dev_info *di);

void print_dev_list(int ctl, int flags)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i;

	if( !(dl = malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t))) ) {
		perror("Can't allocate memory");
		exit(1);
	}
	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if( ioctl(ctl, HCIGETDEVLIST, (void*)dl) ) {
		perror("Can't get device list");
		exit(1);
	}
	for(i=0; i< dl->dev_num; i++) {
		di.dev_id = (dr+i)->dev_id;
		if( ioctl(ctl, HCIGETDEVINFO, (void*)&di) )
			continue;
		print_dev_info(ctl, &di);
	}
}

void print_pkt_type(struct hci_dev_info *di)
{
	printf("\tPacket type: %s\n", hci_ptypetostr(di->pkt_type));
}

void print_link_policy(struct hci_dev_info *di)
{
	printf("\tLink policy: %s\n", hci_lptostr(di->link_policy));
}

void print_link_mode(struct hci_dev_info *di)
{
	printf("\tLink mode: %s\n", hci_lmtostr(di->link_mode));
}

void print_dev_features(struct hci_dev_info *di)
{
	printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n", 
			di->features[0], di->features[1],
			di->features[2], di->features[3] );
}

void cmd_rstat(int ctl, int hdev, char *opt)
{
	/* Reset HCI device stat counters */
	if( ioctl(ctl, HCIDEVRESTAT, hdev) < 0 ) {
		printf("Can't reset stats counters hci%d. %s(%d)\n", hdev, 
				strerror(errno), errno);
		exit(1);
	}
}

void cmd_scan(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr;

	dr.dev_id  = hdev;
	dr.dev_opt = SCAN_DISABLED;
	if( !strcmp(opt, "iscan") )
		dr.dev_opt = SCAN_INQUIRY;
	else if( !strcmp(opt, "pscan") )
		dr.dev_opt = SCAN_PAGE;
	else if( !strcmp(opt, "piscan") )
		dr.dev_opt = SCAN_PAGE | SCAN_INQUIRY;

	if( ioctl(ctl, HCISETSCAN, (unsigned long)&dr) < 0 ) {
		printf("Can't set scan mode on hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
}

void cmd_auth(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr;

	dr.dev_id = hdev;
	if( !strcmp(opt, "auth") )
		dr.dev_opt = AUTH_ENABLED;
	else
		dr.dev_opt = AUTH_DISABLED;

	if( ioctl(ctl, HCISETAUTH, (unsigned long)&dr) < 0 ) {
		printf("Can't set auth on hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
}

void cmd_encrypt(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr;

	dr.dev_id = hdev;
	if( !strcmp(opt, "encrypt") )
		dr.dev_opt = ENCRYPT_P2P;
	else
		dr.dev_opt = ENCRYPT_DISABLED;

	if( ioctl(ctl, HCISETENCRYPT, (unsigned long)&dr) < 0 ) {
		printf("Can't set encrypt on hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
}

void cmd_up(int ctl, int hdev, char *opt)
{
	int ret;

	/* Start HCI device */
	if( (ret = ioctl(ctl, HCIDEVUP, hdev)) < 0 ) {
		if( errno == EALREADY )
			return;
		printf("Can't init device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
	cmd_scan(ctl,  hdev, "piscan");
}

void cmd_down(int ctl, int hdev, char *opt)
{
	/* Stop HCI device */
	if (ioctl(ctl, HCIDEVDOWN, hdev) < 0) {
		printf("Can't down device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
}

void cmd_reset(int ctl, int hdev, char *opt)
{
	/* Reset HCI device
	if( ioctl(ctl, HCIDEVRESET, hdev) < 0 ){
	   printf("Reset failed hci%d. %s(%d)\n", hdev, strerror(errno), errno);
	   exit(1);
	}
	*/
	cmd_down(ctl, hdev, "down");
	cmd_up(ctl, hdev, "up");
}

void cmd_ptype(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr;

	dr.dev_id = hdev;

	if (hci_strtoptype(opt, &dr.dev_opt)) {
		if (ioctl(ctl, HCISETPTYPE, (unsigned long)&dr) < 0) {
			printf("Can't set pkttype on hci%d. %s(%d)\n", hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		print_dev_hdr(&di);
		print_pkt_type(&di);
	}
}

void cmd_lp(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr;

	dr.dev_id = hdev;

	if (hci_strtolp(opt, &dr.dev_opt)) {
		if (ioctl(ctl, HCISETLINKPOL, (unsigned long)&dr) < 0) {
			printf("Can't set link policy on hci%d. %s(%d)\n", 
					hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		print_dev_hdr(&di);
		print_link_policy(&di);
	}
}

void cmd_lm(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr;

	dr.dev_id = hdev;

	if (hci_strtolm(opt, &dr.dev_opt)) {
		if (ioctl(ctl, HCISETLINKMODE, (unsigned long)&dr) < 0) {
			printf("Can't set default link mode on hci%d. %s(%d)\n", 
					hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		print_dev_hdr(&di);
		print_link_mode(&di);
	}
}

void cmd_features(int ctl, int hdev, char *opt)
{
	print_dev_hdr(&di);
	print_dev_features(&di);
}

void cmd_name(int ctl, int hdev, char *opt)
{
	struct hci_request rq;
	int s;
	if ((s = hci_open_dev(hdev)) < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	memset(&rq, 0, sizeof(rq));

	if (opt) {
		change_local_name_cp cp;
		strcpy(cp.name, opt);

		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_CHANGE_LOCAL_NAME;
		rq.cparam = &cp;
		rq.clen = CHANGE_LOCAL_NAME_CP_SIZE;
	
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't change local name on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		read_local_name_rp rp;

		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_READ_LOCAL_NAME;
		rq.rparam = &rp;
		rq.rlen = READ_LOCAL_NAME_RP_SIZE;
		
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't read local name on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
		if (rp.status) {
			printf("Read local name on hci%d returned status %d\n", hdev, rp.status);
			exit(1);
		}
		print_dev_hdr(&di);
		printf("\tName: '%s'\n", rp.name);
	}
}

void cmd_class(int ctl, int hdev, char *opt)
{
	struct hci_request rq;
	int s;

	if ((s = hci_open_dev(hdev)) < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	memset(&rq, 0, sizeof(rq));
	if (opt) {
		uint32_t cod = htobl(strtoul(opt, NULL, 16));
		write_class_of_dev_cp cp;

		memcpy(cp.dev_class, &cod, 3);

		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_WRITE_CLASS_OF_DEV;
		rq.cparam = &cp;
		rq.clen = WRITE_CLASS_OF_DEV_CP_SIZE;

		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't write local class of device on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		read_class_of_dev_rp rp;

		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_READ_CLASS_OF_DEV;
		rq.rparam = &rp;
		rq.rlen = READ_CLASS_OF_DEV_RP_SIZE;

		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't read class of device on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}

		if (rp.status) {
			printf("Read class of device on hci%d returned status %d\n",
				hdev, rp.status);
			exit(1);
		}
		print_dev_hdr(&di);
		printf("\tClass: 0x%02x%02x%02x\n", 
			rp.dev_class[2], rp.dev_class[1], rp.dev_class[0]);
	}
}

void cmd_version(int ctl, int hdev, char *opt)
{
	struct hci_version ver;
	int dd;

	dd = hci_open_dev(hdev);
	if (dd < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		printf("Can't read version info hci%d. %s(%d)\n", 
			hdev, strerror(errno), errno);
		exit(1);
	}

	print_dev_hdr(&di);
	printf( "\tHCI Ver: 0x%x HCI Rev: 0x%x LMP Ver: 0x%x LMP Subver: 0x%x\n"
		"\tManufacturer: %d\n",
		ver.hci_ver, ver.hci_rev, ver.lmp_ver, ver.lmp_subver, 
		ver.manufacturer);
}

void print_dev_hdr(struct hci_dev_info *di)
{
	static int hdr = -1;
	bdaddr_t bdaddr;

	if (hdr == di->dev_id)
		return;
	hdr = di->dev_id;
	
	baswap(&bdaddr, &di->bdaddr);

	printf("%s:\tType: %s\n", di->name, hci_dtypetostr(di->type) );
	printf("\tBD Address: %s ACL MTU: %d:%d  SCO: MTU %d:%d\n",
	       batostr(&bdaddr), di->acl_mtu, di->acl_max,
	       di->sco_mtu, di->sco_max);
}

void print_dev_info(int ctl, struct hci_dev_info *di)
{
	struct hci_dev_stats *st = &di->stat;

	print_dev_hdr(di);

	printf("\t%s\n", hci_dflagstostr(di->flags) );

	printf("\tRX bytes:%d acl:%d sco:%d events:%d errors:%d\n",
	       st->byte_rx, st->acl_rx, st->sco_rx, st->evt_rx, st->err_rx);

	printf("\tTX bytes:%d acl:%d sco:%d commands:%d errors:%d\n",
	       st->byte_tx, st->acl_tx, st->sco_tx, st->cmd_tx, st->err_tx);

	if (all) {
		print_dev_features(di);
		print_pkt_type(di);
		print_link_policy(di);
		print_link_mode(di);

		if (di->flags & (1 << HCI_UP)) {
			cmd_name(ctl, di->dev_id, NULL);
			cmd_class(ctl, di->dev_id, NULL);
			cmd_version(ctl, di->dev_id, NULL);
		}
	}
		
	printf("\n");
}

struct {
	char *cmd;
	void (*func)(int ctl, int hdev, char *opt);
	char *opt;
	char *doc;
} command[] = {
	{ "up",     cmd_up,     0,	"Open and initialize HCI device" },
	{ "down",   cmd_down,   0,	"Close HCI device" },
	{ "reset",  cmd_reset,  0,	"Reset HCI device" },
	{ "rstat",  cmd_rstat,  0,	"Reset statistic counters" },
	{ "auth",   cmd_auth,   0,	"Enable Authentication" },
	{ "noauth", cmd_auth,   0,	"Disable Authentication" },
	{ "encrypt",cmd_encrypt,0,	"Enable Encryption" },
	{ "noencrypt", cmd_encrypt, 0,	"Disable Encryption" },
	{ "piscan", cmd_scan,   0,	"Enable Page and Inquiry scan" },
	{ "noscan", cmd_scan,   0,	"Disable scan" },
	{ "iscan",  cmd_scan,   0,	"Enable Inquiry scan" },
	{ "pscan",  cmd_scan,   0,	"Enable Page scan" },
	{ "ptype",  cmd_ptype,   "[type]",   "Get/Set default packet type" },
	{ "lm",     cmd_lm,      "[mode]",   "Get/Set default link mode"   },
	{ "lp",     cmd_lp,      "[policy]", "Get/Set default link policy" },
	{ "name",   cmd_name,    "[name]",   "Get/Set local name" },
	{ "class",  cmd_class,   "[class]",  "Get/Set class of device" },
	{ "version",	cmd_version, 0,  "Display version information" },
	{ "features",	cmd_features, 0,"Display device features" },
	{ NULL, NULL, 0}
};

void usage(void)
{
	int i;

	printf("hciconfig - HCI device configuration utility\n");
	printf("Usage:\n"
		"\thciconfig\n"
		"\thciconfig [-a] hciX [command]\n");
	printf("Commands:\n");
	for (i=0; command[i].cmd; i++)
		printf("\t%-10s %-8s\t%s\n", command[i].cmd,
		command[i].opt ? command[i].opt : " ",
		command[i].doc);
}

int main(int argc, char *argv[], char *env[])
{
	int opt, ctl, i, cmd=0;
	char *dev;

	while ((opt=getopt(argc, argv,"ha")) != EOF) {
		switch(opt) {
		case 'a':
			all = 1;
			break;
		case 'h':
			usage();
			exit(0);
		}
	}

	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		exit(1);
	}

	if (argc - optind < 1) {
		print_dev_list(ctl, 0);
		exit(0);
	}

	dev  = strdup(argv[optind]);
	di.dev_id = atoi(argv[optind]+3);
	optind++;

	if (ioctl(ctl, HCIGETDEVINFO, (void*)&di)) {
		perror("Can't get device info");
		exit(1);
	}

	while (optind < argc) {
		for (i=0; command[i].cmd; i++) {
			if (strncmp(command[i].cmd, argv[optind],4)) 
				continue;

			if (command[i].opt)
				optind++;
			
			command[i].func(ctl, di.dev_id, argv[optind]);
			cmd = 1;
			break;
		}
		optind++;
	}

	if (!cmd)
		print_dev_info(ctl, &di);

	close(ctl);
	return 0;
}
