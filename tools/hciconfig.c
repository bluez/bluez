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
#include <getopt.h>

#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

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

void print_dev_features(struct hci_dev_info *di, int format)
{
	if (!format) {
		printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n", 
			di->features[0], di->features[1],
			di->features[2], di->features[3] );
	} else {
		printf("\tFeatures: 0x%2.2x 0x%2.2x 0x%2.2x 0x%2.2x\n%s\n", 
			di->features[0], di->features[1],
			di->features[2], di->features[3],
			lmp_featurestostr(di->features, "\t\t", 3));
	}
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

void cmd_aclmtu(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr = { dev_id: hdev };
	uint16_t mtu, mpkt;

	if (!opt)
		return;

	if (sscanf(opt, "%4hu:%4hu", &mtu, &mpkt) != 2)
		return;

	*((uint16_t *)&dr.dev_opt + 1) = mtu;
	*((uint16_t *)&dr.dev_opt + 0) = mpkt;
	
	if (ioctl(ctl, HCISETACLMTU, (unsigned long)&dr) < 0) {
		printf("Can't set ACL mtu on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
		exit(1);
	}
}

void cmd_scomtu(int ctl, int hdev, char *opt)
{
	struct hci_dev_req dr = { dev_id: hdev };
	uint16_t mtu, mpkt;

	if (!opt)
		return;

	if (sscanf(opt, "%4hu:%4hu", &mtu, &mpkt) != 2)
		return;

	*((uint16_t *)&dr.dev_opt + 1) = mtu;
	*((uint16_t *)&dr.dev_opt + 0) = mpkt;
	
	if (ioctl(ctl, HCISETSCOMTU, (unsigned long)&dr) < 0) {
		printf("Can't set SCO mtu on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
		exit(1);
	}
}

void cmd_features(int ctl, int hdev, char *opt)
{
	print_dev_hdr(&di);
	print_dev_features(&di, 1);
}

void cmd_name(int ctl, int hdev, char *opt)
{
	int s = hci_open_dev(hdev);
	if (s < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
	if (opt) {
		if (hci_write_local_name(s, opt, 1000) < 0) {
			printf("Can't change local name on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		char name[248];
		if (hci_read_local_name(s, sizeof(name), name, 1000) < 0) {
			printf("Can't read local name on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
		print_dev_hdr(&di);
		printf("\tName: '%s'\n", name);
	}
}

/* 
 * see http://www.bluetooth.org/assigned-numbers/baseband.htm --- all
 * strings are reproduced verbatim
 */
static char *get_minor_device_name(int major, int minor)
{
	switch(major) {
	case 0:/* misc */
		return "";
	case 1:/* computer */
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
	case 2:/* phone */
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
	case 3:/* lan access */
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
	case 4:/* audio/video */
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
	case 5:/* peripheral */
		switch(minor) {
		case 16:
			return "Keyboard";
		case 32:
			return "Pointing device";
		case 64:
			return "Combo keyboard/pointing device";
		}
		break;
	case 6:/* imaging */
		if (minor & 4)
			return "Display";
		if (minor & 8)
			return "Camera";
		if (minor & 16)
			return "Scanner";
		if (minor & 32)
			return "Printer";
		break;
	case 63:/* uncategorised */
		return "";
	}
	return "Unknown (reserved) minor device class";
}

void cmd_class(int ctl, int hdev, char *opt)
{
	static char *services[] = { "Positioning",
					"Networking",
					"Rendering",
					"Capturing",
					"Object Transfer",
					"Audio",
					"Telephony",
					"Information" };
	static char *major_devices[] = { "Miscellaneous",
					"Computer",
					"Phone",
					"LAN Access",
					"Audio/Video",
					"Peripheral",
					"Imaging",
					"Uncategorized" };
	int s = hci_open_dev(hdev);

	if (s < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
	if (opt) {
		uint32_t cod = strtoul(opt, NULL, 16);
		if (0 > hci_write_class_of_dev(s, cod, 1000)) {
			printf("Can't write local class of device on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		uint8_t cls[3];
		if (0 > hci_read_class_of_dev(s, cls, 1000)) {
			printf("Can't read class of device on hci%d. %s(%d)\n", 
				hdev, strerror(errno), errno);
			exit(1);
		}
		print_dev_hdr(&di);
		printf("\tClass: 0x%02x%02x%02x\n", cls[2], cls[1], cls[0]);
		printf("\tService Classes: ");
		if (cls[2]) {
			int first = 1;
			for(s=0; s < sizeof(services); s++)
				if (cls[2] & (1 << s)) {
					if (!first)
						printf(", ");
					printf(services[s]);
					first = 0;
				}
		} else
			printf("Unspecified");
		printf("\n\tDevice Class: ");
		if (cls[1] > sizeof(major_devices))
			printf("Invalid Device Class!\n");
		else
			printf("%s, %s\n", major_devices[cls[1]], 
				get_minor_device_name(cls[1], cls[0] / 4));
	}
}

void cmd_voice(int ctl, int hdev, char *opt)
{
	static char *icf[] = { "Linear", "u-Law", "A-Law", "Reserved" };
	static char *idf[] = { "1's complement", "2's complement", "Sign-Magnitude", "Reserved" };
	static char *iss[] = { "8 bit", "16 bit" };
	static char *acf[] = { "CVSD", "u-Law", "A-Law", "Reserved" };
	int s = hci_open_dev(hdev);

	if (s < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}
	if (opt) {
		uint16_t vs = htobs(strtoul(opt, NULL, 16));
		if (0 > hci_write_voice_setting(s, vs, 1000)) {
			printf("Can't write voice setting on hci%d. %s(%d)\n",
				hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		uint16_t vs;
		uint8_t ic;
		if (0 > hci_read_voice_setting(s, &vs, 1000)) {
			printf("Can't read voice setting on hci%d. %s(%d)\n",
				hdev, strerror(errno), errno);
			exit(1);
		}
		vs = htobs(vs);
		ic = (vs & 0x0300) >> 8;
		print_dev_hdr(&di);
		printf("\tVoice setting: 0x%04x%s\n", vs,
			((vs & 0x03fc) == 0x0060) ? " (Default Condition)" : "");
		printf("\tInput Coding: %s\n", icf[ic]);
		printf("\tInput Data Format: %s\n", idf[(vs & 0xc0) >> 6]);
		if (!ic) {
			printf("\tInput Sample Size: %s\n", iss[(vs & 0x20) >> 5]);
			printf("\t# of bits padding at MSB: %d\n", (vs & 0x1c) >> 2);
		}
		printf("\tAir Coding Format: %s\n", acf[vs & 0x03]);
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
	printf( "\tHCI Ver: %s (0x%x) HCI Rev: 0x%x LMP Ver: %s (0x%x) LMP Subver: 0x%x\n"
		"\tManufacturer: %s (%d)\n",
		hci_vertostr(ver.hci_ver), ver.hci_ver, ver.hci_rev, 
		lmp_vertostr(ver.lmp_ver), ver.lmp_ver, ver.lmp_subver, 
		bt_compidtostr(ver.manufacturer), ver.manufacturer);
}

void cmd_inq_parms(int ctl, int hdev, char *opt)
{
	struct hci_request rq;
	int s;
	if ((s = hci_open_dev(hdev)) < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	memset(&rq, 0, sizeof(rq));

	if (opt) {
		unsigned int window, interval;
		write_inq_activity_cp cp;

		if (sscanf(opt,"%4u:%4u", &window, &interval) != 2) {
			printf("Invalid argument format\n");
			exit(1);
		}
			
		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_WRITE_INQ_ACTIVITY;
		rq.cparam = &cp;
		rq.clen = WRITE_INQ_ACTIVITY_CP_SIZE;
		
		cp.window = htobs((uint16_t)window);
		cp.interval = htobs((uint16_t)interval);
		
		if (window < 0x12 || window > 0x1000)
			printf("Warning: inquiry window out of range!\n");
		
		if (interval < 0x12 || interval > 0x1000)
			printf("Warning: inquiry interval out of range!\n");
		
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't set inquiry parameters name on hci%d. %s(%d)\n",
						hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		uint16_t window, interval;
		read_inq_activity_rp rp;
		
		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_READ_INQ_ACTIVITY;
		rq.rparam = &rp;
		rq.rlen = READ_INQ_ACTIVITY_RP_SIZE;
		      
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't read inquiry parameters on hci%d. %s(%d)\n", 
							hdev, strerror(errno), errno);
			exit(1);
		}
		if (rp.status) {
			printf("Read inquiry parameters on hci%d returned status %d\n", 
							hdev, rp.status);
			exit(1);
		}
		print_dev_hdr(&di);
		
		window   = btohs(rp.window);
		interval = btohs(rp.interval);
		printf("\tInquiry interval: %u slots (%.2f ms), window: %u slots (%.2f ms)\n",
				interval, (float)interval * 0.625, window, (float)window * 0.625);
	}
}

void cmd_page_parms(int ctl, int hdev, char *opt)
{
	struct hci_request rq;
	int s;
	if ((s = hci_open_dev(hdev)) < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	memset(&rq, 0, sizeof(rq));

	if (opt) {
		unsigned int window, interval;
		write_page_activity_cp cp;

		if (sscanf(opt,"%4u:%4u", &window, &interval) != 2) {
			printf("Invalid argument format\n");
			exit(1);
		}
			
		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_WRITE_PAGE_ACTIVITY;
		rq.cparam = &cp;
		rq.clen = WRITE_PAGE_ACTIVITY_CP_SIZE;
		
		cp.window = htobs((uint16_t)window);
		cp.interval = htobs((uint16_t)interval);
		
		if (window < 0x12 || window > 0x1000)
			printf("Warning: page window out of range!\n");
		
		if (interval < 0x12 || interval > 0x1000)
			printf("Warning: page interval out of range!\n");
		
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't set page parameters name on hci%d. %s(%d)\n",
						hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		uint16_t window, interval;
		read_page_activity_rp rp;
		
		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_READ_PAGE_ACTIVITY;
		rq.rparam = &rp;
		rq.rlen = READ_PAGE_ACTIVITY_RP_SIZE;
		      
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't read page parameters on hci%d. %s(%d)\n", 
							hdev, strerror(errno), errno);
			exit(1);
		}
		if (rp.status) {
			printf("Read page parameters on hci%d returned status %d\n", 
							hdev, rp.status);
			exit(1);
		}
		print_dev_hdr(&di);
		
		window   = btohs(rp.window);
		interval = btohs(rp.interval);
		printf("\tPage interval: %u slots (%.2f ms), window: %u slots (%.2f ms)\n",
				interval, (float)interval * 0.625, window, (float)window * 0.625);
        }
}

void cmd_page_to(int ctl, int hdev, char *opt)
{
	struct hci_request rq;
	int s;
	if ((s = hci_open_dev(hdev)) < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		exit(1);
	}

	memset(&rq, 0, sizeof(rq));

	if (opt) {
		unsigned int timeout;
		write_page_timeout_cp cp;

		if (sscanf(opt,"%5u", &timeout) != 1) {
			printf("Invalid argument format\n");
			exit(1);
		}
			
		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_WRITE_PAGE_TIMEOUT;
		rq.cparam = &cp;
		rq.clen = WRITE_PAGE_TIMEOUT_CP_SIZE;
		
		cp.timeout = htobs((uint16_t)timeout);
		
		if (timeout < 0x01 || timeout > 0xFFFF)
			printf("Warning: page timeout out of range!\n");
		
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't set page timeout on hci%d. %s(%d)\n",
						hdev, strerror(errno), errno);
			exit(1);
		}
	} else {
		uint16_t timeout;
		read_page_timeout_rp rp;
		
		rq.ogf = OGF_HOST_CTL;
		rq.ocf = OCF_READ_PAGE_TIMEOUT;
		rq.rparam = &rp;
		rq.rlen = READ_PAGE_TIMEOUT_RP_SIZE;
		      
		if (hci_send_req(s, &rq, 1000) < 0) {
			printf("Can't read page timeout on hci%d. %s(%d)\n", 
							hdev, strerror(errno), errno);
			exit(1);
		}
		if (rp.status) {
			printf("Read page timeout on hci%d returned status %d\n", 
							hdev, rp.status);
			exit(1);
		}
		print_dev_hdr(&di);
		
		timeout = btohs(rp.timeout);
		printf("\tPage timeout: %u slots (%.2f ms)\n",
				timeout, (float)timeout * 0.625);
        }
}

static void print_rev_ericsson(int dd)
{
	struct hci_request rq;
	unsigned char buf[102];

	memset(&rq, 0, sizeof(rq));
	rq.ogf = 0x3f;
	rq.ocf = 0x000f;
	rq.cparam = NULL;
	rq.clen = 0;
	rq.rparam = &buf;
	rq.rlen = sizeof(buf);

	if (hci_send_req(dd, &rq, 1000) < 0) {
		printf("\n Can't read revision info. %s(%d)\n", strerror(errno), errno);
		return;
	}

	printf("\t%s\n", buf + 1);
}

static struct {
	char  *str;
	uint16_t rev;
} csr_map[] = {
	{ "HCI 11.2 (bc01b)",	114 },
	{ "HCI 11.3 (bc01b)",   115 },
	{ "HCI 12.1 (bc01b)",	119 },
	{ "HCI 12.3 (bc01b)",	134 },
	{ "HCI 12.7 (bc01b)",	188 },
	{ "HCI 12.8 (bc01b)",	218 },
	{ "HCI 12.9 (bc01b)",	283 },
	{ "HCI 13.10 (bc01b)",	309 },
	{ "HCI 13.11 (bc01b)",	351 },
	{ "HCI 16.4 (bc01b)",	523 },
	{ "HCI 14.3 (bc02x)",	272 },
	{ "HCI 14.6 (bc02x)",	336 },
	{ "HCI 14.7 (bc02x)",	373 },
	{ "HCI 14.8 (bc02x)",	487 },
	{ "HCI 15.3 (bc02x)",	443 },
	{ "HCI 16.4 (bc02x)",	525 },
	{ NULL }
};

static void print_rev_csr(uint16_t rev)
{
	int i;

	for (i = 0; csr_map[i].str; i++)
		if (csr_map[i].rev == rev) {
			printf("\t%s\n", csr_map[i].str);
			return;
		}

	printf("\tUnknown firmware\n");
}

static void print_rev_avm(uint16_t rev)
{
	printf("\tFirmware 3.%d.%d\n", rev >> 8, rev & 0xff);
}

static void cmd_revision(int ctl, int hdev, char *opt)
{
	struct hci_version ver;
	int dd;

	dd = hci_open_dev(hdev);
	if (dd < 0) {
		printf("Can't open device hci%d. %s(%d)\n", hdev, strerror(errno), errno);
		return;
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		printf("Can't read version info hci%d. %s(%d)\n",
			hdev, strerror(errno), errno);
		return;
	}

	print_dev_hdr(&di);
	switch (ver.manufacturer) {
	case 0:
		print_rev_ericsson(dd);
		break;
	case 10:
		print_rev_csr(ver.hci_rev);
		break;
	case 31:
		print_rev_avm(ver.hci_rev);
		break;
	default:
		printf("\tUnsupported manufacturer\n");
		break;
	}
	return;
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
	printf("\tBD Address: %s ACL MTU: %d:%d  SCO MTU: %d:%d\n",
	       batostr(&bdaddr), di->acl_mtu, di->acl_pkts,
	       di->sco_mtu, di->sco_pkts);
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
		print_dev_features(di, 0);
		print_pkt_type(di);
		print_link_policy(di);
		print_link_mode(di);

		if (hci_test_bit(HCI_UP, &di->flags)) {
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
	{ "up",		cmd_up,		0,		"Open and initialize HCI device" },
	{ "down",	cmd_down,	0,		"Close HCI device" },
	{ "reset",	cmd_reset,	0,		"Reset HCI device" },
	{ "rstat",	cmd_rstat,	0,		"Reset statistic counters" },
	{ "auth",	cmd_auth,	0,		"Enable Authentication" },
	{ "noauth",	cmd_auth,	0,		"Disable Authentication" },
	{ "encrypt",	cmd_encrypt,	0,		"Enable Encryption" },
	{ "noencrypt",	cmd_encrypt,	0,		"Disable Encryption" },
	{ "piscan",	cmd_scan,	0,		"Enable Page and Inquiry scan" },
	{ "noscan",	cmd_scan,	0,		"Disable scan" },
	{ "iscan",	cmd_scan,	0,		"Enable Inquiry scan" },
	{ "pscan",	cmd_scan,	0,		"Enable Page scan" },
	{ "ptype",	cmd_ptype,	"[type]",	"Get/Set default packet type" },
	{ "lm",		cmd_lm,		"[mode]",	"Get/Set default link mode"   },
	{ "lp",		cmd_lp,		"[policy]",	"Get/Set default link policy" },
	{ "name",	cmd_name,	"[name]",	"Get/Set local name" },
	{ "class",	cmd_class,	"[class]",	"Get/Set class of device" },
	{ "voice",	cmd_voice,	"[voice]",	"Get/Set voice setting" },
	{ "inqparms",	cmd_inq_parms,	"[win:int]",	"Get/Set inquiry scan window and interval" },
	{ "pageparms",	cmd_page_parms,	"[win:int]",	"Get/Set page scan window and interval" },
	{ "pageto",	cmd_page_to,	"[to]",		"Get/Set page timeout" },
	{ "aclmtu",	cmd_aclmtu,	"<mtu:pkt>",	"Set ACL MTU and number of packets" },
	{ "scomtu",	cmd_scomtu,	"<mtu:pkt>",	"Set SCO MTU and number of packets" },
	{ "features",	cmd_features,	0,		"Display device features" },
	{ "version",	cmd_version,	0,		"Display version information" },
	{ "revision",	cmd_revision,	0,		"Display revision information" },
	{ NULL, NULL, 0 }
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

static struct option main_options[] = {
	{"help", 0,0, 'h'},
	{"all",  0,0, 'a'},
	{0, 0, 0, 0}
};

int main(int argc, char **argv, char **env)
{
	int opt, ctl, i, cmd=0;

	while ((opt=getopt_long(argc, argv, "ah", main_options, NULL)) != -1) {
		switch(opt) {
		case 'a':
			all = 1;
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

	/* Open HCI socket  */
	if ((ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)) < 0) {
		perror("Can't open HCI socket.");
		exit(1);
	}

	if (argc < 1) {
		print_dev_list(ctl, 0);
		exit(0);
	}

	di.dev_id = atoi(argv[0] + 3);
	argc--; argv++;

	if (ioctl(ctl, HCIGETDEVINFO, (void*)&di)) {
		perror("Can't get device info");
		exit(1);
	}

	while (argc > 0) {
		for (i=0; command[i].cmd; i++) {
			if (strncmp(command[i].cmd, *argv, 5))
				continue;

			if (command[i].opt) {
				argc--; argv++;
			}
			
			command[i].func(ctl, di.dev_id, *argv);
			cmd = 1;
			break;
		}
		argc--; argv++;
	}

	if (!cmd)
		print_dev_info(ctl, &di);

	close(ctl);
	return 0;
}
