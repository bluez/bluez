/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

typedef struct {
	char  *str; unsigned int val;
} hci_map;

static char *hci_bit2str(hci_map *m, unsigned int val) 
{
	char *str = malloc(120);
	char *ptr = str;

	if (!str)
		return NULL;

	*ptr = 0;
	while (m->str) {
		if ((unsigned int) m->val & val)
			ptr += sprintf(ptr, "%s ", m->str);
		m++;
	}
	return str;
}

static int hci_str2bit(hci_map *map, char *str, unsigned int *val)
{
	char *t, *ptr;
	hci_map *m;
	int set;

	if (!str || !(str = ptr = strdup(str)))
		return 0;

	*val = set = 0;

	while ((t = strsep(&ptr, ","))) {
		for (m = map; m->str; m++) {
			if (!strcasecmp(m->str, t)) {
				*val |= (unsigned int) m->val;
				set = 1;
			}
		}
	}
	free(str);

	return set;
}

static char *hci_uint2str(hci_map *m, unsigned int val) 
{
	char *str = malloc(50);
	char *ptr = str;

	if (!str)
		return NULL;

	*ptr = 0;
	while (m->str) {
		if ((unsigned int) m->val == val) {
			ptr += sprintf(ptr, "%s", m->str);
			break;
		}
		m++;
	}
	return str;
}

static int hci_str2uint(hci_map *map, char *str, unsigned int *val)
{
	char *t, *ptr;
	hci_map *m;
	int set = 0;

	if (!str)
		return 0;

	str = ptr = strdup(str);

	while ((t = strsep(&ptr, ","))) {
		for (m = map; m->str; m++) {
			if (!strcasecmp(m->str,t)) {
				*val = (unsigned int) m->val; set = 1;
				break;
			}
		}
	}
	free(str);

	return set;
}

char *hci_dtypetostr(int type)
{
	switch (type) {
	case HCI_VHCI:
		return "VHCI";
	case HCI_USB:
		return "USB";
	case HCI_PCCARD:
		return "PCCARD";
	case HCI_UART:
		return "UART";
	case HCI_RS232:
		return "RS232";
	case HCI_PCI:
		return "PCI";
	default:
		return "UKNW";
	}
}

/* HCI dev flags mapping */
static hci_map dev_flags_map[] = {
	{ "UP",      HCI_UP      },
	{ "INIT",    HCI_INIT    },
	{ "RUNNING", HCI_RUNNING },
	{ "RAW",     HCI_RAW     },
	{ "PSCAN",   HCI_PSCAN   },
	{ "ISCAN",   HCI_ISCAN   },
	{ "INQUIRY", HCI_INQUIRY },
	{ "AUTH",    HCI_AUTH    },
	{ "ENCRYPT", HCI_ENCRYPT },
	{ "SECMGR",  HCI_SECMGR  },
	{ NULL }
};

char *hci_dflagstostr(uint32_t flags)
{
	char *str = malloc(50);
	char *ptr = str;
	hci_map *m = dev_flags_map;

	if (!str)
		return NULL;

	*ptr = 0;

	if (!hci_test_bit(HCI_UP, &flags))
		ptr += sprintf(ptr, "DOWN ");

	while (m->str) {
		if (hci_test_bit(m->val, &flags))
			ptr += sprintf(ptr, "%s ", m->str);
		m++;
	} 	
	return str;
}

/* HCI packet type mapping */
static hci_map pkt_type_map[] = {
	{ "DM1",   HCI_DM1  },
	{ "DM3",   HCI_DM3  },
	{ "DM5",   HCI_DM5  },
	{ "DH1",   HCI_DH1  },
	{ "DH3",   HCI_DH3  },
	{ "DH5",   HCI_DH5  },
	{ "HV1",   HCI_HV1  },
	{ "HV2",   HCI_HV2  },
	{ "HV3",   HCI_HV3  },
	{ "2-DH1", HCI_2DH1 },
	{ "2-DH3", HCI_2DH3 },
	{ "2-DH5", HCI_2DH5 },
	{ "3-DH1", HCI_3DH1 },
	{ "3-DH3", HCI_3DH3 },
	{ "3-DH5", HCI_3DH5 },
	{ NULL }
};

static hci_map sco_ptype_map[] = {
	{ "HV1",   0x0001   },
	{ "HV2",   0x0002   },
	{ "HV3",   0x0004   },
	{ "EV3",   HCI_EV3  },
	{ "EV4",   HCI_EV4  },
	{ "EV5",   HCI_EV5  },
	{ "2-EV3", HCI_2EV3 },
	{ "2-EV5", HCI_2EV5 },
	{ "3-EV3", HCI_3EV3 },
	{ "3-EV5", HCI_3EV5 },
	{ NULL }
};

char *hci_ptypetostr(unsigned int ptype)
{
	return hci_bit2str(pkt_type_map, ptype);
}

int hci_strtoptype(char *str, unsigned int *val)
{
	return hci_str2bit(pkt_type_map, str, val);
}

char *hci_scoptypetostr(unsigned int ptype)
{
	return hci_bit2str(sco_ptype_map, ptype);
}

int hci_strtoscoptype(char *str, unsigned int *val)
{
	return hci_str2bit(sco_ptype_map, str, val);
}

/* Link policy mapping */
static hci_map link_policy_map[] = {
	{ "NONE",    0 },
	{ "RSWITCH", HCI_LP_RSWITCH },
	{ "HOLD",    HCI_LP_HOLD    },
	{ "SNIFF",   HCI_LP_SNIFF   },
	{ "PARK",    HCI_LP_PARK    },
	{ NULL }
};

char *hci_lptostr(unsigned int lp)
{
	return hci_bit2str(link_policy_map, lp);
}

int hci_strtolp(char *str, unsigned int *val)
{
	return hci_str2bit(link_policy_map, str, val);
}

/* Link mode mapping */
static hci_map link_mode_map[] = {
	{ "NONE",    0 },
	{ "ACCEPT",  HCI_LM_ACCEPT },
	{ "MASTER",  HCI_LM_MASTER },
	{ "AUTH",    HCI_LM_AUTH   },
	{ "ENCRYPT", HCI_LM_ENCRYPT},
	{ "TRUSTED", HCI_LM_TRUSTED},
	{ NULL }
};

char *hci_lmtostr(unsigned int lm)
{
	char *s, *str = malloc(50);
	if (!str)
		return NULL;

	*str = 0;
	if (!(lm & HCI_LM_MASTER))
		strcpy(str, "SLAVE ");

	s = hci_bit2str(link_mode_map, lm);
	if (!s) {
		free(str);
		return NULL;
	}

	strcat(str, s);
	free(s);
	return str;
}

int hci_strtolm(char *str, unsigned int *val)
{
	return hci_str2bit(link_mode_map, str, val);
}

/* Version mapping */
static hci_map ver_map[] = {
	{ "1.0b",    0x00 },
	{ "1.1",     0x01 },
	{ "1.2",     0x02 },
	{ NULL }
};

char *hci_vertostr(unsigned int ver)
{
	char *str = hci_uint2str(ver_map, ver);
	return *str ? str : "n/a";
}

int hci_strtover(char *str, unsigned int *ver)
{
	return hci_str2uint(ver_map, str, ver);
}

char *lmp_vertostr(unsigned int ver)
{
	char *str = hci_uint2str(ver_map, ver);
	return *str ? str : "n/a";
}

int lmp_strtover(char *str, unsigned int *ver)
{
	return hci_str2uint(ver_map, str, ver);
}

/* LMP features mapping */
static hci_map lmp_features_map[8][9] = {
	{	/* Byte 0 */
		{ "<3-slot packets>",	LMP_3SLOT	},	/* Bit 0 */
		{ "<5-slot packets>",	LMP_5SLOT	},	/* Bit 1 */
		{ "<encryption>",	LMP_ENCRYPT	},	/* Bit 2 */
		{ "<slot offset>",	LMP_SOFFSET	},	/* Bit 3 */
		{ "<timing accuracy>",	LMP_TACCURACY	},	/* Bit 4 */
		{ "<role switch>",	LMP_RSWITCH	},	/* Bit 5 */
		{ "<hold mode>",	LMP_HOLD	},	/* Bit 6 */
		{ "<sniff mode>",	LMP_SNIFF	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 1 */
		{ "<park state>",	LMP_PARK	},	/* Bit 0 */
		{ "<RSSI>",		LMP_RSSI	},	/* Bit 1 */
		{ "<channel quality>",	LMP_QUALITY	},	/* Bit 2 */
		{ "<SCO link>",		LMP_SCO		},	/* Bit 3 */
		{ "<HV2 packets>",	LMP_HV2		},	/* Bit 4 */
		{ "<HV3 packets>",	LMP_HV3		},	/* Bit 5 */
		{ "<u-law log>",	LMP_ULAW	},	/* Bit 6 */
		{ "<A-law log>",	LMP_ALAW	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 2 */
		{ "<CVSD>",		LMP_CVSD	},	/* Bit 0 */
		{ "<paging scheme>",	LMP_PSCHEME	},	/* Bit 1 */
		{ "<power control>",	LMP_PCONTROL	},	/* Bit 2 */
		{ "<transparent SCO>",	LMP_TRSP_SCO	},	/* Bit 3 */
		{ "<broadcast encrypt>",LMP_BCAST_ENC	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 3 */
		{ "<EDR ACL 2 Mbps>",	LMP_EDR_ACL_2M	},	/* Bit 1 */
		{ "<EDR ACL 3 Mbps>",	LMP_EDR_ACL_3M	},	/* Bit 2 */
		{ "<enhanced iscan>",	LMP_ENH_ISCAN	},	/* Bit 3 */
		{ "<interlaced iscan>",	LMP_ILACE_ISCAN	},	/* Bit 4 */
		{ "<interlaced pscan>",	LMP_ILACE_PSCAN	},	/* Bit 5 */
		{ "<inquiry with RSSI>",LMP_RSSI_INQ	},	/* Bit 6 */
		{ "<extended SCO>",	LMP_ESCO	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 4 */
		{ "<EV4 packets>",	LMP_EV4		},	/* Bit 0 */
		{ "<EV5 packets>",	LMP_EV5		},	/* Bit 1 */
		{ "<AFH cap. slave>",	LMP_AFH_CAP_SLV	},	/* Bit 3 */
		{ "<AFH class. slave>",	LMP_AFH_CLS_SLV	},	/* Bit 4 */
		{ "<3-slot EDR ACL>",	LMP_EDR_3SLOT	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 5 */
		{ "<5-slot EDR ACL>",	LMP_EDR_5SLOT	},	/* Bit 0 */
		{ "<AFH cap. master>",	LMP_AFH_CAP_MST	},	/* Bit 3 */
		{ "<AFH class. master>",LMP_AFH_CLS_MST	},	/* Bit 4 */
		{ "<EDR eSCO 2 Mbps>",	LMP_EDR_ESCO_2M	},	/* Bit 5 */
		{ "<EDR eSCO 3 Mbps>",	LMP_EDR_ESCO_3M	},	/* Bit 6 */
		{ "<3-slot EDR eSCO>",	LMP_EDR_3S_ESCO	},	/* Bit 7 */
		{ NULL }
	},
	{	/* Byte 6 */
		{ NULL }
	},
	{	/* Byte 7 */
		{ "<extended features>",LMP_EXT_FEAT	},	/* Bit 7 */
		{ NULL }
	},
};

char *lmp_featurestostr(uint8_t *features, char *pref, int width)
{
	char *off, *ptr, *str = malloc(400);
	int i;

	if (!str)
		return NULL;

	ptr = str; *ptr = 0;

	if (pref)
		ptr += sprintf(ptr, "%s", pref);

	off = ptr;

	for (i =  0;  i < 8; i++) {
		hci_map *m;

		m = lmp_features_map[i];
		while (m->str) {
			if ((unsigned int) m->val & (unsigned int) features[i]) {
				if (strlen(off) + strlen(m->str) > width - 1) {
					ptr += sprintf(ptr, "\n%s", pref ? pref : "");
					off = ptr;
				}
				ptr += sprintf(ptr, "%s ", m->str);
			}
			m++;
		}
	}

	return str;
}

/* HCI functions that do not require open device */

int hci_for_each_dev(int flag, int (*func)(int s, int dev_id, long arg), long arg)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int dev_id = -1;
	int s, i;

	s = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (s < 0)
		return -1;

	dl = malloc(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));
	if (!dl) {
		close(s);
		return -1;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(s, HCIGETDEVLIST, (void *)dl))
		goto done;

	for (i=0; i < dl->dev_num; i++, dr++) {
		if (hci_test_bit(flag, &dr->dev_opt))
			if (!func || func(s, dr->dev_id, arg)) {
				dev_id = dr->dev_id;
				break;
			}
	}

done:
	close(s);
	free(dl);
	return dev_id;
}

static int __other_bdaddr(int s, int dev_id, long arg)
{
	struct hci_dev_info di = {dev_id: dev_id};
	if (ioctl(s, HCIGETDEVINFO, (void *) &di))
		return 0;
	return bacmp((bdaddr_t *) arg, &di.bdaddr);
}

static int __same_bdaddr(int s, int dev_id, long arg)
{
	struct hci_dev_info di = {dev_id: dev_id};
	if (ioctl(s, HCIGETDEVINFO, (void *) &di))
		return 0;
	return !bacmp((bdaddr_t *) arg, &di.bdaddr);
}

int hci_get_route(bdaddr_t *bdaddr)
{
	if (bdaddr)
		return hci_for_each_dev(HCI_UP, __other_bdaddr, (long) bdaddr);
	else
		return hci_for_each_dev(HCI_UP, NULL, 0);
}

int hci_devid(const char *str)
{
	bdaddr_t ba;
	int id = -1;

	if (!strncmp(str, "hci", 3) && strlen(str) >= 4) {
		id = atoi(str + 3);
		if (hci_devba(id, &ba) < 0)
			return -1;
	} else {
		errno = ENODEV;
		str2ba(str, &ba);
		id = hci_for_each_dev(HCI_UP, __same_bdaddr, (long) &ba);
	}
	return id;
}

int hci_devinfo(int dev_id, struct hci_dev_info *di)
{
	int s, err;

	s = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (s < 0)
		return s;

	di->dev_id = dev_id;
	err = ioctl(s, HCIGETDEVINFO, (void *) di);
	close(s);

	return err;
}

int hci_devba(int dev_id, bdaddr_t *bdaddr)
{
	struct hci_dev_info di;

	if (hci_devinfo(dev_id, &di))
		return -1;

	if (!hci_test_bit(HCI_UP, &di.flags)) {
		errno = ENETDOWN;
		return -1;
	}

	bacpy(bdaddr, &di.bdaddr);
	return 0;
}

int hci_inquiry(int dev_id, int len, int nrsp, const uint8_t *lap, inquiry_info **ii, long flags)
{
	struct hci_inquiry_req *ir;
	void *buf;
	int s, err;

	if (nrsp <= 0)
		nrsp = 200;	/* enough ? */

	if (dev_id < 0 && (dev_id = hci_get_route(NULL)) < 0) {
		errno = ENODEV;
		return -1;
	}	

	s = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (s < 0)
		return -1;

	buf = malloc(sizeof(*ir) + (sizeof(inquiry_info) * (nrsp)));
	if (!buf) {
		close(s);
		return -1;
	}

	ir = buf;
	ir->dev_id  = dev_id;
	ir->num_rsp = nrsp;
	ir->length  = len;
	ir->flags   = flags;

	if (lap) {
		memcpy(ir->lap, lap, 3);
	} else {
		ir->lap[0] = 0x33;
		ir->lap[1] = 0x8b;
		ir->lap[2] = 0x9e;
	}

	err = ioctl(s, HCIINQUIRY, (unsigned long) buf);
	close(s);

	if (!err) {
		int size = sizeof(inquiry_info) * ir->num_rsp;

		if (!*ii) 
			*ii = (void *) malloc(size);

		if (*ii) {
			memcpy((void *) *ii, buf + sizeof(*ir), size);
			err = ir->num_rsp;
		} else
			err = -1;
	}
	free(buf);
	return err;
}

/* Open HCI device. 
 * Returns device descriptor (dd). */
int hci_open_dev(int dev_id)
{
	struct sockaddr_hci a;
	int dd, err;

	/* Create HCI socket */
	dd = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (dd < 0)
		return dd;

	/* Bind socket to the HCI device */
	a.hci_family = AF_BLUETOOTH;
	a.hci_dev = dev_id;
	if (bind(dd, (struct sockaddr *) &a, sizeof(a)) < 0)
		goto failed;

	return dd;

failed:
	err = errno;
	close(dd);
	errno = err;
	return -1;
}

int hci_close_dev(int dd)
{
	return close(dd);
}

/* HCI functions that require open device
 * dd - Device descriptor returned by hci_open_dev. */

int hci_send_cmd(int dd, uint16_t ogf, uint16_t ocf, uint8_t plen, void *param)
{
	uint8_t type = HCI_COMMAND_PKT;
	hci_command_hdr hc;
	struct iovec iv[3];
	int ivn;

	hc.opcode = htobs(cmd_opcode_pack(ogf, ocf));
	hc.plen= plen;

	iv[0].iov_base = &type;
	iv[0].iov_len  = 1;
	iv[1].iov_base = &hc;
	iv[1].iov_len  = HCI_COMMAND_HDR_SIZE;
	ivn = 2;

	if (plen) {
		iv[2].iov_base = param;
		iv[2].iov_len  = plen;
		ivn = 3;
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int hci_send_req(int dd, struct hci_request *r, int to)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	uint16_t opcode = htobs(cmd_opcode_pack(r->ogf, r->ocf));
	struct hci_filter nf, of;
	hci_event_hdr *hdr;
	int err, len, try;

	len = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &len) < 0)
		return -1;

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT,  &nf);
	hci_filter_set_event(EVT_CMD_STATUS, &nf);
	hci_filter_set_event(EVT_CMD_COMPLETE, &nf);
	hci_filter_set_event(r->event, &nf);
	hci_filter_set_opcode(opcode, &nf);
	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0)
		return -1;

	if (hci_send_cmd(dd, r->ogf, r->ocf, r->clen, r->cparam) < 0)
		goto failed;

	try = 10;
	while (try--) {
		evt_cmd_complete *cc;
		evt_cmd_status   *cs;

		if (to) {
			struct pollfd p;
			int n;

			p.fd = dd; p.events = POLLIN;
			while ((n = poll(&p, 1, to)) < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;
				goto failed;
			}

			if (!n) {
				errno = ETIMEDOUT;
				goto failed;
			}

			to -= 10;
			if (to < 0) to = 0;

		}

		while ((len = read(dd, buf, sizeof(buf))) < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			goto failed;
		}

		hdr = (void *) (buf + 1);
		ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
		len -= (1 + HCI_EVENT_HDR_SIZE);

		switch (hdr->evt) {
		case EVT_CMD_STATUS:
			cs = (void *) ptr;

			if (cs->opcode != opcode)
				continue;

			if (cs->status) {
				errno = EIO;
				goto failed;
			}
			break;

		case EVT_CMD_COMPLETE:
			cc = (void *) ptr;

			if (cc->opcode != opcode)
				continue;

			ptr += EVT_CMD_COMPLETE_SIZE;
			len -= EVT_CMD_COMPLETE_SIZE;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;

		default:
			if (hdr->evt != r->event)
				break;

			r->rlen = MIN(len, r->rlen);
			memcpy(r->rparam, ptr, r->rlen);
			goto done;
		}
	}
	errno = ETIMEDOUT;

failed:
	err = errno;
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	errno = err;
	return -1;

done:
	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));
	return 0;
}

int hci_create_connection(int dd, const bdaddr_t *bdaddr, uint16_t ptype, uint16_t clkoffset, uint8_t rswitch, uint16_t *handle, int to)
{
	evt_conn_complete rp;
	create_conn_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pkt_type       = ptype;
	cp.pscan_rep_mode = 0x02;
	cp.clock_offset   = clkoffset;
	cp.role_switch    = rswitch;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_CREATE_CONN;
	rq.event  = EVT_CONN_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = CREATE_CONN_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CONN_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*handle = rp.handle;
	return 0;
}

int hci_disconnect(int dd, uint16_t handle, uint8_t reason, int to)
{
	evt_disconn_complete rp;
	disconnect_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;
	cp.reason = reason;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_DISCONNECT;
	rq.event  = EVT_DISCONN_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = DISCONNECT_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_DISCONN_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}
	return 0;
}

int hci_local_name(int dd, int len, char *name, int to)
{
	return hci_read_local_name(dd, len, name, to);
}

int hci_read_local_name(int dd, int len, char *name, int to)
{
	read_local_name_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_LOCAL_NAME;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_NAME_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	rp.name[247] = '\0';
	strncpy(name, rp.name, len);
	return 0;
}

int hci_write_local_name(int dd, const char *name, int to)
{
	change_local_name_cp cp;
	struct hci_request rq;

	strncpy(cp.name, name, sizeof(cp.name));
	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_CHANGE_LOCAL_NAME;
	rq.cparam = &cp;
	rq.clen   = CHANGE_LOCAL_NAME_CP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;
	return 0;
}

int hci_remote_name(int dd, const bdaddr_t *bdaddr, int len, char *name, int to)
{
	return hci_read_remote_name(dd, bdaddr, len, name, to);
}

int hci_read_remote_name(int dd, const bdaddr_t *bdaddr, int len, char *name, int to)
{
	evt_remote_name_req_complete rn;
	remote_name_req_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pscan_rep_mode = 0x02;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_REMOTE_NAME_REQ;
	rq.cparam = &cp;
	rq.clen   = REMOTE_NAME_REQ_CP_SIZE;
	rq.event  = EVT_REMOTE_NAME_REQ_COMPLETE;
	rq.rparam = &rn;
	rq.rlen   = EVT_REMOTE_NAME_REQ_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rn.status) {
		errno = EIO;
		return -1;
	}

	rn.name[247] = '\0';
	strncpy(name, rn.name, len);
	return 0;
}

int hci_read_remote_features(int dd, uint16_t handle, uint8_t *features, int to)
{
	evt_read_remote_features_complete rp;
	read_remote_features_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_REMOTE_FEATURES;
	rq.event  = EVT_READ_REMOTE_FEATURES_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_REMOTE_FEATURES_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_REMOTE_FEATURES_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	memcpy(features, rp.features, 8);
	return 0;
}

int hci_read_remote_version(int dd, uint16_t handle, struct hci_version *ver, int to)
{
	evt_read_remote_version_complete rp;
	read_remote_version_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_REMOTE_VERSION;
	rq.event  = EVT_READ_REMOTE_VERSION_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_REMOTE_VERSION_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_REMOTE_VERSION_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	ver->manufacturer = btohs(rp.manufacturer);
	ver->lmp_ver      = rp.lmp_ver;
	ver->lmp_subver   = btohs(rp.lmp_subver);
	return 0;
}

int hci_read_clock_offset(int dd, uint16_t handle, uint16_t *clkoffset, int to)
{
	evt_read_clock_offset_complete rp;
	read_clock_offset_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.handle = handle;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_READ_CLOCK_OFFSET;
	rq.event  = EVT_READ_CLOCK_OFFSET_COMPLETE;
	rq.cparam = &cp;
	rq.clen   = READ_CLOCK_OFFSET_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_READ_CLOCK_OFFSET_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*clkoffset = rp.clock_offset;
	return 0;
}

int hci_read_local_version(int dd, struct hci_version *ver, int to)
{
	read_local_version_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_INFO_PARAM;
	rq.ocf    = OCF_READ_LOCAL_VERSION;
	rq.rparam = &rp;
	rq.rlen   = READ_LOCAL_VERSION_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	ver->manufacturer = btohs(rp.manufacturer);
	ver->hci_ver      = rp.hci_ver;
	ver->hci_rev      = btohs(rp.hci_rev);
	ver->lmp_ver      = rp.lmp_ver;
	ver->lmp_subver   = btohs(rp.lmp_subver);
	return 0;
}

int hci_read_class_of_dev(int dd, uint8_t *cls, int to)
{
	read_class_of_dev_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_CLASS_OF_DEV;
	rq.rparam = &rp;
	rq.rlen   = READ_CLASS_OF_DEV_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	memcpy(cls, rp.dev_class, 3);
	return 0;
}

int hci_write_class_of_dev(int dd, uint32_t cls, int to)
{
	write_class_of_dev_cp cp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	cp.dev_class[0] = cls & 0xff;
	cp.dev_class[1] = (cls >> 8) & 0xff;
	cp.dev_class[2] = (cls >> 16) & 0xff;
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_CLASS_OF_DEV;
	rq.cparam = &cp;
	rq.clen   = WRITE_CLASS_OF_DEV_CP_SIZE;
	return hci_send_req(dd, &rq, to);
}

int hci_read_voice_setting(int dd, uint16_t *vs, int to)
{
	read_voice_setting_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_VOICE_SETTING;
	rq.rparam = &rp;
	rq.rlen   = READ_VOICE_SETTING_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*vs = rp.voice_setting;
	return 0;
}

int hci_write_voice_setting(int dd, uint16_t vs, int to)
{
	write_voice_setting_cp cp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	cp.voice_setting = vs;
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_VOICE_SETTING;
	rq.cparam = &cp;
	rq.clen   = WRITE_VOICE_SETTING_CP_SIZE;

	return hci_send_req(dd, &rq, to);
}

int hci_read_current_iac_lap(int dd, uint8_t *num_iac, uint8_t *lap, int to)
{
	read_current_iac_lap_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_CURRENT_IAC_LAP;
	rq.rparam = &rp;
	rq.rlen   = READ_CURRENT_IAC_LAP_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*num_iac = rp.num_current_iac;
	memcpy(lap, rp.lap, rp.num_current_iac * 3);
	return 0;
}

int hci_write_current_iac_lap(int dd, uint8_t num_iac, uint8_t *lap, int to)
{
	write_current_iac_lap_cp cp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.num_current_iac = num_iac;
	memcpy(&cp.lap, lap, num_iac * 3);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_CURRENT_IAC_LAP;
	rq.cparam = &cp;
	rq.clen   = WRITE_CURRENT_IAC_LAP_CP_SIZE;

	return hci_send_req(dd, &rq, to);
}

int hci_authenticate_link(int dd, uint16_t handle, int to)
{
	auth_requested_cp cp;
	evt_auth_complete rp;
	struct hci_request rq;

	cp.handle = handle;
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.event  = EVT_AUTH_COMPLETE;
	rq.rlen   = EVT_AUTH_COMPLETE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_encrypt_link(int dd, uint16_t handle, uint8_t encrypt, int to)
{
	set_conn_encrypt_cp cp;
	evt_encrypt_change rp;
	struct hci_request rq;

	cp.handle  = handle;
	cp.encrypt = encrypt;
	rq.ogf     = OGF_LINK_CTL;
	rq.ocf     = OCF_SET_CONN_ENCRYPT;
	rq.cparam  = &cp;
	rq.clen    = SET_CONN_ENCRYPT_CP_SIZE;
	rq.event   = EVT_ENCRYPT_CHANGE;
	rq.rlen    = EVT_ENCRYPT_CHANGE_SIZE;
	rq.rparam  = &rp;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}
	return 0;
}

int hci_switch_role(int dd, bdaddr_t *bdaddr, uint8_t role, int to)
{
	switch_role_cp cp;
	evt_role_change rp;
	struct hci_request rq;

	bacpy(&cp.bdaddr, bdaddr);
	cp.role   = role;
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_SWITCH_ROLE;
	rq.cparam = &cp;
	rq.clen   = SWITCH_ROLE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_ROLE_CHANGE_SIZE;
	rq.event  = EVT_ROLE_CHANGE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_park_mode(int dd, uint16_t handle, uint16_t max_interval, uint16_t min_interval, int to)
{
	park_mode_cp cp;
	evt_mode_change rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof (cp));
	cp.handle       = handle;
	cp.max_interval = max_interval;
	cp.min_interval = min_interval;

	memset(&rq, 0, sizeof (rq));
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_PARK_MODE;
	rq.event  = EVT_MODE_CHANGE;
	rq.cparam = &cp;
	rq.clen   = PARK_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_MODE_CHANGE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_exit_park_mode(int dd, uint16_t handle, int to)
{
	exit_park_mode_cp cp;
	evt_mode_change rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof (cp));
	cp.handle = handle;

	memset (&rq, 0, sizeof (rq));
	rq.ogf    = OGF_LINK_POLICY;
	rq.ocf    = OCF_EXIT_PARK_MODE;
	rq.event  = EVT_MODE_CHANGE;
	rq.cparam = &cp;
	rq.clen   = EXIT_PARK_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_MODE_CHANGE_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}

int hci_read_inquiry_mode(int dd, uint8_t *mode, int to)
{
	read_inquiry_mode_rp rp;
	struct hci_request rq;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_READ_INQUIRY_MODE;
	rq.rparam = &rp;
	rq.rlen   = READ_INQUIRY_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	*mode = rp.mode;
	return 0;
}

int hci_write_inquiry_mode(int dd, uint8_t mode, int to)
{
	write_inquiry_mode_cp cp;
	write_inquiry_mode_rp rp;
	struct hci_request rq;

	memset(&cp, 0, sizeof(cp));
	cp.mode = mode;

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_HOST_CTL;
	rq.ocf    = OCF_WRITE_INQUIRY_MODE;
	rq.cparam = &cp;
	rq.clen   = WRITE_INQUIRY_MODE_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = WRITE_INQUIRY_MODE_RP_SIZE;

	if (hci_send_req(dd, &rq, to) < 0)
		return -1;

	if (rp.status) {
		errno = EIO;
		return -1;
	}

	return 0;
}
