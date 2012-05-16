/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>

#define VHCI_DEV		"/dev/vhci"

#define VHCI_MAX_CONN		12

#define VHCI_ACL_MTU		192
#define VHCI_ACL_MAX_PKT	8

struct vhci_device {
	uint8_t		features[8];
	uint8_t		name[248];
	uint8_t		dev_class[3];
	uint8_t		scan_enable;
	uint8_t		ssp_mode;
	uint8_t		inq_mode;
	uint8_t		eir_fec;
	uint8_t		eir_data[HCI_MAX_EIR_LENGTH];
	uint8_t		le_mode;
	uint8_t		le_simul;
	uint16_t	acl_cnt;
	bdaddr_t	bdaddr;
	int		dev_fd;
	int		scan_fd;
	int		dd;
};

struct vhci_conn {
	bdaddr_t	dest;
	uint16_t	handle;
	int		fd;
};

struct vhci_link_info {
	bdaddr_t	bdaddr;
	uint8_t		dev_class[3];
	uint8_t		link_type;
	uint8_t		role;
} __attribute__ ((packed));

static struct vhci_device vdev;
static struct vhci_conn *vconn[VHCI_MAX_CONN];

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

#define MAX_EPOLL_EVENTS 10

static int epoll_fd;

static volatile sig_atomic_t __io_canceled = 0;

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static inline int read_n(int fd, void *buf, int len)
{
	register int w, t = 0;

	while (!__io_canceled && len > 0) {
		if ((w = read(fd, buf, len)) < 0 ){
			if( errno == EINTR || errno == EAGAIN )
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}

/* Write exactly len bytes (Signal safe)*/
static inline int write_n(int fd, void *buf, int len)
{
	register int w, t = 0;

	while (!__io_canceled && len > 0) {
		if ((w = write(fd, buf, len)) < 0 ){
			if( errno == EINTR || errno == EAGAIN )
				continue;
			return -1;
		}
		if (!w)
			return 0;
		len -= w; buf += w; t += w;
	}
	return t;
}

static int create_snoop(char *file)
{
	struct btsnoop_hdr hdr;
	int fd, len;

	fd = open(file, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0)
		return fd;

	memcpy(hdr.id, btsnoop_id, sizeof(btsnoop_id));
	hdr.version = htonl(1);
	hdr.type = htonl(1002);

	len = write(fd, &hdr, BTSNOOP_HDR_SIZE);
	if (len < 0) {
		close(fd);
		return -EIO;
	}

	if (len != BTSNOOP_HDR_SIZE) {
		close(fd);
		return -1;
	}

	return fd;
}

static int write_snoop(int fd, int type, int incoming,
				unsigned char *buf, int len)
{
	struct btsnoop_pkt pkt;
	struct timeval tv;
	uint32_t size = len;
	uint64_t ts;

	if (fd < 0)
		return -1;

	memset(&tv, 0, sizeof(tv));
	gettimeofday(&tv, NULL);
	ts = (tv.tv_sec - 946684800ll) * 1000000ll + tv.tv_usec;

	pkt.size = htonl(size);
	pkt.len  = pkt.size;
	pkt.flags = ntohl(incoming & 0x01);
	pkt.drops = htonl(0);
	pkt.ts = hton64(ts + 0x00E03AB44A676000ll);

	if (type == HCI_COMMAND_PKT || type == HCI_EVENT_PKT)
		pkt.flags |= ntohl(0x02);

	if (write(fd, &pkt, BTSNOOP_PKT_SIZE) < 0)
		return -errno;

	if (write(fd, buf, size) < 0)
		return -errno;

	return 0;
}

static struct vhci_conn *conn_get_by_bdaddr(bdaddr_t *ba)
{
	register int i;

	for (i = 0; i < VHCI_MAX_CONN; i++)
		if (!bacmp(&vconn[i]->dest, ba))
			return vconn[i];

	return NULL;
}

static void reset_vdev(void)
{
	/* Device settings */
	vdev.features[0] = 0xff;
	vdev.features[1] = 0xff;
	vdev.features[2] = 0x8f;
	vdev.features[3] = 0xfe;
	vdev.features[4] = 0x9b;
	vdev.features[5] = 0xf9;
	vdev.features[6] = 0x00;
	vdev.features[7] = 0x80;

	vdev.features[4] |= 0x40;	/* LE Supported */
	vdev.features[6] |= 0x01;	/* Extended Inquiry Response */
	vdev.features[6] |= 0x02;	/* BR/EDR and LE */
	vdev.features[6] |= 0x08;	/* Secure Simple Pairing */

	memset(vdev.name, 0, sizeof(vdev.name));
	strncpy((char *) vdev.name, "BlueZ (Virtual HCI)",
							sizeof(vdev.name) - 1);

	vdev.dev_class[0] = 0x00;
	vdev.dev_class[1] = 0x00;
	vdev.dev_class[2] = 0x00;

	vdev.scan_enable = 0x00;
	vdev.ssp_mode = 0x00;
	vdev.inq_mode = 0x00;
	vdev.eir_fec = 0x00;
	memset(vdev.eir_data, 0, sizeof(vdev.eir_data));
	vdev.le_mode = 0x00;
	vdev.le_simul = 0x00;
}

static void command_status(uint16_t ogf, uint16_t ocf, uint8_t status)
{
	uint8_t buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_cmd_status *cs;
	hci_event_hdr *he;

	/* Packet type */
	*ptr++ = HCI_EVENT_PKT;

	/* Event header */
	he = (void *) ptr; ptr += HCI_EVENT_HDR_SIZE;

	he->evt  = EVT_CMD_STATUS;
	he->plen = EVT_CMD_STATUS_SIZE;

	cs = (void *) ptr; ptr += EVT_CMD_STATUS_SIZE;

	cs->status = status;
	cs->ncmd   = 1;
	cs->opcode = htobs(cmd_opcode_pack(ogf, ocf));

	write_snoop(vdev.dd, HCI_EVENT_PKT, 1, buf, ptr - buf);

	if (write(vdev.dev_fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s(%d)",
						strerror(errno), errno);
}

static void command_complete(uint16_t ogf, uint16_t ocf, int plen, void *data)
{
	uint8_t buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_cmd_complete *cc;
	hci_event_hdr *he;

	/* Packet type */
	*ptr++ = HCI_EVENT_PKT;

	/* Event header */
	he = (void *) ptr; ptr += HCI_EVENT_HDR_SIZE;

	he->evt  = EVT_CMD_COMPLETE;
	he->plen = EVT_CMD_COMPLETE_SIZE + plen;

	cc = (void *) ptr; ptr += EVT_CMD_COMPLETE_SIZE;

	cc->ncmd = 1;
	cc->opcode = htobs(cmd_opcode_pack(ogf, ocf));

	if (plen) {
		memcpy(ptr, data, plen);
		ptr += plen;
	}

	write_snoop(vdev.dd, HCI_EVENT_PKT, 1, buf, ptr - buf);

	if (write(vdev.dev_fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s(%d)",
						strerror(errno), errno);
}

static void connect_request(struct vhci_conn *conn)
{
	uint8_t buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_conn_request *cr;
	hci_event_hdr *he;

	/* Packet type */
	*ptr++ = HCI_EVENT_PKT;

	/* Event header */
	he = (void *) ptr; ptr += HCI_EVENT_HDR_SIZE;

	he->evt  = EVT_CONN_REQUEST;
	he->plen = EVT_CONN_REQUEST_SIZE;

	cr = (void *) ptr; ptr += EVT_CONN_REQUEST_SIZE;

	bacpy(&cr->bdaddr, &conn->dest);
	memset(&cr->dev_class, 0, sizeof(cr->dev_class));
	cr->link_type = ACL_LINK;

	write_snoop(vdev.dd, HCI_EVENT_PKT, 1, buf, ptr - buf);

	if (write(vdev.dev_fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s (%d)",
						strerror(errno), errno);
}

static void connect_complete(struct vhci_conn *conn)
{
	uint8_t buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_conn_complete *cc;
	hci_event_hdr *he;

	/* Packet type */
	*ptr++ = HCI_EVENT_PKT;

	/* Event header */
	he = (void *) ptr; ptr += HCI_EVENT_HDR_SIZE;

	he->evt  = EVT_CONN_COMPLETE;
	he->plen = EVT_CONN_COMPLETE_SIZE;

	cc = (void *) ptr; ptr += EVT_CONN_COMPLETE_SIZE;

	bacpy(&cc->bdaddr, &conn->dest);
	cc->status = 0x00;
	cc->handle = htobs(conn->handle);
	cc->link_type = ACL_LINK;
	cc->encr_mode = 0x00;

	write_snoop(vdev.dd, HCI_EVENT_PKT, 1, buf, ptr - buf);

	if (write(vdev.dev_fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s (%d)",
						strerror(errno), errno);

	/* TODO: Add io_acl_data() handling */
}

static void disconn_complete(struct vhci_conn *conn)
{
	uint8_t buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_disconn_complete *dc;
	hci_event_hdr *he;

	/* Packet type */
	*ptr++ = HCI_EVENT_PKT;

	/* Event header */
	he = (void *) ptr; ptr += HCI_EVENT_HDR_SIZE;

	he->evt  = EVT_DISCONN_COMPLETE;
	he->plen = EVT_DISCONN_COMPLETE_SIZE;

	dc = (void *) ptr; ptr += EVT_DISCONN_COMPLETE_SIZE;

	dc->status = 0x00;
	dc->handle = htobs(conn->handle);
	dc->reason = 0x00;

	write_snoop(vdev.dd, HCI_EVENT_PKT, 1, buf, ptr - buf);

	if (write(vdev.dev_fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s (%d)",
						strerror(errno), errno);

	vdev.acl_cnt = 0;
}

static void num_completed_pkts(struct vhci_conn *conn)
{
	uint8_t buf[HCI_MAX_FRAME_SIZE], *ptr = buf;
	evt_num_comp_pkts *np;
	hci_event_hdr *he;

	/* Packet type */
	*ptr++ = HCI_EVENT_PKT;

	/* Event header */
	he = (void *) ptr; ptr += HCI_EVENT_HDR_SIZE;

	he->evt  = EVT_NUM_COMP_PKTS;
	he->plen = EVT_NUM_COMP_PKTS_SIZE;

	np = (void *) ptr; ptr += EVT_NUM_COMP_PKTS_SIZE;
	np->num_hndl = 1;

	*((uint16_t *) ptr) = htobs(conn->handle); ptr += 2;
	*((uint16_t *) ptr) = htobs(vdev.acl_cnt); ptr += 2;

	write_snoop(vdev.dd, HCI_EVENT_PKT, 1, buf, ptr - buf);

	if (write(vdev.dev_fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s (%d)",
						strerror(errno), errno);
}

static uint8_t scan_enable(uint8_t *data)
{
#if 0
	struct epoll_event scan_event;
	struct sockaddr_in sa;
	bdaddr_t ba;
	int sk, opt;

	if (!(*data & SCAN_PAGE)) {
		if (vdev.scan_fd >= 0) {
			close(vdev.scan_fd);
			vdev.scan_fd = -1;
		}
		return 0;
	}

	if (vdev.scan_fd >= 0)
		return 0;

	if ((sk = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
						strerror(errno), errno);
		return 1;
	}

	opt = 1;
	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	baswap(&ba, &vdev.bdaddr);
	sa.sin_family = AF_INET;
	memcpy(&sa.sin_addr.s_addr, &ba, sizeof(sa.sin_addr.s_addr));
	memcpy(&sa.sin_port, &ba.b[4], sizeof(sa.sin_port));
	if (bind(sk, (struct sockaddr *) &sa, sizeof(sa))) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
						strerror(errno), errno);
		goto failed;
	}

	if (listen(sk, 10)) {
		syslog(LOG_ERR, "Can't listen on socket: %s (%d)",
						strerror(errno), errno);
		goto failed;
	}

	memset(&scan_event, 0, sizeof(scan_event));
	scan_event.events = EPOLLIN;
	scan_event.data.fd = sk;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sk, &scan_event) < 0) {
		syslog(LOG_ERR, "Failed to setup scan event watch");
		goto failed;
	}

	vdev.scan_fd = sk;
	return 0;

failed:
	close(sk);
	return 1;
#endif

	return data[0];
}

static void accept_connection(uint8_t *data)
{
	accept_conn_req_cp *cp = (void *) data;
	struct vhci_conn *conn;

	if (!(conn = conn_get_by_bdaddr(&cp->bdaddr)))
		return;

	connect_complete(conn);
}

static void close_connection(struct vhci_conn *conn)
{
	char addr[18];

	ba2str(&conn->dest, addr);
	syslog(LOG_INFO, "Closing connection %s handle %d",
					addr, conn->handle);

	close(conn->fd);

	vconn[conn->handle - 1] = NULL;
	disconn_complete(conn);
	free(conn);
}

static void disconnect(uint8_t *data)
{
	disconnect_cp *cp = (void *) data;
	struct vhci_conn *conn;
	uint16_t handle;

	handle = btohs(cp->handle);

	if (handle > VHCI_MAX_CONN)
		return;

	if (!(conn = vconn[handle-1]))
		return;

	close_connection(conn);
}

static void create_connection(uint8_t *data)
{
	create_conn_cp *cp = (void *) data;
	struct vhci_link_info info;
	struct vhci_conn *conn;
	struct sockaddr_in sa;
	int h, sk, opt;
	bdaddr_t ba;

	for (h = 0; h < VHCI_MAX_CONN; h++)
		if (!vconn[h])
			goto do_connect;

	syslog(LOG_ERR, "Too many connections");
	return;

do_connect:
	if ((sk = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		syslog(LOG_ERR, "Can't create socket: %s (%d)",
						strerror(errno), errno);
		return;
	}

	opt = 1;
	setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	baswap(&ba, &vdev.bdaddr);
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;	// *(uint32_t *) &ba;
	sa.sin_port = 0;			// *(uint16_t *) &ba.b[4];
	if (bind(sk, (struct sockaddr *) &sa, sizeof(sa))) {
		syslog(LOG_ERR, "Can't bind socket: %s (%d)",
						strerror(errno), errno);
		close(sk);
		return;
	}

	baswap(&ba, &cp->bdaddr);
	sa.sin_family = AF_INET;
	memcpy(&sa.sin_addr.s_addr, &ba, sizeof(sa.sin_addr.s_addr));
	memcpy(&sa.sin_port, &ba.b[4], sizeof(sa.sin_port));
	if (connect(sk, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		syslog(LOG_ERR, "Can't connect: %s (%d)",
						strerror(errno), errno);
		close(sk);
		return;
	}

	/* Send info */
	memset(&info, 0, sizeof(info));
	bacpy(&info.bdaddr, &vdev.bdaddr);
	info.link_type = ACL_LINK;
	info.role = 1;
	write_n(sk, (void *) &info, sizeof(info));

	if (!(conn = malloc(sizeof(*conn)))) {
		syslog(LOG_ERR, "Can't alloc new connection: %s (%d)",
						strerror(errno), errno);
		close(sk);
		return;
	}

	memcpy((uint8_t *) &ba, (uint8_t *) &sa.sin_addr, 4);
	memcpy((uint8_t *) &ba.b[4], (uint8_t *) &sa.sin_port, 2);
	baswap(&conn->dest, &ba);

	vconn[h] = conn;
	conn->handle = h + 1;
	conn->fd = sk;

	connect_complete(conn);
}

static void hci_link_control(uint16_t ocf, int plen, uint8_t *data)
{
	const uint16_t ogf = OGF_LINK_CTL;

	switch (ocf) {
	case OCF_CREATE_CONN:
		command_status(ogf, ocf, 0x00);
		create_connection(data);
		break;

	case OCF_ACCEPT_CONN_REQ:
		command_status(ogf, ocf, 0x00);
		accept_connection(data);
		break;

	case OCF_DISCONNECT:
		command_status(ogf, ocf, 0x00);
		disconnect(data);
		break;

	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_link_policy(uint16_t ocf, int plen, uint8_t *data)
{
	const uint16_t ogf = OGF_INFO_PARAM;

	switch (ocf) {
	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_host_control(uint16_t ocf, int plen, uint8_t *data)
{
	read_scan_enable_rp se;
	read_local_name_rp ln;
	read_class_of_dev_rp cd;
	read_inquiry_mode_rp im;
	read_ext_inquiry_response_rp ir;
	read_simple_pairing_mode_rp pm;
	read_le_host_supported_rp hs;
	uint8_t status;

	const uint16_t ogf = OGF_HOST_CTL;

	switch (ocf) {
	case OCF_RESET:
		status = 0x00;
		reset_vdev();
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_SET_EVENT_FLT:
		status = 0x00;
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_CHANGE_LOCAL_NAME:
		status = 0x00;
		memcpy(vdev.name, data, sizeof(vdev.name));
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_LOCAL_NAME:
		ln.status = 0x00;
		memcpy(ln.name, vdev.name, sizeof(ln.name));
		command_complete(ogf, ocf, sizeof(ln), &ln);
		break;

	case OCF_WRITE_CONN_ACCEPT_TIMEOUT:
	case OCF_WRITE_PAGE_TIMEOUT:
		status = 0x00;
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_SCAN_ENABLE:
		se.status = 0x00;
		se.enable = vdev.scan_enable;
		command_complete(ogf, ocf, sizeof(se), &se);
		break;

	case OCF_WRITE_SCAN_ENABLE:
		status = 0x00;
		vdev.scan_enable = scan_enable(data);
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_WRITE_AUTH_ENABLE:
		status = 0x00;
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_WRITE_ENCRYPT_MODE:
		status = 0x00;
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_CLASS_OF_DEV:
		cd.status = 0x00;
		memcpy(cd.dev_class, vdev.dev_class, 3);
		command_complete(ogf, ocf, sizeof(cd), &cd);
		break;

	case OCF_WRITE_CLASS_OF_DEV:
		status = 0x00;
		memcpy(vdev.dev_class, data, 3);
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_INQUIRY_MODE:
		im.status = 0x00;
		im.mode = vdev.inq_mode;
		command_complete(ogf, ocf, sizeof(im), &im);
		break;

	case OCF_WRITE_INQUIRY_MODE:
		status = 0x00;
		vdev.inq_mode = data[0];
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_EXT_INQUIRY_RESPONSE:
		ir.status = 0x00;
		ir.fec = vdev.eir_fec;
		memcpy(ir.data, vdev.eir_data, HCI_MAX_EIR_LENGTH);
		command_complete(ogf, ocf, sizeof(ir), &ir);
		break;

	case OCF_WRITE_EXT_INQUIRY_RESPONSE:
		status = 0x00;
		vdev.eir_fec = data[0];
		memcpy(vdev.eir_data, data + 1, HCI_MAX_EIR_LENGTH);
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_SIMPLE_PAIRING_MODE:
		pm.status = 0x00;
		pm.mode = vdev.ssp_mode;
		command_complete(ogf, ocf, sizeof(pm), &pm);
		break;

	case OCF_WRITE_SIMPLE_PAIRING_MODE:
		status = 0x00;
		vdev.ssp_mode = data[0];
		command_complete(ogf, ocf, 1, &status);
		break;

	case OCF_READ_LE_HOST_SUPPORTED:
		hs.status = 0x00;
		hs.le = vdev.le_mode;
		hs.simul = vdev.le_simul;
		command_complete(ogf, ocf, sizeof(hs), &hs);
		break;

	case OCF_WRITE_LE_HOST_SUPPORTED:
		status = 0x00;
		vdev.le_mode = data[0];
		vdev.le_simul = data[1];
		command_complete(ogf, ocf, 1, &status);
		break;

	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_info_param(uint16_t ocf, int plen, uint8_t *data)
{
	read_local_version_rp lv;
	read_local_features_rp lf;
	read_local_ext_features_rp ef;
	read_buffer_size_rp bs;
	read_bd_addr_rp ba;

	const uint16_t ogf = OGF_INFO_PARAM;

	switch (ocf) {
	case OCF_READ_LOCAL_VERSION:
		lv.status = 0x00;
		lv.hci_ver = 0x06;
		lv.hci_rev = htobs(0x0000);
		lv.lmp_ver = 0x06;
		lv.manufacturer = htobs(63);
		lv.lmp_subver = htobs(0x0000);
		command_complete(ogf, ocf, sizeof(lv), &lv);
		break;

	case OCF_READ_LOCAL_FEATURES:
		lf.status = 0x00;
		memcpy(lf.features, vdev.features, 8);
		command_complete(ogf, ocf, sizeof(lf), &lf);
		break;

	case OCF_READ_LOCAL_EXT_FEATURES:
		ef.status = 0x00;
		if (*data == 0) {
			ef.page_num = 0;
			ef.max_page_num = 1;
			memcpy(ef.features, vdev.features, 8);
		} else if (*data == 1) {
			ef.page_num = 1;
			ef.max_page_num = 1;
			memset(ef.features, 0, 8);
			ef.features[0] |= (!!vdev.ssp_mode << 0);
			ef.features[0] |= (!!vdev.le_mode << 1);
			ef.features[0] |= (!!vdev.le_simul << 2);
		} else {
			ef.page_num = *data;
			ef.max_page_num = 0;
			memset(ef.features, 0, 8);
		}
		command_complete(ogf, ocf, sizeof(ef), &ef);
		break;

	case OCF_READ_BUFFER_SIZE:
		bs.status = 0x00;
		bs.acl_mtu = htobs(VHCI_ACL_MTU);
		bs.sco_mtu = 0;
		bs.acl_max_pkt = htobs(VHCI_ACL_MAX_PKT);
		bs.sco_max_pkt = htobs(0);
		command_complete(ogf, ocf, sizeof(bs), &bs);
		break;

	case OCF_READ_BD_ADDR:
		ba.status = 0x00;
		bacpy(&ba.bdaddr, &vdev.bdaddr);
		command_complete(ogf, ocf, sizeof(ba), &ba);
		break;

	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_status_param(uint16_t ocf, int plen, uint8_t *data)
{
	read_local_amp_info_rp ai;

	const uint16_t ogf = OGF_STATUS_PARAM;

	switch (ocf) {
	case OCF_READ_LOCAL_AMP_INFO:
		memset(&ai, 0, sizeof(ai));

		/* BT only */
		ai.amp_status = 0x01;
		ai.max_pdu_size = htobl(L2CAP_DEFAULT_MTU);
		ai.controller_type = HCI_AMP;
		ai.max_amp_assoc_length = htobl(HCI_MAX_ACL_SIZE);
		/* No flushing at all */
		ai.max_flush_timeout = 0xFFFFFFFF;
		ai.best_effort_flush_timeout = 0xFFFFFFFF;

		command_complete(ogf, ocf, sizeof(ai), &ai);
		break;

	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_le_control(uint16_t ocf, int plen, uint8_t *data)
{
	le_read_buffer_size_rp bs;

	const uint16_t ogf = OGF_LE_CTL;

	switch (ocf) {
	case OCF_LE_READ_BUFFER_SIZE:
		bs.status = 0;
		bs.pkt_len = htobs(VHCI_ACL_MTU);
		bs.max_pkt = htobs(VHCI_ACL_MAX_PKT);
		command_complete(ogf, ocf, sizeof(bs), &bs);
		break;

	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_command(uint8_t *data)
{
	hci_command_hdr *ch;
	uint8_t *ptr = data;
	uint16_t ogf, ocf;

	ch = (hci_command_hdr *) ptr;
	ptr += HCI_COMMAND_HDR_SIZE;

	ch->opcode = btohs(ch->opcode);
	ogf = cmd_opcode_ogf(ch->opcode);
	ocf = cmd_opcode_ocf(ch->opcode);

	switch (ogf) {
	case OGF_LINK_CTL:
		hci_link_control(ocf, ch->plen, ptr);
		break;

	case OGF_LINK_POLICY:
		hci_link_policy(ocf, ch->plen, ptr);
		break;

	case OGF_HOST_CTL:
		hci_host_control(ocf, ch->plen, ptr);
		break;

	case OGF_INFO_PARAM:
		hci_info_param(ocf, ch->plen, ptr);
		break;

	case OGF_STATUS_PARAM:
		hci_status_param(ocf, ch->plen, ptr);
		break;

	case OGF_LE_CTL:
		hci_le_control(ocf, ch->plen, ptr);
		break;

	default:
		command_status(ogf, ocf, 0x01);
		break;
	}
}

static void hci_acl_data(uint8_t *data)
{
	hci_acl_hdr *ah = (void *) data;
	struct vhci_conn *conn;
	uint16_t handle;

	handle = acl_handle(btohs(ah->handle));

	if (handle > VHCI_MAX_CONN || !(conn = vconn[handle - 1])) {
		syslog(LOG_ERR, "Bad connection handle %d", handle);
		return;
	}

	if (write_n(conn->fd, data, btohs(ah->dlen) + HCI_ACL_HDR_SIZE) < 0) {
		close_connection(conn);
		return;
	}

	if (++vdev.acl_cnt > VHCI_ACL_MAX_PKT - 1) {
		/* Send num of complete packets event */
		num_completed_pkts(conn);
		vdev.acl_cnt = 0;
	}
}

#if 0
static void io_acl_data(void *data)
{
	struct vhci_conn *conn = data;
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	hci_acl_hdr *ah;
	uint16_t flags;
	int len;

	ptr = buf + 1;
	if (read_n(conn->fd, ptr, HCI_ACL_HDR_SIZE) <= 0) {
		close_connection(conn);
		return;
	}

	ah = (void *) ptr;
	ptr += HCI_ACL_HDR_SIZE;

	len = btohs(ah->dlen);
	if (read_n(conn->fd, ptr, len) <= 0) {
		close_connection(conn);
		return;
	}

	buf[0] = HCI_ACLDATA_PKT;

	flags = acl_flags(btohs(ah->handle));
	ah->handle = htobs(acl_handle_pack(conn->handle, flags));
	len += HCI_ACL_HDR_SIZE + 1;

	write_snoop(vdev.dd, HCI_ACLDATA_PKT, 1, buf, len);

	if (write(vdev.dev_fd, buf, len) < 0)
		syslog(LOG_ERR, "ACL data write error");
}
#endif

static void io_conn_ind(void)
{
	struct vhci_link_info info;
	struct vhci_conn *conn;
	struct sockaddr_in sa;
	socklen_t len;
	int nsk, h;

	len = sizeof(sa);
	if ((nsk = accept(vdev.scan_fd, (struct sockaddr *) &sa, &len)) < 0)
		return;

	if (read_n(nsk, &info, sizeof(info)) < 0) {
		syslog(LOG_ERR, "Can't read link info");
		return;
	}

	if (!(conn = malloc(sizeof(*conn)))) {
		syslog(LOG_ERR, "Can't alloc new connection");
		close(nsk);
		return;
	}

	bacpy(&conn->dest, &info.bdaddr);

	for (h = 0; h < VHCI_MAX_CONN; h++)
		if (!vconn[h])
			goto accepted;

	syslog(LOG_ERR, "Too many connections");
	free(conn);
	close(nsk);
	return;

accepted:
	vconn[h] = conn;
	conn->handle = h + 1;
	conn->fd = nsk;
	connect_request(conn);
}

static void io_hci_data(void)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	int type;
	ssize_t len;

	ptr = buf;

	len = read(vdev.dev_fd, buf, sizeof(buf));
	if (len < 0) {
		if (errno == EAGAIN)
			return;

		syslog(LOG_ERR, "Read failed: %s (%d)", strerror(errno), errno);
		__io_canceled = 1;
		return;
	}

	type = *ptr++;

	write_snoop(vdev.dd, type, 0, buf, len);

	switch (type) {
	case HCI_COMMAND_PKT:
		hci_command(ptr);
		break;

	case HCI_ACLDATA_PKT:
		hci_acl_data(ptr);
		break;

	default:
		syslog(LOG_ERR, "Unknown packet type 0x%2.2x", type);
		break;
	}
}

static int getbdaddrbyname(char *str, bdaddr_t *ba)
{
	int i, n, len;

	len = strlen(str);

	/* Check address format */
	for (i = 0, n = 0; i < len; i++)
		if (str[i] == ':')
			n++;

	if (n == 5) {
		/* BD address */
		str2ba(str, ba);
		return 0;
	}

	if (n == 0) {
		/* loopback port */
		in_addr_t addr = INADDR_LOOPBACK;
		uint16_t be16 = htons(atoi(str));
		bdaddr_t b;

		memcpy(&b, &addr, 4);
		memcpy(&b.b[4], &be16, sizeof(be16));
		baswap(ba, &b);

		return 0;
	}

	fprintf(stderr, "Invalid address format\n");

	return -1;
}

static void usage(void)
{
	printf("hciemu - HCI emulator ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\thciemu [options] port_number\n"
		"Options:\n"
		"\t[-d device] use specified device node\n"
		"\t[-s file] create snoop file\n"
		"\t[-n] do not detach\n"
		"\t[-h] help, you are looking at it\n");
}

static const struct option options[] = {
	{ "device",	1, 0, 'd' },
	{ "bdaddr",	1, 0, 'b' },
	{ "snoop",	1, 0, 's' },
	{ "nodetach",	0, 0, 'n' },
	{ "help",	0, 0, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	int exitcode = EXIT_FAILURE;
	struct sigaction sa;
	char *device = NULL, *snoop = NULL;
	int device_fd;
	struct epoll_event device_event;
	int dd, opt, detach = 1;

	while ((opt=getopt_long(argc, argv, "d:s:nh", options, NULL)) != EOF) {
		switch(opt) {
		case 'd':
			device = strdup(optarg);
			break;
		case 's':
			snoop = strdup(optarg);
			break;
		case 'n':
			detach = 0;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc < 1) {
		usage();
		exit(1);
	}

	if (getbdaddrbyname(argv[0], &vdev.bdaddr) < 0)
		exit(1);

	if (detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	}

	/* Start logging to syslog and stderr */
	openlog("hciemu", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "HCI emulation daemon ver %s started", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	if (!device)
		device = strdup(VHCI_DEV);

	/* Open and create virtual HCI device */
	device_fd = open(device, O_RDWR);
	if (device_fd < 0) {
		syslog(LOG_ERR, "Can't open device %s: %s (%d)",
					device, strerror(errno), errno);
		free(device);
		return exitcode;
	}

	free(device);

	/* Create snoop file */
	if (snoop) {
		dd = create_snoop(snoop);
		if (dd < 0)
			syslog(LOG_ERR, "Can't create snoop file %s: %s (%d)",
						snoop, strerror(errno), errno);
		free(snoop);
	} else
		dd = -1;

	/* Create event loop */
	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		perror("Failed to create epoll descriptor");
		goto close_device;
	}

	reset_vdev();

	vdev.dev_fd = device_fd;
	vdev.dd = dd;

	memset(&device_event, 0, sizeof(device_event));
	device_event.events = EPOLLIN;
	device_event.data.fd = device_fd;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, device_fd, &device_event) < 0) {
		perror("Failed to setup device event watch");
		goto close_device;
	}

	setpriority(PRIO_PROCESS, 0, -19);

	/* Start event processor */
	for (;;) {
		struct epoll_event events[MAX_EPOLL_EVENTS];
		int n, nfds;

		if (__io_canceled)
			break;

		nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
		if (nfds < 0)
			continue;

		for (n = 0; n < nfds; n++) {
			if (events[n].data.fd == vdev.dev_fd)
				io_hci_data();
			else if (events[n].data.fd == vdev.scan_fd)
				io_conn_ind();
		}
	}

	exitcode = EXIT_SUCCESS;

	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, device_fd, NULL);

close_device:
	close(device_fd);

	if (dd >= 0)
		close(dd);

	close(epoll_fd);

	syslog(LOG_INFO, "Exit");

	return exitcode;
}
