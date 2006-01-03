/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <netdb.h>

#include "glib-ectomy.h"

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

#define GHCI_DEV		"/dev/ghci"

#define VHCI_DEV		"/dev/vhci"
#define VHCI_UDEV		"/dev/hci_vhci"

#define VHCI_MAX_CONN		12

#define VHCI_ACL_MTU		192
#define VHCI_ACL_MAX_PKT	8

struct vhci_device {
	uint8_t		features[8];
	uint8_t		name[248];
	uint8_t		dev_class[3];
	uint8_t		inq_mode;
	uint8_t		eir_fec;
	uint8_t		eir_data[240];
	uint16_t	acl_cnt;
	bdaddr_t	bdaddr;
	int		fd;
	int		dd;
	GIOChannel	*scan;
};

struct vhci_conn {
	bdaddr_t	dest;
	uint16_t	handle;
	GIOChannel	*chan;
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

static GMainLoop *event_loop;

static volatile sig_atomic_t __io_canceled;

static inline void io_init(void)
{
	__io_canceled = 0;
}

static inline void io_cancel(void)
{
	__io_canceled = 1;
}

static void sig_term(int sig)
{
	io_cancel();
	g_main_quit(event_loop);
}

static gboolean io_acl_data(GIOChannel *chan, GIOCondition cond, gpointer data);
static gboolean io_conn_ind(GIOChannel *chan, GIOCondition cond, gpointer data);
static gboolean io_hci_data(GIOChannel *chan, GIOCondition cond, gpointer data);

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

static int write_snoop(int fd, int type, int incoming, unsigned char *buf, int len)
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

	write(fd, &pkt, BTSNOOP_PKT_SIZE);
	write(fd, buf, size);

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

	if (write(vdev.fd, buf, ptr - buf) < 0)
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

	if (write(vdev.fd, buf, ptr - buf) < 0)
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

	if (write(vdev.fd, buf, ptr - buf) < 0)
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

	if (write(vdev.fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s (%d)",
						strerror(errno), errno);
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

	if (write(vdev.fd, buf, ptr - buf) < 0)
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

	if (write(vdev.fd, buf, ptr - buf) < 0)
		syslog(LOG_ERR, "Can't send event: %s (%d)",
						strerror(errno), errno);
}

static int scan_enable(uint8_t *data)
{
	struct sockaddr_in sa;
	GIOChannel *sk_io;
	bdaddr_t ba;
	int sk, opt;

	if (!(*data & SCAN_PAGE)) {
		if (vdev.scan) {
			g_io_channel_close(vdev.scan);
			vdev.scan = NULL;
		}
		return 0;
	}

	if (vdev.scan)
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
	sa.sin_addr.s_addr = *(uint32_t *) &ba;
	sa.sin_port = *(uint16_t *) &ba.b[4];
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

	sk_io = g_io_channel_unix_new(sk);
	g_io_add_watch(sk_io, G_IO_IN | G_IO_NVAL, io_conn_ind, NULL);
	vdev.scan = sk_io;
	return 0;

failed:
	close(sk);
	return 1;
}

static void accept_connection(uint8_t *data)
{
	accept_conn_req_cp *cp = (void *) data;
	struct vhci_conn *conn;

	if (!(conn = conn_get_by_bdaddr(&cp->bdaddr)))
		return;

	connect_complete(conn);

	g_io_add_watch(conn->chan, G_IO_IN | G_IO_NVAL | G_IO_HUP,
			io_acl_data, (gpointer) conn);
}

static void close_connection(struct vhci_conn *conn)
{
	syslog(LOG_INFO, "Closing connection %s handle %d",
					batostr(&conn->dest), conn->handle);

	g_io_channel_close(conn->chan);

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

	if (handle - 1 > VHCI_MAX_CONN)
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
	sa.sin_addr.s_addr = *(uint32_t *) &ba;
	sa.sin_port = *(uint16_t *) &ba.b[4];
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
	conn->chan = g_io_channel_unix_new(sk);

	connect_complete(conn);
	g_io_add_watch(conn->chan, G_IO_IN | G_IO_NVAL | G_IO_HUP,
				io_acl_data, (gpointer) conn);
	return;
}

static void inline hci_link_control(uint16_t ocf, int plen, uint8_t *data)
{
	uint8_t status;

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
		status = 0x01;
		command_complete(ogf, ocf, 1, &status);
		break;
	}
}

static void inline hci_link_policy(uint16_t ocf, int plen, uint8_t *data)
{
	uint8_t status;

	const uint16_t ogf = OGF_INFO_PARAM;

	switch (ocf) {
	default:
		status = 0x01;
		command_complete(ogf, ocf, 1, &status);
		break;
	}
}

static void inline hci_host_control(uint16_t ocf, int plen, uint8_t *data)
{
	read_local_name_rp ln;
	read_class_of_dev_rp cd;
	read_inquiry_mode_rp im;
	read_ext_inquiry_response_rp ir;
	uint8_t status;

	const uint16_t ogf = OGF_HOST_CTL;

	switch (ocf) {
	case OCF_RESET:
		status = 0x00;
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

	case OCF_WRITE_SCAN_ENABLE:
		status = scan_enable(data);
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
		memcpy(ir.data, vdev.eir_data, 240);
		command_complete(ogf, ocf, sizeof(ir), &ir);
		break;

	case OCF_WRITE_EXT_INQUIRY_RESPONSE:
		status = 0x00;
		vdev.eir_fec = data[0];
		memcpy(vdev.eir_data, data + 1, 240);
		command_complete(ogf, ocf, 1, &status);
		break;

	default:
		status = 0x01;
		command_complete(ogf, ocf, 1, &status);
		break;
	}
}

static void inline hci_info_param(uint16_t ocf, int plen, uint8_t *data)
{
	read_local_version_rp lv;
	read_local_features_rp lf;
	read_local_ext_features_rp ef;
	read_buffer_size_rp bs;
	read_bd_addr_rp ba;
	uint8_t status;

	const uint16_t ogf = OGF_INFO_PARAM;

	switch (ocf) {
	case OCF_READ_LOCAL_VERSION:
		lv.status = 0x00;
		lv.hci_ver = 0x03;
		lv.hci_rev = htobs(0x0000);
		lv.lmp_ver = 0x03;
		lv.manufacturer = htobs(29);
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
			ef.max_page_num = 0;
			memcpy(ef.features, vdev.features, 8);
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
		status = 0x01;
		command_complete(ogf, ocf, 1, &status);
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
	}
}

static void hci_acl_data(uint8_t *data)
{
	hci_acl_hdr *ah = (void *) data;
	struct vhci_conn *conn;
	uint16_t handle;
	int fd;

	handle = acl_handle(btohs(ah->handle));

	if (handle > VHCI_MAX_CONN || !(conn = vconn[handle - 1])) {
		syslog(LOG_ERR, "Bad connection handle %d", handle);
		return;
	}

	fd = g_io_channel_unix_get_fd(conn->chan);
	if (write_n(fd, data, btohs(ah->dlen) + HCI_ACL_HDR_SIZE) < 0) {
		close_connection(conn);
		return;
	}

	if (++vdev.acl_cnt > VHCI_ACL_MAX_PKT - 1) {
		/* Send num of complete packets event */
		num_completed_pkts(conn);
		vdev.acl_cnt = 0;
	}
}

static gboolean io_acl_data(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct vhci_conn *conn = (struct vhci_conn *) data;
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	hci_acl_hdr *ah;
	uint16_t flags;
	int len, fd;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & G_IO_HUP) {
		close_connection(conn);
		return FALSE;
	}

	fd = g_io_channel_unix_get_fd(chan);

	ptr = buf + 1;
	if (read_n(fd, ptr, HCI_ACL_HDR_SIZE) <= 0) {
		close_connection(conn);
		return FALSE;
	}

	ah = (void *) ptr;
	ptr += HCI_ACL_HDR_SIZE;

	len = btohs(ah->dlen);
	if (read_n(fd, ptr, len) <= 0) {
		close_connection(conn);
		return FALSE;
	}

	buf[0] = HCI_ACLDATA_PKT;

	flags = acl_flags(btohs(ah->handle));
	ah->handle = htobs(acl_handle_pack(conn->handle, flags));
	len += HCI_ACL_HDR_SIZE + 1;

	write_snoop(vdev.dd, HCI_ACLDATA_PKT, 1, buf, len);

	write(vdev.fd, buf, len);

	return TRUE;
}

static gboolean io_conn_ind(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct vhci_link_info info;
	struct vhci_conn *conn;
	struct sockaddr_in sa;
	socklen_t len;
	int sk, nsk, h;

	if (cond & G_IO_NVAL)
		return FALSE;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(sa);
	if ((nsk = accept(sk, (struct sockaddr *) &sa, &len)) < 0)
		return TRUE;

	if (read_n(nsk, &info, sizeof(info)) < 0) {
		syslog(LOG_ERR, "Can't read link info");
		return TRUE;
	}

	if (!(conn = malloc(sizeof(*conn)))) {
		syslog(LOG_ERR, "Can't alloc new connection");
		close(nsk);
		return TRUE;
	}

	bacpy(&conn->dest, &info.bdaddr);

	for (h = 0; h < VHCI_MAX_CONN; h++)
		if (!vconn[h])
			goto accepted;

	syslog(LOG_ERR, "Too many connections");
	free(conn);
	close(nsk);
	return TRUE;

accepted:
	vconn[h] = conn;
	conn->handle = h + 1;
	conn->chan = g_io_channel_unix_new(nsk);
	connect_request(conn);

	return TRUE;
}

static gboolean io_hci_data(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	int type;
	gsize len;
	GIOError err;

	ptr = buf;

	if ((err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len))) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;

		syslog(LOG_ERR, "Read failed: %s (%d)", strerror(errno), errno);
		g_main_quit(event_loop);
		return FALSE;
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

	return TRUE;
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
		baswap(ba, strtoba(str));
		return 0;
	}

	if (n == 1) {
		/* IP address + port */
		struct hostent *hent;
		bdaddr_t b;
		char *ptr;

		ptr = strchr(str, ':');
		*ptr++ = 0;

		if (!(hent = gethostbyname(str))) {
			fprintf(stderr, "Can't resolve %s\n", str);
			return -2;
		}

		memcpy(&b, hent->h_addr, 4);
		*(uint16_t *) (&b.b[4]) = htons(atoi(ptr));
		baswap(ba, &b);

		return 0;
	}

	fprintf(stderr, "Invalid address format\n");

	return -1;
}

static void rewrite_bdaddr(unsigned char *buf, int len, bdaddr_t *bdaddr)
{
	hci_event_hdr *eh;
	unsigned char *ptr = buf;
	int type;

	if (!bdaddr)
		return;

	if (!bacmp(bdaddr, BDADDR_ANY))
		return;

	type = *ptr++;

	switch (type) {
	case HCI_EVENT_PKT:
		eh = (hci_event_hdr *) ptr;
		ptr += HCI_EVENT_HDR_SIZE;

		if (eh->evt == EVT_CMD_COMPLETE) {
			evt_cmd_complete *cc = (void *) ptr;

			ptr += EVT_CMD_COMPLETE_SIZE;

			if (cc->opcode == htobs(cmd_opcode_pack(OGF_INFO_PARAM,
						OCF_READ_BD_ADDR))) {
				bacpy((bdaddr_t *) (ptr + 1), bdaddr);
			}
		}
		break;
	}
}

static int run_proxy(int fd, int dev, bdaddr_t *bdaddr)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE + 1];
	struct hci_dev_info di;
	struct hci_filter flt;
	struct pollfd p[2];
	int dd, err, len, need_raw;

	dd = hci_open_dev(dev);
	if (dd < 0) {
		syslog(LOG_ERR, "Can't open device hci%d: %s (%d)",
						dev, strerror(errno), errno);
		return 1;
	}

	if (hci_devinfo(dev, &di) < 0) {
		syslog(LOG_ERR, "Can't get device info for hci%d: %s (%d)",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		return 1;
	}

	need_raw = !hci_test_bit(HCI_RAW, &di.flags);

	hci_filter_clear(&flt);
	hci_filter_all_ptypes(&flt);
	hci_filter_all_events(&flt);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
		syslog(LOG_ERR, "Can't set filter for hci%d: %s (%d)",
						dev, strerror(errno), errno);
		hci_close_dev(dd);
		return 1;
	}

	if (need_raw) {
		if (ioctl(dd, HCISETRAW, 1) < 0) {
			syslog(LOG_ERR, "Can't set raw mode on hci%d: %s (%d)",
						dev, strerror(errno), errno);
			hci_close_dev(dd);
			return 1;
		}
	}

	p[0].fd = fd;
	p[0].events = POLLIN;
	p[1].fd = dd;
	p[1].events = POLLIN;

	while (!__io_canceled) {
		p[0].revents = 0;
		p[1].revents = 0;
		err = poll(p, 2, 100);
		if (err < 0)
			break;
		if (!err)
			continue;

		if (p[0].revents & POLLIN) {
			len = read(fd, buf, sizeof(buf));
			if (len > 0) {
				rewrite_bdaddr(buf, len, bdaddr);
				write(dd, buf, len);
			}
		}

		if (p[1].revents & POLLIN) {
			len = read(dd, buf, sizeof(buf));
			if (len > 0) {
				rewrite_bdaddr(buf, len, bdaddr);
				write(fd, buf, len);
			}
		}
	}

	if (need_raw) {
		if (ioctl(dd, HCISETRAW, 0) < 0)
			syslog(LOG_ERR, "Can't clear raw mode on hci%d: %s (%d)",
						dev, strerror(errno), errno);
	}

	hci_close_dev(dd);

	syslog(LOG_INFO, "Exit");

	return 0;
}

static void usage(void)
{
	printf("hciemu - HCI emulator ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\thciemu [-n] local_address\n");
}

static struct option main_options[] = {
	{ "device",	1, 0, 'd' },
	{ "bdaddr",	1, 0, 'b' },
	{ "snoop",	1, 0, 's' },
	{ "nodetach",	0, 0, 'n' },
	{ "help",	0, 0, 'h' },
	{ 0 }
};

int main(int argc, char *argv[], char *env[])
{
	struct sigaction sa;
	GIOChannel *dev_io;
	char *device = NULL, *snoop = NULL;
	bdaddr_t bdaddr;
	int fd, dd, opt, daemon, dofork, dev = -1;

	bacpy(&bdaddr, BDADDR_ANY);

	/* Configure default settings */
	daemon = 1; dofork = 1;

	while ((opt=getopt_long(argc, argv, "d:b:s:nh", main_options, NULL)) != EOF) {
		switch(opt) {
		case 'd':
			device = strdup(optarg);
			break;

		case 'b':
			str2ba(optarg, &bdaddr);
			break;

		case 's':
			snoop = strdup(optarg);
			break;

		case 'n':
			daemon = 0;
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
		exit(1);
	}

	if (strlen(argv[0]) > 3 && !strncasecmp(argv[0], "hci", 3)) {
		dev = hci_devid(argv[0]);
		if (dev < 0) {
			perror("Invalid device");
			exit(1);
		}
	} else {
		if (getbdaddrbyname(argv[0], &vdev.bdaddr) < 0)
			exit(1);
	}

	if (daemon) {
		if (dofork && fork())
			exit(0);

		/* Direct stdin,stdout,stderr to '/dev/null' */
		fd = open("/dev/null", O_RDWR);
		dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
		close(fd);

		setsid();

		chdir("/");
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

	io_init();

	if (!device && dev >= 0)
		device = strdup(GHCI_DEV);

	/* Open and create virtual HCI device */
	if (device) {
		fd = open(device, O_RDWR);
		if (fd < 0) {
			syslog(LOG_ERR, "Can't open device %s: %s (%d)",
						device, strerror(errno), errno);
			free(device);
			exit(1);
		}
		free(device);
	} else {
		fd = open(VHCI_DEV, O_RDWR);
		if (fd < 0) {
			fd = open(VHCI_UDEV, O_RDWR);
			if (fd < 0) {
				syslog(LOG_ERR, "Can't open device %s: %s (%d)",
						VHCI_DEV, strerror(errno), errno);
				exit(1);
			}
		}
	}

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
	event_loop = g_main_new(FALSE);

	if (dev >= 0)
		return run_proxy(fd, dev, &bdaddr);

	/* Device settings */
	vdev.features[0] = 0xff;
	vdev.features[1] = 0xff;
	vdev.features[2] = 0x8f;
	vdev.features[3] = 0xfe;
	vdev.features[4] = 0x9b;
	vdev.features[5] = 0xf9;
	vdev.features[6] = 0x01;
	vdev.features[7] = 0x80;

	memset(vdev.name, 0, sizeof(vdev.name));
	strncpy((char *) vdev.name, "BlueZ (Virtual HCI)", sizeof(vdev.name));

	vdev.dev_class[0] = 0x00;
	vdev.dev_class[1] = 0x00;
	vdev.dev_class[2] = 0x00;

	vdev.inq_mode = 0x00;
	vdev.eir_fec = 0x00;
	memset(vdev.eir_data, 0, sizeof(vdev.eir_data));

	vdev.fd = fd;
	vdev.dd = dd;

	dev_io = g_io_channel_unix_new(fd);
	g_io_add_watch(dev_io, G_IO_IN, io_hci_data, NULL);

	setpriority(PRIO_PROCESS, 0, -19);

	/* Start event processor */
	g_main_run(event_loop);

	close(fd);

	if (dd >= 0)
		close(dd);

	syslog(LOG_INFO, "Exit");

	return 0;
}
