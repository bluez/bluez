/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "plugin.h"
#include "log.h"
#include "manager.h"

static int child_pipe[2] = { -1, -1 };

static guint child_io_id = 0;
static guint ctl_io_id = 0;

static gboolean child_exit(GIOChannel *io, GIOCondition cond, void *user_data)
{
	int status, fd = g_io_channel_unix_get_fd(io);
	pid_t child_pid;

	if (read(fd, &child_pid, sizeof(child_pid)) != sizeof(child_pid)) {
		error("child_exit: unable to read child pid from pipe");
		return TRUE;
	}

	if (waitpid(child_pid, &status, 0) != child_pid)
		error("waitpid(%d) failed", child_pid);
	else
		DBG("child %d exited", child_pid);

	return TRUE;
}

static void at_child_exit(void)
{
	pid_t pid = getpid();

	if (write(child_pipe[1], &pid, sizeof(pid)) != sizeof(pid))
		error("unable to write to child pipe");
}

static void device_devup_setup(int index)
{
	struct hci_dev_info di;
	uint16_t policy;
	int dd;

	if (hci_devinfo(index, &di) < 0)
		return;

	if (ignore_device(&di))
		return;

	dd = hci_open_dev(index);
	if (dd < 0) {
		error("Can't open device hci%d: %s (%d)", index,
						strerror(errno), errno);
		return;
	}

	/* Set page timeout */
	if ((main_opts.flags & (1 << HCID_SET_PAGETO))) {
		write_page_timeout_cp cp;

		cp.timeout = htobs(main_opts.pageto);
		hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_PAGE_TIMEOUT,
					WRITE_PAGE_TIMEOUT_CP_SIZE, &cp);
	}

	/* Set default link policy */
	policy = htobs(main_opts.link_policy);
	hci_send_cmd(dd, OGF_LINK_POLICY, OCF_WRITE_DEFAULT_LINK_POLICY,
								2, &policy);

	hci_close_dev(dd);

	start_security_manager(index);

	/* Return value 1 means ioctl(DEVDOWN) was performed */
	if (manager_start_adapter(index) == 1)
		stop_security_manager(index);
}

static void init_device(int index)
{
	struct hci_dev_req dr;
	struct hci_dev_info di;
	pid_t pid;
	int dd;

	/* Do initialization in the separate process */
	pid = fork();
	switch (pid) {
		case 0:
			atexit(at_child_exit);
			break;
		case -1:
			error("Fork failed. Can't init device hci%d: %s (%d)",
					index, strerror(errno), errno);
		default:
			DBG("child %d forked", pid);
			return;
	}

	dd = hci_open_dev(index);
	if (dd < 0) {
		error("Can't open device hci%d: %s (%d)",
					index, strerror(errno), errno);
		exit(1);
	}

	memset(&dr, 0, sizeof(dr));
	dr.dev_id = index;

	/* Set link mode */
	dr.dev_opt = main_opts.link_mode;
	if (ioctl(dd, HCISETLINKMODE, (unsigned long) &dr) < 0)
		error("Can't set link mode on hci%d: %s (%d)",
						index, strerror(errno), errno);

	/* Set link policy for BR/EDR HCI devices */
	if (hci_devinfo(index, &di) < 0)
		goto fail;

	if (!ignore_device(&di)) {
		dr.dev_opt = main_opts.link_policy;
		if (ioctl(dd, HCISETLINKPOL, (unsigned long) &dr) < 0 &&
							errno != ENETDOWN) {
			error("Can't set link policy on hci%d: %s (%d)",
						index, strerror(errno), errno);
		}
	}

	/* Start HCI device */
	if (ioctl(dd, HCIDEVUP, index) < 0 && errno != EALREADY) {
		error("Can't init device hci%d: %s (%d)",
					index, strerror(errno), errno);
		goto fail;
	}

	hci_close_dev(dd);
	exit(0);

fail:
	hci_close_dev(dd);
	exit(1);
}

static void device_devreg_setup(int index)
{
	struct hci_dev_info di;
	gboolean devup;

	init_device(index);

	memset(&di, 0, sizeof(di));

	if (hci_devinfo(index, &di) < 0)
		return;

	devup = hci_test_bit(HCI_UP, &di.flags);

	if (!ignore_device(&di))
		manager_register_adapter(index, devup);
}

static void device_event(int event, int index)
{
	switch (event) {
	case HCI_DEV_REG:
		info("HCI dev %d registered", index);
		device_devreg_setup(index);
		break;

	case HCI_DEV_UNREG:
		info("HCI dev %d unregistered", index);
		manager_unregister_adapter(index);
		break;

	case HCI_DEV_UP:
		info("HCI dev %d up", index);
		device_devup_setup(index);
		break;

	case HCI_DEV_DOWN:
		info("HCI dev %d down", index);
		manager_stop_adapter(index);
		stop_security_manager(index);
		break;
	}
}

static int init_known_adapters(int ctl)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	int i, err;
	size_t req_size;

	req_size = HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t);

	dl = g_try_malloc0(req_size);
	if (!dl) {
		error("Can't allocate devlist buffer");
		return -ENOMEM;
	}

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(ctl, HCIGETDEVLIST, dl) < 0) {
		err = -errno;
		error("Can't get device list: %s (%d)", strerror(-err), -err);
		g_free(dl);
		return err;
	}

	for (i = 0; i < dl->dev_num; i++, dr++) {
		device_event(HCI_DEV_REG, dr->dev_id);

		if (hci_test_bit(HCI_UP, &dr->dev_opt))
			device_event(HCI_DEV_UP, dr->dev_id);
	}

	g_free(dl);
	return 0;
}

static gboolean io_stack_event(GIOChannel *chan, GIOCondition cond,
								gpointer data)
{
	unsigned char buf[HCI_MAX_FRAME_SIZE], *ptr;
	evt_stack_internal *si;
	evt_si_device *sd;
	hci_event_hdr *eh;
	int type;
	size_t len;
	GIOError err;

	ptr = buf;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err) {
		if (err == G_IO_ERROR_AGAIN)
			return TRUE;

		error("Read from control socket failed: %s (%d)",
						strerror(errno), errno);
		return FALSE;
	}

	type = *ptr++;

	if (type != HCI_EVENT_PKT)
		return TRUE;

	eh = (hci_event_hdr *) ptr;
	if (eh->evt != EVT_STACK_INTERNAL)
		return TRUE;

	ptr += HCI_EVENT_HDR_SIZE;

	si = (evt_stack_internal *) ptr;
	switch (si->type) {
	case EVT_SI_DEVICE:
		sd = (void *) &si->data;
		device_event(sd->event, sd->dev_id);
		break;
	}

	return TRUE;
}

static int hciops_setup(void)
{
	struct sockaddr_hci addr;
	struct hci_filter flt;
	GIOChannel *ctl_io, *child_io;
	int sock, err;

	if (child_pipe[0] != -1)
		return -EALREADY;

	if (pipe(child_pipe) < 0) {
		err = -errno;
		error("pipe(): %s (%d)", strerror(-err), -err);
		return err;
	}

	child_io = g_io_channel_unix_new(child_pipe[0]);
	g_io_channel_set_close_on_unref(child_io, TRUE);
	child_io_id = g_io_add_watch(child_io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				child_exit, NULL);
	g_io_channel_unref(child_io);

	/* Create and bind HCI socket */
	sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sock < 0) {
		err = -errno;
		error("Can't open HCI socket: %s (%d)", strerror(-err),
								-err);
		return err;
	}

	/* Set filter */
	hci_filter_clear(&flt);
	hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
	hci_filter_set_event(EVT_STACK_INTERNAL, &flt);
	if (setsockopt(sock, SOL_HCI, HCI_FILTER, &flt,
							sizeof(flt)) < 0) {
		err = -errno;
		error("Can't set filter: %s (%d)", strerror(-err), -err);
		return err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.hci_family = AF_BLUETOOTH;
	addr.hci_dev = HCI_DEV_NONE;
	if (bind(sock, (struct sockaddr *) &addr,
							sizeof(addr)) < 0) {
		err = -errno;
		error("Can't bind HCI socket: %s (%d)",
							strerror(-err), -err);
		return err;
	}

	ctl_io = g_io_channel_unix_new(sock);
	g_io_channel_set_close_on_unref(ctl_io, TRUE);

	ctl_io_id = g_io_add_watch(ctl_io, G_IO_IN, io_stack_event, NULL);

	g_io_channel_unref(ctl_io);

	/* Initialize already connected devices */
	return init_known_adapters(sock);
}

static void hciops_cleanup(void)
{
	if (child_io_id) {
		g_source_remove(child_io_id);
		child_io_id = 0;
	}

	if (ctl_io_id) {
		g_source_remove(ctl_io_id);
		ctl_io_id = 0;
	}

	if (child_pipe[0] >= 0) {
		close(child_pipe[0]);
		child_pipe[0] = -1;
	}

	if (child_pipe[1] >= 0) {
		close(child_pipe[1]);
		child_pipe[1] = -1;
	}
}

static int hciops_start(int index)
{
	int dd;
	int err = 0;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	if (ioctl(dd, HCIDEVUP, index) == 0)
		goto done; /* on success */

	if (errno != EALREADY) {
		err = -errno;
		error("Can't init device hci%d: %s (%d)",
				index, strerror(-err), -err);
	}

done:
	hci_close_dev(dd);
	return err;
}

static int hciops_stop(int index)
{
	int dd;
	int err = 0;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	if (ioctl(dd, HCIDEVDOWN, index) == 0)
		goto done; /* on success */

	if (errno != EALREADY) {
		err = -errno;
		error("Can't stop device hci%d: %s (%d)",
				index, strerror(-err), -err);
	}

done:
	hci_close_dev(dd);
	return err;
}

static int hciops_powered(int index, gboolean powered)
{
	int dd, err;
	uint8_t mode = SCAN_DISABLED;

	if (powered)
		return hciops_start(index);

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
					1, &mode);
	if (err < 0) {
		err = -errno;
		hci_close_dev(dd);
		return err;
	}

	hci_close_dev(dd);

	return hciops_stop(index);
}

static int hciops_connectable(int index)
{
	int dd, err;
	uint8_t mode = SCAN_PAGE;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
					1, &mode);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_discoverable(int index)
{
	int dd, err;
	uint8_t mode = (SCAN_PAGE | SCAN_INQUIRY);

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
					1, &mode);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_set_class(int index, uint32_t class)
{
	int dd, err;
	write_class_of_dev_cp cp;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	memcpy(cp.dev_class, &class, 3);

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_CLASS_OF_DEV,
					WRITE_CLASS_OF_DEV_CP_SIZE, &cp);

	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_set_limited_discoverable(int index, uint32_t class,
							gboolean limited)
{
	int dd, err;
	int num = (limited ? 2 : 1);
	uint8_t lap[] = { 0x33, 0x8b, 0x9e, 0x00, 0x8b, 0x9e };
	write_current_iac_lap_cp cp;

	/*
	 * 1: giac
	 * 2: giac + liac
	 */
	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	memset(&cp, 0, sizeof(cp));
	cp.num_current_iac = num;
	memcpy(&cp.lap, lap, num * 3);

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_CURRENT_IAC_LAP,
			(num * 3 + 1), &cp);
	if (err < 0) {
		err = -errno;
		goto fail;
	}

	err = hciops_set_class(index, class);

fail:
	hci_close_dev(dd);
	return err;
}

static int hciops_start_discovery(int index, gboolean periodic)
{
	uint8_t lap[3] = { 0x33, 0x8b, 0x9e };
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	if (periodic) {
		periodic_inquiry_cp cp;

		memset(&cp, 0, sizeof(cp));
		memcpy(&cp.lap, lap, 3);
		cp.max_period = htobs(24);
		cp.min_period = htobs(16);
		cp.length  = 0x08;
		cp.num_rsp = 0x00;

		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_PERIODIC_INQUIRY,
					PERIODIC_INQUIRY_CP_SIZE, &cp);
	} else {
		inquiry_cp inq_cp;

		memset(&inq_cp, 0, sizeof(inq_cp));
		memcpy(&inq_cp.lap, lap, 3);
		inq_cp.length = 0x08;
		inq_cp.num_rsp = 0x00;

		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_INQUIRY,
					INQUIRY_CP_SIZE, &inq_cp);
	}

	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_stop_discovery(int index)
{
	struct hci_dev_info di;
	int dd, err;

	if (hci_devinfo(index, &di) < 0)
		return -errno;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	if (hci_test_bit(HCI_INQUIRY, &di.flags))
		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_INQUIRY_CANCEL, 0, 0);
	else
		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_EXIT_PERIODIC_INQUIRY,
									0, 0);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_resolve_name(int index, bdaddr_t *bdaddr)
{
	remote_name_req_cp cp;
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);
	cp.pscan_rep_mode = 0x02;

	err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_REMOTE_NAME_REQ,
						REMOTE_NAME_REQ_CP_SIZE, &cp);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_set_name(int index, const char *name)
{
	change_local_name_cp cp;
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	memset(&cp, 0, sizeof(cp));
	strncpy((char *) cp.name, name, sizeof(cp.name));

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_CHANGE_LOCAL_NAME,
					CHANGE_LOCAL_NAME_CP_SIZE, &cp);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_read_name(int index)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	err = hci_send_cmd(dd, OGF_HOST_CTL, OCF_READ_LOCAL_NAME, 0, 0);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_cancel_resolve_name(int index, bdaddr_t *bdaddr)
{
	remote_name_req_cancel_cp cp;
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_REMOTE_NAME_REQ_CANCEL,
					REMOTE_NAME_REQ_CANCEL_CP_SIZE, &cp);
	if (err < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_fast_connectable(int index, gboolean enable)
{
	int dd, err = 0;
	write_page_activity_cp cp;
	uint8_t type;

	if (enable) {
		type = PAGE_SCAN_TYPE_INTERLACED;
		cp.interval = 0x0024;	/* 22.5 msec page scan interval */
	} else {
		type = PAGE_SCAN_TYPE_STANDARD;	/* default */
		cp.interval = 0x0800;	/* default 1.28 sec page scan */
	}

	cp.window = 0x0012;	/* default 11.25 msec page scan window */

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_PAGE_ACTIVITY,
					WRITE_PAGE_ACTIVITY_CP_SIZE, &cp) < 0)
		err = -errno;
	else if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_PAGE_SCAN_TYPE,
								1, &type) < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_read_clock(int index, int handle, int which, int timeout,
					uint32_t *clock, uint16_t *accuracy)
{
	int dd, err = 0;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	if (hci_read_clock(dd, handle, which, clock, accuracy, timeout) < 0)
		err = -errno;

	hci_close_dev(dd);

	return err;
}

static int hciops_conn_handle(int index, const bdaddr_t *bdaddr, int *handle)
{
	struct hci_conn_info_req *cr;
	int dd, err = 0;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -EIO;

	cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	bacpy(&cr->bdaddr, bdaddr);
	cr->type = ACL_LINK;

	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
		err = -errno;
		goto fail;
	}

	*handle = htobs(cr->conn_info->handle);

fail:
	hci_close_dev(dd);
	g_free(cr);
	return err;
}

static int hciops_write_eir_data(int index, uint8_t *data)
{
	write_ext_inquiry_response_cp cp;
	int err, dd;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	memset(&cp, 0, sizeof(cp));
	memcpy(cp.data, data, 240);

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_EXT_INQUIRY_RESPONSE,
				WRITE_EXT_INQUIRY_RESPONSE_CP_SIZE, &cp) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_read_bdaddr(int index, bdaddr_t *bdaddr)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_read_bd_addr(dd, bdaddr, HCI_REQ_TIMEOUT) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_set_event_mask(int index, uint8_t *events, size_t count)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_SET_EVENT_MASK,
						count, events) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_write_inq_mode(int index, uint8_t mode)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_write_inquiry_mode(dd, mode, HCI_REQ_TIMEOUT) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_read_inq_tx_pwr(int index)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_send_cmd(dd, OGF_HOST_CTL,
			OCF_READ_INQ_RESPONSE_TX_POWER_LEVEL, 0, NULL) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_block_device(int index, bdaddr_t *bdaddr)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (ioctl(dd, HCIBLOCKADDR, bdaddr) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_unblock_device(int index, bdaddr_t *bdaddr)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (ioctl(dd, HCIUNBLOCKADDR, bdaddr) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_get_conn_list(int index, GSList **conns)
{
	struct hci_conn_list_req *cl;
	struct hci_conn_info *ci;
	int dd, err, i;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = index;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dd, HCIGETCONNLIST, cl) < 0) {
		err = -errno;
		goto fail;
	}

	err = 0;
	*conns = NULL;

	for (i = 0; i < cl->conn_num; i++, ci++)
		*conns = g_slist_append(*conns, g_memdup(ci, sizeof(*ci)));

fail:
	hci_close_dev(dd);
	g_free(cl);
	return err;
}

static int hciops_read_local_version(int index, struct hci_version *ver)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_read_local_version(dd, ver, HCI_REQ_TIMEOUT) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_read_local_features(int index, uint8_t *features)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_read_local_features(dd, features, HCI_REQ_TIMEOUT) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_init_ssp_mode(int index, uint8_t *mode)
{
	write_simple_pairing_mode_cp cp;
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (ioctl(dd, HCIGETAUTHINFO, NULL) < 0 && errno == EINVAL) {
		err = 0;
		goto done;
	}

	memset(&cp, 0, sizeof(cp));
	cp.mode = 0x01;

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SIMPLE_PAIRING_MODE,
				WRITE_SIMPLE_PAIRING_MODE_CP_SIZE, &cp) < 0)
		err = -errno;
	else
		err = 0;

done:
	hci_close_dev(dd);
	return err;
}

static int hciops_read_link_policy(int index)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_send_cmd(dd, OGF_LINK_POLICY, OCF_READ_DEFAULT_LINK_POLICY,
								0, NULL) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_disconnect(int index, uint16_t handle)
{
	int dd, err;
	disconnect_cp cp;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);
	cp.reason = HCI_OE_USER_ENDED_CONNECTION;

	if (hci_send_cmd(dd, OGF_LINK_CTL, OCF_DISCONNECT,
						DISCONNECT_CP_SIZE, &cp) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_remove_bonding(int index, bdaddr_t *bdaddr)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	/* Delete the link key from the Bluetooth chip */
	if (hci_delete_stored_link_key(dd, bdaddr, 0, HCI_REQ_TIMEOUT) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_request_authentication(int index, uint16_t handle,
							uint8_t *status)
{
	struct hci_request rq;
	auth_requested_cp cp;
	evt_cmd_status rp;
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	memset(&rp, 0, sizeof(rp));

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(handle);

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_LINK_CTL;
	rq.ocf    = OCF_AUTH_REQUESTED;
	rq.cparam = &cp;
	rq.clen   = AUTH_REQUESTED_CP_SIZE;
	rq.rparam = &rp;
	rq.rlen   = EVT_CMD_STATUS_SIZE;
	rq.event  = EVT_CMD_STATUS;

	if (hci_send_req(dd, &rq, HCI_REQ_TIMEOUT) < 0) {
		err = -errno;
		goto fail;
	}

	if (status)
		*status = rp.status;

	err = 0;

fail:
	hci_close_dev(dd);
	return err;
}

static int hciops_pincode_reply(int index, bdaddr_t *bdaddr, const char *pin)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (pin) {
		pin_code_reply_cp pr;
		size_t len = strlen(pin);

		memset(&pr, 0, sizeof(pr));
		bacpy(&pr.bdaddr, bdaddr);
		memcpy(pr.pin_code, pin, len);
		pr.pin_len = len;
		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_PIN_CODE_REPLY,
						PIN_CODE_REPLY_CP_SIZE, &pr);
	} else
		err = hci_send_cmd(dd, OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, bdaddr);

	hci_close_dev(dd);

	return err;
}

static int hciops_confirm_reply(int index, bdaddr_t *bdaddr, gboolean success)
{
	int dd, err;
	user_confirm_reply_cp cp;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	memset(&cp, 0, sizeof(cp));
	bacpy(&cp.bdaddr, bdaddr);

	if (success)
		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_CONFIRM_REPLY,
					USER_CONFIRM_REPLY_CP_SIZE, &cp);
	else
		err = hci_send_cmd(dd, OGF_LINK_CTL,
					OCF_USER_CONFIRM_NEG_REPLY,
					USER_CONFIRM_REPLY_CP_SIZE, &cp);

	hci_close_dev(dd);

	return err;
}

static int hciops_passkey_reply(int index, bdaddr_t *bdaddr, uint32_t passkey)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (passkey != INVALID_PASSKEY) {
		user_passkey_reply_cp cp;

		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, bdaddr);
		cp.passkey = passkey;

		err = hci_send_cmd(dd, OGF_LINK_CTL, OCF_USER_PASSKEY_REPLY,
					USER_PASSKEY_REPLY_CP_SIZE, &cp);
	} else
		err = hci_send_cmd(dd, OGF_LINK_CTL,
					OCF_USER_PASSKEY_NEG_REPLY, 6, bdaddr);

	hci_close_dev(dd);

	return err;
}

static int hciops_get_auth_info(int index, bdaddr_t *bdaddr, uint8_t *auth)
{
	struct hci_auth_info_req req;
	int err, dd;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	memset(&req, 0, sizeof(req));
	bacpy(&req.bdaddr, bdaddr);

	if (ioctl(dd, HCIGETAUTHINFO, (unsigned long) &req) < 0) {
		err = -errno;
		goto fail;
	}

	err = 0;

	if (auth)
		*auth = req.type;

fail:
	hci_close_dev(dd);
	return err;
}

static int hciops_read_scan_enable(int index)
{
	int err, dd;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_READ_SCAN_ENABLE, 0, NULL) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static int hciops_read_ssp_mode(int index)
{
	int dd, err;

	dd = hci_open_dev(index);
	if (dd < 0)
		return -errno;

	if (hci_send_cmd(dd, OGF_HOST_CTL, OCF_READ_SIMPLE_PAIRING_MODE,
								0, NULL) < 0)
		err = -errno;
	else
		err = 0;

	hci_close_dev(dd);

	return err;
}

static struct btd_adapter_ops hci_ops = {
	.setup = hciops_setup,
	.cleanup = hciops_cleanup,
	.start = hciops_start,
	.stop = hciops_stop,
	.set_powered = hciops_powered,
	.set_connectable = hciops_connectable,
	.set_discoverable = hciops_discoverable,
	.set_limited_discoverable = hciops_set_limited_discoverable,
	.start_discovery = hciops_start_discovery,
	.stop_discovery = hciops_stop_discovery,
	.resolve_name = hciops_resolve_name,
	.cancel_resolve_name = hciops_cancel_resolve_name,
	.set_name = hciops_set_name,
	.read_name = hciops_read_name,
	.set_class = hciops_set_class,
	.set_fast_connectable = hciops_fast_connectable,
	.read_clock = hciops_read_clock,
	.get_conn_handle = hciops_conn_handle,
	.write_eir_data = hciops_write_eir_data,
	.read_bdaddr = hciops_read_bdaddr,
	.set_event_mask = hciops_set_event_mask,
	.write_inq_mode = hciops_write_inq_mode,
	.read_inq_tx_pwr = hciops_read_inq_tx_pwr,
	.block_device = hciops_block_device,
	.unblock_device = hciops_unblock_device,
	.get_conn_list = hciops_get_conn_list,
	.read_local_version = hciops_read_local_version,
	.read_local_features = hciops_read_local_features,
	.init_ssp_mode = hciops_init_ssp_mode,
	.read_link_policy = hciops_read_link_policy,
	.disconnect = hciops_disconnect,
	.remove_bonding = hciops_remove_bonding,
	.request_authentication = hciops_request_authentication,
	.pincode_reply = hciops_pincode_reply,
	.confirm_reply = hciops_confirm_reply,
	.passkey_reply = hciops_passkey_reply,
	.get_auth_info = hciops_get_auth_info,
	.read_scan_enable = hciops_read_scan_enable,
	.read_ssp_mode = hciops_read_ssp_mode,
};

static int hciops_init(void)
{
	return btd_register_adapter_ops(&hci_ops);
}
static void hciops_exit(void)
{
	btd_adapter_cleanup_ops(&hci_ops);
}

BLUETOOTH_PLUGIN_DEFINE(hciops, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, hciops_init, hciops_exit)
