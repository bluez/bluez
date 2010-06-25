/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *  Copyright (C) 2010 Signove
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
 *  Elvis Pfützenreuter <epx at signove.com>
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

#include "btio.h"
#include <stdint.h>
#include <netinet/in.h>
#include <time.h>
#include <stdlib.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/ioctl.h>

#include "config.h"
#include "log.h"

#include <bluetooth/bluetooth.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

struct mcap_csp {
	uint64_t		base_tmstamp;	/* CSP base timestamp */
	struct timespec		base_time;	/* CSP base time when timestamp set */
	guint			local_caps;	/* CSP-Master: have got remote caps */
	guint			remote_caps;	/* CSP-Slave: remote master got caps */
	guint			rem_req_acc;	/* CSP-Slave: accuracy required by master */
	guint			ind_expected;	/* CSP-Master: indication expected */
	MCAPCtrl		csp_req;	/* CSP-Master: Request control flag */
	guint			ind_timer;	/* CSP-Slave: indication timer */
	guint			set_timer;	/* CSP-Slave: delayed set timer */
	void			*set_data;	/* CSP-Slave: delayed set data */
	gint			dev_id;		/* CSP-Slave: device ID */
	gint			dev_hci_fd;	/* CSP-Slave fd to read BT clock */
	void			*csp_priv_data;	/* CSP-Master: In-flight request data */
};

#define MCAP_BTCLOCK_HALF (MCAP_BTCLOCK_FIELD / 2)

/*
static int send_unsupported_cap_req(struct mcap_mcl *mcl)
{
	mcap_md_sync_cap_rsp *cmd;
	int sock, sent;

	cmd = g_new0(mcap_md_sync_cap_rsp, 1);
	cmd->op = MCAP_MD_SYNC_CAP_RSP;
	cmd->rc = MCAP_REQUEST_NOT_SUPPORTED;

	sock = g_io_channel_unix_get_fd(mcl->cc);
	sent = mcap_send_data(sock, cmd, sizeof(*cmd));
	g_free(cmd);

	return sent;
}
*/

static int send_unsupported_set_req(struct mcap_mcl *mcl)
{
	mcap_md_sync_set_rsp *cmd;
	int sock, sent;

	cmd = g_new0(mcap_md_sync_set_rsp, 1);
	cmd->op = MCAP_MD_SYNC_SET_RSP;
	cmd->rc = MCAP_REQUEST_NOT_SUPPORTED;

	sock = g_io_channel_unix_get_fd(mcl->cc);
	sent = mcap_send_data(sock, cmd, sizeof(*cmd));
	g_free(cmd);

	return sent;
}

static void proc_sync_cap_req(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len);

void proc_sync_cmd(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	switch (cmd[0]) {
	case MCAP_MD_SYNC_CAP_REQ:
		proc_sync_cap_req(mcl, cmd, len);
		break;
	case MCAP_MD_SYNC_CAP_RSP:
		DBG("TODO: received MCAP_MD_SYNC_CAP_RSP: %d",
							MCAP_MD_SYNC_CAP_RSP);
		break;
	case MCAP_MD_SYNC_SET_REQ:
		DBG("TODO: received MCAP_MD_SYNC_SET_REQ: %d",
							MCAP_MD_SYNC_SET_REQ);
		/* Not implemented yet. Reply with unsupported request */
		send_unsupported_set_req(mcl);
		break;
	case MCAP_MD_SYNC_SET_RSP:
		DBG("TODO: received MCAP_MD_SYNC_SET_RSP: %d",
							MCAP_MD_SYNC_SET_RSP);
		break;
	case MCAP_MD_SYNC_INFO_IND:
		DBG("TODO: received MCAP_MD_SYNC_INFO_IND :%d",
							MCAP_MD_SYNC_INFO_IND);
		break;
	}
}

static void reset_tmstamp(struct mcap_csp *csp, struct timespec *base_time,
				uint64_t new_tmstamp)
{
	csp->base_tmstamp = new_tmstamp;
	if (base_time)
		csp->base_time = *base_time;
	else
		clock_gettime(CLOCK_MONOTONIC, &csp->base_time);
}

void mcap_sync_init(struct mcap_mcl *mcl)
{
	mcl->csp = g_new0(struct mcap_csp, 1);

	mcl->csp->rem_req_acc = 10000; /* safe divisor */
	mcl->csp->set_data = NULL;
	mcl->csp->dev_id = -1;
	mcl->csp->dev_hci_fd = -1;
	mcl->csp->csp_priv_data = NULL;

	reset_tmstamp(mcl->csp, NULL, 0);
}

static uint64_t time_us(struct timespec *tv)
{
	return tv->tv_sec * 1000000 + tv->tv_nsec / 1000;
}

/*
static int64_t bt2us(int bt)
{
	return bt * 312.5;
}

static int bt2ms(int bt)
{
	return bt * 0.3125;
}

static int btoffset(uint32_t btclk1, uint32_t btclk2)
{
	int offset = ((signed) btclk2) - ((signed) btclk1);

	if (offset <= -MCAP_BTCLOCK_HALF)
		offset += MCAP_BTCLOCK_FIELD;
	else if (offset > MCAP_BTCLOCK_HALF)
		offset -= MCAP_BTCLOCK_FIELD;

	return offset;
}

static int btdiff(uint32_t btclk1, uint32_t btclk2)
{
	return btoffset(btclk1, btclk2);
}
*/

static gboolean read_btclock(struct mcap_mcl *mcl, uint32_t *btclock,
						uint16_t* btaccuracy)
{
	int fd, dev_id, result, handle, which;
	struct hci_conn_info_req *cr;

	if (mcl) {
		if (mcl->csp->dev_hci_fd < 0) {
			dev_id = hci_get_route(&mcl->addr);
			mcl->csp->dev_hci_fd = hci_open_dev(dev_id);
		}
		fd = mcl->csp->dev_hci_fd;
		which = 1;

		cr = g_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
		bacpy(&cr->bdaddr, &mcl->addr);
		cr->type = ACL_LINK;

		if (ioctl(fd, HCIGETCONNINFO, (unsigned long) cr) < 0) {
			hci_close_dev(fd);
			g_free(cr);
			return FALSE;
		}

		handle = htobs(cr->conn_info->handle);
		g_free(cr);

	} else {
		dev_id = hci_get_route(NULL);
		fd = hci_open_dev(dev_id);
		which = 0;
		handle = 0;
	}

	result = hci_read_clock(fd, handle, which, btclock, btaccuracy, 1000);

	if (!mcl)
		hci_close_dev(fd);

	return result;
}

uint64_t mcap_get_timestamp(struct mcap_mcl *mcl,
				struct timespec *given_time)
{
	struct timespec now;
	uint64_t tmstamp;

	if (given_time)
		now = *given_time;
	else
		clock_gettime(CLOCK_MONOTONIC, &now);

	tmstamp = time_us(&now) - time_us(&mcl->csp->base_time)
		+ mcl->csp->base_tmstamp;

	return tmstamp;
}

struct csp_caps {
	uint16_t ts_acc;		/* timestamp accuracy */
	uint16_t ts_res;		/* timestamp resolution */
	uint32_t latency;		/* Read BT clock latency */
	uint32_t preempt_thresh;	/* Preemption threshold for latency */
};

static struct csp_caps _caps;
static gboolean csp_caps_initialized = FALSE;

static void initialize_caps(struct mcap_mcl *mcl)
{
	struct timespec t1, t2;
	int latencies[20];
	int latency, avg, dev;
	uint32_t btclock;
	uint16_t btaccuracy;
	int i;

	clock_getres(CLOCK_MONOTONIC, &t1);

	_caps.ts_res = time_us(&t1);
	_caps.ts_acc = 20; /* ppm, estimated */

	/* Do clock read a number of times and measure latency */
	avg = 0;
	for (i = 0; i < 20; ++i) {
		clock_gettime(CLOCK_MONOTONIC, &t1);
		read_btclock(mcl, &btclock, &btaccuracy);
		clock_gettime(CLOCK_MONOTONIC, &t2);

		latency = time_us(&t2) - time_us(&t1);
		latencies[i] = latency;
		avg += latency;
	}
	avg /= 20;

	/* Calculate deviation */
	dev = 0;
	for (i = 0; i < 20; ++i)
		dev += abs(latencies[i] - avg);
	dev /= 20;

	/* Calculate corrected average, without 'freak' latencies */
	latency = 0;
	for (i = 0; i < 20; ++i)
		if (latencies[i] > (avg + dev * 6))
			latency += avg;
		else
			latency += latencies[i];
	latency /= 20;

	_caps.latency = latency;
	_caps.preempt_thresh = latency * 4;

	csp_caps_initialized = TRUE;
}

static struct csp_caps *caps(struct mcap_mcl *mcl)
{
	if (!csp_caps_initialized)
		initialize_caps(mcl);

	return &_caps;
}

static int send_sync_cap_rsp(struct mcap_mcl *mcl, uint8_t rspcode,
			uint8_t btclockres, uint16_t synclead,
			uint16_t tmstampres, uint16_t tmstampacc)
{
	mcap_md_sync_cap_rsp *rsp;
	int sent;
	int sock;

	rsp = g_new0(mcap_md_sync_cap_rsp, 1);

	rsp->op = MCAP_MD_SYNC_CAP_RSP;
	rsp->rc = rspcode;
	rsp->btclock = btclockres;
	rsp->sltime = htons(synclead);
	rsp->timestnr = htons(tmstampres);
	rsp->timestna = htons(tmstampacc);

	sock = g_io_channel_unix_get_fd(mcl->cc);
	sent = mcap_send_data(sock, rsp, sizeof(*rsp));
	g_free(rsp);

	return sent;
}

static void proc_sync_cap_req(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	mcap_md_sync_cap_req *req;
	uint16_t required_accuracy;
	uint16_t our_accuracy;
	uint32_t btclock;
	uint16_t btres;

	if (len != sizeof(mcap_md_sync_cap_req)) {
		send_sync_cap_rsp(mcl, MCAP_INVALID_PARAM_VALUE,
					0, 0, 0, 0);
		return;
	}

	req = (mcap_md_sync_cap_req*) cmd;
	required_accuracy = ntohs(req->timest);
	our_accuracy = caps(mcl)->ts_acc;

	if (required_accuracy < our_accuracy) {
		send_sync_cap_rsp(mcl, MCAP_RESOURCE_UNAVAILABLE,
					0, 0, 0, 0);
		return;
	}

	if (read_btclock(mcl, &btclock, &btres)) {
		send_sync_cap_rsp(mcl, MCAP_RESOURCE_UNAVAILABLE,
					0, 0, 0, 0);
		return;
	}

	send_sync_cap_rsp(mcl, MCAP_SUCCESS, btres, caps(mcl)->latency / 1000,
				caps(mcl)->ts_res, our_accuracy);
}
