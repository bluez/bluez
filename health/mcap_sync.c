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
#include <bluetooth/l2cap.h>
#include "../src/adapter.h"
#include "../src/manager.h"
#include <sys/ioctl.h>

#include "config.h"
#include "log.h"

#include <bluetooth/bluetooth.h>
#include "mcap.h"
#include "mcap_lib.h"
#include "mcap_internal.h"

#define MCAP_BTCLOCK_HALF (MCAP_BTCLOCK_FIELD / 2)
#define CLK CLOCK_MONOTONIC

#define MCAP_CSP_ERROR g_quark_from_static_string("mcap-csp-error-quark")
#define MAX_RETRIES	10
#define SAMPLE_COUNT	20

struct mcap_csp {
	uint64_t	base_tmstamp;	/* CSP base timestamp */
	struct timespec	base_time;	/* CSP base time when timestamp set */
	guint		local_caps;	/* CSP-Master: have got remote caps */
	guint		remote_caps;	/* CSP-Slave: remote master got caps */
	guint		rem_req_acc;	/* CSP-Slave: accuracy required by master */
	guint		ind_expected;	/* CSP-Master: indication expected */
	MCAPCtrl	csp_req;	/* CSP-Master: Request control flag */
	guint		ind_timer;	/* CSP-Slave: indication timer */
	guint		set_timer;	/* CSP-Slave: delayed set timer */
	void		*set_data;	/* CSP-Slave: delayed set data */
	void		*csp_priv_data;	/* CSP-Master: In-flight request data */
};

struct mcap_sync_cap_cbdata {
	mcap_sync_cap_cb	cb;
	gpointer		user_data;
};

struct mcap_sync_set_cbdata {
	mcap_sync_set_cb	cb;
	gpointer		user_data;
};

struct csp_caps {
	int ts_acc;		/* timestamp accuracy */
	int ts_res;		/* timestamp resolution */
	int latency;		/* Read BT clock latency */
	int preempt_thresh;	/* Preemption threshold for latency */
	int syncleadtime_ms;	/* SyncLeadTime in ms */
};

struct sync_set_data {
	uint8_t update;
	uint32_t sched_btclock;
	uint64_t timestamp;
	int ind_freq;
	gboolean role;
};

#define hton64(x)     ntoh64(x)

static gboolean csp_caps_initialized = FALSE;
struct csp_caps _caps;

static int send_sync_cmd(struct mcap_mcl *mcl, const void *buf, uint32_t size)
{
	int sock;

	if (mcl->cc == NULL)
		return -1;

	sock = g_io_channel_unix_get_fd(mcl->cc);
	return mcap_send_data(sock, buf, size);
}

static int send_unsupported_cap_req(struct mcap_mcl *mcl)
{
	mcap_md_sync_cap_rsp *cmd;
	int sent;

	cmd = g_new0(mcap_md_sync_cap_rsp, 1);
	cmd->op = MCAP_MD_SYNC_CAP_RSP;
	cmd->rc = MCAP_REQUEST_NOT_SUPPORTED;

	sent = send_sync_cmd(mcl, cmd, sizeof(*cmd));
	g_free(cmd);

	return sent;
}

static int send_unsupported_set_req(struct mcap_mcl *mcl)
{
	mcap_md_sync_set_rsp *cmd;
	int sent;

	cmd = g_new0(mcap_md_sync_set_rsp, 1);
	cmd->op = MCAP_MD_SYNC_SET_RSP;
	cmd->rc = MCAP_REQUEST_NOT_SUPPORTED;

	sent = send_sync_cmd(mcl, cmd, sizeof(*cmd));
	g_free(cmd);

	return sent;
}

static void reset_tmstamp(struct mcap_csp *csp, struct timespec *base_time,
				uint64_t new_tmstamp)
{
	csp->base_tmstamp = new_tmstamp;
	if (base_time)
		csp->base_time = *base_time;
	else
		clock_gettime(CLK, &csp->base_time);
}

void mcap_sync_init(struct mcap_mcl *mcl)
{
	if (!mcl->mi->csp_enabled) {
		mcl->csp = NULL;
		return;
	}

	mcl->csp = g_new0(struct mcap_csp, 1);

	mcl->csp->rem_req_acc = 10000; /* safe divisor */
	mcl->csp->set_data = NULL;
	mcl->csp->csp_priv_data = NULL;

	reset_tmstamp(mcl->csp, NULL, 0);
}

void mcap_sync_stop(struct mcap_mcl *mcl)
{
	if (!mcl->csp)
		return;

	if (mcl->csp->ind_timer)
		g_source_remove(mcl->csp->ind_timer);

	if (mcl->csp->set_timer)
		g_source_remove(mcl->csp->set_timer);

	if (mcl->csp->set_data)
		g_free(mcl->csp->set_data);

	if (mcl->csp->csp_priv_data)
		g_free(mcl->csp->csp_priv_data);

	mcl->csp->ind_timer = 0;
	mcl->csp->set_timer = 0;
	mcl->csp->set_data = NULL;
	mcl->csp->csp_priv_data = NULL;

	g_free(mcl->csp);
	mcl->csp = NULL;
}

static uint64_t time_us(struct timespec *tv)
{
	return tv->tv_sec * 1000000 + tv->tv_nsec / 1000;
}

static int64_t bt2us(int bt)
{
	return bt * 312.5;
}

static int bt2ms(int bt)
{
	return bt * 312.5 / 1000;
}

static int btoffset(uint32_t btclk1, uint32_t btclk2)
{
	int offset = btclk2 - btclk1;

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

static gboolean valid_btclock(uint32_t btclk)
{
	return btclk <= MCAP_BTCLOCK_MAX;
}

/* This call may fail; either deal with retry or use read_btclock_retry */
static gboolean read_btclock(struct mcap_mcl *mcl, uint32_t *btclock,
							uint16_t *btaccuracy)
{
	int which = 1;
	struct btd_adapter *adapter;

	adapter = manager_find_adapter(&mcl->mi->src);

	if (!adapter)
		return FALSE;

	if (btd_adapter_read_clock(adapter, &mcl->addr, which, 1000,
						btclock, btaccuracy) < 0)
		return FALSE;

	return TRUE;
}

static gboolean read_btclock_retry(struct mcap_mcl *mcl, uint32_t *btclock,
							uint16_t *btaccuracy)
{
	int retries = 5;

	while (--retries >= 0) {
		if (read_btclock(mcl, btclock, btaccuracy))
			return TRUE;
		DBG("CSP: retrying to read bt clock...");
	}

	return FALSE;
}

static gboolean get_btrole(struct mcap_mcl *mcl)
{
	int sock, flags;
	socklen_t len;

	if (mcl->cc == NULL)
		return -1;

	sock = g_io_channel_unix_get_fd(mcl->cc);
	len = sizeof(flags);

	if (getsockopt(sock, SOL_L2CAP, L2CAP_LM, &flags, &len))
		DBG("CSP: could not read role");

	return flags & L2CAP_LM_MASTER;
}

uint64_t mcap_get_timestamp(struct mcap_mcl *mcl,
				struct timespec *given_time)
{
	struct timespec now;
	uint64_t tmstamp;

	if (!mcl->csp)
		return MCAP_TMSTAMP_DONTSET;

	if (given_time)
		now = *given_time;
	else
		clock_gettime(CLK, &now);

	tmstamp = time_us(&now) - time_us(&mcl->csp->base_time)
		+ mcl->csp->base_tmstamp;

	return tmstamp;
}

uint32_t mcap_get_btclock(struct mcap_mcl *mcl)
{
	uint32_t btclock;
	uint16_t accuracy;

	if (!mcl->csp)
		return MCAP_BTCLOCK_IMMEDIATE;

	if (!read_btclock_retry(mcl, &btclock, &accuracy))
		btclock = 0xffffffff;

	return btclock;
}

static gboolean initialize_caps(struct mcap_mcl *mcl)
{
	struct timespec t1, t2;
	int latencies[SAMPLE_COUNT];
	int latency, avg, dev;
	uint32_t btclock;
	uint16_t btaccuracy;
	int i;
	int retries;

	clock_getres(CLK, &t1);

	_caps.ts_res = time_us(&t1);
	if (_caps.ts_res < 1)
		_caps.ts_res = 1;

	_caps.ts_acc = 20; /* ppm, estimated */

	/* A little exercise before measuing latency */
	clock_gettime(CLK, &t1);
	read_btclock_retry(mcl, &btclock, &btaccuracy);

	/* Read clock a number of times and measure latency */
	avg = 0;
	i = 0;
	retries = MAX_RETRIES;
	while (i < SAMPLE_COUNT && retries > 0) {
		clock_gettime(CLK, &t1);
		if (!read_btclock(mcl, &btclock, &btaccuracy)) {
			retries--;
			continue;
		}
		clock_gettime(CLK, &t2);

		latency = time_us(&t2) - time_us(&t1);
		latencies[i] = latency;
		avg += latency;
		i++;
	}

	if (retries <= 0)
		return FALSE;

	/* Calculate average and deviation */
	avg /= SAMPLE_COUNT;
	dev = 0;
	for (i = 0; i < SAMPLE_COUNT; ++i)
		dev += abs(latencies[i] - avg);
	dev /= SAMPLE_COUNT;

	/* Calculate corrected average, without 'freak' latencies */
	latency = 0;
	for (i = 0; i < SAMPLE_COUNT; ++i) {
		if (latencies[i] > (avg + dev * 6))
			latency += avg;
		else
			latency += latencies[i];
	}
	latency /= SAMPLE_COUNT;

	_caps.latency = latency;
	_caps.preempt_thresh = latency * 4;
	_caps.syncleadtime_ms = latency * 50 / 1000;

	csp_caps_initialized = TRUE;
	return TRUE;
}

static struct csp_caps *caps(struct mcap_mcl *mcl)
{
	if (!csp_caps_initialized)
		if (!initialize_caps(mcl)) {
			/* Temporary failure in reading BT clock */
			return NULL;
		}

	return &_caps;
}

static int send_sync_cap_rsp(struct mcap_mcl *mcl, uint8_t rspcode,
			uint8_t btclockres, uint16_t synclead,
			uint16_t tmstampres, uint16_t tmstampacc)
{
	mcap_md_sync_cap_rsp *rsp;
	int sent;

	rsp = g_new0(mcap_md_sync_cap_rsp, 1);

	rsp->op = MCAP_MD_SYNC_CAP_RSP;
	rsp->rc = rspcode;

	rsp->btclock = btclockres;
	rsp->sltime = htons(synclead);
	rsp->timestnr = htons(tmstampres);
	rsp->timestna = htons(tmstampacc);

	sent = send_sync_cmd(mcl, rsp, sizeof(*rsp));
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

	if (!caps(mcl)) {
		send_sync_cap_rsp(mcl, MCAP_RESOURCE_UNAVAILABLE,
					0, 0, 0, 0);
		return;
	}

	req = (mcap_md_sync_cap_req *) cmd;
	required_accuracy = ntohs(req->timest);
	our_accuracy = caps(mcl)->ts_acc;

	if (required_accuracy < our_accuracy || required_accuracy < 1) {
		send_sync_cap_rsp(mcl, MCAP_RESOURCE_UNAVAILABLE,
					0, 0, 0, 0);
		return;
	}

	if (!read_btclock_retry(mcl, &btclock, &btres)) {
		send_sync_cap_rsp(mcl, MCAP_RESOURCE_UNAVAILABLE,
					0, 0, 0, 0);
		return;
	}

	mcl->csp->remote_caps = 1;
	mcl->csp->rem_req_acc = required_accuracy;

	send_sync_cap_rsp(mcl, MCAP_SUCCESS, btres,
				caps(mcl)->syncleadtime_ms,
				caps(mcl)->ts_res, our_accuracy);
}

static int send_sync_set_rsp(struct mcap_mcl *mcl, uint8_t rspcode,
			uint32_t btclock, uint64_t timestamp,
			uint16_t tmstampres)
{
	mcap_md_sync_set_rsp *rsp;
	int sent;

	rsp = g_new0(mcap_md_sync_set_rsp, 1);

	rsp->op = MCAP_MD_SYNC_SET_RSP;
	rsp->rc = rspcode;
	rsp->btclock = htonl(btclock);
	rsp->timestst = hton64(timestamp);
	rsp->timestsa = htons(tmstampres);

	sent = send_sync_cmd(mcl, rsp, sizeof(*rsp));
	g_free(rsp);

	return sent;
}

static gboolean get_all_clocks(struct mcap_mcl *mcl, uint32_t *btclock,
				struct timespec *base_time,
				uint64_t *timestamp)
{
	int latency;
	int retry = 5;
	uint16_t btres;
	struct timespec t0;

	if (!caps(mcl))
		return FALSE;

	latency = caps(mcl)->preempt_thresh + 1;

	while (latency > caps(mcl)->preempt_thresh && --retry >= 0) {

		clock_gettime(CLK, &t0);

		if (!read_btclock(mcl, btclock, &btres))
			continue;

		clock_gettime(CLK, base_time);

		/* Tries to detect preemption between clock_gettime
		 * and read_btclock by measuring transaction time
		 */
		latency = time_us(base_time) - time_us(&t0);
	}

	*timestamp = mcap_get_timestamp(mcl, base_time);

	return TRUE;
}

static gboolean sync_send_indication(gpointer user_data)
{
	struct mcap_mcl *mcl;
	mcap_md_sync_info_ind *cmd;
	uint32_t btclock;
	uint64_t tmstamp;
	struct timespec base_time;
	int sent;

	if (!user_data)
		return FALSE;

	mcl = user_data;

	if (!caps(mcl))
		return FALSE;

	if (!get_all_clocks(mcl, &btclock, &base_time, &tmstamp))
		return FALSE;

	cmd = g_new0(mcap_md_sync_info_ind, 1);

	cmd->op = MCAP_MD_SYNC_INFO_IND;
	cmd->btclock = htonl(btclock);
	cmd->timestst = hton64(tmstamp);
	cmd->timestsa = htons(caps(mcl)->latency);

	sent = send_sync_cmd(mcl, cmd, sizeof(*cmd));
	g_free(cmd);

	return !sent;
}

static gboolean proc_sync_set_req_phase2(gpointer user_data)
{
	struct mcap_mcl *mcl;
	struct sync_set_data *data;
	uint8_t update;
	uint32_t sched_btclock;
	uint64_t new_tmstamp;
	int ind_freq;
	int role;
	uint32_t btclock;
	uint64_t tmstamp;
	struct timespec base_time;
	uint16_t tmstampacc;
	gboolean reset;
	int delay;

	if (!user_data)
		return FALSE;

	mcl = user_data;

	if (!mcl->csp->set_data)
		return FALSE;

	data = mcl->csp->set_data;
	update = data->update;
	sched_btclock = data->sched_btclock;
	new_tmstamp = data->timestamp;
	ind_freq = data->ind_freq;
	role = data->role;

	if (!caps(mcl)) {
		send_sync_set_rsp(mcl, MCAP_UNSPECIFIED_ERROR, 0, 0, 0);
		return FALSE;
	}

	if (!get_all_clocks(mcl, &btclock, &base_time, &tmstamp)) {
		send_sync_set_rsp(mcl, MCAP_UNSPECIFIED_ERROR, 0, 0, 0);
		return FALSE;
	}

	if (get_btrole(mcl) != role) {
		send_sync_set_rsp(mcl, MCAP_INVALID_OPERATION, 0, 0, 0);
		return FALSE;
	}

	reset = (new_tmstamp != MCAP_TMSTAMP_DONTSET);

	if (reset) {
		if (sched_btclock != MCAP_BTCLOCK_IMMEDIATE) {
			delay = bt2us(btdiff(sched_btclock, btclock));
			if (delay >= 0 || ((new_tmstamp - delay) > 0)) {
				new_tmstamp += delay;
				DBG("CSP: reset w/ delay %dus, compensated",
									delay);
			} else
				DBG("CSP: reset w/ delay %dus, uncompensated",
									delay);
		}

		reset_tmstamp(mcl->csp, &base_time, new_tmstamp);
		tmstamp = new_tmstamp;
	}

	tmstampacc = caps(mcl)->latency + caps(mcl)->ts_acc;

	if (mcl->csp->ind_timer) {
		g_source_remove(mcl->csp->ind_timer);
		mcl->csp->ind_timer = 0;
	}

	if (update) {
		int when = ind_freq + caps(mcl)->syncleadtime_ms;
		mcl->csp->ind_timer = g_timeout_add(when,
						sync_send_indication,
						mcl);
	}

	send_sync_set_rsp(mcl, MCAP_SUCCESS, btclock, tmstamp, tmstampacc);

	/* First indication after set is immediate */
	if (update)
		sync_send_indication(mcl);

	return FALSE;
}

static void proc_sync_set_req(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	mcap_md_sync_set_req *req;
	uint32_t sched_btclock, cur_btclock;
	uint16_t btres;
	uint8_t update;
	uint64_t timestamp;
	struct sync_set_data *set_data;
	int phase2_delay, ind_freq, when;

	if (len != sizeof(mcap_md_sync_set_req)) {
		send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE, 0, 0, 0);
		return;
	}

	req = (mcap_md_sync_set_req *) cmd;
	sched_btclock = ntohl(req->btclock);
	update = req->timestui;
	timestamp = ntoh64(req->timestst);

	if (sched_btclock != MCAP_BTCLOCK_IMMEDIATE &&
			!valid_btclock(sched_btclock)) {
		send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE, 0, 0, 0);
		return;
	}

	if (update > 1) {
		send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE, 0, 0, 0);
		return;
	}

	if (!mcl->csp->remote_caps) {
		/* Remote side did not ask our capabilities yet */
		send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE, 0, 0, 0);
		return;
	}

	if (!caps(mcl)) {
		send_sync_set_rsp(mcl, MCAP_UNSPECIFIED_ERROR, 0, 0, 0);
		return;
	}

	if (!read_btclock_retry(mcl, &cur_btclock, &btres)) {
		send_sync_set_rsp(mcl, MCAP_UNSPECIFIED_ERROR, 0, 0, 0);
		return;
	}

	if (sched_btclock == MCAP_BTCLOCK_IMMEDIATE)
		phase2_delay = 0;
	else {
		phase2_delay = btdiff(cur_btclock, sched_btclock);

		if (phase2_delay < 0) {
			/* can not reset in the past tense */
			send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE,
						0, 0, 0);
			return;
		}

		/* Convert to miliseconds */
		phase2_delay = bt2ms(phase2_delay);

		if (phase2_delay > 61*1000) {
			/* More than 60 seconds in the future */
			send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE,
						0, 0, 0);
			return;
		} else if (phase2_delay < caps(mcl)->latency / 1000) {
			/* Too fast for us to do in time */
			send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE,
						0, 0, 0);
			return;
		}
	}

	if (update) {
		/* Indication frequency: required accuracy divided by ours */
		/* Converted to milisseconds */
		ind_freq = (1000 * mcl->csp->rem_req_acc) / caps(mcl)->ts_acc;

		if (ind_freq < MAX(caps(mcl)->latency * 2 / 1000, 100)) {
			/* Too frequent, we can't handle */
			send_sync_set_rsp(mcl, MCAP_INVALID_PARAM_VALUE,
						0, 0, 0);
			return;
		}

		DBG("CSP: indication every %dms", ind_freq);
	} else
		ind_freq = 0;

	if (mcl->csp->ind_timer) {
		/* Old indications are no longer sent */
		g_source_remove(mcl->csp->ind_timer);
		mcl->csp->ind_timer = 0;
	}

	if (!mcl->csp->set_data)
		mcl->csp->set_data = g_new0(struct sync_set_data, 1);

	set_data = (struct sync_set_data *) mcl->csp->set_data;

	set_data->update = update;
	set_data->sched_btclock = sched_btclock;
	set_data->timestamp = timestamp;
	set_data->ind_freq = ind_freq;
	set_data->role = get_btrole(mcl);

	/* TODO is there some way to schedule a call based directly on
	 * a BT clock value, instead of this estimation that uses
	 * the SO clock? */

	if (phase2_delay > 0) {
		when = phase2_delay + caps(mcl)->syncleadtime_ms;
		mcl->csp->set_timer = g_timeout_add(when,
						proc_sync_set_req_phase2,
						mcl);
	} else
		proc_sync_set_req_phase2(mcl);

	/* First indication is immediate */
	if (update)
		sync_send_indication(mcl);
}

static void proc_sync_cap_rsp(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	mcap_md_sync_cap_rsp *rsp;
	uint8_t mcap_err;
	uint8_t btclockres;
	uint16_t synclead;
	uint16_t tmstampres;
	uint16_t tmstampacc;
	struct mcap_sync_cap_cbdata *cbdata;
	mcap_sync_cap_cb cb;
	gpointer user_data;

	if (mcl->csp->csp_req != MCAP_MD_SYNC_CAP_REQ) {
		DBG("CSP: got unexpected cap respose");
		return;
	}

	if (!mcl->csp->csp_priv_data) {
		DBG("CSP: no priv data for cap respose");
		return;
	}

	cbdata = mcl->csp->csp_priv_data;
	cb = cbdata->cb;
	user_data = cbdata->user_data;
	g_free(cbdata);

	mcl->csp->csp_priv_data = NULL;
	mcl->csp->csp_req = 0;

	if (len != sizeof(mcap_md_sync_cap_rsp)) {
		DBG("CSP: got corrupted cap respose");
		return;
	}

	rsp = (mcap_md_sync_cap_rsp *) cmd;
	mcap_err = rsp->rc;
	btclockres = rsp->btclock;
	synclead = ntohs(rsp->sltime);
	tmstampres = ntohs(rsp->timestnr);
	tmstampacc = ntohs(rsp->timestna);

	if (!mcap_err)
		mcl->csp->local_caps = TRUE;

	cb(mcl, mcap_err, btclockres, synclead, tmstampres, tmstampacc, NULL,
								user_data);
}

static void proc_sync_set_rsp(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	mcap_md_sync_set_rsp *rsp;
	uint8_t mcap_err;
	uint32_t btclock;
	uint64_t timestamp;
	uint16_t accuracy;
	struct mcap_sync_set_cbdata *cbdata;
	mcap_sync_set_cb cb;
	gpointer user_data;

	if (mcl->csp->csp_req != MCAP_MD_SYNC_SET_REQ) {
		DBG("CSP: got unexpected set respose");
		return;
	}

	if (!mcl->csp->csp_priv_data) {
		DBG("CSP: no priv data for set respose");
		return;
	}

	cbdata = mcl->csp->csp_priv_data;
	cb = cbdata->cb;
	user_data = cbdata->user_data;
	g_free(cbdata);

	mcl->csp->csp_priv_data = NULL;
	mcl->csp->csp_req = 0;

	if (len != sizeof(mcap_md_sync_set_rsp)) {
		DBG("CSP: got corrupted set respose");
		return;
	}

	rsp = (mcap_md_sync_set_rsp *) cmd;
	mcap_err = rsp->rc;
	btclock = ntohl(rsp->btclock);
	timestamp = ntoh64(rsp->timestst);
	accuracy = ntohs(rsp->timestsa);

	if (!mcap_err && !valid_btclock(btclock))
		mcap_err = MCAP_ERROR_INVALID_ARGS;

	cb(mcl, mcap_err, btclock, timestamp, accuracy, NULL, user_data);
}

static void proc_sync_info_ind(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	mcap_md_sync_info_ind *req;
	struct sync_info_ind_data data;
	uint32_t btclock;

	if (!mcl->csp->ind_expected) {
		DBG("CSP: received unexpected info indication");
		return;
	}

	if (len != sizeof(mcap_md_sync_info_ind))
		return;

	req = (mcap_md_sync_info_ind *) cmd;

	btclock = ntohl(req->btclock);

	if (!valid_btclock(btclock))
		return;

	data.btclock = btclock;
	data.timestamp = ntoh64(req->timestst);
	data.accuracy = ntohs(req->timestsa);

	if (mcl->mi->mcl_sync_infoind_cb)
		mcl->mi->mcl_sync_infoind_cb(mcl, &data);
}

void proc_sync_cmd(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len)
{
	if (!mcl->mi->csp_enabled || !mcl->csp) {
		switch (cmd[0]) {
		case MCAP_MD_SYNC_CAP_REQ:
			send_unsupported_cap_req(mcl);
			break;
		case MCAP_MD_SYNC_SET_REQ:
			send_unsupported_set_req(mcl);
			break;
		}
		return;
	}

	switch (cmd[0]) {
	case MCAP_MD_SYNC_CAP_REQ:
		proc_sync_cap_req(mcl, cmd, len);
		break;
	case MCAP_MD_SYNC_CAP_RSP:
		proc_sync_cap_rsp(mcl, cmd, len);
		break;
	case MCAP_MD_SYNC_SET_REQ:
		proc_sync_set_req(mcl, cmd, len);
		break;
	case MCAP_MD_SYNC_SET_RSP:
		proc_sync_set_rsp(mcl, cmd, len);
		break;
	case MCAP_MD_SYNC_INFO_IND:
		proc_sync_info_ind(mcl, cmd, len);
		break;
	}
}

void mcap_sync_cap_req(struct mcap_mcl *mcl, uint16_t reqacc,
			mcap_sync_cap_cb cb, gpointer user_data,
			GError **err)
{
	struct mcap_sync_cap_cbdata *cbdata;
	mcap_md_sync_cap_req *cmd;

	if (!mcl->mi->csp_enabled || !mcl->csp) {
		g_set_error(err,
			MCAP_CSP_ERROR,
			MCAP_ERROR_RESOURCE_UNAVAILABLE,
			"CSP not enabled for the instance");
		return;
	}

	if (mcl->csp->csp_req) {
		g_set_error(err,
			MCAP_CSP_ERROR,
			MCAP_ERROR_RESOURCE_UNAVAILABLE,
			"Pending CSP request");
		return;
	}

	mcl->csp->csp_req = MCAP_MD_SYNC_CAP_REQ;
	cmd = g_new0(mcap_md_sync_cap_req, 1);

	cmd->op = MCAP_MD_SYNC_CAP_REQ;
	cmd->timest = htons(reqacc);

	cbdata = g_new0(struct mcap_sync_cap_cbdata, 1);
	cbdata->cb = cb;
	cbdata->user_data = user_data;
	mcl->csp->csp_priv_data = cbdata;

	send_sync_cmd(mcl, cmd, sizeof(*cmd));

	g_free(cmd);
}

void mcap_sync_set_req(struct mcap_mcl *mcl, uint8_t update, uint32_t btclock,
			uint64_t timestamp, mcap_sync_set_cb cb,
			gpointer user_data, GError **err)
{
	mcap_md_sync_set_req *cmd;
	struct mcap_sync_set_cbdata *cbdata;

	if (!mcl->mi->csp_enabled || !mcl->csp) {
		g_set_error(err,
			MCAP_CSP_ERROR,
			MCAP_ERROR_RESOURCE_UNAVAILABLE,
			"CSP not enabled for the instance");
		return;
	}

	if (!mcl->csp->local_caps) {
		g_set_error(err,
			MCAP_CSP_ERROR,
			MCAP_ERROR_RESOURCE_UNAVAILABLE,
			"Did not get CSP caps from slave yet");
		return;
	}

	if (mcl->csp->csp_req) {
		g_set_error(err,
			MCAP_CSP_ERROR,
			MCAP_ERROR_RESOURCE_UNAVAILABLE,
			"Pending CSP request");
		return;
	}

	mcl->csp->csp_req = MCAP_MD_SYNC_SET_REQ;
	cmd = g_new0(mcap_md_sync_set_req, 1);

	cmd->op = MCAP_MD_SYNC_SET_REQ;
	cmd->timestui = update;
	cmd->btclock = htonl(btclock);
	cmd->timestst = hton64(timestamp);

	mcl->csp->ind_expected = update;

	cbdata = g_new0(struct mcap_sync_set_cbdata, 1);
	cbdata->cb = cb;
	cbdata->user_data = user_data;
	mcl->csp->csp_priv_data = cbdata;

	send_sync_cmd(mcl, cmd, sizeof(*cmd));

	g_free(cmd);
}

void mcap_enable_csp(struct mcap_instance *mi)
{
	mi->csp_enabled = TRUE;
}

void mcap_disable_csp(struct mcap_instance *mi)
{
	mi->csp_enabled = FALSE;
}
