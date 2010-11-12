/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *
 *  Authors:
 *  Santiago Carot-Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#ifndef __MCAP_INTERNAL_H
#define __MCAP_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	MCL_CONNECTED,
	MCL_PENDING,
	MCL_ACTIVE,
	MCL_IDLE
} MCLState;

typedef enum {
	MCL_ACCEPTOR,
	MCL_INITIATOR
} MCLRole;

typedef enum {
	MCL_AVAILABLE,
	MCL_WAITING_RSP
} MCAPCtrl;

typedef enum {
	MDL_WAITING,
	MDL_CONNECTED,
	MDL_DELETING,
	MDL_CLOSED
} MDLState;

struct mcap_mdl_cb {
	mcap_mdl_event_cb		mdl_connected;	/* Remote device has created a MDL */
	mcap_mdl_event_cb		mdl_closed;	/* Remote device has closed a MDL */
	mcap_mdl_event_cb		mdl_deleted;	/* Remote device requested deleting a MDL */
	mcap_mdl_event_cb		mdl_aborted;	/* Remote device aborted the mdl creation */
	mcap_remote_mdl_conn_req_cb	mdl_conn_req;	/* Remote device requested creating a MDL */
	mcap_remote_mdl_reconn_req_cb	mdl_reconn_req;	/* Remote device requested reconnecting a MDL */
	gpointer			user_data;	/* User data */
};

struct mcap_instance {
	bdaddr_t		src;			/* Source address */
	GIOChannel		*ccio;			/* Control Channel IO */
	GIOChannel		*dcio;			/* Data Channel IO */
	GSList			*mcls;			/* MCAP instance list */
	GSList			*cached;		/* List with all cached MCLs (MAX_CACHED macro) */
	BtIOSecLevel		sec;			/* Security level */
	mcap_mcl_event_cb	mcl_connected_cb;	/* New MCL connected */
	mcap_mcl_event_cb	mcl_reconnected_cb;	/* Old MCL has been reconnected */
	mcap_mcl_event_cb	mcl_disconnected_cb;	/* MCL disconnected */
	mcap_mcl_event_cb	mcl_uncached_cb;	/* MCL has been removed from MCAP cache */
	mcap_info_ind_event_cb	mcl_sync_infoind_cb;	/* (CSP Master) Received info indication */
	gpointer		user_data;		/* Data to be provided in callbacks */
	gint			ref;			/* Reference counter */

	gboolean		csp_enabled;		/* CSP: functionality enabled */
};

struct mcap_csp;
struct mcap_mdl_op_cb;

struct mcap_mcl {
	struct mcap_instance	*mi;		/* MCAP instance where this MCL belongs */
	bdaddr_t		addr;		/* Device address */
	GIOChannel		*cc;		/* MCAP Control Channel IO */
	guint			wid;		/* MCL Watcher id */
	GSList			*mdls;		/* List of Data Channels shorted by mdlid */
	MCLState		state;		/* Current MCL State */
	MCLRole			role;		/* Initiator or acceptor of this MCL */
	MCAPCtrl		req;		/* Request control flag */
	struct mcap_mdl_op_cb	*priv_data;	/* Temporal data to manage responses */
	struct mcap_mdl_cb	*cb;		/* MDL callbacks */
	guint			tid;		/* Timer id for waiting for a response */
	uint8_t			*lcmd;		/* Last command sent */
	gint			ref;		/* References counter */
	uint8_t			ctrl;		/* MCL control flag */
	uint16_t		next_mdl;	/* id used to create next MDL */
	struct mcap_csp		*csp;		/* CSP control structure */
};

#define	MCAP_CTRL_CACHED	0x01	/* MCL is cached */
#define	MCAP_CTRL_STD_OP	0x02	/* Support for standard op codes */
#define	MCAP_CTRL_SYNC_OP	0x04	/* Support for synchronization commands */
#define	MCAP_CTRL_CONN		0x08	/* MCL is in connecting process */
#define	MCAP_CTRL_FREE		0x10	/* MCL is marked as releasable */
#define	MCAP_CTRL_NOCACHE	0x20	/* MCL is marked as not cacheable */

struct mcap_mdl {
	struct mcap_mcl		*mcl;		/* MCL where this MDL belongs */
	GIOChannel		*dc;		/* MCAP Data Channel IO */
	guint			wid;		/* MDL Watcher id */
	uint16_t		mdlid;		/* MDL id */
	uint8_t			mdep_id;	/* MCAP Data End Point */
	MDLState		state;		/* MDL state */
	gint			ref;		/* References counter */
};

struct sync_info_ind_data {
	uint32_t	btclock;
	uint64_t	timestamp;
	uint16_t	accuracy;
};

int mcap_send_data(int sock, const void *buf, uint32_t size);

void proc_sync_cmd(struct mcap_mcl *mcl, uint8_t *cmd, uint32_t len);
void mcap_sync_init(struct mcap_mcl *mcl);
void mcap_sync_stop(struct mcap_mcl *mcl);

#ifdef __cplusplus
}
#endif

#endif /* __MCAP_INTERNAL_H */
