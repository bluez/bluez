/*
 *
 *  MCAP for BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
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

#ifndef __MCAP_LIB_H
#define __MCAP_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
/* MCAP Error Response Codes */
	MCAP_ERROR_INVALID_OP_CODE = 1,
	MCAP_ERROR_INVALID_PARAM_VALUE,
	MCAP_ERROR_INVALID_MDEP,
	MCAP_ERROR_MDEP_BUSY,
	MCAP_ERROR_INVALID_MDL,
	MCAP_ERROR_MDL_BUSY,
	MCAP_ERROR_INVALID_OPERATION,
	MCAP_ERROR_RESOURCE_UNAVAILABLE,
	MCAP_ERROR_UNSPECIFIED_ERROR,
	MCAP_ERROR_REQUEST_NOT_SUPPORTED,
	MCAP_ERROR_CONFIGURATION_REJECTED,
/* MCAP Internal Errors */
	MCAP_ERROR_INVALID_ARGS,
	MCAP_ERROR_ALREADY_EXISTS,
	MCAP_ERROR_REQ_IGNORED,
	MCAP_ERROR_MCL_CLOSED,
	MCAP_ERROR_FAILED
} McapError;

typedef enum {
	MCAP_MDL_CB_INVALID,
	MCAP_MDL_CB_CONNECTED,		/* mcap_mdl_event_cb */
	MCAP_MDL_CB_CLOSED,		/* mcap_mdl_event_cb */
	MCAP_MDL_CB_DELETED,		/* mcap_mdl_event_cb */
	MCAP_MDL_CB_ABORTED,		/* mcap_mdl_event_cb */
	MCAP_MDL_CB_REMOTE_CONN_REQ,	/* mcap_remote_mdl_conn_req_cb */
	MCAP_MDL_CB_REMOTE_RECONN_REQ	/* mcap_remote_mdl_reconn_req_cb */
} McapMclCb;

struct mcap_instance;
struct mcap_mcl;
struct mcap_mdl;
struct sync_info_ind_data;

/************ Callbacks ************/

/* MDL callbacks */

typedef void (* mcap_mdl_event_cb) (struct mcap_mdl *mdl, gpointer data);
typedef void (* mcap_mdl_operation_conf_cb) (struct mcap_mdl *mdl, uint8_t conf,
						GError *err, gpointer data);
typedef void (* mcap_mdl_operation_cb) (struct mcap_mdl *mdl, GError *err,
						gpointer data);
typedef void (* mcap_mdl_notify_cb) (GError *err, gpointer data);

/* Next function should return an MCAP appropriate response code */
typedef uint8_t (* mcap_remote_mdl_conn_req_cb) (struct mcap_mcl *mcl,
						uint8_t mdepid, uint16_t mdlid,
						uint8_t *conf, gpointer data);
typedef uint8_t (* mcap_remote_mdl_reconn_req_cb) (struct mcap_mdl *mdl,
						gpointer data);

/* MCL callbacks */

typedef void (* mcap_mcl_event_cb) (struct mcap_mcl *mcl, gpointer data);
typedef void (* mcap_mcl_connect_cb) (struct mcap_mcl *mcl, GError *err,
								gpointer data);

/* CSP callbacks */

typedef void (* mcap_info_ind_event_cb) (struct mcap_mcl *mcl,
					struct sync_info_ind_data *data);

typedef void (* mcap_sync_cap_cb) (struct mcap_mcl *mcl,
					uint8_t mcap_err,
					uint8_t btclockres,
					uint16_t synclead,
					uint16_t tmstampres,
					uint16_t tmstampacc,
					GError *err,
					gpointer data);

typedef void (* mcap_sync_set_cb) (struct mcap_mcl *mcl,
					uint8_t mcap_err,
					uint32_t btclock,
					uint64_t timestamp,
					uint16_t accuracy,
					GError *err,
					gpointer data);

/************ Operations ************/

/* MDL operations */

gboolean mcap_create_mdl(struct mcap_mcl *mcl,
				uint8_t mdepid,
				uint8_t conf,
				mcap_mdl_operation_conf_cb connect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);
gboolean mcap_reconnect_mdl(struct mcap_mdl *mdl,
				mcap_mdl_operation_cb reconnect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);
gboolean mcap_delete_all_mdls(struct mcap_mcl *mcl,
				mcap_mdl_notify_cb delete_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);
gboolean mcap_delete_mdl(struct mcap_mdl *mdl,
				mcap_mdl_notify_cb delete_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);
gboolean mcap_connect_mdl(struct mcap_mdl *mdl,
				uint8_t mode,
				uint16_t dcpsm,
				mcap_mdl_operation_cb connect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);
gboolean mcap_mdl_abort(struct mcap_mdl *mdl,
				mcap_mdl_notify_cb abort_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);

int mcap_mdl_get_fd(struct mcap_mdl *mdl);
uint16_t mcap_mdl_get_mdlid(struct mcap_mdl *mdl);

struct mcap_mdl *mcap_mdl_ref(struct mcap_mdl *mdl);
void mcap_mdl_unref(struct mcap_mdl *mdl);

/* MCL operations */

gboolean mcap_create_mcl(struct mcap_instance *mi,
				const bdaddr_t *addr,
				uint16_t ccpsm,
				mcap_mcl_connect_cb connect_cb,
				gpointer user_data,
				GDestroyNotify destroy,
				GError **err);
void mcap_close_mcl(struct mcap_mcl *mcl, gboolean cache);
gboolean mcap_mcl_set_cb(struct mcap_mcl *mcl, gpointer user_data,
					GError **gerr, McapMclCb cb1, ...);
void mcap_mcl_get_addr(struct mcap_mcl *mcl, bdaddr_t *addr);

struct mcap_mcl *mcap_mcl_ref(struct mcap_mcl *mcl);
void mcap_mcl_unref(struct mcap_mcl *mcl);

/* CSP operations */

void mcap_enable_csp(struct mcap_instance *mi);
void mcap_disable_csp(struct mcap_instance *mi);

uint64_t mcap_get_timestamp(struct mcap_mcl *mcl,
				struct timespec *given_time);
uint32_t mcap_get_btclock(struct mcap_mcl *mcl);

void mcap_sync_cap_req(struct mcap_mcl *mcl,
			uint16_t reqacc,
			mcap_sync_cap_cb cb,
			gpointer user_data,
			GError **err);

void mcap_sync_set_req(struct mcap_mcl *mcl,
			uint8_t update,
			uint32_t btclock,
			uint64_t timestamp,
			mcap_sync_set_cb cb,
			gpointer user_data,
			GError **err);

/* MCAP main operations */

struct mcap_instance *mcap_create_instance(bdaddr_t *src,
					BtIOSecLevel sec, uint16_t ccpsm,
					uint16_t dcpsm,
					mcap_mcl_event_cb mcl_connected,
					mcap_mcl_event_cb mcl_reconnected,
					mcap_mcl_event_cb mcl_disconnected,
					mcap_mcl_event_cb mcl_uncached,
					mcap_info_ind_event_cb mcl_sync_info_ind,
					gpointer user_data,
					GError **gerr);
void mcap_release_instance(struct mcap_instance *mi);

struct mcap_instance *mcap_instance_ref(struct mcap_instance *mi);
void mcap_instance_unref(struct mcap_instance *mi);

uint16_t mcap_get_ctrl_psm(struct mcap_instance *mi, GError **err);
uint16_t mcap_get_data_psm(struct mcap_instance *mi, GError **err);

gboolean mcap_set_data_chan_mode(struct mcap_instance *mi, uint8_t mode,
								GError **err);

#ifdef __cplusplus
}
#endif

#endif /* __MCAP_LIB_H */
