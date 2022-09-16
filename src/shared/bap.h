/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 */

#include <stdbool.h>
#include <inttypes.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define BT_BAP_SINK			0x01
#define	BT_BAP_SOURCE			0x02

#define BT_BAP_STREAM_STATE_IDLE	0x00
#define BT_BAP_STREAM_STATE_CONFIG	0x01
#define BT_BAP_STREAM_STATE_QOS		0x02
#define BT_BAP_STREAM_STATE_ENABLING	0x03
#define BT_BAP_STREAM_STATE_STREAMING	0x04
#define BT_BAP_STREAM_STATE_DISABLING	0x05
#define BT_BAP_STREAM_STATE_RELEASING	0x06

#define BT_BAP_CONFIG_LATENCY_LOW	0x01
#define BT_BAP_CONFIG_LATENCY_BALACED	0x02
#define BT_BAP_CONFIG_LATENCY_HIGH	0x03

#define BT_BAP_CONFIG_PHY_1M		0x01
#define BT_BAP_CONFIG_PHY_2M		0x02
#define BT_BAP_CONFIG_PHY_CODEC		0x03

struct bt_bap;
struct bt_bap_pac;
struct bt_bap_stream;

struct bt_bap_codec {
	uint8_t  id;
	uint16_t vid;
	uint16_t cid;
} __packed;

struct bt_ltv {
	uint8_t  len;
	uint8_t  type;
	uint8_t  value[0];
} __packed;

struct bt_bap_qos {
	uint8_t  cig_id;
	uint8_t  cis_id;
	uint32_t interval;		/* Frame interval */
	uint8_t  framing;		/* Frame framing */
	uint8_t  phy;			/* PHY */
	uint16_t sdu;			/* Maximum SDU Size */
	uint8_t  rtn;			/* Retransmission Effort */
	uint16_t latency;		/* Transport Latency */
	uint32_t delay;			/* Presentation Delay */
	uint8_t  target_latency;	/* Target Latency */
};

typedef void (*bt_bap_ready_func_t)(struct bt_bap *bap, void *user_data);
typedef void (*bt_bap_destroy_func_t)(void *user_data);
typedef void (*bt_bap_debug_func_t)(const char *str, void *user_data);
typedef void (*bt_bap_pac_func_t)(struct bt_bap_pac *pac, void *user_data);
typedef bool (*bt_bap_pac_foreach_t)(struct bt_bap_pac *lpac,
					struct bt_bap_pac *rpac,
					void *user_data);
typedef void (*bt_bap_pac_select_t)(struct bt_bap_pac *pac, int err,
					struct iovec *caps,
					struct iovec *metadata,
					struct bt_bap_qos *qos,
					void *user_data);
typedef void (*bt_bap_pac_config_t)(struct bt_bap_stream *stream, int err);
typedef void (*bt_bap_state_func_t)(struct bt_bap_stream *stream,
					uint8_t old_state, uint8_t new_state,
					void *user_data);
typedef void (*bt_bap_connecting_func_t)(struct bt_bap_stream *stream,
					bool state, int fd,
					void *user_data);
typedef void (*bt_bap_stream_func_t)(struct bt_bap_stream *stream,
					uint8_t code, uint8_t reason,
					void *user_data);
typedef void (*bt_bap_func_t)(struct bt_bap *bap, void *user_data);

/* Local PAC related functions */

unsigned int bt_bap_pac_register(bt_bap_pac_func_t added,
				bt_bap_pac_func_t removed, void *user_data,
				bt_bap_destroy_func_t destroy);
bool bt_bap_pac_unregister(unsigned int id);

struct bt_bap_pac_qos {
	uint8_t  framing;
	uint8_t  phy;
	uint8_t  rtn;
	uint16_t latency;
	uint32_t pd_min;
	uint32_t pd_max;
	uint32_t ppd_min;
	uint32_t ppd_max;
};

struct bt_bap_pac *bt_bap_add_vendor_pac(struct gatt_db *db,
					const char *name, uint8_t type,
					uint8_t id, uint16_t cid, uint16_t vid,
					struct bt_bap_pac_qos *qos,
					struct iovec *data,
					struct iovec *metadata);

struct bt_bap_pac *bt_bap_add_pac(struct gatt_db *db, const char *name,
					uint8_t type, uint8_t id,
					struct bt_bap_pac_qos *qos,
					struct iovec *data,
					struct iovec *metadata);

struct bt_bap_pac_ops {
	int (*select)(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
			struct bt_bap_pac_qos *qos,
			bt_bap_pac_select_t cb, void *cb_data, void *user_data);
	int (*config)(struct bt_bap_stream *stream, struct iovec *cfg,
			struct bt_bap_qos *qos, bt_bap_pac_config_t cb,
			void *user_data);
	void (*clear)(struct bt_bap_stream *stream, void *user_data);
};

bool bt_bap_pac_set_ops(struct bt_bap_pac *pac, struct bt_bap_pac_ops *ops,
					void *user_data);

bool bt_bap_remove_pac(struct bt_bap_pac *pac);

uint8_t bt_bap_pac_get_type(struct bt_bap_pac *pac);

struct bt_bap_stream *bt_bap_pac_get_stream(struct bt_bap_pac *pac);

/* Session related function */
unsigned int bt_bap_register(bt_bap_func_t added, bt_bap_func_t removed,
							void *user_data);
bool bt_bap_unregister(unsigned int id);

struct bt_bap *bt_bap_new(struct gatt_db *ldb, struct gatt_db *rdb);

bool bt_bap_set_user_data(struct bt_bap *bap, void *user_data);

void *bt_bap_get_user_data(struct bt_bap *bap);

struct bt_att *bt_bap_get_att(struct bt_bap *bap);

struct bt_bap *bt_bap_ref(struct bt_bap *bap);
void bt_bap_unref(struct bt_bap *bap);

bool bt_bap_attach(struct bt_bap *bap, struct bt_gatt_client *client);
void bt_bap_detach(struct bt_bap *bap);

bool bt_bap_set_debug(struct bt_bap *bap, bt_bap_debug_func_t cb,
			void *user_data, bt_bap_destroy_func_t destroy);

bool bap_print_cc(void *data, size_t len, util_debug_func_t func,
						void *user_data);

unsigned int bt_bap_ready_register(struct bt_bap *bap,
				bt_bap_ready_func_t func, void *user_data,
				bt_bap_destroy_func_t destroy);
bool bt_bap_ready_unregister(struct bt_bap *bap, unsigned int id);

unsigned int bt_bap_state_register(struct bt_bap *bap,
				bt_bap_state_func_t func,
				bt_bap_connecting_func_t connecting,
				void *user_data, bt_bap_destroy_func_t destroy);
bool bt_bap_state_unregister(struct bt_bap *bap, unsigned int id);

const char *bt_bap_stream_statestr(uint8_t state);

void bt_bap_foreach_pac(struct bt_bap *bap, uint8_t type,
			bt_bap_pac_foreach_t func, void *user_data);

int bt_bap_pac_get_vendor_codec(struct bt_bap_pac *pac, uint8_t *id,
				uint16_t *cid, uint16_t *vid,
				struct iovec **data, struct iovec **metadata);

int bt_bap_pac_get_codec(struct bt_bap_pac *pac, uint8_t *id,
				struct iovec **data, struct iovec **metadata);

void bt_bap_pac_set_user_data(struct bt_bap_pac *pac, void *user_data);
void *bt_bap_pac_get_user_data(struct bt_bap_pac *pac);

/* Stream related functions */
int bt_bap_select(struct bt_bap_pac *lpac, struct bt_bap_pac *rpac,
			bt_bap_pac_select_t func, void *user_data);

struct bt_bap_stream *bt_bap_config(struct bt_bap *bap,
					struct bt_bap_pac *lpac,
					struct bt_bap_pac *rpac,
					struct bt_bap_qos *pqos,
					struct iovec *data,
					bt_bap_stream_func_t func,
					void *user_data);

struct bt_bap *bt_bap_stream_get_session(struct bt_bap_stream *stream);
uint8_t bt_bap_stream_get_state(struct bt_bap_stream *stream);

bool bt_bap_stream_set_user_data(struct bt_bap_stream *stream, void *user_data);

void *bt_bap_stream_get_user_data(struct bt_bap_stream *stream);

unsigned int bt_bap_stream_config(struct bt_bap_stream *stream,
					struct bt_bap_qos *pqos,
					struct iovec *data,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_qos(struct bt_bap_stream *stream,
					struct bt_bap_qos *qos,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_enable(struct bt_bap_stream *stream,
					bool enable_links,
					struct iovec *metadata,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_start(struct bt_bap_stream *stream,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_disable(struct bt_bap_stream *stream,
					bool disable_links,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_stop(struct bt_bap_stream *stream,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_metadata(struct bt_bap_stream *stream,
					struct iovec *metadata,
					bt_bap_stream_func_t func,
					void *user_data);

unsigned int bt_bap_stream_release(struct bt_bap_stream *stream,
					bt_bap_stream_func_t func,
					void *user_data);

uint8_t bt_bap_stream_get_dir(struct bt_bap_stream *stream);
uint32_t bt_bap_stream_get_location(struct bt_bap_stream *stream);
struct iovec *bt_bap_stream_get_config(struct bt_bap_stream *stream);
struct bt_bap_qos *bt_bap_stream_get_qos(struct bt_bap_stream *stream);
struct iovec *bt_bap_stream_get_metadata(struct bt_bap_stream *stream);

struct io *bt_bap_stream_get_io(struct bt_bap_stream *stream);

bool bt_bap_stream_set_io(struct bt_bap_stream *stream, int fd);

int bt_bap_stream_cancel(struct bt_bap_stream *stream, unsigned int id);

int bt_bap_stream_io_link(struct bt_bap_stream *stream,
					struct bt_bap_stream *link);
struct queue *bt_bap_stream_io_get_links(struct bt_bap_stream *stream);
bool bt_bap_stream_io_get_qos(struct bt_bap_stream *stream,
					struct bt_bap_qos **in,
					struct bt_bap_qos **out);

uint8_t bt_bap_stream_io_dir(struct bt_bap_stream *stream);

int bt_bap_stream_io_connecting(struct bt_bap_stream *stream, int fd);
bool bt_bap_stream_io_is_connecting(struct bt_bap_stream *stream, int *fd);
