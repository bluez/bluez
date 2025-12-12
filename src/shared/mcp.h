/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 */

#include <stdbool.h>
#include <inttypes.h>

struct bt_mcp;
struct bt_mcs;

/*
 * Media Control Client
 */

struct bt_mcp_callback {
	/* New player seen */
	void (*ccid)(void *data, uint8_t ccid, bool gmcs);

	/* Client command complete */
	void (*complete)(void *data, unsigned int id, uint8_t status);

	/* Attach complete */
	void (*ready)(void *data);

	/* Debug message */
	void (*debug)(void *data, const char *str);

	/* mcp destroyed (no further callbacks) */
	void (*destroy)(void *data);
};

struct bt_mcp_listener_callback {
	/* Value notification */
	void (*media_player_name)(void *data, const uint8_t *value,
							uint16_t length);
	void (*track_changed)(void *data);
	void (*track_title)(void *data, const uint8_t *value, uint16_t length);
	void (*track_duration)(void *data, int32_t duration_centisecond);
	void (*track_position)(void *data, int32_t position_centisecond);
	void (*playback_speed)(void *data, int8_t log2_speed);
	void (*seeking_speed)(void *data, int8_t log2_speed);
	void (*playing_order)(void *data, uint8_t order);
	void (*media_state)(void *data, uint8_t state);

	/* TODO: OTS */

	/* Listener destroyed (no further callbacks) */
	void (*destroy)(void *data);
};

unsigned int bt_mcp_play(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_pause(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_fast_rewind(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_fast_forward(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_stop(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_move_relative(struct bt_mcp *mcp, uint8_t ccid,
								int32_t offset);

unsigned int bt_mcp_previous_segment(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_next_segment(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_first_segment(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_last_segment(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_goto_segment(struct bt_mcp *mcp, uint8_t ccid, int32_t n);

unsigned int bt_mcp_previous_track(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_next_track(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_first_track(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_last_track(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_goto_track(struct bt_mcp *mcp, uint8_t ccid, int32_t n);

unsigned int bt_mcp_previous_group(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_next_group(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_first_group(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_last_group(struct bt_mcp *mcp, uint8_t ccid);
unsigned int bt_mcp_goto_group(struct bt_mcp *mcp, uint8_t ccid, int32_t n);

unsigned int bt_mcp_set_track_position(struct bt_mcp *mcp, uint8_t ccid,
							int32_t position);
unsigned int bt_mcp_set_playback_speed(struct bt_mcp *mcp, uint8_t ccid,
							int8_t speed);
unsigned int bt_mcp_set_playing_order(struct bt_mcp *mcp, uint8_t ccid,
							uint8_t order);

uint16_t bt_mcp_get_supported_playing_order(struct bt_mcp *mcp, uint8_t ccid);
uint32_t bt_mcp_get_supported_commands(struct bt_mcp *mcp, uint8_t ccid);

bool bt_mcp_add_listener(struct bt_mcp *mcp, uint8_t ccid,
				const struct bt_mcp_listener_callback *cb,
				void *user_data);

struct bt_mcp *bt_mcp_attach(struct bt_gatt_client *client, bool gmcs,
				const struct bt_mcp_callback *cb,
				void *user_data);
void bt_mcp_detach(struct bt_mcp *mcp);

/*
 * Media Control Server
 */

struct bt_mcs_callback {
	/* Value requests */
	void (*media_player_name)(void *data, struct iovec *buf, size_t size);
	void (*track_title)(void *data, struct iovec *buf, size_t size);
	int32_t (*track_duration)(void *data);
	int32_t (*track_position)(void *data);
	int8_t (*playback_speed)(void *data);
	int8_t (*seeking_speed)(void *data);
	uint8_t (*playing_order)(void *data);
	uint16_t (*playing_order_supported)(void *data);
	uint32_t (*media_cp_op_supported)(void *data);

	/* TODO: OTS */

	/* Set value notification */
	bool (*set_track_position)(void *data, int32_t value);
	bool (*set_playback_speed)(void *data, int8_t value);
	bool (*set_playing_order)(void *data, uint8_t value);

	/* Command notification */
	bool (*play)(void *data);
	bool (*pause)(void *data);
	bool (*fast_rewind)(void *data);
	bool (*fast_forward)(void *data);
	bool (*stop)(void *data);
	bool (*move_relative)(void *data, int32_t offset);

	bool (*previous_segment)(void *data);
	bool (*next_segment)(void *data);
	bool (*first_segment)(void *data);
	bool (*last_segment)(void *data);
	bool (*goto_segment)(void *data, int32_t n);

	bool (*previous_track)(void *data);
	bool (*next_track)(void *data);
	bool (*first_track)(void *data);
	bool (*last_track)(void *data);
	bool (*goto_track)(void *data, int32_t n);

	bool (*previous_group)(void *data);
	bool (*next_group)(void *data);
	bool (*first_group)(void *data);
	bool (*last_group)(void *data);
	bool (*goto_group)(void *data, int32_t n);

	/* Debug message */
	void (*debug)(void *data, const char *str);

	/* Player destroyed (no further callbacks) */
	void (*destroy)(void *data);
};

void bt_mcs_set_media_state(struct bt_mcs *mcs, uint8_t state);
uint8_t bt_mcs_get_media_state(struct bt_mcs *mcs);

void bt_mcs_changed(struct bt_mcs *mcs, uint16_t chrc_uuid);
uint8_t bt_mcs_get_ccid(struct bt_mcs *mcs);

struct bt_mcs *bt_mcs_register(struct gatt_db *db, bool is_gmcs,
			const struct bt_mcs_callback *cb, void *user_data);
void bt_mcs_unregister(struct bt_mcs *mcs);
void bt_mcs_unregister_all(struct gatt_db *db);

/* For tests: */
void bt_mcs_test_util_reset_ccid(void);
