/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct bt_hog;
struct gatt_db;
struct bt_gatt_client;

/* HID Control Point values enabling the HID SCI modes */
#define BT_HOG_SCI_MODE_DEFAULT		0x02
#define BT_HOG_SCI_MODE_FAST		0x03
#define BT_HOG_SCI_MODE_LOW_POWER	0x04
#define BT_HOG_SCI_MODE_FULL_RANGE	0x05

typedef void (*bt_hog_debug_func_t)(const char *str, void *user_data);
typedef void (*bt_hog_destroy_func_t)(void *user_data);
typedef void (*bt_hog_sci_mode_func_t)(uint8_t mode, void *user_data);

struct bt_hog *bt_hog_new_default(const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type, struct gatt_db *db);

struct bt_hog *bt_hog_new(int fd, const char *name, uint16_t vendor,
					uint16_t product, uint16_t version,
					uint8_t type, struct gatt_db *db);

struct bt_hog *bt_hog_ref(struct bt_hog *hog);
void bt_hog_unref(struct bt_hog *hog);

bool bt_hog_set_debug(struct bt_hog *hog, bt_hog_debug_func_t func,
			void *user_data, bt_hog_destroy_func_t destroy);

/* Set the vendor, product and version used when creating the uHID device,
 * e.g. once known from the PnP ID of the Device Information Service.
 */
void bt_hog_set_ids(struct bt_hog *hog, uint16_t vendor, uint16_t product,
							uint16_t version);

bool bt_hog_attach(struct bt_hog *hog, struct bt_gatt_client *client);
void bt_hog_detach(struct bt_hog *hog, bool force);

int bt_hog_set_control_point(struct bt_hog *hog, bool suspend);

/* Request the HID Device to enable the given HID SCI mode, by writing it to
 * the HID Control Point. There is no response, the HID Device updates the
 * connection rate and then notifies the new mode with HID SCI Mode.
 */
int bt_hog_set_sci_mode(struct bt_hog *hog, uint8_t mode);

/* Current HID SCI mode, as read or notified with HID SCI Mode */
uint8_t bt_hog_get_sci_mode(struct bt_hog *hog);

/* Called when the HID Device notifies a new HID SCI mode */
bool bt_hog_set_sci_mode_callback(struct bt_hog *hog,
					bt_hog_sci_mode_func_t func,
					void *user_data);
int bt_hog_send_report(struct bt_hog *hog, void *data, size_t size, int type);
