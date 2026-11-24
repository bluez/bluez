/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright © 2025 Collabora Ltd.
 *
 *
 */

struct hfp_device;

typedef void (*hfp_hf_sco_closed_cb) (struct hfp_device *dev, void *user_data);

bool hfp_hf_sco_listen(struct btd_adapter *adapter, void *endpoint);
void hfp_hf_sco_remove(struct btd_adapter *adapter, void *endpoint);
unsigned int hfp_hf_sco_start(struct hfp_device *dev, void *cb,
							void *user_data);
unsigned int hfp_hf_sco_stop(struct hfp_device *dev);
void hfp_hf_set_sco_closed_cb(struct hfp_device *dev,
				hfp_hf_sco_closed_cb cb, void *user_data);

struct btd_device *hfp_hf_get_device(struct hfp_device *dev);
int hfp_hf_device_get_fd(struct hfp_device *dev);
uint16_t hfp_hf_device_get_imtu(struct hfp_device *dev);
uint16_t hfp_hf_device_get_omtu(struct hfp_device *dev);
