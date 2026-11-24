/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024 StreamUnlimited Engineering GmbH
 *
 *
 */

#ifdef HAVE_VCP

int bt_audio_vcp_get_volume(struct btd_device *device);
int bt_audio_vcp_set_volume(struct btd_device *device, uint8_t volume);

#else

static inline int bt_audio_vcp_get_volume(struct btd_device *device)
{
	return -ENODEV;
}

static inline int bt_audio_vcp_set_volume(struct btd_device *device,
								uint8_t volume)
{
	return -ENODEV;
}

#endif
