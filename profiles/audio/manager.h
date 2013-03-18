/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
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

struct enabled_interfaces {
	gboolean sink;
	gboolean source;
	gboolean control;
	gboolean media_player;
};

void audio_sink_connected(struct btd_device *dev, int err);
void audio_sink_disconnected(struct btd_device *dev, int err);
void audio_source_connected(struct btd_device *dev, int err);
void audio_source_disconnected(struct btd_device *dev, int err);
void audio_target_connected(struct btd_device *dev, int err);
void audio_target_disconnected(struct btd_device *dev, int err);
void audio_controller_connected(struct btd_device *dev, int err);
void audio_controller_disconnected(struct btd_device *dev, int err);

int audio_manager_init(GKeyFile *config);
void audio_manager_exit(void);

struct audio_device *manager_get_audio_device(struct btd_device *device,
							gboolean create);

/* TRUE to enable fast connectable and FALSE to disable fast connectable for all
 * audio adapters. */
void manager_set_fast_connectable(gboolean enable);
