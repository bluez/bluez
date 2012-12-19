/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2012-2012  Intel Corporation
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

struct media_player;

struct media_player_callback {
	bool (*set_setting) (struct media_player *mp, const char *key,
				const char *value, void *user_data);
};

struct media_player *media_player_controller_create(const char *path);
void media_player_destroy(struct media_player *mp);
void media_player_set_position(struct media_player *mp, uint32_t position);
void media_player_set_setting(struct media_player *mp, const char *key,
							const char *value);
const char *media_player_get_status(struct media_player *mp);
void media_player_set_status(struct media_player *mp, const char *status);
void media_player_set_metadata(struct media_player *mp, const char *key,
						void *data, size_t len);

void media_player_set_callbacks(struct media_player *mp,
				const struct media_player_callback *cbs,
				void *user_data);
