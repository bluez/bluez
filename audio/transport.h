/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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

struct media_transport;

struct media_transport *media_transport_create(DBusConnection *conn,
						struct media_endpoint *endpoint,
						struct audio_device *device,
						uint8_t *configuration,
						size_t size);

void media_transport_destroy(struct media_transport *transport);
const char *media_transport_get_path(struct media_transport *transport);
void media_transport_update_delay(struct media_transport *transport,
							uint16_t delay);
void transport_get_properties(struct media_transport *transport,
							DBusMessageIter *iter);
