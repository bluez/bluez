/*
 *
 *  OBEX
 *
 *  Copyright (C) 2013  BMW Car IT GmbH. All rights reserved.
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

enum map_event_type {
	MAP_ET_NEW_MESSAGE,
	MAP_ET_DELIVERY_SUCCESS,
	MAP_ET_SENDING_SUCCESS,
	MAP_ET_DELIVERY_FAILURE,
	MAP_ET_SENDING_FAILURE,
	MAP_ET_MEMORY_FULL,
	MAP_ET_MEMORY_AVAILABLE,
	MAP_ET_MESSAGE_DELETED,
	MAP_ET_MESSAGE_SHIFT
};

struct map_event {
	enum map_event_type type;
	char *handle;
	char *folder;
	char *old_folder;
	char *msg_type;
};
