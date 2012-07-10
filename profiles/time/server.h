/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

enum {
	UPDATE_RESULT_SUCCESSFUL = 0,
	UPDATE_RESULT_CANCELED = 1,
	UPDATE_RESULT_NO_CONN = 2,
	UPDATE_RESULT_ERROR = 3,
	UPDATE_RESULT_TIMEOUT = 4,
	UPDATE_RESULT_NOT_ATTEMPTED = 5,
};

enum {
	UPDATE_STATE_IDLE = 0,
	UPDATE_STATE_PENDING = 1,
};

enum {
	GET_REFERENCE_UPDATE = 1,
	CANCEL_REFERENCE_UPDATE = 2,
};

int time_server_init(struct btd_adapter *adapter);
void time_server_exit(struct btd_adapter *adapter);
