/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

/*
 * Important: Changes in this table must be reflected in the
 * the entries of error_table[] in dbus.c
 */
enum mesh_error {
	MESH_ERROR_NONE,
	MESH_ERROR_FAILED,
	MESH_ERROR_NOT_AUTHORIZED,
	MESH_ERROR_NOT_FOUND,
	MESH_ERROR_INVALID_ARGS,
	MESH_ERROR_BUSY,
	MESH_ERROR_ALREADY_EXISTS,
	MESH_ERROR_DOES_NOT_EXIST,
	MESH_ERROR_CANCELED,
	MESH_ERROR_NOT_IMPLEMENTED,
};
