/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2006  Marcel Holtmann <marcel@holtmann.org>
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

extern int lineno;

struct keyword_t {
	char *string;
	int type;
};

extern struct keyword_t rfcomm_keyword[]; 

int rfcomm_find_keyword(struct keyword_t *keyword, char *string);

#define MAXCOMMENTLEN  100

struct rfcomm_opts {
	int bind;
	bdaddr_t bdaddr;
	int channel;
	char comment[MAXCOMMENTLEN + 1];
};

extern struct rfcomm_opts rfcomm_opts[RFCOMM_MAX_DEV];

int rfcomm_read_config(char *filename);
