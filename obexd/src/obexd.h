/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

#define OPENOBEX_SERVICE  "org.openobex"

#define OPENOBEX_MANAGER_PATH		"/"
#define OPENOBEX_MANAGER_INTERFACE	OPENOBEX_SERVICE ".Manager"
#define ERROR_INTERFACE			OPENOBEX_SERVICE ".Error"

void obex_connect_cb(GIOChannel *io, GError *err, gpointer user_data);

gboolean manager_init(void);
void manager_cleanup(void);

gboolean plugin_init(void);
void plugin_cleanup(void);
