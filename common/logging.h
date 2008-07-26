/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#ifndef __LOGGING_H
#define __LOGGING_H

void info(const char *format, ...);
void error(const char *format, ...);
void debug(const char *format, ...);
void toggle_debug(void);
void enable_debug(void);
void disable_debug(void);
void start_logging(const char *ident, const char *message, ...);
void stop_logging(void);

#define DBG(fmt, arg...)  debug("%s: " fmt "\n" , __FUNCTION__ , ## arg)

#endif /* __LOGGING_H */
