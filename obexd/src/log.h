/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

void info(const char *format, ...) __attribute__((format(printf, 1, 2)));
void error(const char *format, ...) __attribute__((format(printf, 1, 2)));
void log_debug(const char *format, ...) __attribute__((format(printf, 1, 2)));
void obex_debug(int evt, int cmd, int rsp);

void log_init(const char *ident, const char *debug, int log_option);
void log_cleanup(void);
void log_enable_debug(void);

struct log_debug_desc {
	const char *name;
	const char *file;
#define LOG_DEBUG_FLAG_DEFAULT (0)
#define LOG_DEBUG_FLAG_PRINT   (1 << 0)
	unsigned int flags;
} __attribute__((aligned(8)));

/**
 * DBG:
 * @fmt: format string
 * @arg...: list of arguments
 *
 * Simple macro around debug() which also include the function
 * name it is called in.
 */
#define DBG(fmt, arg...) do { \
	static struct log_debug_desc __log_debug_desc \
	__attribute__((used, section("__debug"), aligned(8))) = { \
		.file = __FILE__, .flags = LOG_DEBUG_FLAG_DEFAULT, \
	}; \
	if (__log_debug_desc.flags & LOG_DEBUG_FLAG_PRINT) \
		log_debug("%s:%s() " fmt,  __FILE__, __FUNCTION__ , ## arg); \
} while (0)
