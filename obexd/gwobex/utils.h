/**
  @file utils.h

  @author Johan Hedberg <johan.hedberg@nokia.com>

  Copyright (C) 2004-2006 Nokia Corporation. All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License, version 2.1, as published by the Free Software Foundation.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.

*/
#ifndef _UTILS_H_
#define _UTILS_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

/** Create ISO8601 time format string from time_t
 * @param time Time to convert
 * @param str  Pointer where result is stored
 * @param len  Maximum amount of chars written
 * @returns length of created string.
 */
int make_iso8601(time_t time, char *str, int len);

/** Convert a time string in ISO8601 format to time_t
 * @param str Time string in ISO8601 format
 * @param len Length of string
 * @returns time as time_t format
 */
time_t parse_iso8601(const gchar *str, int len);

#ifdef DEBUG
char *bytestr(const uint8_t *uuid, int len);
#endif

/** Convert an UTF-8 string to UTF-16 (Network byte order)
 * @param uname, Place to store the new UTF-16 string
 * @param name, Original UTF-8 string
 * @returns Size in bytes allocated for the UTF-16 string (uname)
 */
glong get_uname(gunichar2 **uname, const gchar *name);

gboolean fd_raw_mode(int fd);

#endif /* _UTILS_H */
