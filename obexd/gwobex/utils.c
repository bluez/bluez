/**
  @file utils.c

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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <glib.h>
#include <termios.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "log.h"
#include "utils.h"

#ifdef DEBUG
char *bytestr(const uint8_t *uuid, int len) {
    int i;
    char *str = g_malloc((len << 1) + 1);

    for (i = 0; i < len; i++)
        sprintf(str + (2*i), "%02X", uuid[i]);

    return str;
}
#endif

gboolean fd_raw_mode(int fd) {
    struct termios mode;

    memset(&mode, 0, sizeof (mode));
    if (tcgetattr(fd, &mode) < 0) {
        debug("tcgetattr(%d, &mode): %s", fd, strerror(errno));
        return FALSE;
    }

    mode.c_iflag = 0;
    mode.c_oflag &= ~OPOST;
    mode.c_lflag &= ~(ISIG | ICANON | ECHO
#ifdef XCASE
            | XCASE
#endif
            );
    mode.c_cc[VMIN] = 1;
    mode.c_cc[VTIME] = 0;

    if (tcsetattr(fd, TCSADRAIN, &mode) < 0) {
        debug("tcsetattr(%d, TCSADRAIN, &mode): %s", fd, strerror(errno));
        return FALSE;
    }

    return TRUE;
}

glong get_uname(gunichar2 **uname, const gchar *name) {
    glong uname_len;

    if (*name == '\0') {
        *uname = NULL;
        return 0;
    }

    *uname = g_utf8_to_utf16(name, -1, NULL, &uname_len, NULL);

    if (*uname == NULL)
        uname_len = -1;
    else {
        int i;
        /* g_utf8_to_utf16 produces host-byteorder UTF-16,
         * but OBEX requires network byteorder (big endian) */
        for (i = 0; i < uname_len; i++)
            (*uname)[i] = g_htons((*uname)[i]);
        uname_len = (uname_len + 1) << 1;
    }

    return uname_len;
}

int make_iso8601(time_t time, char *str, int len) {
    struct tm tm;
#if defined(HAVE_TIMEZONE) && defined(USE_LOCALTIME)
    time_t tz_offset = 0;

    tz_offset = -timezone;
    if (daylight > 0)
        tz_offset += 3600;
    time += tz_offset;
#endif

    if (gmtime_r(&time, &tm) == NULL)
        return -1;

    tm.tm_year += 1900;
    tm.tm_mon++;

    return snprintf(str, len,
#ifdef USE_LOCALTIME
                    "%04u%02u%02uT%02u%02u%02u",
#else
                    "%04u%02u%02uT%02u%02u%02uZ",
#endif
                    tm.tm_year, tm.tm_mon, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* From Imendio's GnomeVFS OBEX module (om-utils.c) */
time_t parse_iso8601(const gchar *str, int len) {
    gchar    *tstr;
    struct tm tm;
    gint      nr;
    gchar     tz;
    time_t    time;
    time_t    tz_offset = 0;

    memset (&tm, 0, sizeof (struct tm));

    /* According to spec the time doesn't have to be null terminated */
    if (str[len - 1] != '\0') {
        tstr = g_malloc(len + 1);
        strncpy(tstr, str, len);
        tstr[len] = '\0';
    }
    else
        tstr = g_strdup(str);

    nr = sscanf (tstr, "%04u%02u%02uT%02u%02u%02u%c",
            &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
            &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
            &tz);

    g_free(tstr);

    /* Fixup the tm values */
    tm.tm_year -= 1900;       /* Year since 1900 */
    tm.tm_mon--;              /* Months since January, values 0-11 */
    tm.tm_isdst = -1;         /* Daylight savings information not avail */

    if (nr < 6) {
        /* Invalid time format */
        return -1;
    }

    time = mktime (&tm);

#if defined(HAVE_TM_GMTOFF)
    tz_offset = tm.tm_gmtoff;
#elif defined(HAVE_TIMEZONE)
    tz_offset = -timezone;
    if (tm.tm_isdst > 0) {
        tz_offset += 3600;
    }
#endif

    if (nr == 7) { /* Date/Time was in localtime (to remote device)
                    * already. Since we don't know anything about the
                    * timezone on that one we won't try to apply UTC offset
                    */
        time += tz_offset;
    }

    return time;
}

