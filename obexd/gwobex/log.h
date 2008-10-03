/**
  @file log.h

  @author Johan Hedberg <johan.hedberg@nokia.com>

  Copyright (C) 2004 Nokia Corporation. All rights reserved.

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
#ifndef _LOG_H_
#define _LOG_H_

#ifdef DEBUG
# ifdef DEBUG_STDOUT
#  include <glib.h>
#  define debug(...) g_print(__VA_ARGS__)
# else
#  include <syslog.h>
#  define debug(fmt, arg...) syslog(LOG_DEBUG, "gwobex: " fmt, ## arg)
# endif
#else
# define debug(...) ((void)(0))
#endif

#endif /* _LOG_H_ */
