/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "hcid.h"
#include "kword.h"
#include "parser.h"

struct kword cfg_keyword[] = {
	{ "options",		K_OPTIONS	},
	{ "default",		K_DEVICE	},
	{ "device",		K_DEVICE	},
	{ "autoinit",		K_AUTOINIT	},
	{ "security",		K_SECURITY	},
	{ "pairing",		K_PAIRING	},
	{ "pkt_type",		K_PTYPE		},
	{ "lm", 		K_LM		},
	{ "lp", 		K_LP		},
	{ "iscan",		K_ISCAN		},
	{ "pscan",		K_PSCAN		},
	{ "name",		K_NAME		},
	{ "class",		K_CLASS		},
	{ "voice",		K_VOICE		},
	{ "inqmode",		K_INQMODE	},
	{ "pageto",		K_PAGETO	},
	{ "auth",		K_AUTH		},
	{ "encrypt",		K_ENCRYPT	},
	{ "pin_helper",		K_PINHELP	},
	{ "dbus_pin_helper",	K_DBUSPINHELP	},

	{ "yes",		K_YES		},
	{ "no",			K_NO		},
	{ "enable",		K_YES		},
	{ "disable",		K_NO		},
	{ NULL , 0 }
};

struct kword sec_param[] = {
	{ "none",		HCID_SEC_NONE	},
	{ "auto",		HCID_SEC_AUTO	},
	{ "user",		HCID_SEC_USER	},
	{ NULL , 0 }
};

struct kword pair_param[] = {
	{ "none",	HCID_PAIRING_NONE	},
	{ "multi",	HCID_PAIRING_MULTI	},
	{ "once",	HCID_PAIRING_ONCE	},
	{ NULL , 0 }
};

int lineno;

int find_keyword(struct kword *kw, char *str)
{
	while (kw->str) {
		if (!strcmp(str,kw->str))
			return kw->type;
		kw++;
	}
	return -1;
}
