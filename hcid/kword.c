/* 
   BlueZ - Bluetooth protocol stack for Linux
   Copyright (C) 2000-2001 Qualcomm Incorporated
   
   Written 2000,2001 by Maxim Krasnyansky <maxk@qualcomm.com>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as
   published by the Free Software Foundation;
   
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
   IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
   OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
   RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
   NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
   USE OR PERFORMANCE OF THIS SOFTWARE.
   
   ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
   TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/
/*
 * $Id$
 */ 

#include <stdlib.h>
#include <string.h>

#include "hcid.h"
#include "kword.h"
#include "parser.h"

struct kword cfg_keyword[] = {
   { "options",  K_OPTIONS	}, 
   { "default",  K_DEVICE	}, 
   { "device",   K_DEVICE	}, 
   { "autoinit", K_AUTOINIT	}, 
   { "security", K_SECURITY	}, 
   { "pkt_type", K_PTYPE	}, 
   { "lm", 	 K_LM		}, 
   { "lp", 	 K_LP		}, 
   { "iscan", 	 K_ISCAN	}, 
   { "pscan", 	 K_PSCAN	}, 
   { "name",     K_NAME		}, 
   { "class",    K_CLASS	}, 
   { "auth",	 K_AUTH		},
   { "encrypt",  K_ENCRYPT	},
   { "pin_helper",  K_PINHELP	},

   { "yes",      K_YES		},
   { "no",       K_NO		},
   { "enable",	 K_YES		},
   { "disable",	 K_NO		},
   { NULL , 0 }
};

struct kword sec_param[] = {
   { "none",	 HCID_SEC_NONE	},
   { "auto",	 HCID_SEC_AUTO	},
   { "user",	 HCID_SEC_USER	},
   { NULL , 0 }
};

int lineno;

int find_keyword(struct kword *kw, char *str)
{
    while( kw->str ){
	if( !strcmp(str,kw->str) )
	   return kw->type;
	kw++;
    }
    return -1;
}
