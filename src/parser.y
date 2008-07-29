%{
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdarg.h>

#include <sys/socket.h>
#include <asm/types.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "hcid.h"
#include "kword.h"

int cfg_error(const char *fmt, ...);

int yyparse(void);
int yylex(void);
int yyerror(char *s); 

void yylex_destroy(void);

%}

%union {
	char *str;
	long  num;
}

%token K_OPTIONS K_DEVICE
%token K_AUTOINIT K_SECURITY K_PAIRING K_OFFMODE K_DEVICEID
%token K_PTYPE K_NAME K_CLASS K_VOICE K_PAGETO K_LM K_LP K_ISCAN K_PSCAN K_DISCOVTO
%token K_PASSKEY
%token K_YES K_NO

%token <str> WORD PATH STRING LIST HCI BDADDR ID
%token <num> NUM

%type  <num> bool pkt_type link_mode link_policy sec_mode pair_mode off_mode
%type  <str> dev_name dev_id hci bdaddr

%%
config: statement | config statement;
statement: 
  K_OPTIONS hcid_options

  | device device_options

  | WORD	{
			cfg_error("Invalid statement '%s'", $1);
		}

  | error	{
			yyclearin; yyerrok;
		}
  ;

device:
  K_DEVICE		{
				parser_device = &default_device;
			}

  | K_DEVICE hci	{
				parser_device = alloc_device_opts($2);
			}

  | K_DEVICE bdaddr	{
				parser_device = alloc_device_opts($2);
			}
  ;

hcid_options: '{' hcid_opts '}';
hcid_opts: | hcid_opt ';' | error ';' | hcid_opts hcid_opt ';';
hcid_opt: 
  K_AUTOINIT bool	{
				hcid.auto_init = $2;
			}

  | K_SECURITY sec_mode	{
				hcid.security = $2;
			}

  | K_PAIRING pair_mode	{
				hcid.pairing = $2;
			}

  | K_OFFMODE off_mode	{
				hcid.offmode = $2;
			}

  | K_DEVICEID dev_id	{
				strncpy((char *) hcid.deviceid, $2, 15);
			}

  | K_PASSKEY STRING	{
  				strncpy((char *) hcid.pin_code, $2, 16);
				hcid.pin_len = strlen($2);
				if (hcid.pin_len > 16)
					hcid.pin_len = 16;
			}


  | WORD		{
				cfg_error("Unknown option '%s'", $1);
			}
  ;

sec_mode:
  WORD		{
			int opt = find_keyword(sec_param, $1);
			if (opt < 0) {
				cfg_error("Unknown security mode '%s'", $1);
				$$ = 0;
			} else
				$$ = opt;
		}

  | K_NO	{
			$$ = HCID_SEC_NONE;
		}
  ;

pair_mode:
  WORD		{
			int opt = find_keyword(pair_param, $1);
			if (opt < 0) {
				cfg_error("Unknown pairing mode '%s'", $1);
				$$ = 0;
			} else
				$$ = opt;
		}
  ;

off_mode:
  WORD		{
			int opt = find_keyword(off_param, $1);
			if (opt < 0) {
				cfg_error("Unknown off mode '%s'", $1);
				$$ = 0;
			} else
				$$ = opt;
		}
  ;

dev_id:
  ID		{
		}
  ;

device_options: '{' device_opts '}';
device_opts: | device_opt ';' | error ';' | device_opts device_opt ';';
device_opt:
  K_PTYPE pkt_type	{
				parser_device->flags |= (1 << HCID_SET_PTYPE);
				parser_device->pkt_type = $2;
			}

  | K_LM link_mode	{
				parser_device->flags |= (1 << HCID_SET_LM);
				parser_device->link_mode = $2;
			}

  | K_LP link_policy	{
				parser_device->flags |= (1 << HCID_SET_LP);
				parser_device->link_policy = $2;
			}

  | K_NAME dev_name	{
				if (parser_device->name)
					g_free(parser_device->name);
				parser_device->flags |= (1 << HCID_SET_NAME);
				parser_device->name = g_strdup($2);
			}

  | K_CLASS NUM		{
				parser_device->flags |= (1 << HCID_SET_CLASS);
				parser_device->class = $2;
			}

  | K_VOICE NUM		{
				parser_device->flags |= (1 << HCID_SET_VOICE);
				parser_device->voice = $2;
			}

  | K_PAGETO NUM	{
				parser_device->flags |= (1 << HCID_SET_PAGETO);
				parser_device->pageto = $2;
			}

  | K_DISCOVTO NUM	{
				parser_device->flags |= (1 << HCID_SET_DISCOVTO);
				parser_device->discovto = $2;
			}

  | K_ISCAN bool	{
				if ($2)
					parser_device->scan |=  SCAN_INQUIRY;
				else
					parser_device->scan &= ~SCAN_INQUIRY;
			}

  | K_PSCAN bool	{
				if ($2)
					parser_device->scan |=  SCAN_PAGE;
				else
					parser_device->scan &= ~SCAN_PAGE;
			}

  | WORD		{
				cfg_error("Unknown option '%s'",$1);
				YYABORT;
			}
  ;

dev_name:
  WORD		{
			$$ = $1;
		}

  |  STRING	{
			$$ = $1;
		}
  ;

hci:
  HCI		{
			$$ = $1;
		}
  ;

bdaddr:
  BDADDR	{
			$$ = $1;
		}
  ;

pkt_type:
  WORD		{
			unsigned int opt;
			if (!hci_strtoptype($1, &opt))
				cfg_error("Unknown packet type '%s'", $1);
			$$ = opt;
		}

  | LIST	{
			unsigned int opt;
			if (!hci_strtoptype($1, &opt))
				cfg_error("Unknown packet type '%s'", $1);
			$$ = opt;
		}
  ;

link_mode:
  WORD		{
			unsigned int opt;
			if (!hci_strtolm($1, &opt))
				cfg_error("Unknown link mode '%s'", $1);
			$$ = opt;
		}

  | LIST	{
			unsigned int opt;
			if (!hci_strtolm($1, &opt))
				cfg_error("Unknown link mode '%s'", $1);
			$$ = opt;
		}
  ;

link_policy:
  WORD		{
			unsigned int opt;
			if (!hci_strtolp($1, &opt))
				cfg_error("Unknown link policy '%s'", $1);
			$$ = opt;
		}

  | LIST	{
			unsigned int opt;
			if (!hci_strtolp($1, &opt))
				cfg_error("Unknown link policy '%s'", $1);
			$$ = opt;
		}
  ;

bool: K_YES { $$ = 1; } | K_NO  { $$ = 0; };

%%

int yyerror(char *s) 
{
	error("%s line %d", s, lineno);
	return 0;
}

int cfg_error(const char *fmt, ...)
{
	char buf[255];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf,sizeof(buf),fmt,ap);
	va_end(ap);

	yyerror(buf);
	return 0;
}

/* 
 * Read config file. 
 */ 
int read_config(char *file) 
{
	extern FILE *yyin;

	if (!(yyin = fopen(file, "r"))) {
		error("Can't open config file %s", file);
		return -1;
	}

	lineno = 1;
	yyparse();

	fclose(yyin);

	return 0;
}
