%{
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2004  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation;
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY
 *  CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES 
 *  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN 
 *  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF 
 *  OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *  ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, 
 *  COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS 
 *  SOFTWARE IS DISCLAIMED.
 *
 *
 *  $Id$
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include "kword.h"

int yyparse(void);
int yylex(void);
int yyerror(char *s); 

struct rfcomm_opts *opts;

%}

%union {
	int number;
	char *string;
	bdaddr_t *bdaddr;
}

%token K_BIND K_DEVICE K_CHANNEL K_COMMENT
%token K_YES K_NO

%token <number> NUMBER RFCOMM
%token <string> STRING WORD
%token <bdaddr> BDADDR

%type <number> bool

%%

config		:
		| statement
		| config statement
		;

statement	: section '{' rfcomm_options '}'
		| rfcomm  '{' rfcomm_options '}'
		| WORD
			{
			}
		| error
			{
				yyclearin;
				yyerrok;
			}
		;

section		: WORD
			{
				opts = NULL;
			}
		;

rfcomm		: RFCOMM
			{
				if (($1 >= 0) && ($1 < RFCOMM_MAX_DEV))
					opts = &rfcomm_opts[$1];
				else
					opts = NULL;
			}
		;

rfcomm_options	: rfcomm_option ';'
		| error ';'
		| rfcomm_options rfcomm_option ';'
		;

rfcomm_option	: K_BIND bool
			{
				if (opts)
					opts->bind = $2;
			}
		| K_DEVICE BDADDR
			{
				if (opts)
					bacpy(&opts->bdaddr, $2);
			}
		| K_CHANNEL NUMBER
			{
				if (opts)
					opts->channel = $2;
			}
		| K_COMMENT STRING
			{
				if (opts)
					snprintf(opts->comment, MAXCOMMENTLEN, "%s", $2);
			}
		| WORD
			{
				// Unknown option
			}
		;

bool		: K_YES	{ $$ = 1; }
		| K_NO	{ $$ = 0; }
		;

%%

int yyerror(char *s) 
{
	fprintf(stderr, "%s line %d\n", s, lineno);
	return 0;
}

int rfcomm_read_config(char *filename)
{
	extern FILE *yyin;
	char file[MAXPATHLEN + 1];
	int i;

	for (i = 0; i < RFCOMM_MAX_DEV; i++) {
		rfcomm_opts[i].bind = 0;
		bacpy(&rfcomm_opts[i].bdaddr, BDADDR_ANY);
		rfcomm_opts[i].channel = 1;
	}

	if (filename) {
		snprintf(file, MAXPATHLEN,  "%s", filename);
	} else {
		snprintf(file, MAXPATHLEN, "%s/.bluetooth/rfcomm.conf", getenv("HOME"));

		if ((getuid() == 0) || (access(file, R_OK) < 0))
			snprintf(file, MAXPATHLEN, "/etc/bluetooth/rfcomm.conf");
	}

	if (!(yyin = fopen(file, "r")))
		return -1;

	lineno = 1;
	yyparse();

	fclose(yyin);

	return 0;
}
