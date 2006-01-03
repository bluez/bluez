%{
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include "kword.h"
#include "parser.h"


#define ECHO {;}
#define YY_DECL int yylex(void)

int yyerror(char *str);

%}

space		[ \t]
linebreak	\n
comment		\#.*\n
keyword		[A-Za-z0-9\_\-]+

number		[0-9]+
string		\".*\"
bdaddr		[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}:[A-Za-z0-9]{2}

%%

{space}		{
			/* Skip spaces and tabs */
			;
		}

{comment}	{
			/* Skip comments */
			lineno++; 
		}

{number}	{
			yylval.number = atoi(yytext);
			return NUMBER;
		}

{string}	{
			yylval.string = yytext;
			return STRING;
		}

{bdaddr}	{
			bdaddr_t *ba = malloc(sizeof(bdaddr_t));
			str2ba(yytext, ba);
			yylval.bdaddr = ba;
			return BDADDR;
		}

{keyword}	{
			int keyword = rfcomm_find_keyword(rfcomm_keyword, yytext);
			if (keyword != -1)
				return keyword;

			if (strncmp(yytext, "rfcomm", 6) == 0) {
				yylval.number = atoi(yytext + 6);
				return RFCOMM;
			}

			yylval.string = yytext;
			return WORD;
		}

{linebreak}	{
			lineno++;
		}

.		{
			return *yytext;
		}

%%

int yywrap(void) 
{
	return 1;
}
