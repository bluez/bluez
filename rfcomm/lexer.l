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
