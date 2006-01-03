%{
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
#include <string.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "hcid.h"
#include "kword.h"
#include "parser.h"

static char str_buf[255];

#define ECHO {;}
#define YY_DECL int yylex(void)

int cfg_error(const char *ftm, ...);
int yyerror(char *str);

%}

hex		0x[0-9a-zA-Z]+
num		[0-9]+
kword		[A-Za-z0-9\_\-]+
word		[A-Za-z0-9\-\_+=\!\$\#\%\&\*\^\@@\\\~\.]+
wordnm		{word}:{num}
list		({word}\,*)+
comment		\#.*\n
fname		[A-Za-z0-9\_\.\-]+
path		(\/{fname})+
string		\".*\"
hci		hci[0-9]+
hextuple	[0-9a-zA-Z][0-9a-zA-Z]
bdaddr		{hextuple}:{hextuple}:{hextuple}:{hextuple}:{hextuple}:{hextuple}

%x OPTION PARAM

%%
[ \t] {
	/* Skip spaces and tabs */
	;
}

{comment} {
	/* Skip comments */
	lineno++; 
}

\n {
	lineno++;
}

{hci} {
	yylval.str = yytext;
	return HCI;
}

{bdaddr} {
	yylval.str = yytext;
	return BDADDR;
}

{hex} {
	yylval.num = strtol(yytext, NULL, 16);
	return NUM;
}

{num} {
	yylval.num = atoi(yytext);
	return NUM;
}

{kword}	{
	int kw = find_keyword(cfg_keyword, yytext);
	if( kw != -1 )
		return kw;

	yylval.str = yytext;
	return WORD;
}

{word} {
	yylval.str = yytext;
	return WORD;
}

{string} {
	if(yyleng > sizeof(str_buf) - 1){
		yyerror("string too long");
		return 0;
	}

	strncpy(str_buf, yytext + 1, yyleng - 2);
	str_buf[yyleng - 2] = '\0';

	yylval.str = str_buf;
	return STRING;
}

{list} {
	yylval.str = yytext;
	return LIST;
}

{path} {
	yylval.str = yytext;
	return PATH;
}

. {
	return *yytext;
}

%%

int yywrap(void)
{
	return 1;
}
