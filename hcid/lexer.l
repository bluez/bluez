%{
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

#include <string.h>

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
	if(yyleng > sizeof(str_buf)-1){
		yyerror("string too long");
		return 0;
	}

	strncpy(str_buf, yytext+1, yyleng-2);
	str_buf[yyleng-2] = '\0';

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
