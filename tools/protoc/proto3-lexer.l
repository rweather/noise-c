%{
/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "proto3-ast.h"
#include "proto3-grammar.h"

#define YY_NO_INPUT

%}

%option noyywrap nounput

ID          [a-zA-Z][a-zA-Z_0-9]*
NUMBER      [0-9]+
WHITE       [ \t\v\r]+
QUOTE       ["]
STRCHAR     [^"\n]

%%

"syntax"    { return K_SYNTAX; }
"message"   { return K_MESSAGE; }
"repeated"  { return K_REPEATED; }
"required"  { return K_REQUIRED; }
"optional"  { return K_OPTIONAL; }
"reserved"  { return K_RESERVED; }
"to"        { return K_TO; }
"enum"      { return K_ENUM; }
"option"    { return K_OPTION; }
"import"    { return K_IMPORT; }
"public"    { return K_PUBLIC; }
"map"       { return K_MAP; }
"package"   { return K_PACKAGE; }
"double"    { return K_DOUBLE; }
"float"     { return K_FLOAT; }
"int32"     { return K_INT32; }
"int64"     { return K_INT64; }
"uint32"    { return K_UINT32; }
"uint64"    { return K_UINT64; }
"sint32"    { return K_SINT32; }
"sint64"    { return K_SINT64; }
"fixed32"   { return K_FIXED32; }
"fixed64"   { return K_FIXED64; }
"sfixed32"  { return K_SFIXED32; }
"sfixed64"  { return K_SFIXED64; }
"bool"      { return K_BOOL; }
"string"    { return K_STRING; }
"bytes"     { return K_BYTES; }
"true"      { return K_TRUE; }
"false"     { return K_FALSE; }

{ID}        {
                yylval.name = proto3_basic_name(yytext);
                return K_IDENTIFIER;
            }
{NUMBER}    {
                yylval.number = strtoull(yytext, NULL, 10);
                return K_NUMBER;
            }

{QUOTE}{STRCHAR}*{QUOTE} {
                size_t len = strlen(yytext) - 2;
                yylval.name = proto3_string(yytext + 1, len);
                return K_STRING_LITERAL;
            }

{WHITE}     ;

\n          { ++yylloc.first_line; }

"//".*\n    { ++yylloc.first_line; }

.           { return yytext[0]; }

%%
