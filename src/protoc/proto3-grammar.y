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
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include "proto3-grammar.h"

extern FILE *yyin;
extern int yylex(void);
extern void yyrestart(FILE *file);

int error_count = 0;
const char *input_filename = 0;

static void yyerror(const char *msg, ...)
{
    va_list va;
    va_start(va, msg);
    if (input_filename)
        fprintf(stderr, "%s:%ld: ", input_filename, (long)yylloc.first_line);
    else
        fprintf(stderr, "%ld: ", (long)yylloc.first_line);
    vfprintf(stderr, msg, va);
    putc('\n', stderr);
    ++error_count;
    va_end(va);
}

static void yywarning(const char *msg, ...)
{
    va_list va;
    va_start(va, msg);
    if (input_filename)
        fprintf(stderr, "%s:%ld: warning: ", input_filename, (long)yylloc.first_line);
    else
        fprintf(stderr, "%ld: warning: ", (long)yylloc.first_line);
    vfprintf(stderr, msg, va);
    putc('\n', stderr);
    ++error_count;
    va_end(va);
}

int parse_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    int retval;
    if (!file) {
        perror(filename);
        return 0;
    }
    input_filename = filename;
    yylloc.first_line = 1;
    yyrestart(file);
    retval = yyparse();
    yyin = NULL;
    input_filename = 0;
    if (error_count)
        return 0;
    else
        return retval ? 0 : 1;
}

%}

%locations

%token K_IDENTIFIER "an identifier"
%token K_STRING_LITERAL "a string"
%token K_NUMBER "a number"
%token K_SYNTAX "`syntax'"
%token K_MESSAGE "`message'"
%token K_REPEATED "`repeated'"
%token K_REQUIRED "`required'"
%token K_OPTIONAL "`optional'"
%token K_RESERVED "`reserved'"
%token K_TO "`to'"
%token K_ENUM "`enum'"
%token K_OPTION "`option'"
%token K_IMPORT "`import'"
%token K_PUBLIC "`public'"
/* %token K_ONEOF "`oneof'"         -- not supported */
%token K_MAP "`map'"
%token K_PACKAGE "`package'"
/* %token K_SERVICE "`service'"     -- not supported */
%token K_DOUBLE "`double'"
%token K_FLOAT "`float'"
%token K_INT32 "`int32'"
%token K_INT64 "`int64'"
%token K_UINT32 "`uint32'"
%token K_UINT64 "`uint64'"
%token K_SINT32 "`sint32'"
%token K_SINT64 "`sint64'"
%token K_FIXED32 "`fixed32'"
%token K_FIXED64 "`fixed64'"
%token K_SFIXED32 "`sfixed32'"
%token K_SFIXED64 "`sfixed64'"
%token K_BOOL "`bool'"
%token K_STRING "`string'"
%token K_BYTES "`bytes'"
%token K_TRUE "`true'"
%token K_FALSE "`false'"

%union {
    char *name;
    char *string;
    uint64_t number;
}

%type <string>      K_STRING_LITERAL

%%

Proto3File
    : SyntaxDeclaration ImportDeclarations Declarations
    ;

SyntaxDeclaration
    : K_SYNTAX '=' K_STRING_LITERAL ';'     {
            if (strcmp($3, "proto3") != 0) {
                yyerror("unsupported syntax '%s'", $3);
            }
        }
    | /* empty */       {
            yywarning("proto2 syntax not supported; assuming proto3");
        }
    ;

ImportDeclarations
    : ImportDeclarationList     {
            yywarning("imports are not yet supported; ignoring");
        }
    | /* empty */
    ;

ImportDeclarationList
    : ImportDeclarationList ImportDeclaration
    | ImportDeclaration
    ;

ImportDeclaration
    : K_IMPORT K_STRING_LITERAL ';'
    | K_IMPORT K_PUBLIC K_STRING_LITERAL ';'
    ;

Declarations
    : DeclarationList
    | /* empty */
    ;

DeclarationList
    : DeclarationList Declaration
    | Declaration
    ;

Declaration
    : MessageDeclaration
    | EnumDeclaration
    | OptionDeclaration
    | PackageDeclaration
    ;

PackageDeclaration
    : K_PACKAGE QualifiedName ';'
    ;

MessageDeclaration
    : K_MESSAGE Name '{' Fields '}'
    ;

Fields
    : FieldList
    | /* empty */
    ;

FieldList
    : FieldList Field
    | Field
    ;

Field
    : FieldQualifier Type Name '=' Tag FieldOption ';'
    | K_RESERVED ReservedNumbers ';'
    | K_RESERVED ReservedNames ';'
    | MessageDeclaration
    | EnumDeclaration
    | OptionDeclaration
    ;

FieldQualifier
    : K_REPEATED
    | K_REQUIRED
    | K_OPTIONAL
    | /* empty */
    ;

Tag
    : K_NUMBER
    ;

EnumDeclaration
    : K_ENUM Name '{' Enums '}'
    ;

Enums
    : EnumList
    | /* empty */
    ;

EnumList
    : EnumList Enum
    | Enum
    ;

Enum
    : Name '=' K_NUMBER ';'
    | OptionDeclaration
    ;

FieldOption
    : '[' Name '=' OptionValue ']'
    | /* empty */
    ;

OptionDeclaration
    : K_OPTION Name '=' OptionValue ';'
    ;

OptionValue
    : K_NUMBER
    | K_TRUE
    | K_FALSE
    | K_STRING_LITERAL
    | K_IDENTIFIER
    ;

ReservedNumbers
    : ReservedNumbers ',' ReservedNumber
    | ReservedNumber
    ;

ReservedNumber
    : K_NUMBER
    | K_NUMBER K_TO K_NUMBER
    ;

ReservedNames
    : ReservedNames ',' K_STRING_LITERAL
    | K_STRING_LITERAL
    ;

Name
    : K_IDENTIFIER      {
    }
    ;

QualifiedName
    : QualifiedName '.' K_IDENTIFIER
    | Name
    ;

Type
    : ScalarType
    | QualifiedName
    | K_MAP '<' KeyType ',' Type '>'
    ;

ScalarType
    : K_DOUBLE
    | K_FLOAT
    | K_INT32
    | K_INT64
    | K_UINT32
    | K_UINT64
    | K_SINT32
    | K_SINT64
    | K_FIXED32
    | K_FIXED64
    | K_SFIXED32
    | K_SFIXED64
    | K_BOOL
    | K_STRING
    | K_BYTES
    ;

KeyType
    : K_INT32
    | K_INT64
    | K_UINT32
    | K_UINT64
    | K_SINT32
    | K_SINT64
    | K_FIXED32
    | K_FIXED64
    | K_SFIXED32
    | K_SFIXED64
    | K_BOOL
    | K_STRING
    ;

%%
