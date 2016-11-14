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
#include "proto3-ast.h"
#include "proto3-grammar.h"

extern FILE *yyin;
extern int yylex(void);
extern int yyparse(void);
extern void yyrestart(FILE *file);

int error_count = 0;
const char *input_filename = 0;

void yyerror(const char *msg, ...)
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

void yyerror_on_line(const char *msg, long line, ...)
{
    va_list va;
    va_start(va, line);
    if (input_filename)
        fprintf(stderr, "%s:%ld: ", input_filename, line);
    else
        fprintf(stderr, "%ld: ", line);
    vfprintf(stderr, msg, va);
    putc('\n', stderr);
    ++error_count;
    va_end(va);
}

void yywarning(const char *msg, ...)
{
    va_list va;
    va_start(va, msg);
    if (input_filename)
        fprintf(stderr, "%s:%ld: warning: ", input_filename, (long)yylloc.first_line);
    else
        fprintf(stderr, "%ld: warning: ", (long)yylloc.first_line);
    vfprintf(stderr, msg, va);
    putc('\n', stderr);
    va_end(va);
}

void yywarning_on_line(const char *msg, long line, ...)
{
    va_list va;
    va_start(va, line);
    if (input_filename)
        fprintf(stderr, "%s:%ld: warning: ", input_filename, line);
    else
        fprintf(stderr, "%ld: warning: ", line);
    vfprintf(stderr, msg, va);
    putc('\n', stderr);
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
    Proto3Name string;
    uint64_t number;
    Proto3Type type;
    Proto3Name name;
    Proto3FieldQualifier qualifier;
    Proto3OptionValue optvalue;
    Proto3Option option;
}

%type <string>      K_STRING_LITERAL
%type <number>      K_NUMBER Tag
%type <type>        Type ScalarType KeyType
%type <name>        K_IDENTIFIER Name QualifiedName
%type <qualifier>   FieldQualifier
%type <optvalue>    OptionValue
%type <option>      FieldOption OptionDeclaration

%%

Proto3File
    : SyntaxDeclaration ImportDeclarations Declarations {
            proto3_resolve_types();
        }
    ;

SyntaxDeclaration
    : K_SYNTAX '=' K_STRING_LITERAL ';'     {
            if (strcmp($3.name, "proto3") != 0) {
                yyerror("unsupported syntax '%s'", $3);
            }
        }
    | /* empty */       {
            yywarning("proto2 syntax not supported; assuming proto3");
        }
    ;

ImportDeclarations
    : ImportDeclarationList     {
            yywarning("imports are not supported; ignoring");
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
    | OptionDeclaration {
            proto3_add_scope_option($1);
        }
    | PackageDeclaration
    ;

PackageDeclaration
    : K_PACKAGE QualifiedName ';'   {
                proto3_set_package_name($2);
            }
    ;

MessageDeclaration
    : K_MESSAGE Name {
            proto3_push_scope(PROTO3_SCOPE_MESSAGE, proto3_qualify_name($2), @2.first_line);
        } Fields {
            if (!proto3_have_scope_fields())
                yyerror("no message fields defined");
            proto3_pop_scope();
        }
    ;

Fields
    : '{' FieldList '}'
    | '{' '}'
    | '{' error '}'
    ;

FieldList
    : FieldList Field
    | Field
    ;

Field
    : FieldQualifier Type Name '=' Tag FieldOption ';'  {
            Proto3FieldQualifier qualifier = $1;
            int pack_type = -1;
            if ($6.name.name && !strcmp($6.name.name, "packed")) {
                if ($6.value.type == PROTO3_VALUE_BOOL) {
                    pack_type = ($6.value.num_value != 0);
                } else {
                    yyerror("'packed' option must have a boolean value");
                    pack_type = 1;
                }
            }
            if (qualifier == PROTO3_QUAL_REPEATED) {
                if (proto3_can_pack_type($2)) {
                    if (pack_type == -1 || pack_type == 1)
                        qualifier = PROTO3_QUAL_PACKED;
                } else if (pack_type == 1) {
                    yyerror("cannot pack repeated fields of this type");
                }
            }
            proto3_add_field(qualifier, $2, $3, $5, $6, @3.first_line);
        }
    | K_RESERVED ReservedNumbers ';'
    | K_RESERVED ReservedNames ';'
    | MessageDeclaration
    | EnumDeclaration
    | OptionDeclaration     {
            proto3_add_scope_option($1);
        }
    | error ';'
    ;

FieldQualifier
    : K_REPEATED        { $$ = PROTO3_QUAL_REPEATED; }
    | K_REQUIRED        { $$ = PROTO3_QUAL_REQUIRED; }
    | K_OPTIONAL        { $$ = PROTO3_QUAL_OPTIONAL; }
    | /* empty */       { $$ = PROTO3_QUAL_OPTIONAL; }
    ;

Tag
    : K_NUMBER  {
            uint64_t tag = $1;
            if ((tag >= 1 && tag <= 536870911) && !(tag >= 19000 && tag <= 19999)) {
                $$ = tag;
            } else {
                yyerror("invalid tag number");
                $$ = 0;
            }
        }
    ;

EnumDeclaration
    : K_ENUM Name {
            proto3_push_scope(PROTO3_SCOPE_ENUM, proto3_qualify_name($2), @2.first_line);
        } Enums {
            if (!proto3_have_scope_enums())
                yyerror("no enumerated values defined");
            proto3_pop_scope();
        }
    ;

Enums
    : '{' EnumList '}'
    | '{' '}'
    | '{' error '}'
    ;

EnumList
    : EnumList Enum
    | Enum
    ;

Enum
    : Name '=' K_NUMBER ';' {
            if (!proto3_have_scope_enums() && $3 != 0) {
                yywarning("first enumerated value should be zero");
            }
            if ($3 > 2147483647ULL) {
                yywarning("enumerated value is not 32-bit");
            }
            proto3_add_enum($1, $3, @1.first_line);
        }
    | OptionDeclaration     {
            proto3_add_scope_option($1);
        }
    | error ';'
    ;

FieldOption
    : '[' Name '=' OptionValue ']'      {
            $$.name = $2;
            $$.value = $4;
        }
    | /* empty */   {
            memset(&($$), 0, sizeof($$));
            $$.value.type = PROTO3_VALUE_NONE;
        }
    ;

OptionDeclaration
    : K_OPTION Name '=' OptionValue ';' {
            $$.name = $2;
            $$.value = $4;
        }
    ;

OptionValue
    : K_NUMBER          {
            memset(&($$), 0, sizeof($$));
            $$.type = PROTO3_VALUE_NUMBER;
            $$.num_value = $1;
        }
    | K_TRUE            {
            memset(&($$), 0, sizeof($$));
            $$.type = PROTO3_VALUE_BOOL;
            $$.num_value = 1;
        }
    | K_FALSE           {
            memset(&($$), 0, sizeof($$));
            $$.type = PROTO3_VALUE_BOOL;
            $$.num_value = 0;
        }
    | K_STRING_LITERAL  {
            memset(&($$), 0, sizeof($$));
            $$.type = PROTO3_VALUE_STRING;
            $$.name_value = $1;
        }
    | K_IDENTIFIER      {
            memset(&($$), 0, sizeof($$));
            $$.type = PROTO3_VALUE_IDENTIFIER;
            $$.name_value = $1;
        }
    ;

ReservedNumbers
    : ReservedNumbers ',' ReservedNumber
    | ReservedNumber
    ;

ReservedNumber
    : Tag                                   {}
    | Tag K_TO Tag                          {}
    ;

ReservedNames
    : ReservedNames ',' K_STRING_LITERAL    {}
    | K_STRING_LITERAL                      {}
    ;

Name
    : K_IDENTIFIER  { $$ = $1; }
    ;

QualifiedName
    : QualifiedName '.' K_IDENTIFIER    { $$ = proto3_qualified_name($1, $3); }
    | Name                              { $$ = $1; }
    ;

Type
    : ScalarType                        { $$ = $1; }
    | QualifiedName                     { $$ = proto3_named_type($1);   }
    | K_MAP '<' KeyType ',' Type '>'    {
            yyerror("map types are not supported");
            $$ = proto3_map_type($3, $5);
        }
    ;

ScalarType
    : K_DOUBLE          { $$ = proto3_basic_type(PROTO3_TYPE_DOUBLE);   }
    | K_FLOAT           { $$ = proto3_basic_type(PROTO3_TYPE_FLOAT);    }
    | K_INT32           { $$ = proto3_basic_type(PROTO3_TYPE_INT32);    }
    | K_INT64           { $$ = proto3_basic_type(PROTO3_TYPE_INT64);    }
    | K_UINT32          { $$ = proto3_basic_type(PROTO3_TYPE_UINT32);   }
    | K_UINT64          { $$ = proto3_basic_type(PROTO3_TYPE_UINT64);   }
    | K_SINT32          { $$ = proto3_basic_type(PROTO3_TYPE_SINT32);   }
    | K_SINT64          { $$ = proto3_basic_type(PROTO3_TYPE_SINT64);   }
    | K_FIXED32         { $$ = proto3_basic_type(PROTO3_TYPE_FIXED32);  }
    | K_FIXED64         { $$ = proto3_basic_type(PROTO3_TYPE_FIXED64);  }
    | K_SFIXED32        { $$ = proto3_basic_type(PROTO3_TYPE_SFIXED32); }
    | K_SFIXED64        { $$ = proto3_basic_type(PROTO3_TYPE_SFIXED64); }
    | K_BOOL            { $$ = proto3_basic_type(PROTO3_TYPE_BOOL);     }
    | K_STRING          { $$ = proto3_basic_type(PROTO3_TYPE_STRING);   }
    | K_BYTES           { $$ = proto3_basic_type(PROTO3_TYPE_BYTES);    }
    ;

KeyType
    : K_INT32           { $$ = proto3_basic_type(PROTO3_TYPE_INT32);    }
    | K_INT64           { $$ = proto3_basic_type(PROTO3_TYPE_INT64);    }
    | K_UINT32          { $$ = proto3_basic_type(PROTO3_TYPE_UINT32);   }
    | K_UINT64          { $$ = proto3_basic_type(PROTO3_TYPE_UINT64);   }
    | K_SINT32          { $$ = proto3_basic_type(PROTO3_TYPE_SINT32);   }
    | K_SINT64          { $$ = proto3_basic_type(PROTO3_TYPE_SINT64);   }
    | K_FIXED32         { $$ = proto3_basic_type(PROTO3_TYPE_FIXED32);  }
    | K_FIXED64         { $$ = proto3_basic_type(PROTO3_TYPE_FIXED64);  }
    | K_SFIXED32        { $$ = proto3_basic_type(PROTO3_TYPE_SFIXED32); }
    | K_SFIXED64        { $$ = proto3_basic_type(PROTO3_TYPE_SFIXED64); }
    | K_BOOL            { $$ = proto3_basic_type(PROTO3_TYPE_BOOL);     }
    | K_STRING          { $$ = proto3_basic_type(PROTO3_TYPE_STRING);   }
    ;

%%
