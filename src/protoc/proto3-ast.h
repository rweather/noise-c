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

#ifndef __PROTO3_AST_H__
#define __PROTO3_AST_H__

#include <stdint.h>
#include <stddef.h>

#define PROTO3_MAX_NAME_LEN 128

typedef struct {
    char *name;
} Proto3Name;

typedef enum {
    PROTO3_TYPE_INVALID,
    PROTO3_TYPE_INT32,
    PROTO3_TYPE_UINT32,
    PROTO3_TYPE_INT64,
    PROTO3_TYPE_UINT64,
    PROTO3_TYPE_SINT32,
    PROTO3_TYPE_SINT64,
    PROTO3_TYPE_FIXED32,
    PROTO3_TYPE_SFIXED32,
    PROTO3_TYPE_FIXED64,
    PROTO3_TYPE_SFIXED64,
    PROTO3_TYPE_FLOAT,
    PROTO3_TYPE_DOUBLE,
    PROTO3_TYPE_BOOL,
    PROTO3_TYPE_STRING,
    PROTO3_TYPE_BYTES,
    PROTO3_TYPE_MAP,
    PROTO3_TYPE_NAMED,
    PROTO3_TYPE_ENUM
} Proto3TypeId;

typedef struct {
    Proto3TypeId id;
    Proto3Name name;
    Proto3TypeId key_type_id;
    Proto3TypeId value_type_id;
} Proto3Type;

typedef enum {
    PROTO3_SCOPE_MESSAGE,
    PROTO3_SCOPE_ENUM
} Proto3ScopeId;

typedef enum {
    PROTO3_QUAL_REPEATED,
    PROTO3_QUAL_REQUIRED,
    PROTO3_QUAL_OPTIONAL,
    PROTO3_QUAL_PACKED
} Proto3FieldQualifier;

typedef enum {
    PROTO3_VALUE_NONE,
    PROTO3_VALUE_NUMBER,
    PROTO3_VALUE_BOOL,
    PROTO3_VALUE_STRING,
    PROTO3_VALUE_IDENTIFIER
} Proto3ValueTypeId;

typedef struct {
    Proto3ValueTypeId type;
    uint64_t num_value;
    Proto3Name name_value;
} Proto3OptionValue;

typedef struct {
    Proto3Name name;
    Proto3OptionValue value;
} Proto3Option;

typedef struct _Proto3Field {
    struct _Proto3Field *next;
    Proto3FieldQualifier qualifier;
    Proto3Name name;
    Proto3Type type;
    uint64_t tag;
    Proto3Option option;
    int line;
} Proto3Field;

typedef struct _Proto3Message {
    struct _Proto3Message *next;
    Proto3Name name;
    Proto3Field *fields;
    int line;
} Proto3Message;

typedef struct _Proto3EnumValue {
    struct _Proto3EnumValue *next;
    Proto3Name name;
    uint64_t value;
    int line;
} Proto3EnumValue;

typedef struct _Proto3Enum {
    struct _Proto3Enum *next;
    Proto3Name name;
    Proto3EnumValue *values;
    int line;
} Proto3Enum;

Proto3Name proto3_string(const char *str, size_t len);

Proto3Name proto3_basic_name(const char *name);
Proto3Name proto3_qualified_name(Proto3Name parent, Proto3Name name);
Proto3Name proto3_qualify_name(Proto3Name name);

void proto3_push_scope(Proto3ScopeId id, Proto3Name name, int line);
void proto3_pop_scope(void);

Proto3Type proto3_basic_type(Proto3TypeId id);
Proto3Type proto3_map_type(Proto3Type key_type, Proto3Type value_type);
Proto3Type proto3_named_type(Proto3Name name);
int proto3_can_pack_type(Proto3Type type);

void proto3_add_field(Proto3FieldQualifier qualifier, Proto3Type type,
                      Proto3Name name, uint64_t tag, Proto3Option option,
                      int line);
void proto3_add_enum(Proto3Name name, uint64_t value, int line);
void proto3_add_scope_option(Proto3Option option);
int proto3_have_scope_fields(void);
int proto3_have_scope_enums(void);

void proto3_set_package_name(Proto3Name name);

void proto3_resolve_types(void);

void proto3_cleanup(void);

Proto3Message *proto3_first_message(void);
Proto3Enum *proto3_first_enum(void);

#endif
