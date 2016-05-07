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

#include "proto3-ast.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void yyerror(const char *msg, ...);
void yyerror_on_line(const char *msg, long line, ...);
void yywarning(const char *msg, ...);
void yywarning_on_line(const char *msg, long line, ...);

typedef struct _Proto3StringBlock
{
    struct _Proto3StringBlock *next;
    char data[1];

} Proto3StringBlock;

typedef struct _Proto3Scope
{
    struct _Proto3Scope *next;
    Proto3ScopeId id;
    Proto3Name name;
    Proto3Message *message;
    Proto3Enum *enum_node;

} Proto3Scope;

static Proto3StringBlock *blocks = 0;
static Proto3Scope *scopes = 0;
static Proto3Name package_name = {0};
static Proto3Message *messages = 0;
static Proto3Enum *enums = 0;

/**
 * \brief Interns a string into the global string table.
 *
 * \param str The string to be interned.
 * \param len The length of the string in bytes.
 *
 * \return The interned version of the string.
 */
Proto3Name proto3_string(const char *str, size_t len)
{
    Proto3Name n;
    Proto3StringBlock *block;
    block = (Proto3StringBlock *)malloc(sizeof(Proto3StringBlock) + len);
    if (!block)
        exit(1);
    block->next = blocks;
    blocks = block;
    memcpy(block->data, str, len);
    block->data[len] = '\0';
    n.name = block->data;
    return n;
}

/**
 * \brief Interns a name into the global string table.
 *
 * \param name The name to be interned.
 *
 * \return The interned version of the name.
 */
Proto3Name proto3_basic_name(const char *name)
{
    return proto3_string(name, strlen(name));
}

/**
 * \brief Creates a qualified name.
 *
 * \param parent The name of the parent scope.
 * \param name The name within the scope.
 *
 * \return The concatenation of \a parent, ".", and \a name.
 */
Proto3Name proto3_qualified_name(Proto3Name parent, Proto3Name name)
{
    Proto3Name n;
    Proto3StringBlock *block;
    size_t parent_len = strlen(parent.name);
    size_t name_len = strlen(name.name);
    size_t len = parent_len + name_len + 1;
    block = (Proto3StringBlock *)malloc(sizeof(Proto3StringBlock) + len);
    if (!block)
        exit(1);
    block->next = blocks;
    blocks = block;
    memcpy(block->data, parent.name, parent_len);
    block->data[parent_len] = '.';
    memcpy(block->data + parent_len + 1, name.name, name_len);
    block->data[len] = '\0';
    n.name = block->data;
    return n;
}

/**
 * \brief Creates a qualified name.
 *
 * \param parent The name of the parent scope.
 * \param parent_len The length of the parent's name.
 * \param name The name within the scope.
 *
 * \return The concatenation of \a parent, ".", and \a name.
 */
Proto3Name proto3_qualified_name_2(Proto3Name parent, size_t parent_len, Proto3Name name)
{
    Proto3Name n;
    Proto3StringBlock *block;
    size_t name_len = strlen(name.name);
    size_t len = parent_len + name_len + 1;
    block = (Proto3StringBlock *)malloc(sizeof(Proto3StringBlock) + len);
    if (!block)
        exit(1);
    block->next = blocks;
    blocks = block;
    memcpy(block->data, parent.name, parent_len);
    block->data[parent_len] = '.';
    memcpy(block->data + parent_len + 1, name.name, name_len);
    block->data[len] = '\0';
    n.name = block->data;
    return n;
}

/**
 * \brief Qualifies a name using the current scope or package name.
 *
 * \param name The basic name to be qualified.
 *
 * \return The qualified form of \a name.
 */
Proto3Name proto3_qualify_name(Proto3Name name)
{
    if (scopes)
        return proto3_qualified_name(scopes->name, name);
    else if (package_name.name)
        return proto3_qualified_name(package_name, name);
    else
        return name;
}

/**
 * \brief Pushes into a new scope.
 *
 * \param id The identifier for the scope, message or enum.
 * \param name The name of the scope.
 * \param line The line where the name was declared.
 */
void proto3_push_scope(Proto3ScopeId id, Proto3Name name, int line)
{
    Proto3Message *message, *prev_message;
    Proto3Enum *enum_node, *prev_enum;
    Proto3Scope *scope = (Proto3Scope *)calloc(1, sizeof(Proto3Scope));
    if (!scope)
        exit(1);
    scope->next = scopes;
    scope->id = id;
    scope->name = name;
    scopes = scope;
    if (id == PROTO3_SCOPE_MESSAGE) {
        message = messages;
        prev_message = 0;
        while (message != 0) {
            if (!strcmp(message->name.name, name.name)) {
                yyerror("'%s' redeclared", name.name);
                yyerror_on_line("previous declaration here", message->line);
            }
            prev_message = message;
            message = message->next;
        }
        enum_node = enums;
        while (enum_node != 0) {
            if (!strcmp(enum_node->name.name, name.name)) {
                yyerror("'%s' redeclared", name.name);
                yyerror_on_line("previous declaration here", enum_node->line);
            }
            enum_node = enum_node->next;
        }
        message = (Proto3Message *)calloc(1, sizeof(Proto3Message));
        if (!message)
            exit(1);
        message->next = 0;
        if (prev_message)
            prev_message->next = message;
        else
            messages = message;
        message->name = name;
        message->fields = 0;
        message->line = line;
        scope->message = message;
    } else {
        enum_node = enums;
        prev_enum = 0;
        while (enum_node != 0) {
            if (!strcmp(enum_node->name.name, name.name)) {
                yyerror("'%s' redeclared", name.name);
                yyerror_on_line("previous declaration here", enum_node->line);
            }
            prev_enum = enum_node;
            enum_node = enum_node->next;
        }
        message = messages;
        while (message != 0) {
            if (!strcmp(message->name.name, name.name)) {
                yyerror("'%s' redeclared", name.name);
                yyerror_on_line("previous declaration here", message->line);
            }
            message = message->next;
        }
        enum_node = (Proto3Enum *)calloc(1, sizeof(Proto3Enum));
        if (!enum_node)
            exit(1);
        enum_node->next = 0;
        if (prev_enum)
            prev_enum->next = enum_node;
        else
            enums = enum_node;
        enum_node->name = name;
        enum_node->values = 0;
        enum_node->line = line;
        scope->enum_node = enum_node;
    }
}

/**
 * \brief Pop from the current scope level.
 */
void proto3_pop_scope(void)
{
    if (scopes) {
        Proto3Scope *next = scopes->next;
        free(scopes);
        scopes = next;
    }
}

/**
 * \brief Creates a basic type descriptor.
 *
 * \param id The type identifier.
 *
 * \return The type descriptor.
 */
Proto3Type proto3_basic_type(Proto3TypeId id)
{
    Proto3Type type;
    memset(&type, 0, sizeof(type));
    type.id = id;
    return type;
}

/**
 * \brief Creates a map type descriptor.
 *
 * \param key_type The type descriptor for keys.
 * \param value_type The type descriptor for values.
 *
 * \return The descriptor for the map type.
 */
Proto3Type proto3_map_type(Proto3Type key_type, Proto3Type value_type)
{
    Proto3Type type;
    memset(&type, 0, sizeof(type));
    type.id = PROTO3_TYPE_MAP;
    type.key_type_id = key_type.id;
    type.value_type_id = value_type.id;
    type.name = value_type.name;
    return type;
}

/**
 * \brief Creates a named type descriptor.
 *
 * \param name The type name.
 *
 * \return The type descriptor.
 */
Proto3Type proto3_named_type(Proto3Name name)
{
    Proto3Type type;
    memset(&type, 0, sizeof(type));
    type.id = PROTO3_TYPE_NAMED;
    type.name = name;
    return type;
}

/**
 * \brief Determine if a type can be used with the "packed" encoding.
 *
 * \param type The type to test.
 *
 * \return Non-zero if the \a type can be packed, zero otherwise.
 */
int proto3_can_pack_type(Proto3Type type)
{
    switch (type.id) {
    case PROTO3_TYPE_INT32:
    case PROTO3_TYPE_UINT32:
    case PROTO3_TYPE_INT64:
    case PROTO3_TYPE_UINT64:
    case PROTO3_TYPE_SINT32:
    case PROTO3_TYPE_SINT64:
    case PROTO3_TYPE_FIXED32:
    case PROTO3_TYPE_SFIXED32:
    case PROTO3_TYPE_FIXED64:
    case PROTO3_TYPE_SFIXED64:
    case PROTO3_TYPE_FLOAT:
    case PROTO3_TYPE_DOUBLE:
    case PROTO3_TYPE_BOOL:
        return 1;
    default:
        return 0;
    }
}

/**
 * \brief Adds a field to a message scope.
 *
 * \param qualifier The field qualifier: required, repeated, etc.
 * \param type The field type.
 * \param name The field name.
 * \param tag The numeric tag for the field.
 * \param option An extra field option.
 * \param line The line where the name was declared.
 */
void proto3_add_field(Proto3FieldQualifier qualifier, Proto3Type type,
                      Proto3Name name, uint64_t tag, Proto3Option option,
                      int line)
{
    Proto3Message *message;
    Proto3Field *field, *prev;
    if (!scopes || !scopes->message) {
        yyerror("field outside a message block");
        return;
    }
    message = scopes->message;
    field = message->fields;
    while (field != 0) {
        if (!strcmp(field->name.name, name.name)) {
            yyerror("'%s' redeclared", name.name);
            yyerror_on_line("previous declaration here", field->line);
        }
        if (field->tag == tag) {
            yyerror("tag number %lu reused", (unsigned long)tag);
            yyerror_on_line("previous use here", field->line);
        }
        field = field->next;
    }
    field = message->fields;
    prev = 0;
    while (field != 0 && field->tag <= tag) {
        prev = field;
        field = field->next;
    }
    field = (Proto3Field *)calloc(1, sizeof(Proto3Field));
    if (!field)
        exit(1);
    if (prev) {
        field->next = prev->next;
        prev->next = field;
    } else {
        field->next = message->fields;
        message->fields = field;
    }
    field->qualifier = qualifier;
    field->name = name;
    field->type = type;
    field->tag = tag;
    field->option = option;
    field->line = line;
}

/**
 * \brief Adds an enum value to an enum scope.
 *
 * \param name The name of the enum.
 * \param value The numeric value to associate with the enum.
 * \param line The line where the name was declared.
 */
void proto3_add_enum(Proto3Name name, uint64_t value, int line)
{
    Proto3Enum *enum_node;
    Proto3EnumValue *enum_value, *prev;
    if (!scopes || !scopes->enum_node) {
        yyerror("enum value outside an enum block");
        return;
    }
    enum_node = scopes->enum_node;
    enum_value = enum_node->values;
    prev = 0;
    while (enum_value != 0) {
        if (!strcmp(enum_value->name.name, name.name)) {
            yyerror("'%s' redeclared", name.name);
            yyerror("previous declaration here", enum_value->line);
        }
        prev = enum_value;
        enum_value = enum_value->next;
    }
    enum_value = (Proto3EnumValue *)calloc(1, sizeof(Proto3EnumValue));
    if (!enum_value)
        exit(1);
    if (prev) {
        enum_value->next = prev->next;
        prev->next = enum_value;
    } else {
        enum_value->next = enum_node->values;
        enum_node->values = enum_value;
    }
    enum_value->name = name;
    enum_value->value = value;
    enum_value->line = line;
}

/**
 * \brief Adds an option to the current scope.
 *
 * \param option The option to add.
 */
void proto3_add_scope_option(Proto3Option option)
{
    /* Nothing to do here yet: ignore all options */
}

/**
 * \brief Determine if the current message scope has fields.
 *
 * \return Non-zero if the message has fields, zero if not.
 */
int proto3_have_scope_fields(void)
{
    if (!scopes || !scopes->message)
        return 0;
    else
        return scopes->message->fields != 0;
}

/**
 * \brief Determine if the current enum scope has enumerated values.
 *
 * \return Non-zero if the enum has values, zero if not.
 */
int proto3_have_scope_enums(void)
{
    if (!scopes || !scopes->enum_node)
        return 0;
    else
        return scopes->enum_node->values != 0;
}

/**
 * \brief Sets the name of the package for definitions in the current file.
 *
 * \param name The name of the package.
 */
void proto3_set_package_name(Proto3Name name)
{
    if (!package_name.name) {
        package_name = name;
    } else {
        yyerror("package name has already been declared");
    }
}

/**
 * \brief Tries to resolve a fully-qualified type name.
 *
 * \param name The name to try.
 *
 * \return Non-zero if the name is found, zero if not.
 */
static int proto3_resolve_try_name(Proto3Name name)
{
    Proto3Message *message = messages;
    Proto3Enum *enum_node = enums;
    while (message != 0) {
        if (!strcmp(message->name.name, name.name))
            return 1;
        message = message->next;
    }
    while (enum_node != 0) {
        if (!strcmp(enum_node->name.name, name.name))
            return 1;
        enum_node = enum_node->next;
    }
    return 0;
}

/**
 * \brief Resolves a name to a fully-qualified type name.
 *
 * \param parent Name of the parent scope.
 * \param name The name to be resolved.
 *
 * \return The resolved version of the name, or NULL if not found.
 */
static Proto3Name proto3_resolve_name(Proto3Name parent, Proto3Name name)
{
    size_t len = strlen(parent.name);
    Proto3Name trial;
    char *ptr;
    for (;;) {
        if (len)
            trial = proto3_qualified_name_2(parent, len, name);
        else
            trial = name;
        if (proto3_resolve_try_name(trial))
            return trial;
        if (!len)
            break;
        ptr = parent.name + len;
        while (ptr != parent.name) {
            --ptr;
            if (*ptr == '.')
                break;
        }
        len = ptr - parent.name;
    }
    trial.name = 0;
    return trial;
}

/**
 * \brief Resolves a reference to a type.
 *
 * \param parent Name of the parent scope.
 * \param type The type to be resolved.
 * \param line The line number where the field was declared.
 *
 * \return The resolved version of the type.
 */
static Proto3Type proto3_resolve_type
    (Proto3Name parent, Proto3Type type, int line)
{
    if (type.id == PROTO3_TYPE_NAMED) {
        /* Resolve a type name to either an enum or message type */
        Proto3Name name = proto3_resolve_name(parent, type.name);
        if (!name.name) {
            yywarning_on_line("'%s' cannot be resolved to a type", line,
                              type.name.name);
            return type;
        }
        return proto3_named_type(name);
    } else if (type.id == PROTO3_TYPE_MAP) {
        /* Resolve a map type */
        Proto3Type key_type;
        Proto3Type value_type;
        memset(&key_type, 0, sizeof(key_type));
        memset(&value_type, 0, sizeof(value_type));
        key_type.id = type.key_type_id;
        value_type.id = type.value_type_id;
        value_type.name = type.name;
        return proto3_map_type
            (key_type, proto3_resolve_type(parent, value_type, line));
    }
    return type;
}

/**
 * \brief Resolves all type name references.
 */
void proto3_resolve_types(void)
{
    Proto3Message *message = messages;
    Proto3Field *field;
    while (message != 0) {
        field = message->fields;
        while (field != 0) {
            field->type = proto3_resolve_type
                (message->name, field->type, field->line);
            field = field->next;
        }
        message = message->next;
    }
}

#define proto3_cleanup_list(type, list) \
    do { \
        type *current, *next; \
        current = (list); \
        while (current != 0) { \
            next = current->next; \
            free(current); \
            current = next; \
        } \
        (list) = 0; \
    } while (0)

/**
 * \brief Cleans up all structures that were allocated during parsing.
 */
void proto3_cleanup(void)
{
    proto3_cleanup_list(Proto3StringBlock, blocks);
    proto3_cleanup_list(Proto3Scope, scopes);
    proto3_cleanup_list(Proto3Message, messages);
    proto3_cleanup_list(Proto3Enum, enums);
    package_name.name = 0;
}

/**
 * \brief Gets a pointer to the first message declaration.
 */
Proto3Message *proto3_first_message(void)
{
    return messages;
}

/**
 * \brief Gets a pointer to the first enum declaration.
 */
Proto3Enum *proto3_first_enum(void)
{
    return enums;
}
