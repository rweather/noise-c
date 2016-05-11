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

extern char *license_file;

static FILE *output = NULL;
static int indent_level = 0;

typedef struct _Proto3TypeOps Proto3TypeOps;
struct _Proto3TypeOps
{
    const char *proto_name;
    const char *c_name;
    void (*declare_field)(const Proto3TypeOps *type, Proto3Field *field);
    void (*free_field)(const Proto3TypeOps *type, Proto3Field *field);
    void (*clear_field)(const Proto3TypeOps *type, Proto3Field *field);
    void (*write_field)(const Proto3TypeOps *type, int tag, Proto3Field *field);
    void (*read_field)(const Proto3TypeOps *type, int tag, Proto3Message *message, Proto3Field *field);
    void (*declare_field_ops)(const Proto3TypeOps *type, Proto3Message *message, Proto3Field *field, int header_only);
};

static void print_indent(void)
{
    int indent = indent_level;
    while (indent > 0) {
        fputs("    ", output);
        --indent;
    }
}

/**
 * \brief Generates a name into the output with '.' replaced by '_'.
 */
static void generate_name(FILE *output, const char *name)
{
    while (name && *name != '\0') {
        int ch = (*name++ & 0xFF);
        if (ch != '.')
            putc(ch, output);
        else
            putc('_', output);
    }
}

/**
 * \brief Declares a numeric field in a struct.
 */
static void type_numeric_declare_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "%s *%s;\n", type->c_name, field->name.name);
        print_indent();
        fprintf(output, "size_t %s_count_;\n", field->name.name);
        print_indent();
        fprintf(output, "size_t %s_max_;\n", field->name.name);
    } else {
        print_indent();
        fprintf(output, "%s %s;\n", type->c_name, field->name.name);
    }
}

/**
 * \brief Free a numeric field.
 */
static void type_numeric_free_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "noise_protobuf_free_memory(obj->%s, obj->%s_max_ * sizeof(%s));\n",
                field->name.name, field->name.name, type->c_name);
    }
}

/**
 * \brief Clears a numeric field.
 */
static void type_numeric_clear_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    type_numeric_free_field(type, field);
    print_indent();
    fprintf(output, "obj->%s = 0;\n", field->name.name);
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "obj->%s_count_ = 0;\n", field->name.name);
        print_indent();
        fprintf(output, "obj->%s_max_ = 0;\n", field->name.name);
    }
}

/**
 * \brief Writes a numeric field.
 */
static void type_numeric_write_field
    (const Proto3TypeOps *type, int tag, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED) {
        print_indent();
        fprintf(output, "for (index = obj->%s_count_; index > 0; --index)\n", field->name.name);
        ++indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, %d, obj->%s[index - 1]);\n",
                type->proto_name, tag, field->name.name);
        --indent_level;
    } else if (field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "noise_protobuf_write_end_element(pbuf, &end_packed);\n");
        print_indent();
        fprintf(output, "for (index = obj->%s_count_; index > 0; --index)\n", field->name.name);
        ++indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, 0, obj->%s[index - 1]);\n",
                type->proto_name, field->name.name);
        --indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_write_start_element(pbuf, %d, end_packed);\n", tag);
    } else if (field->qualifier == PROTO3_QUAL_OPTIONAL &&
                    (field->type.id != PROTO3_TYPE_FLOAT &&
                     field->type.id != PROTO3_TYPE_DOUBLE)) {
        print_indent();
        fprintf(output, "if (obj->%s)\n", field->name.name);
        ++indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, %d, obj->%s);\n",
                type->proto_name, tag, field->name.name);
        --indent_level;
    } else {
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, %d, obj->%s);\n",
                type->proto_name, tag, field->name.name);
    }
}

/**
 * \brief Reads a numeric field.
 */
static void type_numeric_read_field
    (const Proto3TypeOps *type, int tag, Proto3Message *message, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED) {
        print_indent();
        fprintf(output, "%s value = 0;\n", type->c_name);
        print_indent();
        fprintf(output, "noise_protobuf_read_%s(pbuf, %d, &value);\n",
                type->proto_name, tag);
        print_indent();
        generate_name(output, message->name.name);
        fprintf(output, "_add_%s(*obj, value);\n", field->name.name);
    } else if (field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "size_t end_packed = 0;\n");
        print_indent();
        fprintf(output, "noise_protobuf_read_start_element(pbuf, %d, &end_packed);\n", tag);
        print_indent();
        fprintf(output, "while (!noise_protobuf_read_at_end_element(pbuf, end_packed)) {\n");
        ++indent_level;
        print_indent();
        fprintf(output, "%s value = 0;\n", type->c_name);
        print_indent();
        fprintf(output, "noise_protobuf_read_%s(pbuf, 0, &value);\n",
                type->proto_name);
        print_indent();
        generate_name(output, message->name.name);
        fprintf(output, "_add_%s(*obj, value);\n", field->name.name);
        --indent_level;
        print_indent();
        fprintf(output, "}\n");
        print_indent();
        fprintf(output, "noise_protobuf_read_end_element(pbuf, end_packed);\n");
    } else {
        print_indent();
        fprintf(output, "noise_protobuf_read_%s(pbuf, %d, &((*obj)->%s));\n",
                type->proto_name, tag, field->name.name);
    }
}

/**
 * \brief Declare the field operations for a numeric field.
 */
static void type_numeric_declare_field_ops
    (const Proto3TypeOps *type, Proto3Message *message, Proto3Field *field, int header_only)
{
    /* Output the clear() method */
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_clear_%s(", field->name.name);
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (header_only) {
        fprintf(output, ";\n");
    } else {
        fprintf(output, "\n{\n");
        fprintf(output, "    if (obj) {\n");
        indent_level = 2;
        (*(type->clear_field))(type, field);
        print_indent();
        fprintf(output, "return NOISE_ERROR_NONE;\n");
        fprintf(output, "    }\n");
        fprintf(output, "    return NOISE_ERROR_INVALID_PARAM;\n");
        fprintf(output, "}\n\n");
    }

    /* Output the has() method */
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_has_%s(const ", field->name.name);
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (header_only) {
        fprintf(output, ";\n");
    } else {
        fprintf(output, "\n{\n");
        if (field->qualifier == PROTO3_QUAL_REPEATED ||
                field->qualifier == PROTO3_QUAL_PACKED) {
            fprintf(output, "    return obj ? (obj->%s_count_ != 0) : 0;\n",
                    field->name.name);
        } else if (field->qualifier == PROTO3_QUAL_REQUIRED) {
            fprintf(output, "    return obj ? 1 : 0;\n");
        } else {
            fprintf(output, "    return obj ? (obj->%s != 0) : 0;\n",
                    field->name.name);
        }
        fprintf(output, "}\n\n");
    }

    /* Output the value accessors */
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        /* Output the count() method */
        fprintf(output, "size_t ");
        generate_name(output, message->name.name);
        fprintf(output, "_count_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s_count_ : 0;\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the get_at() method */
        fprintf(output, "%s ", type->c_name);
        generate_name(output, message->name.name);
        fprintf(output, "_get_at_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, size_t index)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (obj && index < obj->%s_count_)\n",
                    field->name.name);
            fprintf(output, "        return obj->%s[index];\n",
                    field->name.name);
            fprintf(output, "    else\n");
            fprintf(output, "        return 0;\n");
            fprintf(output, "}\n\n");
        }

        /* Output the add() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_add_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, %s value)", type->c_name);
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (!obj)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "    return noise_protobuf_add_to_array(");
            fprintf(output, "(void **)&(obj->%s), &(obj->%s_count_), ",
                    field->name.name, field->name.name);
            fprintf(output, "&(obj->%s_max_), &value, sizeof(%s));\n",
                    field->name.name, type->c_name);
            fprintf(output, "}\n\n");
        }
    } else {
        /* Output the get() method */
        fprintf(output, "%s ", type->c_name);
        generate_name(output, message->name.name);
        fprintf(output, "_get_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s : 0;\n", field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the set() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_set_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, %s value)", type->c_name);
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (obj) {\n");
            fprintf(output, "        obj->%s = value;\n", field->name.name);
            fprintf(output, "        return NOISE_ERROR_NONE;\n");
            fprintf(output, "    }\n");
            fprintf(output, "    return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "}\n\n");
        }
    }
}

/**
 * \brief Declares a string field in a struct.
 */
static void type_string_declare_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "%s*%s;\n", type->c_name, field->name.name);
        print_indent();
        fprintf(output, "size_t *%s_size_;\n", field->name.name);
        print_indent();
        fprintf(output, "size_t %s_count_;\n", field->name.name);
        print_indent();
        fprintf(output, "size_t %s_max_;\n", field->name.name);
    } else {
        print_indent();
        fprintf(output, "%s%s;\n", type->c_name, field->name.name);
        print_indent();
        fprintf(output, "size_t %s_size_;\n", field->name.name);
    }
}

/**
 * \brief Free a string field.
 */
static void type_string_free_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "for (index = 0; index < obj->%s_count_; ++index)\n",
                field->name.name);
        ++indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_free_memory(obj->%s[index], obj->%s_size_[index]);\n",
                field->name.name, field->name.name);
        --indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_free_memory(obj->%s, obj->%s_max_ * sizeof(%s));\n",
                field->name.name, field->name.name, type->c_name);
        print_indent();
        fprintf(output, "noise_protobuf_free_memory(obj->%s_size_, obj->%s_max_ * sizeof(size_t));\n",
                field->name.name, field->name.name);
    } else {
        print_indent();
        fprintf(output, "noise_protobuf_free_memory(obj->%s, obj->%s_size_);\n",
                field->name.name, field->name.name);
    }
}

/**
 * \brief Clears a string field.
 */
static void type_string_clear_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    type_string_free_field(type, field);
    print_indent();
    fprintf(output, "obj->%s = 0;\n", field->name.name);
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "obj->%s_count_ = 0;\n", field->name.name);
        print_indent();
        fprintf(output, "obj->%s_max_ = 0;\n", field->name.name);
    } else {
        print_indent();
        fprintf(output, "obj->%s_size_ = 0;\n", field->name.name);
    }
}

/**
 * \brief Writes a string field.
 */
static void type_string_write_field
    (const Proto3TypeOps *type, int tag, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "for (index = obj->%s_count_; index > 0; --index)\n", field->name.name);
        ++indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, %d, obj->%s[index - 1], obj->%s_size_[index - 1]);\n",
                type->proto_name, tag, field->name.name, field->name.name);
        --indent_level;
    } else if (field->qualifier == PROTO3_QUAL_OPTIONAL) {
        print_indent();
        fprintf(output, "if (obj->%s)\n", field->name.name);
        ++indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, %d, obj->%s, obj->%s_size_);\n",
                type->proto_name, tag, field->name.name, field->name.name);
        --indent_level;
    } else {
        print_indent();
        fprintf(output, "noise_protobuf_write_%s(pbuf, %d, obj->%s, obj->%s_size_);\n",
                type->proto_name, tag, field->name.name, field->name.name);
    }
}

/**
 * \brief Reads a string field.
 */
static void type_string_read_field
    (const Proto3TypeOps *type, int tag, Proto3Message *message, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "%svalue = 0;\n", type->c_name);
        print_indent();
        fprintf(output, "size_t len = 0;\n");
        if (field->type.id == PROTO3_TYPE_STRING) {
            fprintf(output, "noise_protobuf_read_alloc_string(pbuf, %d, &value, 0, &len);\n", tag);
        } else {
            fprintf(output, "noise_protobuf_read_alloc_bytes(pbuf, %d, &value, 0, &len);\n", tag);
        }
        print_indent();
        generate_name(output, message->name.name);
        fprintf(output, "_add_%s(*obj, value, len);\n", field->name.name);
    } else {
        print_indent();
        fprintf(output, "noise_protobuf_free_memory((*obj)->%s, (*obj)->%s_size_);\n",
                field->name.name, field->name.name);
        print_indent();
        fprintf(output, "(*obj)->%s = 0;\n", field->name.name);
        print_indent();
        fprintf(output, "(*obj)->%s_size_ = 0;\n", field->name.name);
        print_indent();
        if (field->type.id == PROTO3_TYPE_STRING) {
            fprintf(output, "noise_protobuf_read_alloc_string(pbuf, %d, &((*obj)->%s), 0, &((*obj)->%s_size_));\n",
                    tag, field->name.name, field->name.name);
        } else {
            fprintf(output, "noise_protobuf_read_alloc_bytes(pbuf, %d, &((*obj)->%s), 0, &((*obj)->%s_size_));\n",
                    tag, field->name.name, field->name.name);
        }
    }
}

/**
 * \brief Declare the field operations for a string field.
 */
static void type_string_declare_field_ops
    (const Proto3TypeOps *type, Proto3Message *message, Proto3Field *field, int header_only)
{
    /* Output the clear() method */
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_clear_%s(", field->name.name);
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (header_only) {
        fprintf(output, ";\n");
    } else {
        fprintf(output, "\n{\n");
        if (field->qualifier == PROTO3_QUAL_REPEATED ||
                field->qualifier == PROTO3_QUAL_PACKED) {
            fprintf(output, "    size_t index;\n");
        }
        fprintf(output, "    if (obj) {\n");
        indent_level = 2;
        (*(type->clear_field))(type, field);
        print_indent();
        fprintf(output, "return NOISE_ERROR_NONE;\n");
        fprintf(output, "    }\n");
        fprintf(output, "    return NOISE_ERROR_INVALID_PARAM;\n");
        fprintf(output, "}\n\n");
    }

    /* Output the has() method */
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_has_%s(const ", field->name.name);
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (header_only) {
        fprintf(output, ";\n");
    } else {
        fprintf(output, "\n{\n");
        if (field->qualifier == PROTO3_QUAL_REPEATED ||
                field->qualifier == PROTO3_QUAL_PACKED) {
            fprintf(output, "    return obj ? (obj->%s_count_ != 0) : 0;\n",
                    field->name.name);
        } else {
            fprintf(output, "    return obj ? (obj->%s != 0) : 0;\n",
                    field->name.name);
        }
        fprintf(output, "}\n\n");
    }

    /* Output the value accessors */
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        /* Output the count() method */
        fprintf(output, "size_t ");
        generate_name(output, message->name.name);
        fprintf(output, "_count_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s_count_ : 0;\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the get_at() method */
        fprintf(output, "const %s", type->c_name);
        generate_name(output, message->name.name);
        fprintf(output, "_get_at_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, size_t index)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (obj && index < obj->%s_count_)\n",
                    field->name.name);
            fprintf(output, "        return obj->%s[index];\n",
                    field->name.name);
            fprintf(output, "    else\n");
            fprintf(output, "        return 0;\n");
            fprintf(output, "}\n\n");
        }

        /* Output the get_size_at() method */
        fprintf(output, "size_t ");
        generate_name(output, message->name.name);
        fprintf(output, "_get_size_at_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, size_t index)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (obj && index < obj->%s_count_)\n",
                    field->name.name);
            fprintf(output, "        return obj->%s_size_[index];\n",
                    field->name.name);
            fprintf(output, "    else\n");
            fprintf(output, "        return 0;\n");
            fprintf(output, "}\n\n");
        }

        /* Output the add() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_add_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, const %svalue, size_t size)", type->c_name);
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (!obj)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            if (field->type.id == PROTO3_TYPE_STRING) {
                fprintf(output, "    return noise_protobuf_add_to_string_array(");
                fprintf(output, "&(obj->%s), &(obj->%s_size_), &(obj->%s_count_), ",
                        field->name.name, field->name.name, field->name.name);
                fprintf(output, "&(obj->%s_max_), value, size);\n",
                        field->name.name);
            } else {
                fprintf(output, "    return noise_protobuf_add_to_bytes_array(");
                fprintf(output, "&(obj->%s), &(obj->%s_size_), &(obj->%s_count_), ",
                        field->name.name, field->name.name, field->name.name);
                fprintf(output, "&(obj->%s_max_), value, size);\n",
                        field->name.name);
            }
            fprintf(output, "}\n\n");
        }
    } else {
        /* Output the get() method */
        fprintf(output, "const %s", type->c_name);
        generate_name(output, message->name.name);
        fprintf(output, "_get_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s : 0;\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the get_size() method */
        fprintf(output, "size_t ");
        generate_name(output, message->name.name);
        fprintf(output, "_get_size_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s_size_ : 0;\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the set() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_set_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, const %svalue, size_t size)", type->c_name);
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (obj) {\n");
            indent_level = 2;
            (*(type->free_field))(type, field);
            if (field->type.id == PROTO3_TYPE_STRING) {
                fprintf(output, "        obj->%s = (%s)malloc(size + 1);\n",
                        field->name.name, type->c_name);
                fprintf(output, "        if (obj->%s) {\n", field->name.name);
                fprintf(output, "            memcpy(obj->%s, value, size);\n",
                        field->name.name);
                fprintf(output, "            obj->%s[size] = 0;\n",
                        field->name.name);
            } else {
                fprintf(output, "        obj->%s = (%s)malloc(size ? size : 1);\n",
                        field->name.name, type->c_name);
                fprintf(output, "        if (obj->%s) {\n", field->name.name);
                fprintf(output, "            memcpy(obj->%s, value, size);\n",
                        field->name.name);
            }
            fprintf(output, "            obj->%s_size_ = size;\n",
                    field->name.name);
            fprintf(output, "            return NOISE_ERROR_NONE;\n");
            fprintf(output, "        } else {\n");
            fprintf(output, "            obj->%s_size_ = 0;\n",
                    field->name.name);
            fprintf(output, "            return NOISE_ERROR_NO_MEMORY;\n");
            fprintf(output, "        }\n");
            fprintf(output, "    }\n");
            fprintf(output, "    return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "}\n\n");
        }
    }
}

/**
 * \brief Declares a named object field in a struct.
 */
static void type_named_declare_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, " **%s;\n", field->name.name);
        print_indent();
        fprintf(output, "size_t %s_count_;\n", field->name.name);
        print_indent();
        fprintf(output, "size_t %s_max_;\n", field->name.name);
    } else {
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, " *%s;\n", field->name.name);
    }
}

/**
 * \brief Free a named object field.
 */
static void type_named_free_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "for (index = 0; index < obj->%s_count_; ++index)\n",
                field->name.name);
        ++indent_level;
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_free(obj->%s[index]);\n", field->name.name);
        --indent_level;
        print_indent();
        fprintf(output, "noise_protobuf_free_memory(obj->%s, obj->%s_max_ * sizeof(",
                field->name.name, field->name.name);
        generate_name(output, field->type.name.name);
        fprintf(output, " *));\n");
    } else {
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_free(obj->%s);\n", field->name.name);
    }
}

/**
 * \brief Clears a named object field.
 */
static void type_named_clear_field
    (const Proto3TypeOps *type, Proto3Field *field)
{
    type_named_free_field(type, field);
    print_indent();
    fprintf(output, "obj->%s = 0;\n", field->name.name);
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "obj->%s_count_ = 0;\n", field->name.name);
        print_indent();
        fprintf(output, "obj->%s_max_ = 0;\n", field->name.name);
    }
}

/**
 * \brief Writes a named object field.
 */
static void type_named_write_field
    (const Proto3TypeOps *type, int tag, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        fprintf(output, "for (index = obj->%s_count_; index > 0; --index)\n", field->name.name);
        ++indent_level;
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_write(pbuf, %d, obj->%s[index - 1]);\n",
                tag, field->name.name);
        --indent_level;
    } else if (field->qualifier == PROTO3_QUAL_REQUIRED) {
        /* If a named object field is required but the value is NULL,
           we write out an empty object with no fields */
        print_indent();
        fprintf(output, "if (obj->%s) {\n", field->name.name);
        ++indent_level;
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_write(pbuf, %d, obj->%s);\n",
                tag, field->name.name);
        --indent_level;
        print_indent();
        fprintf(output, "} else {\n");
        ++indent_level;
        print_indent();
        fprintf(output, "size_t end;\n");
        print_indent();
        fprintf(output, "noise_protobuf_write_end_element(pbuf, &end);\n");
        print_indent();
        fprintf(output, "noise_protobuf_write_start_element(pbuf, %d, end);\n", tag);
        --indent_level;
        print_indent();
        fprintf(output, "}\n");
    } else {
        print_indent();
        fprintf(output, "if (obj->%s)\n", field->name.name);
        ++indent_level;
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_write(pbuf, %d, obj->%s);\n",
                tag, field->name.name);
        --indent_level;
    }
}

/**
 * \brief Reads a named object field.
 */
static void type_named_read_field
    (const Proto3TypeOps *type, int tag, Proto3Message *message, Proto3Field *field)
{
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, " *value = 0;\n");
        print_indent();
        fprintf(output, "int err;\n");
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_read(pbuf, %d, &value);\n", tag);
        print_indent();
        fprintf(output, "err = noise_protobuf_add_to_array(");
        fprintf(output, "(void **)&((*obj)->%s), &((*obj)->%s_count_), ",
                field->name.name, field->name.name);
        fprintf(output, "&((*obj)->%s_max_), &value, sizeof(value));\n",
                field->name.name);
        print_indent();
        fprintf(output, "if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)\n");
        print_indent();
        fprintf(output, "   pbuf->error = err;\n");
    } else {
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_free((*obj)->%s);\n", field->name.name);
        print_indent();
        fprintf(output, "(*obj)->%s = 0;\n", field->name.name);
        print_indent();
        generate_name(output, field->type.name.name);
        fprintf(output, "_read(pbuf, %d, &((*obj)->%s));\n",
                tag, field->name.name);
    }
}

/**
 * \brief Declare the field operations for a named object field.
 */
static void type_named_declare_field_ops
    (const Proto3TypeOps *type, Proto3Message *message, Proto3Field *field, int header_only)
{
    /* Output the clear() method */
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_clear_%s(", field->name.name);
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (header_only) {
        fprintf(output, ";\n");
    } else {
        fprintf(output, "\n{\n");
        if (field->qualifier == PROTO3_QUAL_REPEATED ||
                field->qualifier == PROTO3_QUAL_PACKED) {
            fprintf(output, "    size_t index;\n");
        }
        fprintf(output, "    if (obj) {\n");
        indent_level = 2;
        (*(type->clear_field))(type, field);
        print_indent();
        fprintf(output, "return NOISE_ERROR_NONE;\n");
        fprintf(output, "    }\n");
        fprintf(output, "    return NOISE_ERROR_INVALID_PARAM;\n");
        fprintf(output, "}\n\n");
    }

    /* Output the has() method */
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_has_%s(const ", field->name.name);
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (header_only) {
        fprintf(output, ";\n");
    } else {
        fprintf(output, "\n{\n");
        if (field->qualifier == PROTO3_QUAL_REPEATED ||
                field->qualifier == PROTO3_QUAL_PACKED) {
            fprintf(output, "    return obj ? (obj->%s_count_ != 0) : 0;\n",
                    field->name.name);
        } else {
            fprintf(output, "    return obj ? (obj->%s != 0) : 0;\n",
                    field->name.name);
        }
        fprintf(output, "}\n\n");
    }

    /* Output the value accessors */
    if (field->qualifier == PROTO3_QUAL_REPEATED ||
            field->qualifier == PROTO3_QUAL_PACKED) {
        /* Output the count() method */
        fprintf(output, "size_t ");
        generate_name(output, message->name.name);
        fprintf(output, "_count_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s_count_ : 0;\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the get_at() method */
        generate_name(output, field->type.name.name);
        fprintf(output, " *");
        generate_name(output, message->name.name);
        fprintf(output, "_get_at_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, size_t index)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (obj && index < obj->%s_count_)\n",
                    field->name.name);
            fprintf(output, "        return obj->%s[index];\n",
                    field->name.name);
            fprintf(output, "    else\n");
            fprintf(output, "        return 0;\n");
            fprintf(output, "}\n\n");
        }

        /* Output the add() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_add_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, ");
        generate_name(output, field->type.name.name);
        fprintf(output, " **value)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    int err;\n");
            fprintf(output, "    if (!value)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "    *value = 0;\n");
            fprintf(output, "    if (!obj)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "    err = ");
            generate_name(output, field->type.name.name);
            fprintf(output, "_new(value);\n");
            fprintf(output, "    if (err != NOISE_ERROR_NONE)\n");
            fprintf(output, "        return err;\n");
            fprintf(output, "    err = noise_protobuf_add_to_array(");
            fprintf(output, "(void **)&(obj->%s), &(obj->%s_count_), ",
                    field->name.name, field->name.name);
            fprintf(output, "&(obj->%s_max_), value, sizeof(*value));\n",
                    field->name.name);
            fprintf(output, "    if (err != NOISE_ERROR_NONE) {\n");
            fprintf(output, "        ");
            generate_name(output, field->type.name.name);
            fprintf(output, "_free(*value);\n");
            fprintf(output, "        *value = 0;\n");
            fprintf(output, "        return err;\n");
            fprintf(output, "    }\n");
            fprintf(output, "    return NOISE_ERROR_NONE;\n");
            fprintf(output, "}\n\n");
        }

        /* Output the insert() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_insert_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, size_t index, ");
        generate_name(output, field->type.name.name);
        fprintf(output, " *value)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    if (!obj || !value)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "    return noise_protobuf_insert_into_array(");
            fprintf(output, "(void **)&(obj->%s), &(obj->%s_count_), ",
                    field->name.name, field->name.name);
            fprintf(output, "&(obj->%s_max_), index, &value, sizeof(value));\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }
    } else {
        /* Output the get() method */
        generate_name(output, field->type.name.name);
        fprintf(output, " *");
        generate_name(output, message->name.name);
        fprintf(output, "_get_%s(const ", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    return obj ? obj->%s : 0;\n",
                    field->name.name);
            fprintf(output, "}\n\n");
        }

        /* Output the get_new() method */
        fprintf(output, "int ");
        generate_name(output, message->name.name);
        fprintf(output, "_get_new_%s(", field->name.name);
        generate_name(output, message->name.name);
        fprintf(output, " *obj, ");
        generate_name(output, field->type.name.name);
        fprintf(output, " **value)");
        if (header_only) {
            fprintf(output, ";\n");
        } else {
            fprintf(output, "\n{\n");
            fprintf(output, "    int err;\n");
            fprintf(output, "    if (!value)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "    *value = 0;\n");
            fprintf(output, "    if (!obj)\n");
            fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
            fprintf(output, "    err = ");
            generate_name(output, field->type.name.name);
            fprintf(output, "_new(value);\n");
            fprintf(output, "    if (err != NOISE_ERROR_NONE)\n");
            fprintf(output, "        return err;\n");
            fprintf(output, "    ");
            generate_name(output, field->type.name.name);
            fprintf(output, "_free(obj->%s);\n", field->name.name);
            fprintf(output, "    obj->%s = *value;\n", field->name.name);
            fprintf(output, "    return NOISE_ERROR_NONE;\n");
            fprintf(output, "}\n\n");
        }
    }
}

/* Field operations for all of the protobuf types */
static Proto3TypeOps const type_int32 = {
    .proto_name = "int32",
    .c_name = "int32_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_uint32 = {
    .proto_name = "uint32",
    .c_name = "uint32_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_int64 = {
    .proto_name = "int64",
    .c_name = "int64_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_uint64 = {
    .proto_name = "uint64",
    .c_name = "uint64_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_sint32 = {
    .proto_name = "sint32",
    .c_name = "int32_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_sint64 = {
    .proto_name = "sint64",
    .c_name = "int64_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_fixed32 = {
    .proto_name = "fixed32",
    .c_name = "uint32_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_sfixed32 = {
    .proto_name = "sfixed32",
    .c_name = "int32_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_fixed64 = {
    .proto_name = "fixed64",
    .c_name = "uint64_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_sfixed64 = {
    .proto_name = "sfixed64",
    .c_name = "int64_t",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_float = {
    .proto_name = "float",
    .c_name = "float",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_double = {
    .proto_name = "double",
    .c_name = "double",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_bool = {
    .proto_name = "bool",
    .c_name = "int",
    .declare_field = type_numeric_declare_field,
    .free_field = type_numeric_free_field,
    .clear_field = type_numeric_clear_field,
    .write_field = type_numeric_write_field,
    .read_field = type_numeric_read_field,
    .declare_field_ops = type_numeric_declare_field_ops
};
static Proto3TypeOps const type_string = {
    .proto_name = "string",
    .c_name = "char *",
    .declare_field = type_string_declare_field,
    .free_field = type_string_free_field,
    .clear_field = type_string_clear_field,
    .write_field = type_string_write_field,
    .read_field = type_string_read_field,
    .declare_field_ops = type_string_declare_field_ops
};
static Proto3TypeOps const type_bytes = {
    .proto_name = "bytes",
    .c_name = "void *",
    .declare_field = type_string_declare_field,
    .free_field = type_string_free_field,
    .clear_field = type_string_clear_field,
    .write_field = type_string_write_field,
    .read_field = type_string_read_field,
    .declare_field_ops = type_string_declare_field_ops
};
static Proto3TypeOps const type_named = {
    .proto_name = "named",
    .c_name = "void *",
    .declare_field = type_named_declare_field,
    .free_field = type_named_free_field,
    .clear_field = type_named_clear_field,
    .write_field = type_named_write_field,
    .read_field = type_named_read_field,
    .declare_field_ops = type_named_declare_field_ops
};

/**
 * \brief Gets the operation list for a type.
 */
static const Proto3TypeOps *type_ops(Proto3Type type)
{
    switch (type.id) {
    case PROTO3_TYPE_INVALID:
        break;

    case PROTO3_TYPE_INT32:
    case PROTO3_TYPE_ENUM:
        return &type_int32;

    case PROTO3_TYPE_UINT32:
        return &type_uint32;

    case PROTO3_TYPE_INT64:
        return &type_int64;

    case PROTO3_TYPE_UINT64:
        return &type_uint64;

    case PROTO3_TYPE_SINT32:
        return &type_sint32;

    case PROTO3_TYPE_SINT64:
        return &type_sint64;

    case PROTO3_TYPE_FIXED32:
        return &type_fixed32;

    case PROTO3_TYPE_SFIXED32:
        return &type_sfixed32;

    case PROTO3_TYPE_FIXED64:
        return &type_fixed64;

    case PROTO3_TYPE_SFIXED64:
        return &type_sfixed64;

    case PROTO3_TYPE_FLOAT:
        return &type_float;

    case PROTO3_TYPE_DOUBLE:
        return &type_double;

    case PROTO3_TYPE_BOOL:
        return &type_bool;

    case PROTO3_TYPE_STRING:
        return &type_string;

    case PROTO3_TYPE_BYTES:
        return &type_bytes;

    case PROTO3_TYPE_MAP:
        /* TODO */
        break;

    case PROTO3_TYPE_NAMED:
        return &type_named;
    }
    return 0;
}

/**
 * \brief Generates the license block at the top of a header/source file.
 */
static void generate_license(FILE *output)
{
    FILE *lfile;
    char buffer[BUFSIZ];
    if (!license_file)
        return;
    lfile = fopen(license_file, "r");
    if (!lfile) {
        perror(license_file);
        return;
    }
    fprintf(output, "/*\n");
    while (fgets(buffer, sizeof(buffer), lfile)) {
        fprintf(output, " * ");
        fputs(buffer, output);
    }
    fprintf(output, " */\n\n");
    fclose(lfile);
}

/**
 * \brief Determine if a message contains repeated fields.
 */
static int has_repeated(const Proto3Message *message)
{
    const Proto3Field *field = message->fields;
    while (field != 0) {
        if (field->qualifier == PROTO3_QUAL_REPEATED)
            return 1;
        field = field->next;
    }
    return 0;
}

/**
 * \brief Determine if a message contains packed fields.
 */
static int has_packed(const Proto3Message *message)
{
    const Proto3Field *field = message->fields;
    while (field != 0) {
        if (field->qualifier == PROTO3_QUAL_PACKED)
            return 1;
        field = field->next;
    }
    return 0;
}

/**
 * \brief Generates the declaration for a constructor.
 */
static void generate_declare_ctor
    (FILE *output, Proto3Message *message, int is_h)
{
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_new(");
    generate_name(output, message->name.name);
    fprintf(output, " **obj)");
    if (is_h)
        putc(';', output);
    fprintf(output, "\n");
}

/**
 * \brief Generates the declaration for a destructor.
 */
static void generate_declare_dtor
    (FILE *output, Proto3Message *message, int is_h)
{
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_free(");
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (is_h)
        putc(';', output);
    fprintf(output, "\n");
}

/**
 * \brief Generates the write function declaration for a message type.
 */
static void generate_declare_write
    (FILE *output, Proto3Message *message, int is_h)
{
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_write(NoiseProtobuf *pbuf, int tag, const ");
    generate_name(output, message->name.name);
    fprintf(output, " *obj)");
    if (is_h)
        putc(';', output);
    fprintf(output, "\n");
}

/**
 * \brief Generates the read function declaration for a message type.
 */
static void generate_declare_read
    (FILE *output, Proto3Message *message, int is_h)
{
    fprintf(output, "int ");
    generate_name(output, message->name.name);
    fprintf(output, "_read(NoiseProtobuf *pbuf, int tag, ");
    generate_name(output, message->name.name);
    fprintf(output, " **obj)");
    if (is_h)
        putc(';', output);
    fprintf(output, "\n");
}

/**
 * \brief Generates the header file for the protobuf definition.
 */
static void generate_c_header(const char *output_h_name, FILE *output_h)
{
    Proto3Enum *enum_node;
    Proto3EnumValue *enum_value;
    Proto3Message *message;
    Proto3Field *field;
    const Proto3TypeOps *ops;
    int need_space = 0;

    /* Output the header */
    output = output_h;
    generate_license(output);
    fprintf(output, "#ifndef __");
    generate_name(output, output_h_name);
    fprintf(output, "__\n#define __");
    generate_name(output, output_h_name);
    fprintf(output, "__\n\n");
    fprintf(output, "#include <noise/protobufs.h>\n\n");
    fprintf(output, "#ifdef __cplusplus\n");
    fprintf(output, "extern \"C\" {\n");
    fprintf(output, "#endif\n\n");

    /* Generate macros for all enumerated constants */
    enum_node = proto3_first_enum();
    while (enum_node != 0) {
        if (need_space)
            fprintf(output, "\n");
        enum_value = enum_node->values;
        while (enum_value != 0) {
            fprintf(output, "#define ");
            generate_name(output, enum_node->name.name);
            putc('_', output);
            generate_name(output, enum_value->name.name);
            fprintf(output, " %lu\n", (unsigned long)(enum_value->value));
            enum_value = enum_value->next;
        }
        need_space = 1;
        enum_node = enum_node->next;
    }
    if (need_space) {
        fprintf(output, "\n");
        need_space = 0;
    }

    /* Generate typedef's for all message types */
    message = proto3_first_message();
    while (message != 0) {
        fprintf(output, "typedef struct _");
        generate_name(output, message->name.name);
        putc(' ', output);
        generate_name(output, message->name.name);
        fprintf(output, ";\n");
        need_space = 1;
        message = message->next;
    }

    /* Generate the accessor API's for all message types */
    message = proto3_first_message();
    while (message != 0) {
        if (need_space)
            fprintf(output, "\n");
        generate_declare_ctor(output, message, 1);
        generate_declare_dtor(output, message, 1);
        generate_declare_write(output, message, 1);
        generate_declare_read(output, message, 1);
        field = message->fields;
        while (field != 0) {
            ops = type_ops(field->type);
            (*(ops->declare_field_ops))(ops, message, field, 1);
            field = field->next;
        }
        need_space = 1;
        message = message->next;
    }

    /* Output the footer */
    if (need_space)
        fprintf(output, "\n");
    fprintf(output, "#ifdef __cplusplus\n");
    fprintf(output, "};\n");
    fprintf(output, "#endif\n\n");
    fprintf(output, "#endif\n");
}

/**
 * \brief Generates the implementation for a constructor.
 */
static void generate_implement_ctor(FILE *output, Proto3Message *message)
{
    generate_declare_ctor(output, message, 0);
    fprintf(output, "{\n");
    fprintf(output, "    if (!obj)\n");
    fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
    fprintf(output, "    *obj = (");
    generate_name(output, message->name.name);
    fprintf(output, " *)calloc(1, sizeof(");
    generate_name(output, message->name.name);
    fprintf(output, "));\n");
    fprintf(output, "    if (!(*obj))\n");
    fprintf(output, "        return NOISE_ERROR_NO_MEMORY;\n");
    fprintf(output, "    return NOISE_ERROR_NONE;\n");
    fprintf(output, "}\n\n");
}

/**
 * \brief Generates the implementation for a destructor.
 */
static void generate_implement_dtor(FILE *output, Proto3Message *message)
{
    const Proto3TypeOps *ops;
    Proto3Field *field = message->fields;
    generate_declare_dtor(output, message, 0);
    fprintf(output, "{\n");
    if (has_repeated(message) || has_packed(message))
        fprintf(output, "    size_t index;\n");
    fprintf(output, "    if (!obj)\n");
    fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
    indent_level = 1;
    while (field != 0) {
        ops = type_ops(field->type);
        ops->free_field(ops, field);
        field = field->next;
    }
    fprintf(output, "    noise_protobuf_free_memory(obj, sizeof(");
    generate_name(output, message->name.name);
    fprintf(output, "));\n");
    fprintf(output, "    return NOISE_ERROR_NONE;\n");
    fprintf(output, "}\n\n");
}

/**
 * \brief Generates the write function implementation for a message field.
 *
 * Field writes are output in reverse order of tag number.
 */
static void generate_implement_field_write
    (Proto3Message *message, Proto3Field *field)
{
    const Proto3TypeOps *ops;
    if (!field)
        return;
    generate_implement_field_write(message, field->next);
    ops = type_ops(field->type);
    ops->write_field(ops, (int)(field->tag), field);
}

/**
 * \brief Generates the write function implementation for a message type.
 */
static void generate_implement_write(Proto3Message *message)
{
    generate_declare_write(output, message, 0);
    fprintf(output, "{\n");
    fprintf(output, "    size_t end_posn;\n");
    if (has_packed(message)) {
        fprintf(output, "    size_t end_packed;\n");
        fprintf(output, "    size_t index;\n");
    } else if (has_repeated(message)) {
        fprintf(output, "    size_t index;\n");
    }
    fprintf(output, "    if (!pbuf || !obj)\n");
    fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
    fprintf(output, "    noise_protobuf_write_end_element(pbuf, &end_posn);\n");
    indent_level = 1;
    generate_implement_field_write(message, message->fields);
    fprintf(output, "    return noise_protobuf_write_start_element(pbuf, tag, end_posn);\n");
    fprintf(output, "}\n\n");
}

/**
 * \brief Generates the read function implementation for a message type.
 */
static void generate_implement_read(FILE *output, Proto3Message *message)
{
    const Proto3TypeOps *ops;
    Proto3Field *field;
    int tag;
    generate_declare_read(output, message, 0);
    fprintf(output, "{\n");
    fprintf(output, "    int err;\n");
    fprintf(output, "    size_t end_posn;\n");
    fprintf(output, "    if (!obj)\n");
    fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
    fprintf(output, "    *obj = 0;\n");
    fprintf(output, "    if (!pbuf)\n");
    fprintf(output, "        return NOISE_ERROR_INVALID_PARAM;\n");
    fprintf(output, "    err = ");
    generate_name(output, message->name.name);
    fprintf(output, "_new(obj);\n");
    fprintf(output, "    if (err != NOISE_ERROR_NONE)\n");
    fprintf(output, "        return err;\n");
    fprintf(output, "    noise_protobuf_read_start_element(pbuf, tag, &end_posn);\n");
    fprintf(output, "    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {\n");
    fprintf(output, "        switch (noise_protobuf_peek_tag(pbuf)) {\n");
    indent_level = 3;
    field = message->fields;
    while (field != 0) {
        tag = (int)(field->tag);
        ops = type_ops(field->type);
        print_indent();
        fprintf(output, "case %d: {\n", tag);
        ++indent_level;
        ops->read_field(ops, tag, message, field);
        --indent_level;
        print_indent();
        fprintf(output, "} break;\n");
        field = field->next;
    }
    fprintf(output, "            default: {\n");
    fprintf(output, "                noise_protobuf_read_skip(pbuf);\n");
    fprintf(output, "            } break;\n");
    fprintf(output, "        }\n");
    fprintf(output, "    }\n");
    fprintf(output, "    err = noise_protobuf_read_end_element(pbuf, end_posn);\n");
    fprintf(output, "    if (err != NOISE_ERROR_NONE) {\n");
    fprintf(output, "        ");
    generate_name(output, message->name.name);
    fprintf(output, "_free(*obj);\n");
    fprintf(output, "        *obj = 0;\n");
    fprintf(output, "    }\n");
    fprintf(output, "    return err;\n");
    fprintf(output, "}\n\n");
}

/**
 * \brief Generates the source file for the protobuf definition.
 */
static void generate_c_source(const char *output_c_name,
                              const char *output_h_name,
                              FILE *output_c)
{
    const Proto3TypeOps *ops;
    Proto3Message *message;
    Proto3Field *field;

    /* Output the header */
    output = output_c;
    indent_level = 0;
    generate_license(output);
    fprintf(output, "#include \"%s\"\n", output_h_name);
    fprintf(output, "#include <stdlib.h>\n");
    fprintf(output, "#include <string.h>\n");
    fprintf(output, "\n");

    /* Output the message struct definitions */
    message = proto3_first_message();
    while (message != 0) {
        print_indent();
        fprintf(output, "struct _");
        generate_name(output, message->name.name);
        fprintf(output, " {\n");
        ++indent_level;
        field = message->fields;
        while (field != 0) {
            ops = type_ops(field->type);
            ops->declare_field(ops, field);
            field = field->next;
        }
        --indent_level;
        print_indent();
        fprintf(output, "};\n\n");
        message = message->next;
    }

    /* Output the accessor implementations for all message types */
    message = proto3_first_message();
    while (message != 0) {
        generate_implement_ctor(output, message);
        generate_implement_dtor(output, message);
        generate_implement_write(message);
        generate_implement_read(output, message);
        field = message->fields;
        while (field != 0) {
            ops = type_ops(field->type);
            (*(ops->declare_field_ops))(ops, message, field, 0);
            field = field->next;
        }
        message = message->next;
    }

}

void generate_c(const char *output_c_name, FILE *output_c,
                const char *output_h_name, FILE *output_h)
{
    char *ptr;

    /* Trim the filenames to remove paths */
    ptr = strrchr(output_c_name, '/');
    if (!ptr)
        ptr = strrchr(output_c_name, '\\');
    if (ptr)
        output_c_name = ptr + 1;
    ptr = strrchr(output_h_name, '/');
    if (!ptr)
        ptr = strrchr(output_h_name, '\\');
    if (ptr)
        output_h_name = ptr + 1;

    /* Output the header definitions */
    generate_c_header(output_h_name, output_h);

    /* Output the source definitions */
    generate_c_source(output_c_name, output_h_name, output_c);
}
