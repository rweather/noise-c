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

#include "test-helpers.h"
#include <noise/protobufs.h>

/* Tests for the "prepare" functions */
static void test_protobufs_prepare(void)
{
    uint8_t data[128];
    NoiseProtobuf pbuf;

    memset(data, 0xAA, sizeof(data));
    memset(&pbuf, 0x66, sizeof(pbuf));

    compare(noise_protobuf_prepare_input(&pbuf, data, sizeof(data)),
            NOISE_ERROR_NONE);
    verify(pbuf.data == data);
    compare(pbuf.size, sizeof(data));
    compare(pbuf.posn, 0);
    compare(pbuf.error, NOISE_ERROR_NONE);

    compare(noise_protobuf_prepare_input(0, data, sizeof(data)),
            NOISE_ERROR_INVALID_PARAM);
    pbuf.data = 0;
    compare(noise_protobuf_prepare_input(&pbuf, 0, sizeof(data)),
            NOISE_ERROR_INVALID_PARAM);
    verify(pbuf.data == 0);

    memset(&pbuf, 0x66, sizeof(pbuf));
    compare(noise_protobuf_prepare_output(&pbuf, data, sizeof(data)),
            NOISE_ERROR_NONE);
    verify(pbuf.data == data);
    compare(pbuf.size, sizeof(data));
    compare(pbuf.posn, sizeof(data));
    compare(pbuf.error, NOISE_ERROR_NONE);

    compare(noise_protobuf_prepare_output(0, data, sizeof(data)),
            NOISE_ERROR_INVALID_PARAM);
    pbuf.data = 0;
    compare(noise_protobuf_prepare_output(&pbuf, 0, sizeof(data)),
            NOISE_ERROR_INVALID_PARAM);
    verify(pbuf.data == 0);

    memset(&pbuf, 0x66, sizeof(pbuf));
    compare(noise_protobuf_prepare_measure(&pbuf, sizeof(data)),
            NOISE_ERROR_NONE);
    verify(pbuf.data == 0);
    compare(pbuf.size, sizeof(data));
    compare(pbuf.posn, sizeof(data));
    compare(pbuf.error, NOISE_ERROR_NONE);

    compare(noise_protobuf_prepare_measure(0, sizeof(data)),
            NOISE_ERROR_INVALID_PARAM);
}

#define is_int32(x)     ((x) >= -2147483648LL && (x) <= 2147483647LL)
#define is_uint32(x)    ((x) >= 0 && (x) <= 4294967295LL)
#define is_tag(x)       ((x) >= 1 && (x) <= 536870911LL)

/* Check the encoding/decoding of a specific integer value */
static void check_integer(int64_t value, const char *varint, const char *sint)
{
    uint8_t vinput[128];
    uint8_t sinput[128];
    uint8_t output[128];
    size_t vlen;
    size_t slen;
    NoiseProtobuf pbuf;
    uint8_t *out;
    size_t olen;
    static char number[64];
    int32_t val32;
    uint32_t uval32;
    int64_t val64;
    uint64_t uval64;
    int valbool;

    snprintf(number, sizeof(number), "%Ld", (long long)value);
    data_name = number;

    vlen = string_to_data(vinput, sizeof(vinput), varint);
    slen = string_to_data(sinput, sizeof(sinput), sint);

    /* Check int32 functions */
    if (is_int32(value)) {
        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_int32(&pbuf, 0, (int32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare_blocks(out, olen, vinput, vlen);

        compare(noise_protobuf_read_int32(&pbuf, 0, &val32),
                NOISE_ERROR_NONE);
        compare(val32, value);

        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_int32(&pbuf, 0, (int32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output_shift(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        verify(out == output);
        compare_blocks(out, olen, vinput, vlen);

        compare(noise_protobuf_prepare_input(&pbuf, output, olen),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_read_int32(&pbuf, 0, &val32),
                NOISE_ERROR_NONE);
        compare(val32, value);

        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_sint32(&pbuf, 0, (int32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare_blocks(out, olen, sinput, slen);

        compare(noise_protobuf_read_sint32(&pbuf, 0, &val32),
                NOISE_ERROR_NONE);
        compare(val32, value);

        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_sfixed32(&pbuf, 15, (int32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare(olen, 5);
        compare(out[0], (15 << 3) | 5);
        compare(out[1], (uint8_t)value);
        compare(out[2], (uint8_t)(value >> 8));
        compare(out[3], (uint8_t)(value >> 16));
        compare(out[4], (uint8_t)(value >> 24));

        compare(noise_protobuf_read_sfixed32(&pbuf, 15, &val32),
                NOISE_ERROR_NONE);
        compare(val32, value);

        compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
                NOISE_ERROR_NONE);
        verify(pbuf.data == 0);
        compare(noise_protobuf_write_int32(&pbuf, 0, (int32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_measure(&pbuf, &olen),
                NOISE_ERROR_NONE);
        compare(olen, vlen);

        compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_int32(&pbuf, 15, (int32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_measure(&pbuf, &olen),
                NOISE_ERROR_NONE);
        compare(olen, vlen + 1);
    }

    /* Check uint32 functions */
    if (is_uint32(value)) {
        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_uint32(&pbuf, 0, (uint32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare_blocks(out, olen, vinput, vlen);

        compare(noise_protobuf_read_uint32(&pbuf, 0, &uval32),
                NOISE_ERROR_NONE);
        compare(uval32, value);

        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_uint32(&pbuf, 0, (uint32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output_shift(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        verify(out == output);
        compare_blocks(out, olen, vinput, vlen);

        compare(noise_protobuf_prepare_input(&pbuf, output, olen),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_read_uint32(&pbuf, 0, &uval32),
                NOISE_ERROR_NONE);
        compare(uval32, value);

        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_sfixed32(&pbuf, 15, (uint32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare(olen, 5);
        compare(out[0], (15 << 3) | 5);
        compare(out[1], (uint8_t)value);
        compare(out[2], (uint8_t)(value >> 8));
        compare(out[3], (uint8_t)(value >> 16));
        compare(out[4], (uint8_t)(value >> 24));

        compare(noise_protobuf_read_fixed32(&pbuf, 15, &uval32),
                NOISE_ERROR_NONE);
        compare(uval32, value);

        compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
                NOISE_ERROR_NONE);
        verify(pbuf.data == 0);
        compare(noise_protobuf_write_uint32(&pbuf, 0, (uint32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_measure(&pbuf, &olen),
                NOISE_ERROR_NONE);
        compare(olen, vlen);

        compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_uint32(&pbuf, 15, (uint32_t)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_measure(&pbuf, &olen),
                NOISE_ERROR_NONE);
        compare(olen, vlen + 1);
    }

    /* Check int64 functions */
    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_int64(&pbuf, 0, value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    compare_blocks(out, olen, vinput, vlen);

    compare(noise_protobuf_read_int64(&pbuf, 0, &val64),
            NOISE_ERROR_NONE);
    compare(val64, value);

    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_int64(&pbuf, 0, value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output_shift(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    verify(out == output);
    compare_blocks(out, olen, vinput, vlen);

    compare(noise_protobuf_prepare_input(&pbuf, output, olen),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_read_int64(&pbuf, 0, &val64),
            NOISE_ERROR_NONE);
    compare(val64, value);

    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_sint64(&pbuf, 0, value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    compare_blocks(out, olen, sinput, slen);

    compare(noise_protobuf_read_sint64(&pbuf, 0, &val64),
            NOISE_ERROR_NONE);
    compare(val64, value);

    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_sfixed64(&pbuf, 15, value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    compare(olen, 9);
    compare(out[0], (15 << 3) | 1);
    compare(out[1], (uint8_t)value);
    compare(out[2], (uint8_t)(value >> 8));
    compare(out[3], (uint8_t)(value >> 16));
    compare(out[4], (uint8_t)(value >> 24));
    compare(out[5], (uint8_t)(value >> 32));
    compare(out[6], (uint8_t)(value >> 40));
    compare(out[7], (uint8_t)(value >> 48));
    compare(out[8], (uint8_t)(value >> 56));

    compare(noise_protobuf_read_sfixed64(&pbuf, 15, &val64),
            NOISE_ERROR_NONE);
    compare(val64, value);

    compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
            NOISE_ERROR_NONE);
    verify(pbuf.data == 0);
    compare(noise_protobuf_write_int64(&pbuf, 0, (int64_t)value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_measure(&pbuf, &olen),
            NOISE_ERROR_NONE);
    compare(olen, vlen);

    compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_int64(&pbuf, 15, (int64_t)value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_measure(&pbuf, &olen),
            NOISE_ERROR_NONE);
    compare(olen, vlen + 1);

    /* Check uint64 functions */
    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_uint64(&pbuf, 0, (uint64_t)value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    compare_blocks(out, olen, vinput, vlen);

    compare(noise_protobuf_read_uint64(&pbuf, 0, &uval64),
            NOISE_ERROR_NONE);
    compare(uval64, value);

    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_uint64(&pbuf, 0, (uint64_t)value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output_shift(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    verify(out == output);
    compare_blocks(out, olen, vinput, vlen);

    compare(noise_protobuf_prepare_input(&pbuf, output, olen),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_read_uint64(&pbuf, 0, &uval64),
            NOISE_ERROR_NONE);
    compare(uval64, value);

    compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_fixed64(&pbuf, 15, (uint64_t)value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
            NOISE_ERROR_NONE);
    compare(olen, 9);
    compare(out[0], (15 << 3) | 1);
    compare(out[1], (uint8_t)value);
    compare(out[2], (uint8_t)(value >> 8));
    compare(out[3], (uint8_t)(value >> 16));
    compare(out[4], (uint8_t)(value >> 24));
    compare(out[5], (uint8_t)(value >> 32));
    compare(out[6], (uint8_t)(value >> 40));
    compare(out[7], (uint8_t)(value >> 48));
    compare(out[8], (uint8_t)(value >> 56));

    compare(noise_protobuf_read_fixed64(&pbuf, 15, &uval64),
            NOISE_ERROR_NONE);
    compare(uval64, value);

    compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
            NOISE_ERROR_NONE);
    verify(pbuf.data == 0);
    compare(noise_protobuf_write_uint64(&pbuf, 0, value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_measure(&pbuf, &olen),
            NOISE_ERROR_NONE);
    compare(olen, vlen);

    compare(noise_protobuf_prepare_measure(&pbuf, sizeof(output)),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_write_uint64(&pbuf, 15, value),
            NOISE_ERROR_NONE);
    compare(noise_protobuf_finish_measure(&pbuf, &olen),
            NOISE_ERROR_NONE);
    compare(olen, vlen + 1);

    /* Check bool functions (non-zero is true, zero is false) */
    if (value >= -32768 && value <= 32767) {
        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_bool(&pbuf, 0, (int)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare(olen, 1);
        if (value)
            compare(out[0], 1);
        else
            compare(out[0], 0);

        compare(noise_protobuf_read_bool(&pbuf, 0, &valbool),
                NOISE_ERROR_NONE);
        if (value)
            compare(valbool, 1);
        else
            compare(valbool, 0);

        output[0] = 42;
        compare(noise_protobuf_prepare_input(&pbuf, output, 1),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_read_bool(&pbuf, 0, &valbool),
                NOISE_ERROR_NONE);
        compare(valbool, 1);

        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_bool(&pbuf, 15, (int)value),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);
        compare(olen, 2);
        compare(out[0], (15 << 3));
        if (value)
            compare(out[1], 1);
        else
            compare(out[1], 0);

        compare(noise_protobuf_read_bool(&pbuf, 15, &valbool),
                NOISE_ERROR_NONE);
        if (value)
            compare(valbool, 1);
        else
            compare(valbool, 0);
    }

    /* Check the use of the integer as a tag */
    if (is_tag(value)) {
        compare(noise_protobuf_prepare_output(&pbuf, output, sizeof(output)),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_write_uint64(&pbuf, (int)value, 128),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_finish_output(&pbuf, &out, &olen),
                NOISE_ERROR_NONE);

        compare(noise_protobuf_read_uint64(&pbuf, 0, &uval64),
                NOISE_ERROR_NONE);
        compare(uval64, (value << 3));
        compare(noise_protobuf_read_uint64(&pbuf, 0, &uval64),
                NOISE_ERROR_NONE);
        compare(uval64, 128);

        compare(noise_protobuf_prepare_input(&pbuf, out, olen),
                NOISE_ERROR_NONE);
        compare(noise_protobuf_read_uint64(&pbuf, (int)value, &uval64),
                NOISE_ERROR_NONE);
        compare(uval64, 128);
    }
}

/* Test the encoding and decoding of integer values */
static void test_protobufs_integers(void)
{
    /* Check values around multiples of 8 bits and 7 bits */
    check_integer(0LL, "0x00", "0x00");
    check_integer(1LL, "0x01", "0x02");
    check_integer(-1LL, "0xFFFFFFFFFFFFFFFFFF01", "0x01");
    check_integer(-2LL, "0xFEFFFFFFFFFFFFFFFF01", "0x03");
    check_integer(127LL, "0x7F", "0xFE01");
    check_integer(-127LL, "0x81FFFFFFFFFFFFFFFF01", "0xFD01");
    check_integer(128LL, "0x8001", "0x8002");
    check_integer(-128LL, "0x80FFFFFFFFFFFFFFFF01", "0xFF01");
    check_integer(16383LL, "0xFF7F", "0xFEFF01");
    check_integer(16384LL, "0x808001", "0x808002");
    check_integer(-16383LL, "0x8180FFFFFFFFFFFFFF01", "0xFDFF01");
    check_integer(-16384LL, "0x8080FFFFFFFFFFFFFF01", "0xFFFF01");
    check_integer(32767LL, "0xFFFF01", "0xFEFF03");
    check_integer(32768LL, "0x808002", "0x808004");
    check_integer(-32767LL, "0x8180FEFFFFFFFFFFFF01", "0xFDFF03");
    check_integer(-32768LL, "0x8080FEFFFFFFFFFFFF01", "0xFFFF03");
    check_integer(65535LL, "0xFFFF03", "0xFEFF07");
    check_integer(65536LL, "0x808004", "0x808008");
    check_integer(-65535LL, "0x8180FCFFFFFFFFFFFF01", "0xFDFF07");
    check_integer(-65536LL, "0x8080FCFFFFFFFFFFFF01", "0xFFFF07");
    check_integer(2097151LL, "0xFFFF7F", "0xFEFFFF01");
    check_integer(2097152LL, "0x80808001", "0x80808002");
    check_integer(-2097151LL, "0x818080FFFFFFFFFFFF01", "0xFDFFFF01");
    check_integer(-2097152LL, "0x808080FFFFFFFFFFFF01", "0xFFFFFF01");
    check_integer(16777215LL, "0xFFFFFF07", "0xFEFFFF0F");
    check_integer(16777216LL, "0x80808008", "0x80808010");
    check_integer(-16777215LL, "0x818080F8FFFFFFFFFF01", "0xFDFFFF0F");
    check_integer(-16777216LL, "0x808080F8FFFFFFFFFF01", "0xFFFFFF0F");
    check_integer(268435455LL, "0xFFFFFF7F", "0xFEFFFFFF01");
    check_integer(268435456LL, "0x8080808001", "0x8080808002");
    check_integer(-268435455LL, "0x81808080FFFFFFFFFF01", "0xFDFFFFFF01");
    check_integer(-268435456LL, "0x80808080FFFFFFFFFF01", "0xFFFFFFFF01");
    check_integer(2147483647LL, "0xFFFFFFFF07", "0xFEFFFFFF0F");
    check_integer(2147483648LL, "0x8080808008", "0x8080808010");
    check_integer(-2147483647LL, "0x81808080F8FFFFFFFF01", "0xFDFFFFFF0F");
    check_integer(-2147483648LL, "0x80808080F8FFFFFFFF01", "0xFFFFFFFF0F");
    check_integer(34359738367LL, "0xFFFFFFFF7F", "0xFEFFFFFFFF01");
    check_integer(34359738368LL, "0x808080808001", "0x808080808002");
    check_integer(-34359738367LL, "0x8180808080FFFFFFFF01", "0xFDFFFFFFFF01");
    check_integer(-34359738368LL, "0x8080808080FFFFFFFF01", "0xFFFFFFFFFF01");
    check_integer(4294967295LL, "0xFFFFFFFF0F", "0xFEFFFFFF1F");
    check_integer(4294967296LL, "0x8080808010", "0x8080808020");
    check_integer(-4294967295LL, "0x81808080F0FFFFFFFF01", "0xFDFFFFFF1F");
    check_integer(-4294967296LL, "0x80808080F0FFFFFFFF01", "0xFFFFFFFF1F");
    check_integer(1099511627775LL, "0xFFFFFFFFFF1F", "0xFEFFFFFFFF3F");
    check_integer(1099511627776LL, "0x808080808020", "0x808080808040");
    check_integer(-1099511627775LL, "0x8180808080E0FFFFFF01", "0xFDFFFFFFFF3F");
    check_integer(-1099511627776LL, "0x8080808080E0FFFFFF01", "0xFFFFFFFFFF3F");
    check_integer(4398046511103LL, "0xFFFFFFFFFF7F", "0xFEFFFFFFFFFF01");
    check_integer(4398046511104LL, "0x80808080808001", "0x80808080808002");
    check_integer(-4398046511103LL, "0x818080808080FFFFFF01", "0xFDFFFFFFFFFF01");
    check_integer(-4398046511104LL, "0x808080808080FFFFFF01", "0xFFFFFFFFFFFF01");
    check_integer(281474976710655LL, "0xFFFFFFFFFFFF3F", "0xFEFFFFFFFFFF7F");
    check_integer(281474976710656LL, "0x80808080808040", "0x8080808080808001");
    check_integer(-281474976710655LL, "0x818080808080C0FFFF01", "0xFDFFFFFFFFFF7F");
    check_integer(-281474976710656LL, "0x808080808080C0FFFF01", "0xFFFFFFFFFFFF7F");
    check_integer(562949953421311LL, "0xFFFFFFFFFFFF7F", "0xFEFFFFFFFFFFFF01");
    check_integer(562949953421312LL, "0x8080808080808001", "0x8080808080808002");
    check_integer(-562949953421311LL, "0x81808080808080FFFF01", "0xFDFFFFFFFFFFFF01");
    check_integer(-562949953421312LL, "0x80808080808080FFFF01", "0xFFFFFFFFFFFFFF01");
    check_integer(72057594037927935LL, "0xFFFFFFFFFFFFFF7F", "0xFEFFFFFFFFFFFFFF01");
    check_integer(72057594037927936LL, "0x808080808080808001", "0x808080808080808002");
    check_integer(-72057594037927935LL, "0x8180808080808080FF01", "0xFDFFFFFFFFFFFFFF01");
    check_integer(-72057594037927936LL, "0x8080808080808080FF01", "0xFFFFFFFFFFFFFFFF01");
    check_integer(9223372036854775807LL, "0xFFFFFFFFFFFFFFFF7F", "0xFEFFFFFFFFFFFFFFFF01");
    check_integer(-9223372036854775807LL, "0x81808080808080808001", "0xFDFFFFFFFFFFFFFFFF01");
    check_integer(9223372036854775808ULL, "0x80808080808080808001", "0xFFFFFFFFFFFFFFFFFF01");
}

void test_protobufs(void)
{
    test_protobufs_prepare();
    test_protobufs_integers();
}
