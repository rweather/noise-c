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

#ifndef NOISE_PROTOBUFS_H
#define NOISE_PROTOBUFS_H

#include <noise/protocol/constants.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint8_t *data;
    size_t size;
    size_t posn;
    int error;

} NoiseProtobuf;

int noise_protobuf_prepare_input
    (NoiseProtobuf *pbuf, const uint8_t *data, size_t size);
int noise_protobuf_prepare_output
    (NoiseProtobuf *pbuf, uint8_t *data, size_t size);
int noise_protobuf_prepare_measure(NoiseProtobuf *pbuf, size_t max_size);

int noise_protobuf_finish_input(NoiseProtobuf *pbuf);
int noise_protobuf_finish_output
    (NoiseProtobuf *pbuf, uint8_t **data, size_t *size);
int noise_protobuf_finish_output_shift
    (NoiseProtobuf *pbuf, uint8_t **data, size_t *size);
int noise_protobuf_finish_measure(NoiseProtobuf *pbuf, size_t *size);

int noise_protobuf_write_int32(NoiseProtobuf *pbuf, int tag, int32_t value);
int noise_protobuf_write_uint32(NoiseProtobuf *pbuf, int tag, uint32_t value);
int noise_protobuf_write_int64(NoiseProtobuf *pbuf, int tag, int64_t value);
int noise_protobuf_write_uint64(NoiseProtobuf *pbuf, int tag, uint64_t value);
int noise_protobuf_write_sint32(NoiseProtobuf *pbuf, int tag, int32_t value);
int noise_protobuf_write_sint64(NoiseProtobuf *pbuf, int tag, int64_t value);
int noise_protobuf_write_sfixed32(NoiseProtobuf *pbuf, int tag, int32_t value);
int noise_protobuf_write_fixed32(NoiseProtobuf *pbuf, int tag, uint32_t value);
int noise_protobuf_write_sfixed64(NoiseProtobuf *pbuf, int tag, int64_t value);
int noise_protobuf_write_fixed64(NoiseProtobuf *pbuf, int tag, uint64_t value);
int noise_protobuf_write_float(NoiseProtobuf *pbuf, int tag, float value);
int noise_protobuf_write_double(NoiseProtobuf *pbuf, int tag, double value);
int noise_protobuf_write_bool(NoiseProtobuf *pbuf, int tag, int value);
int noise_protobuf_write_string
    (NoiseProtobuf *pbuf, int tag, const char *str, size_t size);
int noise_protobuf_write_bytes
    (NoiseProtobuf *pbuf, int tag, const void *data, size_t size);
int noise_protobuf_write_end_element(NoiseProtobuf *pbuf, size_t *end_posn);
int noise_protobuf_write_start_element
    (NoiseProtobuf *pbuf, int tag, size_t end_posn);

int noise_protobuf_peek_tag(const NoiseProtobuf *pbuf);
size_t noise_protobuf_peek_size(const NoiseProtobuf *pbuf);
int noise_protobuf_read_int32(NoiseProtobuf *pbuf, int tag, int32_t *value);
int noise_protobuf_read_uint32(NoiseProtobuf *pbuf, int tag, uint32_t *value);
int noise_protobuf_read_int64(NoiseProtobuf *pbuf, int tag, int64_t *value);
int noise_protobuf_read_uint64(NoiseProtobuf *pbuf, int tag, uint64_t *value);
int noise_protobuf_read_sint32(NoiseProtobuf *pbuf, int tag, int32_t *value);
int noise_protobuf_read_sint64(NoiseProtobuf *pbuf, int tag, int64_t *value);
int noise_protobuf_read_sfixed32(NoiseProtobuf *pbuf, int tag, int32_t *value);
int noise_protobuf_read_fixed32(NoiseProtobuf *pbuf, int tag, uint32_t *value);
int noise_protobuf_read_sfixed64(NoiseProtobuf *pbuf, int tag, int64_t *value);
int noise_protobuf_read_fixed64(NoiseProtobuf *pbuf, int tag, uint64_t *value);
int noise_protobuf_read_float(NoiseProtobuf *pbuf, int tag, float *value);
int noise_protobuf_read_double(NoiseProtobuf *pbuf, int tag, double *value);
int noise_protobuf_read_bool(NoiseProtobuf *pbuf, int tag, int *value);
int noise_protobuf_read_string
    (NoiseProtobuf *pbuf, int tag, char *str, size_t max_size, size_t *size);
int noise_protobuf_read_alloc_string
    (NoiseProtobuf *pbuf, int tag, char **str, size_t max_size, size_t *size);
int noise_protobuf_read_bytes
    (NoiseProtobuf *pbuf, int tag, void *data, size_t max_size, size_t *size);
int noise_protobuf_read_alloc_bytes
    (NoiseProtobuf *pbuf, int tag, void **data, size_t max_size, size_t *size);
int noise_protobuf_read_start_element
    (NoiseProtobuf *pbuf, int tag, size_t *end_posn);
int noise_protobuf_read_end_element(NoiseProtobuf *pbuf, size_t end_posn);
int noise_protobuf_read_at_end_element
    (const NoiseProtobuf *pbuf, size_t end_posn);
int noise_protobuf_read_stop(NoiseProtobuf *pbuf);
int noise_protobuf_read_skip(NoiseProtobuf *pbuf);

int noise_protobuf_add_to_array
    (void **array, size_t *count, size_t *max, const void *value, size_t size);
int noise_protobuf_add_to_string_array
    (char ***array, size_t **len_array, size_t *count, size_t *max,
     const char *value, size_t size);
int noise_protobuf_add_to_bytes_array
    (void ***array, size_t **len_array, size_t *count, size_t *max,
     const void *value, size_t size);

int noise_protobuf_insert_into_array
    (void **array, size_t *count, size_t *max, size_t index,
     const void *value, size_t size);

void noise_protobuf_free_memory(void *ptr, size_t size);

#ifdef __cplusplus
};
#endif

#endif
