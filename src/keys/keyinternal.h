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

#ifndef NOISE_KEYINTERNAL_H
#define NOISE_KEYINTERNAL_H

#include <noise/keys.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file keyinternal.h
 * \brief Internal definitions for the Noise keys library.
 *
 * \note This file and its definitions are not part of the public API.
 * The definitions are subject to change without notice.
 */

#define MAX_KEY_LEN 64

typedef struct
{
    FILE *file;
    NoiseBuffer *buffer;
    size_t posn;
    int saw_eof;
    NoiseDHState *dh;
    NoiseSignState *sign;
    uint8_t key[MAX_KEY_LEN];   /* TODO: get rid of this from here */

} NoiseKeyStream;

void noise_key_stream_close(NoiseKeyStream *stream);

int noise_key_stream_getc(NoiseKeyStream *stream);
void noise_key_stream_ungetc(NoiseKeyStream *stream, int ch);

int noise_key_stream_expect_eof(NoiseKeyStream *stream);
int noise_key_stream_expect_white_eof(NoiseKeyStream *stream);

size_t noise_key_stream_read_binary
    (NoiseKeyStream *stream, uint8_t *data, size_t max_len);
size_t noise_key_stream_read_base64
    (NoiseKeyStream *stream, uint8_t *data, size_t max_len, int multi_line);

int noise_key_stream_write_binary
    (NoiseKeyStream *stream, const uint8_t *data, size_t len);
int noise_key_stream_write_base64
    (NoiseKeyStream *stream, const uint8_t *data, size_t len, int multi_line);

#ifdef __cplusplus
};
#endif

#endif
