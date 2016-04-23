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

#ifndef NOISE_BUFFER_H
#define NOISE_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint8_t *data;      /**< Points to the data in the buffer */
    size_t size;        /**< Current size of the data in the buffer */
    size_t max_size;    /**< Maximum size of the data in the buffer */

} NoiseBuffer;

#define noise_buffer_init(buffer)   \
    ((buffer).data = 0, (buffer).size = 0, (buffer).max_size = 0)
#define noise_buffer_set_output(buffer, ptr, len) \
    ((buffer).data = (ptr), (buffer).size = 0, (buffer).max_size = (len))
#define noise_buffer_set_input(buffer, ptr, len) \
    ((buffer).data = (ptr), (buffer).size = (buffer).max_size = (len))
#define noise_buffer_set_inout(buffer, ptr, len, max) \
    ((buffer).data = (ptr), (buffer).size = (len), (buffer).max_size = (max))

#ifdef __cplusplus
};
#endif

#endif
