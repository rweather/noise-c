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

#ifndef __BLAKE2_ENDIAN_H__
#define __BLAKE2_ENDIAN_H__

#if defined(__WIN32__) || defined(WIN32)
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif
#elif defined(__APPLE__)
#include <machine/endian.h>
#if !defined( __BYTE_ORDER) && defined(__DARWIN_BYTE_ORDER)
#define __BYTE_ORDER __DARWIN_BYTE_ORDER
#endif
#if !defined( __BIG_ENDIAN) && defined(__DARWIN_BIG_ENDIAN)
#define __BIG_ENDIAN __DARWIN_BIG_ENDIAN
#endif
#if !defined( __LITTLE_ENDIAN) && defined(__DARWIN_LITTLE_ENDIAN)
#define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#endif
#else
#include <endian.h>
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define BLAKE2_LITTLE_ENDIAN 1
#endif

#endif
