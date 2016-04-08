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

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <noise/noise.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int test_count;
extern int test_failures;
extern jmp_buf test_jump_back;

/**
 * \brief Verifies that a condition is true, failing the test if not.
 *
 * \param condition The boolean condition to test.
 */
#define _verify(condition)   \
    do { \
        if (!(condition)) { \
            printf(#condition " failed at " __FILE__ ":%d\n", __LINE__); \
            longjmp(test_jump_back, 1); \
        } \
    } while (0)
#define verify(condition) _verify((condition))

/**
 * \brief Compares two integer values for equality, failing the test if not.
 *
 * \param actual The actual value that was computed by the code under test.
 * \param expected The value that is expected.
 */
#define compare(actual, expected) \
    do { \
        long long _actual = (long long)(actual); \
        long long _expected = (long long)(expected); \
        if (_actual != _expected) { \
            printf(#actual " != " #expected " at " __FILE__ ":%d\n", __LINE__); \
            printf("    actual  : %Ld (0x%Lx)\n", _actual, _actual); \
            printf("    expected: %Ld (0x%Lx)\n", _expected, _expected); \
            longjmp(test_jump_back, 1); \
        } \
    } while (0)

/**
 * \brief Runs a test function.
 *
 * \param func The name of the function to run, excluding the "test_" prefix.
 */
#define test(func)   \
    do { \
        extern void test_##func(void); \
        if (!setjmp(test_jump_back)) { \
            ++test_count; \
            printf(#func " ... "); \
            fflush(stdout); \
            test_##func(); \
            printf("ok\n"); \
        } else { \
            ++test_failures; \
        } \
    } while (0)

#ifdef __cplusplus
};
#endif

#endif
