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

#include <noise/protocol.h>
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
extern const char *data_name;
extern int verbose;

/**
 * \brief Immediate fail of the test.
 *
 * \param message The failure message to print.
 */
#define _fail(message)   \
    do { \
        if (data_name) \
            printf("%s: ", data_name); \
        printf("%s, failed at " __FILE__ ":%d\n", (message), __LINE__); \
        longjmp(test_jump_back, 1); \
    } while (0)
#define fail(message) _fail((message))

/**
 * \brief Verifies that a condition is true, failing the test if not.
 *
 * \param condition The boolean condition to test.
 */
#define _verify(condition)   \
    do { \
        if (!(condition)) { \
            if (data_name) \
                printf("%s: ", data_name); \
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
            if (data_name) \
                printf("%s: ", data_name); \
            printf(#actual " != " #expected " at " __FILE__ ":%d\n", __LINE__); \
            printf("    actual  : %lld (0x%llx)\n", _actual, _actual); \
            printf("    expected: %lld (0x%llx)\n", _expected, _expected); \
            longjmp(test_jump_back, 1); \
        } \
    } while (0)

/**
 * \brief Compares two memory blocks for equality.
 *
 * \param actual Points to the actual memory block from the code under test.
 * \param actual_len The length of the actual memory block.
 * \param expected Points to the expected memory block.
 * \param expected_len The length of the expected memory block.
 */
#define compare_blocks(actual, actual_len, expected, expected_len) \
    do { \
        size_t _actual_len = (size_t)(actual_len); \
        size_t _expected_len = (size_t)(expected_len); \
        if (_actual_len != _expected_len || memcmp((actual), (expected), _actual_len) != 0) { \
            if (data_name) \
                printf("%s: ", data_name); \
            printf(#actual " != " #expected " at " __FILE__ ":%d\n", __LINE__); \
            print_block("    actual  ", (actual), _actual_len); \
            print_block("    expected", (expected), _expected_len); \
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
        data_name = 0; \
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

/**
 * \brief Converts a string from ASCII or hex into binary.
 *
 * \param data The data buffer to fill.
 * \param max_len The maximum length of \a data in bytes.
 * \param str The string to convert.  If the string starts with "0x", then
 * the remaining characters are assumed to be in hex.  Otherwise the string
 * is represented in ASCII.
 *
 * \return The actual length of the \a data in bytes.
 *
 * This function will fail the test case if the string is longer
 * than \a max_len.
 */
size_t string_to_data(uint8_t *data, size_t max_len, const char *str);

/**
 * \brief Prints a memory block in hex.
 *
 * \param tag Tag string indicating "actual" vs "expected".
 * \param data The data block to print.
 * \param size The size of the \a data block in bytes.
 */
void print_block(const char *tag, const uint8_t *data, size_t size);

#ifdef __cplusplus
};
#endif

#endif
