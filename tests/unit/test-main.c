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

int test_count = 0;
int test_failures = 0;
jmp_buf test_jump_back;
const char *data_name = 0;
int verbose = 0;

int main(int argc, char *argv[])
{
    /* Parse the command-line arguments */
    if (argc > 1 && !strcmp(argv[1], "--verbose"))
        verbose = 1;

    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    /* Run all tests */
    test(cipherstate);
    test(dhstate);
    test(errors);
    test(handshakestate);
    test(hashstate);
    test(names);
    test(patterns);
    test(protobufs);
    test(randstate);
    test(signstate);
    test(symmetricstate);

    /* Report the results */
    if (!test_failures) {
        printf("All tests succeeded\n");
    } else {
        printf("%d test%s failed\n", test_failures, test_failures == 1 ? "" : "s");
    }
    return test_failures ? 1 : 0;
}

static int from_hex(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    verify(0);
    return 0;
}

size_t string_to_data(uint8_t *data, size_t max_len, const char *str)
{
    size_t len;
    if (str[0] == '0' && str[1] == 'x') {
        /* Hexadecimal string */
        len = 0;
        str += 2;
        while (str[0] != '\0') {
            if (str[0] == ' ') {
                /* Skip spaces in the hexadecimal string */
                ++str;
                continue;
            }
            verify(str[1] != '\0');
            verify(len < max_len);
            data[len++] = from_hex(str[0]) * 16 + from_hex(str[1]);
            str += 2;
        }
        return len;
    } else {
        /* ASCII string */
        len = strlen(str);
        verify(len <= max_len);
        memcpy(data, str, len);
        return len;
    }
}

void print_block(const char *tag, const uint8_t *data, size_t size)
{
    printf("%s:", tag);
    while (size > 0) {
        printf(" %02x", *data);
        ++data;
        --size;
    }
    printf("\n");
}
