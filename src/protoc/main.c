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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#define short_options "c:h:"

static struct option const long_options[] = {
    {"output-c",                required_argument,      NULL,       'c'},
    {"output-h",                required_argument,      NULL,       'h'},
    {NULL,                      0,                      NULL,        0 }
};

int parse_file(const char *filename);

static char *output_c_file = "proto_defs.c";
static char *output_h_file = "proto_defs.h";
static char *input_file = NULL;

/* Print usage information */
static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options] proto-file\n\n", progname);
    fprintf(stderr, "Options:\n\n");
    fprintf(stderr, "    --output-c=filename, -c filename\n");
    fprintf(stderr, "        Name of the file for the output C source code.\n");
    fprintf(stderr, "        Defaults to proto_defs.c in the current directory.\n\n");
    fprintf(stderr, "    --output-h=filename, -h filename\n");
    fprintf(stderr, "        Name of the file for the output C header definitions.\n");
    fprintf(stderr, "        Defaults to proto_defs.h in the current directory.\n\n");
}

/* Parse the command-line options */
static int parse_options(int argc, char *argv[])
{
    const char *progname = argv[0];
    int index = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (ch) {
        case 'c':   output_c_file = optarg; break;
        case 'h':   output_h_file = optarg; break;
        default:
            usage(progname);
            return 0;
        }
    }
    if ((optind + 1) != argc) {
        usage(progname);
        return 0;
    }
    input_file = argv[optind];
    return 1;
}

int main(int argc, char *argv[])
{
    /* Parse the command-line options */
    if (!parse_options(argc, argv))
        return 1;

    /* Parse the input file */
    if (!parse_file(input_file))
        return 1;

    return 0;
}
