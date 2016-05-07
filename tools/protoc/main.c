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
#include "proto3-ast.h"

#define short_options "c:h:l:"

static struct option const long_options[] = {
    {"output-c",                required_argument,      NULL,       'c'},
    {"output-h",                required_argument,      NULL,       'h'},
    {"license",                 required_argument,      NULL,       'l'},
    {NULL,                      0,                      NULL,        0 }
};

int parse_file(const char *filename);
void generate_c(const char *output_c_name, FILE *output_c,
                const char *output_h_name, FILE *output_h);

static char *output_c_file = "proto_defs.c";
static char *output_h_file = "proto_defs.h";
static char *input_file = NULL;
char *license_file = NULL;

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
    fprintf(stderr, "    --license=filename, -l filename\n");
    fprintf(stderr, "        File containing Copyright license details to add to all outputs.\n");
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
        case 'l':   license_file = optarg; break;
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
    int retval = 0;
    FILE *output_c = NULL;
    FILE *output_h = NULL;

    /* Parse the command-line options */
    if (!parse_options(argc, argv))
        return 1;

    /* Parse the input file */
    if (!parse_file(input_file))
        retval = 1;

    /* Open the output files */
    if (!retval) {
        output_c = fopen(output_c_file, "w");
        if (!output_c) {
            perror(output_c_file);
            retval = 1;
        }
    }
    if (!retval) {
        output_h = fopen(output_h_file, "w");
        if (!output_h) {
            perror(output_h_file);
            retval = 1;
        }
    }

    /* Generate the output */
    if (!retval) {
        generate_c(output_c_file, output_c, output_h_file, output_h);
    }

    /* Close the output files */
    if (output_c)
        fclose(output_c);
    if (output_h)
        fclose(output_h);

    /* Clean up and exit */
    proto3_cleanup();
    if (retval) {
        unlink(output_c_file);
        unlink(output_h_file);
    }
    return retval;
}
