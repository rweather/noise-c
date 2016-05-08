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

#include "keytool.h"

/* Print usage information */
static void usage(const char *progname)
{
    fprintf(stdout, "Usage: %s command [options] ...\n\n", progname);
    fprintf(stdout, "Commands:\n\n");
    fprintf(stdout, "    generate   Generate a private key and certificate.\n");
    fprintf(stdout, "    show       Show information about a key or certificate.\n");
    fprintf(stdout, "    sign       Sign a certificate.\n");
    fprintf(stdout, "    help       Show command-specific help.\n");
    fprintf(stdout, "\n");
}

int main(int argc, char *argv[])
{
    const char *progname = argv[0];

    /* Need at least 1 argument for the subcommand name */
    if (argc < 2) {
        usage(progname);
        return 1;
    }

    /* Determine which subcommand to run */
    if (!strcmp(argv[1], "generate")) {
        return main_generate(progname, argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "show")) {
        return main_show(progname, argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "sign")) {
        return main_sign(progname, argc - 1, argv + 1);
    } else if (!strcmp(argv[1], "help") && argc > 2) {
        if (!strcmp(argv[2], "generate")) {
            help_generate(progname);
            return 0;
        } else if (!strcmp(argv[2], "show")) {
            help_show(progname);
            return 0;
        } else if (!strcmp(argv[2], "sign")) {
            help_sign(progname);
            return 0;
        }
    }

    /* No idea what to do - print generic usage information */
    usage(progname);
    return 1;
}
