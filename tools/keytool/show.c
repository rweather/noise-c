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

#define short_options "p:fF"

static struct option const long_options[] = {
    {"passphrase",              required_argument,      NULL,       'p'},
    {"basic-fingerprint",       no_argument,            NULL,       'f'},
    {"full-fingerprint",        no_argument,            NULL,       'F'},
    {NULL,                      0,                      NULL,        0 }
};

static char *passphrase = NULL;
static int fingerprint_type = NOISE_FINGERPRINT_BASIC;
static int first_file_index = 0;

/* Print usage/help information */
void help_show(const char *progname)
{
    fprintf(stdout, "Usage: %s show [options] file ...\n\n", progname);
    fprintf(stdout, "Options:\n\n");
    fprintf(stdout, "    --passphrase=PASSPHRASE, -p PASSPHRASE\n");
    fprintf(stdout, "        Specifies the passphrase to unlock a private key file.\n");
    fprintf(stdout, "        Prompt the user if not specified on the command-line.\n\n");
    fprintf(stdout, "    --basic-fingerprint, -f\n");
    fprintf(stdout, "        Show a basic fingerprint for all public keys (default).\n\n");
    fprintf(stdout, "    --full-fingerprint, -F\n");
    fprintf(stdout, "        Show a full fingerprint for all public keys.\n\n");
}

/* Parse the command-line options */
static int parse_options_show(const char *progname, int argc, char *argv[])
{
    int index = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (ch) {
        case 'p':   passphrase = optarg; break;
        case 'f':   fingerprint_type = NOISE_FINGERPRINT_BASIC; break;
        case 'F':   fingerprint_type = NOISE_FINGERPRINT_FULL; break;
        default:
            help_show(progname);
            return 0;
        }
    }
    if ((optind + 1) > argc) {
        help_show(progname);
        return 0;
    }
    first_file_index = optind;
    return 1;
}

/* Main entry point for the "show" subcommand */
int main_show(const char *progname, int argc, char *argv[])
{
    int retval = 0;

    /* Parse the command-line options */
    if (!parse_options_show(progname, argc, argv))
        return 1;

    // TODO

    /* Clean up and exit */
    return retval;
}
