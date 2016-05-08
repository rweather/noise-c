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

#define short_options "k:a:p:m:n:"

static struct option const long_options[] = {
    {"signing-key",             required_argument,      NULL,       'k'},
    {"algorithm",               required_argument,      NULL,       'a'},
    {"passphrase",              required_argument,      NULL,       'p'},
    {"valid-months",            required_argument,      NULL,       'm'},
    {"nonce-size",              required_argument,      NULL,       'n'},
    {NULL,                      0,                      NULL,        0 }
};

static char *algorithm = NULL;
static char *passphrase = NULL;
static char *signing_key_file = NULL;
static char *input_certificate = NULL;
static char *output_certificate = NULL;
static int valid_months = 24;
static int nonce_size = 16;

/* Print usage/help information */
void help_sign(const char *progname)
{
    fprintf(stdout, "Usage: %s sign [options] input-certificate output-certificate\n\n", progname);
    fprintf(stdout, "Options:\n\n");
    fprintf(stdout, "    --signing-key=FILE, -s FILE\n");
    fprintf(stdout, "        Specifies the private key to sign the certificate with (required).\n\n");
    fprintf(stdout, "    --passphrase=PASSPHRASE, -p PASSPHRASE\n");
    fprintf(stdout, "        Specifies the passphrase to use to unlock the private key.\n");
    fprintf(stdout, "        Prompt the user if not specified on the command-line.\n\n");
    fprintf(stdout, "    --algorithm=ALG, -a ALG\n");
    fprintf(stdout, "        Specifies the algorithm to sign with.  Default is to use the first\n");
    fprintf(stdout, "        key value that is capable of signing.\n\n");
    fprintf(stdout, "    --valid-months=NUM-MONTHS, -m NUM-MONTHS\n");
    fprintf(stdout, "        Number of months that the certificate is valid for.  Default is 24.\n");
    fprintf(stdout, "        If the value is zero, then the validity period is unspecified.\n\n");
    fprintf(stdout, "    --nonce-size=SIZE, -n SIZE\n");
    fprintf(stdout, "        Size of the nonce value in bytes: 0, 16, 32, or 64.  Default is 16.\n\n");
}

/* Parse the command-line options */
static int parse_options_sign(const char *progname, int argc, char *argv[])
{
    int index = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (ch) {
        case 'k':   signing_key_file = optarg; break;
        case 'a':   algorithm = optarg; break;
        case 'p':   passphrase = optarg; break;
        case 'm':
            /* Sanity check the range a little bit: 0 to 20 years */
            valid_months = atoi(optarg);
            if (valid_months < 0)
                valid_months = 0;
            else if (valid_months > (20 * 12))
                valid_months = 20 * 12;
            break;
        case 'n':
            nonce_size = atoi(optarg);
            if (nonce_size != 0 && nonce_size != 16 &&
                    nonce_size != 32 && nonce_size != 64) {
                help_sign(progname);
                return 0;
            }
            break;
        default:
            help_sign(progname);
            return 0;
        }
    }
    if (!signing_key_file || (optind + 2) != argc) {
        help_sign(progname);
        return 0;
    }
    input_certificate = argv[optind];
    output_certificate = argv[optind + 1];
    return 1;
}

/* Main entry point for the "sign" subcommand */
int main_sign(const char *progname, int argc, char *argv[])
{
    int retval = 0;

    /* Parse the command-line options */
    if (!parse_options_sign(progname, argc, argv))
        return 1;

    // TODO

    /* Clean up and exit */
    return retval;
}
