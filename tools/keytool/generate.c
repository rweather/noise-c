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

#define short_options "i:n:r:a:p:"

static struct option const long_options[] = {
    {"id",                      required_argument,      NULL,       'i'},
    {"name",                    required_argument,      NULL,       'n'},
    {"role",                    required_argument,      NULL,       'r'},
    {"algorithms",              required_argument,      NULL,       'a'},
    {"passphrase",              required_argument,      NULL,       'p'},
    {NULL,                      0,                      NULL,        0 }
};

static char *id = NULL;
static char *name = NULL;
static char *role = NULL;
static char *algorithms = "all";
static char *passphrase = NULL;
static char *certificate_file = NULL;
static char *private_key_file = NULL;

/* Print help/usage information */
void help_generate(const char *progname)
{
    fprintf(stdout, "Usage: %s generate [options] certificate-file private-key-file\n\n", progname);
    fprintf(stdout, "Options:\n\n");
    fprintf(stdout, "    --id=ID, -i ID\n");
    fprintf(stdout, "        Identifier for the key owner; e.g. foo@domain.\n\n");
    fprintf(stdout, "    --name=NAME, -n NAME\n");
    fprintf(stdout, "        Human-readable name for the key owner.\n\n");
    fprintf(stdout, "    --role=ROLE, -r ROLE\n");
    fprintf(stdout, "        Role indicating how the key will be used.\n\n");
    fprintf(stdout, "    --algorithms=ALGS, -a ALGS\n");
    fprintf(stdout, "        Comma-separated list of the public key algorithms to generate keys for.\n");
    fprintf(stdout, "        Allowed values: '25519', '448', 'Ed25519', 'all'.  Default is 'all'.\n\n");
    fprintf(stdout, "    --passphrase=PASSPHRASE, -p PASSPHRASE\n");
    fprintf(stdout, "        Specifies the passphrase to use to protect the private key.\n");
    fprintf(stdout, "        Prompt the user if not specified on the command-line.\n\n");
}

/* Parse the command-line options */
static int parse_options_generate(const char *progname, int argc, char *argv[])
{
    int index = 0;
    int ch;
    while ((ch = getopt_long(argc, argv, short_options, long_options, &index)) != -1) {
        switch (ch) {
        case 'i':   id = optarg; break;
        case 'n':   name = optarg; break;
        case 'r':   role = optarg; break;
        case 'a':   algorithms = optarg; break;
        case 'p':   passphrase = optarg; break;
        default:
            help_generate(progname);
            return 0;
        }
    }
    if ((optind + 2) != argc) {
        help_generate(progname);
        return 0;
    }
    certificate_file = argv[optind];
    private_key_file = argv[optind + 1];
    return 1;
}

/* Main entry point for the "generate" subcommand */
int main_generate(const char *progname, int argc, char *argv[])
{
    int retval = 0;

    /* Parse the command-line options */
    if (!parse_options_generate(progname, argc, argv))
        return 1;

    // TODO

    /* Clean up and exit */
    return retval;
}
