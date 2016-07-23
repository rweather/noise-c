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

/* Name of the encryption scheme to use to protect private keys */
#define PROTECT_NAME    "ChaChaPoly_BLAKE2b_PBKDF2"

#define MAX_ALGS 16

static char *id = NULL;
static char *name = NULL;
static char *role = NULL;
static char *passphrase = NULL;
static char *certificate_file = NULL;
static char *private_key_file = NULL;
static int alg_ids[MAX_ALGS];
static int num_alg_ids = 0;

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

/* Adds an ID to the list of algorithms to generate keys for */
static void add_algorithm_id(int id)
{
    int index;
    for (index = 0; index < num_alg_ids; ++index) {
        if (alg_ids[index] == id)
            return;
    }
    if (num_alg_ids < MAX_ALGS)
        alg_ids[num_alg_ids++] = id;
}

/* Parse the algorithm names */
static int parse_algorithms(const char *names)
{
    char *end;
    size_t len;
    while (*names != '\0') {
        end = strchr(names, ',');
        if (end)
            len = end - names;
        else
            len = strlen(names);
        if (len == 3 && !strncmp(names, "all", 3)) {
            add_algorithm_id(NOISE_DH_CURVE25519);
            add_algorithm_id(NOISE_DH_CURVE448);
            add_algorithm_id(NOISE_SIGN_ED25519);
        } else {
            int id = noise_name_to_id(NOISE_DH_CATEGORY, names, len);
            if (id == NOISE_DH_NONE) {
                id = noise_name_to_id(NOISE_SIGN_CATEGORY, names, len);
                if (id == NOISE_SIGN_NONE) {
                    fprintf(stderr, "Unknown algorithm id '");
                    fwrite(names, 1, len, stderr);
                    fprintf(stderr, "'\n");
                    return 0;
                }
                add_algorithm_id(id);
            }
        }
        names += len;
        if (*names == ',')
            ++names;
    }
    return 1;
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
        case 'a':
            if (!parse_algorithms(optarg))
                return 0;
            break;
        case 'p':   passphrase = optarg; break;
        default:
            help_generate(progname);
            return 0;
        }
    }
    if (!num_alg_ids) {
        parse_algorithms("all");
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
    Noise_PrivateKey *key = 0;
    Noise_Certificate *cert = 0;
    Noise_SubjectInfo *subject = 0;
    uint8_t *private_key = 0;
    uint8_t *public_key = 0;
    size_t private_key_length = 0;
    size_t public_key_length = 0;
    int index, err;

    /* Parse the command-line options */
    if (!parse_options_generate(progname, argc, argv))
        return 1;

    /* If there was no passphrase on the command-line, then prompt for one */
    if (!passphrase) {
        passphrase = ask_for_passphrase(1);
        if (!passphrase)
            return 1;
    }

    /* Create the private key and certificate objects */
    CHECK_ERROR(Noise_PrivateKey_new(&key));
    CHECK_ERROR(Noise_Certificate_new(&cert));
    CHECK_ERROR(Noise_Certificate_set_version(cert, 1));
    CHECK_ERROR(Noise_Certificate_get_new_subject(cert, &subject));
    if (id) {
        CHECK_ERROR(Noise_PrivateKey_set_id(key, id, strlen(id)));
        CHECK_ERROR(Noise_SubjectInfo_set_id(subject, id, strlen(id)));
    }
    if (name) {
        CHECK_ERROR(Noise_PrivateKey_set_name(key, name, strlen(name)));
        CHECK_ERROR(Noise_SubjectInfo_set_name(subject, name, strlen(name)));
    }
    if (role) {
        CHECK_ERROR(Noise_PrivateKey_set_role(key, role, strlen(role)));
        CHECK_ERROR(Noise_SubjectInfo_set_role(subject, role, strlen(role)));
    }

    /* Generate the key pairs */
    for (index = 0; index < num_alg_ids; ++index) {
        int id = alg_ids[index];
        const char *name = noise_id_to_name(0, id);
        Noise_PublicKeyInfo *pub_key = 0;
        Noise_PrivateKeyInfo *priv_key = 0;
        if (!name)
            continue;   /* Shouldn't happen, but just in case */
        CHECK_ERROR(Noise_SubjectInfo_add_keys(subject, &pub_key));
        CHECK_ERROR(Noise_PublicKeyInfo_set_algorithm
                        (pub_key, name, strlen(name)));
        CHECK_ERROR(Noise_PrivateKey_add_keys(key, &priv_key));
        CHECK_ERROR(Noise_PrivateKeyInfo_set_algorithm
                        (priv_key, name, strlen(name)));
        if ((id & 0xFF00) == NOISE_DH_CATEGORY) {
            /* Create a Diffie-Hellman keypair */
            NoiseDHState *dh = 0;
            if (noise_dhstate_new_by_id(&dh, id) == NOISE_ERROR_NONE) {
                public_key_length = noise_dhstate_get_public_key_length(dh);
                private_key_length = noise_dhstate_get_private_key_length(dh);
                public_key = (uint8_t *)malloc(public_key_length);
                private_key = (uint8_t *)malloc(private_key_length);
                if (!public_key || !private_key) {
                    fprintf(stderr, "Insufficient memory for key objects\n");
                    retval = 1;
                    goto cleanup;
                }
                err = noise_dhstate_generate_keypair(dh);
                if (err != NOISE_ERROR_NONE) {
                    noise_perror(name, err);
                    retval = 1;
                    goto cleanup;
                }
                noise_dhstate_get_keypair
                    (dh, private_key, private_key_length,
                     public_key, public_key_length);
                noise_dhstate_free(dh);
            } else {
                fprintf(stderr, "Unknown Diffie-Hellman algorithm '%s'\n",
                        name);
                retval = 1;
                goto cleanup;
            }
        } else {
            /* Create a signing keypair */
            NoiseSignState *sign = 0;
            if (noise_signstate_new_by_id(&sign, id) == NOISE_ERROR_NONE) {
                public_key_length = noise_signstate_get_public_key_length(sign);
                private_key_length = noise_signstate_get_private_key_length(sign);
                public_key = (uint8_t *)malloc(public_key_length);
                private_key = (uint8_t *)malloc(private_key_length);
                if (!public_key || !private_key) {
                    fprintf(stderr, "Insufficient memory for key objects\n");
                    retval = 1;
                    goto cleanup;
                }
                err = noise_signstate_generate_keypair(sign);
                if (err != NOISE_ERROR_NONE) {
                    noise_perror(name, err);
                    retval = 1;
                    goto cleanup;
                }
                noise_signstate_get_keypair
                    (sign, private_key, private_key_length,
                     public_key, public_key_length);
                noise_signstate_free(sign);
            } else {
                fprintf(stderr, "Unknown signing algorithm '%s'\n",
                        name);
                retval = 1;
                goto cleanup;
            }
        }
        CHECK_ERROR(Noise_PublicKeyInfo_set_key
                        (pub_key, public_key, public_key_length));
        CHECK_ERROR(Noise_PrivateKeyInfo_set_key
                        (priv_key, private_key, private_key_length));
        noise_free(private_key, private_key_length);
        noise_free(public_key, public_key_length);
        private_key = 0;
        public_key = 0;
        private_key_length = 0;
        public_key_length = 0;
    }

    /* Save the certificate and private key */
    err = noise_save_certificate_to_file(cert, certificate_file);
    if (err == NOISE_ERROR_SYSTEM) {
        perror(certificate_file);
        retval = 1;
        goto cleanup;
    } else if (err != NOISE_ERROR_NONE) {
        noise_perror(certificate_file, err);
        retval = 1;
        goto cleanup;
    }
    err = noise_save_private_key_to_file
        (key, private_key_file, passphrase, strlen(passphrase),
         PROTECT_NAME);
    if (err == NOISE_ERROR_SYSTEM) {
        perror(private_key_file);
        retval = 1;
        goto cleanup;
    } else if (err != NOISE_ERROR_NONE) {
        noise_perror(private_key_file, err);
        retval = 1;
        goto cleanup;
    }

    /* Clean up and exit */
cleanup:
    Noise_PrivateKey_free(key);
    Noise_Certificate_free(cert);
    noise_free(private_key, private_key_length);
    noise_free(public_key, public_key_length);
    return retval;
}
