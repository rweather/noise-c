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
static int multiple_files = 0;

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
    if ((optind + 2) <= argc) {
        multiple_files = 1;
    }
    first_file_index = optind;
    return 1;
}

/* Dump the information within a certificate */
static void dump_certificate(const Noise_Certificate *cert)
{
    size_t index, count;
    char fingerprint[NOISE_MAX_FINGERPRINT_LEN];
    printf("Version: %lu\n",
           (unsigned long)Noise_Certificate_get_version(cert));
    if (Noise_Certificate_has_subject(cert)) {
        const Noise_SubjectInfo *subject = Noise_Certificate_get_subject(cert);
        if (Noise_SubjectInfo_has_id(subject)) {
            printf("Id: %s\n", Noise_SubjectInfo_get_id(subject));
        }
        if (Noise_SubjectInfo_has_name(subject)) {
            printf("Name: %s\n", Noise_SubjectInfo_get_name(subject));
        }
        if (Noise_SubjectInfo_has_role(subject)) {
            printf("Role: %s\n", Noise_SubjectInfo_get_role(subject));
        }
        count = Noise_SubjectInfo_count_keys(subject);
        for (index = 0; index < count; ++index) {
            const Noise_PublicKeyInfo *key =
                Noise_SubjectInfo_get_at_keys(subject, index);
            const char *algorithm = Noise_PublicKeyInfo_get_algorithm(key);
            size_t key_size = Noise_PublicKeyInfo_get_size_key(key);
            const uint8_t *key_data =
                (const uint8_t *)Noise_PublicKeyInfo_get_key(key);
            if (!algorithm)
                algorithm = "Unknown";
            if (key_size) {
                int err = noise_format_fingerprint
                    (fingerprint_type, fingerprint, sizeof(fingerprint),
                     key_data, key_size);
                if (err != NOISE_ERROR_NONE)
                    noise_perror("fingerprint", err);
                printf("Public-Key-%s: %s\n", algorithm, fingerprint);
            } else {
                printf("Public-Key-%s: Not-Specified\n", algorithm);
            }
        }
        count = Noise_SubjectInfo_count_meta(subject);
        for (index = 0; index < count; ++index) {
            const Noise_MetaInfo *meta =
                Noise_SubjectInfo_get_at_meta(subject, index);
            const char *name = Noise_MetaInfo_get_name(meta);
            const char *value = Noise_MetaInfo_get_name(meta);
            if (!name)
                name = "Unknown";
            if (!value)
                value = "";
            printf("Meta: %s=%s\n", name, value);
        }
    }
}

/* Shows details for a certificate */
static int show_certificate(const char *filename, NoiseProtobuf *pbuf)
{
    Noise_Certificate *cert;
    int err;

    /* Load the certificate from the buffer */
    err = noise_load_certificate_from_buffer(&cert, pbuf);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(filename, err);
        return 0;
    }

    /* Dump the certificate details */
    if (multiple_files) {
        printf("--------\n");
        printf("%s:\n", filename);
    }
    dump_certificate(cert);

    /* Clean up and exit */
    Noise_Certificate_free(cert);
    return 1;
}

/* Shows details for a certificate chain */
static int show_certificate_chain(const char *filename, NoiseProtobuf *pbuf)
{
    Noise_CertificateChain *chain;
    size_t index, count;
    int err;

    /* Load the certificate chain from the buffer */
    err = noise_load_certificate_chain_from_buffer(&chain, pbuf);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(filename, err);
        return 0;
    }

    /* Dump the certificate chain details */
    if (multiple_files) {
        printf("--------\n");
        printf("%s:\n", filename);
    }
    count = Noise_CertificateChain_count_certs(chain);
    for (index = 0; index < count; ++index) {
        if (index != 0)
            printf("--------\n");
        dump_certificate(Noise_CertificateChain_get_at_certs(chain, index));
    }

    /* Clean up and exit */
    Noise_CertificateChain_free(chain);
    return 1;
}

/* Dump the information within a private key */
static void dump_private_key(const Noise_PrivateKey *priv_key)
{
    size_t index, count;
    char fingerprint[NOISE_MAX_FINGERPRINT_LEN];
    if (Noise_PrivateKey_has_id(priv_key)) {
        printf("Id: %s\n", Noise_PrivateKey_get_id(priv_key));
    }
    if (Noise_PrivateKey_has_name(priv_key)) {
        printf("Name: %s\n", Noise_PrivateKey_get_name(priv_key));
    }
    if (Noise_PrivateKey_has_role(priv_key)) {
        printf("Role: %s\n", Noise_PrivateKey_get_role(priv_key));
    }
    count = Noise_PrivateKey_count_keys(priv_key);
    for (index = 0; index < count; ++index) {
        const Noise_PrivateKeyInfo *key =
            Noise_PrivateKey_get_at_keys(priv_key, index);
        const char *algorithm = Noise_PrivateKeyInfo_get_algorithm(key);
        size_t key_size = Noise_PrivateKeyInfo_get_size_key(key);
        const uint8_t *key_data =
            (const uint8_t *)Noise_PrivateKeyInfo_get_key(key);
        if (!algorithm)
            algorithm = "Unknown";
        if (key_size) {
            NoiseDHState *dh = 0;
            NoiseSignState *sign = 0;
            int err;
            strcpy(fingerprint, "Unknown");
            if (noise_dhstate_new_by_name(&dh, algorithm) == NOISE_ERROR_NONE) {
                err = noise_dhstate_set_keypair_private
                        (dh, key_data, key_size);
                if (err == NOISE_ERROR_NONE) {
                    noise_dhstate_format_fingerprint
                        (dh, fingerprint_type, fingerprint,
                         sizeof(fingerprint));
                }
            } else if (noise_signstate_new_by_name(&sign, algorithm) == NOISE_ERROR_NONE) {
                err = noise_signstate_set_keypair_private
                        (sign, key_data, key_size);
                if (err == NOISE_ERROR_NONE) {
                    noise_signstate_format_fingerprint
                        (sign, fingerprint_type, fingerprint,
                         sizeof(fingerprint));
                }
            }
            printf("Public-Key-%s: %s\n", algorithm, fingerprint);
            noise_dhstate_free(dh);
            noise_signstate_free(sign);
        } else {
            printf("Public-Key-%s: Not-Specified\n", algorithm);
        }
    }
    count = Noise_PrivateKey_count_meta(priv_key);
    for (index = 0; index < count; ++index) {
        const Noise_MetaInfo *meta =
            Noise_PrivateKey_get_at_meta(priv_key, index);
        const char *name = Noise_MetaInfo_get_name(meta);
        const char *value = Noise_MetaInfo_get_name(meta);
        if (!name)
            name = "Unknown";
        if (!value)
            value = "";
        printf("Meta: %s=%s\n", name, value);
    }
}

/* Shows details for a private key after decrypting it */
static int show_private_key(const char *filename, NoiseProtobuf *pbuf)
{
    Noise_PrivateKey *priv_key;
    const char *pp;
    int err;

    /* Prompt for the passphrase if necessary */
    if (passphrase) {
        pp = passphrase;
    } else {
        pp = ask_for_passphrase(0);
        if (!pp)
            return 0;
    }

    /* Load the certificate from the buffer */
    err = noise_load_private_key_from_buffer(&priv_key, pbuf, pp, strlen(pp));
    if (err == NOISE_ERROR_MAC_FAILURE) {
        fprintf(stderr, "%s: Incorrect passphrase\n", filename);
        return 0;
    } else if (err != NOISE_ERROR_NONE) {
        noise_perror(filename, err);
        return 0;
    }

    /* Dump the private key details */
    if (multiple_files) {
        printf("--------\n");
        printf("%s:\n", filename);
    }
    dump_private_key(priv_key);

    /* Clean up and exit */
    Noise_PrivateKey_free(priv_key);
    return 1;
}

/* Shows the contents of a certificate or key file */
static int show_file(const char *filename)
{
    FILE *file;
    int ok = 1;
    uint8_t *data;
    size_t len;
    NoiseProtobuf pbuf;

    /* Read the file's contents into memory */
    data = (uint8_t *)malloc(NOISE_MAX_PAYLOAD_LEN);
    if (!data) {
        perror("malloc");
        return 0;
    }
    file = fopen(filename, "rb");
    if (!file) {
        perror(filename);
        noise_free(data, NOISE_MAX_PAYLOAD_LEN);
        return 0;
    }
    len = fread(data, 1, NOISE_MAX_PAYLOAD_LEN, file);
    if (!len) {
        if (ferror(file))
            perror(filename);
        else
            fprintf(stderr, "%s: Empty file\n", filename);
        fclose(file);
        noise_free(data, NOISE_MAX_PAYLOAD_LEN);
        return 0;
    }
    fclose(file);

    /* Based on the first tag byte, determine whether we have a
       certificate, a certificate chain, or a private key */
    noise_protobuf_prepare_input(&pbuf, data, len);
    if (data[0] == 0x50) {
        /* Encrypted private key */
        ok = show_private_key(filename, &pbuf);
    } else if (data[0] == 0x40) {
        /* Certificate chain */
        ok = show_certificate_chain(filename, &pbuf);
    } else {
        /* Everything else is assumed to be a plain certificate */
        ok = show_certificate(filename, &pbuf);
    }

    /* Clean up and exit */
    noise_free(data, NOISE_MAX_PAYLOAD_LEN);
    return ok;
}

/* Main entry point for the "show" subcommand */
int main_show(const char *progname, int argc, char *argv[])
{
    int retval = 0;

    /* Parse the command-line options */
    if (!parse_options_show(progname, argc, argv))
        return 1;

    /* Process all files */
    while (first_file_index < argc) {
        if (!show_file(argv[first_file_index]))
            retval = 1;
        ++first_file_index;
    }

    /* Clean up and exit */
    return retval;
}
