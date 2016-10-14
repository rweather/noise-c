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

/* Utility for creating keypairs for use with echo-client and echo-server */

#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int save_private_key(const char *filename, const uint8_t *key, size_t len);
int save_public_key(const char *filename, const uint8_t *key, size_t len);

int main(int argc, char *argv[])
{
    NoiseDHState *dh;
    const char *key_type = NULL;
    const char *priv_key_file = NULL;
    const char *pub_key_file = NULL;
    uint8_t *priv_key = 0;
    size_t priv_key_len = 0;
    uint8_t *pub_key = 0;
    size_t pub_key_len = 0;
    int ok = 1;
    int err;

    /* Parse the command-line arguments */
    if (argc < 4) {
        fprintf(stderr, "Usage: %s key-type private-key-file public-key-file\n\n", argv[0]);
        fprintf(stderr, "e.g. : %s 25519 client_key_25519 client_key_25519.pub\n", argv[0]);
        fprintf(stderr, "       %s 448 server_key_448 server_key_448.pub\n", argv[0]);
        return 1;
    }
    key_type = argv[1];
    priv_key_file = argv[2];
    pub_key_file = argv[3];

    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    /* Generate a keypair */
    err = noise_dhstate_new_by_name(&dh, key_type);
    if (err != NOISE_ERROR_NONE) {
        noise_perror(key_type, err);
        return 1;
    }
    err = noise_dhstate_generate_keypair(dh);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("generate keypair", err);
        noise_dhstate_free(dh);
        return 1;
    }

    /* Fetch the keypair to be saved */
    priv_key_len = noise_dhstate_get_private_key_length(dh);
    pub_key_len = noise_dhstate_get_public_key_length(dh);
    priv_key = (uint8_t *)malloc(priv_key_len);
    pub_key = (uint8_t *)malloc(pub_key_len);
    if (!priv_key || !pub_key) {
        fprintf(stderr, "Out of memory\n");
        return 1;
    }
    err = noise_dhstate_get_keypair
        (dh, priv_key, priv_key_len, pub_key, pub_key_len);
    if (err != NOISE_ERROR_NONE) {
        noise_perror("get keypair for saving", err);
        ok = 0;
    }

    /* Save the keys */
    if (ok)
        ok = save_private_key(priv_key_file, priv_key, priv_key_len);
    if (ok)
        ok = save_public_key(pub_key_file, pub_key, pub_key_len);

    /* Clean up */
    noise_dhstate_free(dh);
    noise_free(priv_key, priv_key_len);
    noise_free(pub_key, pub_key_len);
    if (!ok) {
        unlink(priv_key_file);
        unlink(pub_key_file);
    }
    return ok ? 0 : 1;
}

/* Saves a binary private key to a file.  Returns non-zero if OK. */
int save_private_key(const char *filename, const uint8_t *key, size_t len)
{
    FILE *file = fopen(filename, "wb");
    size_t posn;
    if (!file) {
        perror(filename);
        return 0;
    }
    for (posn = 0; posn < len; ++posn)
        putc(key[posn], file);
    fclose(file);
    return 1;
}

/* Saves a base64-encoded public key to a file.  Returns non-zero if OK. */
int save_public_key(const char *filename, const uint8_t *key, size_t len)
{
    static char const base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    FILE *file = fopen(filename, "wb");
    size_t posn = 0;
    uint32_t group;
    if (!file) {
        perror(filename);
        return 0;
    }
    while ((len - posn) >= 3) {
        group = (((uint32_t)(key[posn])) << 16) |
                (((uint32_t)(key[posn + 1])) << 8) |
                 ((uint32_t)(key[posn + 2]));
        putc(base64_chars[(group >> 18) & 0x3F], file);
        putc(base64_chars[(group >> 12) & 0x3F], file);
        putc(base64_chars[(group >> 6) & 0x3F], file);
        putc(base64_chars[group & 0x3F], file);
        posn += 3;
    }
    if ((len - posn) == 2) {
        group = (((uint32_t)(key[posn])) << 16) |
                (((uint32_t)(key[posn + 1])) << 8);
        putc(base64_chars[(group >> 18) & 0x3F], file);
        putc(base64_chars[(group >> 12) & 0x3F], file);
        putc(base64_chars[(group >> 6) & 0x3F], file);
        putc('=', file);
    } else if ((len - posn) == 1) {
        group = ((uint32_t)(key[posn])) << 16;
        putc(base64_chars[(group >> 18) & 0x3F], file);
        putc(base64_chars[(group >> 12) & 0x3F], file);
        putc('=', file);
        putc('=', file);
    }
    fclose(file);
    return 1;
}
