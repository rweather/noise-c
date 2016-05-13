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

#ifndef NOISE_KEYS_LOADER_H
#define NOISE_KEYS_LOADER_H

#include <noise/keys/certificate.h>

#ifdef __cplusplus
extern "C" {
#endif

int noise_load_certificate_from_file
    (Noise_Certificate **cert, const char *filename);
int noise_load_certificate_from_buffer
    (Noise_Certificate **cert, NoiseProtobuf *pbuf);

int noise_load_certificate_chain_from_file
    (Noise_CertificateChain **chain, const char *filename);
int noise_load_certificate_chain_from_buffer
    (Noise_CertificateChain **chain, NoiseProtobuf *pbuf);

int noise_load_private_key_from_file
    (Noise_PrivateKey **key, const char *filename,
     const void *passphrase, size_t passphrase_len);
int noise_load_private_key_from_buffer
    (Noise_PrivateKey **key, NoiseProtobuf *pbuf,
     const void *passphrase, size_t passphrase_len);

int noise_save_certificate_to_file
    (const Noise_Certificate *cert, const char *filename);
int noise_save_certificate_to_buffer
    (const Noise_Certificate *cert, NoiseProtobuf *pbuf);

int noise_save_certificate_chain_to_file
    (const Noise_CertificateChain *chain, const char *filename);
int noise_save_certificate_chain_to_buffer
    (const Noise_CertificateChain *chain, NoiseProtobuf *pbuf);

int noise_save_private_key_to_file
    (const Noise_PrivateKey *key, const char *filename,
     const void *passphrase, size_t passphrase_len,
     const char *protect_name);
int noise_save_private_key_to_buffer
    (const Noise_PrivateKey *key, NoiseProtobuf *pbuf,
     const void *passphrase, size_t passphrase_len,
     const char *protect_name);

#ifdef __cplusplus
};
#endif

#endif
