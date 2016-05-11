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

#include <noise/keys.h>

/**
 * \file keyloader.h
 * \brief Key loading and saving interface
 */

/**
 * \file keyloader.c
 * \brief Key loading and saving implementation
 */

/**
 * \defgroup keyloader Key loading and saving API
 */
/**@{*/

int noise_load_certificate_from_file
    (Noise_Certificate **cert, const char *filename)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Loads a certificate from a protobuf.
 *
 * \param cert Variable that returns the certificate if one is loaded.
 * \param pbuf The protobuf to load the certificate from.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a cert or \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of \a pbuf is not
 * as expected for a certificate or certificate chain.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the certificate.
 *
 * The certificate is expected to occupy the entire buffer.  Trailing
 * unknown data will be rejected as invalid.
 *
 * If the buffer contains a certificate chain, then this function will
 * load the first certificate in the chain and discard the rest.
 * No verification will be performed on the certificate even if the
 * remaining certificates in the chain would allow verification.
 *
 * \sa noise_load_certificate_from_file(), noise_save_certificate_to_buffer()
 */
int noise_load_certificate_from_buffer
    (Noise_Certificate **cert, NoiseProtobuf *pbuf)
{
    /* Validate the parameters */
    if (!cert)
        return NOISE_ERROR_INVALID_PARAM;
    *cert = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;

    /* No point continuing if the protobuf already has an error */
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;

    /* Peek at the first tag to determine if this is a certificate chain */
    if (noise_protobuf_peek_tag(pbuf) == 8) {
        int err;
        size_t end_posn = 0;
        Noise_Certificate *cert2 = 0;
        noise_protobuf_read_start_element(pbuf, 0, &end_posn);
        while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
            err = Noise_Certificate_read(pbuf, 8, &cert2);
            if (err != NOISE_ERROR_NONE)
                break;
            if (!(*cert))
                *cert = cert2;
            else
                Noise_Certificate_free(cert2);
        }
        err = noise_protobuf_read_end_element(pbuf, end_posn);
        if (err != NOISE_ERROR_NONE) {
            Noise_Certificate_free(*cert);
            *cert = 0;
        }
        return err;
    }

    /* Load the entire buffer as a certificate */
    return Noise_Certificate_read(pbuf, 0, cert);
}

int noise_load_certificate_chain_from_file
    (Noise_CertificateChain **chain, const char *filename)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_load_certificate_chain_from_buffer
    (Noise_CertificateChain **chain, NoiseProtobuf *pbuf)
{
    /* Validate the parameters */
    if (!chain)
        return NOISE_ERROR_INVALID_PARAM;
    *chain = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;

    /* No point continuing if the protobuf already has an error */
    if (pbuf->error != NOISE_ERROR_NONE)
        return pbuf->error;

    /* Peek at the first tag to determine if this is a singleton certificate */
    if (noise_protobuf_peek_tag(pbuf) != 8) {
        Noise_Certificate *cert = 0;
        int err;
        err = Noise_CertificateChain_new(chain);
        if (err != NOISE_ERROR_NONE)
            return err;
        err = Noise_Certificate_read(pbuf, 0, &cert);
        if (err == NOISE_ERROR_NONE)
            err = Noise_CertificateChain_insert_certs(*chain, 0, cert);
        if (err != NOISE_ERROR_NONE) {
            Noise_CertificateChain_free(*chain);
            *chain = 0;
        }
        return err;
    }

    /* Load the entire buffer as a certificate chain */
    return Noise_CertificateChain_read(pbuf, 0, chain);
}

int noise_load_private_key_from_file
    (Noise_PrivateKey **key, const char *filename,
     const void *passphrase, size_t passphrase_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_load_private_key_from_buffer
    (Noise_PrivateKey **key, NoiseProtobuf *pbuf,
     const void *passphrase, size_t passphrase_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_save_certificate_to_file
    (const Noise_Certificate *cert, const char *filename)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_save_certificate_to_buffer
    (const Noise_Certificate *cert, NoiseProtobuf *pbuf)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_save_certificate_chain_to_file
    (const Noise_CertificateChain *chain, const char *filename)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_save_certificate_chain_to_buffer
    (const Noise_CertificateChain *chain, NoiseProtobuf *pbuf)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_save_private_key_to_file
    (const Noise_PrivateKey *key, const char *filename,
     const void *passphrase, size_t passphrase_len,
     const char *protect_name)
{
    // TODO
    return NOISE_ERROR_NONE;
}

int noise_save_private_key_to_buffer
    (const Noise_PrivateKey *key, NoiseProtobuf *pbuf,
     const void *passphrase, size_t passphrase_len,
     const char *protect_name)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**@}*/
