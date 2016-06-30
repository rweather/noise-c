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
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/hashstate.h>
#include <noise/protocol/util.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * \file loader.h
 * \brief Key loading and saving interface
 */

/**
 * \file loader.c
 * \brief Key loading and saving implementation
 */

/**
 * \defgroup keyloader Key loading and saving API
 */
/**@{*/

/**
 * \brief Loads the entire contents of a file into memory.
 *
 * \param filename The name of the file to load from.
 * \param pbuf The buffer to fill with the loaded data.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a filename is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of \a filename is not
 * as expected.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the file's contents.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened or read,
 * with further information in the system errno variable.
 *
 * A maximum of NOISE_MAX_PAYLOAD_LEN bytes will be loaded from the file.
 * Longer files will result in NOISE_ERROR_INVALID_FORMAT.
 */
static int noise_load_file
    (const char *filename, NoiseProtobuf *pbuf)
{
    FILE *file;
    size_t size;

    /* Initialize the buffer */
    pbuf->data = 0;
    pbuf->size = 0;
    pbuf->posn = 0;
    pbuf->error = NOISE_ERROR_NONE;

    /* Attempt to open the file */
    if (!filename)
        return NOISE_ERROR_INVALID_PARAM;
    file = fopen(filename, "rb");
    if (!file)
        return NOISE_ERROR_SYSTEM;

    /* Can we get the length of the file now?  If not, allocate
       the maximum possible size */
    if (fseek(file, 0L, SEEK_END) >= 0) {
        off_t length = ftell(file);
        if (length <= 0 || length > NOISE_MAX_PAYLOAD_LEN) {
            fclose(file);
            return NOISE_ERROR_INVALID_FORMAT;
        }
        if (fseek(file, 0L, SEEK_SET) < 0) {
            fclose(file);
            return NOISE_ERROR_SYSTEM;
        }
        pbuf->size = (size_t)length;
    } else {
        pbuf->size = NOISE_MAX_PAYLOAD_LEN;
    }
    pbuf->data = (uint8_t *)malloc(pbuf->size);
    if (!(pbuf->data)) {
        fclose(file);
        return NOISE_ERROR_NO_MEMORY;
    }

    /* Read the entire contents of the file into memory */
    size = fread(pbuf->data, 1, pbuf->size, file);
    if (!size && ferror(file)) {
        noise_free(pbuf->data, pbuf->size);
        pbuf->data = 0;
        fclose(file);
        return NOISE_ERROR_SYSTEM;
    }
    pbuf->size = size;

    /* Clean up and exit */
    fclose(file);
    return NOISE_ERROR_NONE;
}

/**
 * \brief Frees the data that was loaded by noise_load_file().
 *
 * \param pbuf The protobuf to free.
 */
static void noise_load_free(NoiseProtobuf *pbuf)
{
    noise_free(pbuf->data, pbuf->size);
}

/**
 * \brief Loads a certificate from a file.
 *
 * \param cert Variable that returns the certificate if one is loaded.
 * \param filename The name of the file to load the certificate from.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a cert or \a filename is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of \a filename is not
 * as expected for a certificate or certificate chain.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the certificate.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened or read,
 * with further information in the system errno variable.
 *
 * The certificate is expected to occupy the entire file.  Trailing
 * unknown data will be rejected as invalid.
 *
 * If the file contains a certificate chain, then this function will
 * load the first certificate in the chain and discard the rest.
 * No verification will be performed on the certificate even if the
 * remaining certificates in the chain would allow verification.
 *
 * \sa noise_load_certificate_from_buffer(), noise_save_certificate_to_file()
 */
int noise_load_certificate_from_file
    (Noise_Certificate **cert, const char *filename)
{
    NoiseProtobuf pbuf;
    int err = noise_load_file(filename, &pbuf);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_load_certificate_from_buffer(cert, &pbuf);
    noise_load_free(&pbuf);
    return err;
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

/**
 * \brief Loads a certificate chain from a file.
 *
 * \param chain Variable that returns the certificate chain if one is loaded.
 * \param filename The name of the file to load the certificate chain from.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a chain or \a filename is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of \a filename is not
 * as expected for a certificate or certificate chain.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the certificate chain.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened or read,
 * with further information in the system errno variable.
 *
 * The certificate chain is expected to occupy the entire file.  Trailing
 * unknown data will be rejected as invalid.
 *
 * If the file contains a certificate instead of a full chain, then this
 * function will load the certificate and convert it into a chain containing
 * a single certificate.
 *
 * \sa noise_load_certificate_chain_from_file(),
 * noise_save_certificate_chain_to_file()
 */
int noise_load_certificate_chain_from_file
    (Noise_CertificateChain **chain, const char *filename)
{
    NoiseProtobuf pbuf;
    int err = noise_load_file(filename, &pbuf);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_load_certificate_chain_from_buffer(chain, &pbuf);
    noise_load_free(&pbuf);
    return err;
}

/**
 * \brief Loads a certificate chain from a protobuf.
 *
 * \param chain Variable that returns the certificate chain if one is loaded.
 * \param pbuf The protobuf to load the certificate chain from.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a chain or \a pbuf is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of \a pbuf is not
 * as expected for a certificate or certificate chain.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the certificate chain.
 *
 * The certificate chain is expected to occupy the entire buffer.  Trailing
 * unknown data will be rejected as invalid.
 *
 * If the buffer contains a certificate instead of a full chain, then this
 * function will load the certificate and convert it into a chain containing
 * a single certificate.
 *
 * \sa noise_load_certificate_chain_from_file(),
 * noise_save_certificate_chain_to_buffer()
 */
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

/**
 * \brief Loads a private key from a file.
 *
 * \param key Variable that returns the private key if one is loaded.
 * \param filename The name of the file to load the private key from.
 * \param passphrase Points to the passphrase to use to unlock the private key.
 * \param passphrase_len Length of the passphrase in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a key, \a filename, or \a passphrase
 * is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of the file is not
 * as expected for a private key.
 * \return NOISE_ERROR_UNKNOWN_NAME if the algorithm that was used to
 * encrypt the private key is unknown.
 * \return NOISE_ERROR_MAC_FAILURE if the \a passphrase is incorrect.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the private key.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened or read,
 * with further information in the system errno variable.
 *
 * The private key is expected to occupy the entire buffer.  Trailing
 * unknown data will be rejected as invalid.
 *
 * \sa noise_load_private_key_from_buffer(), noise_save_private_key_to_file()
 */
int noise_load_private_key_from_file
    (Noise_PrivateKey **key, const char *filename,
     const void *passphrase, size_t passphrase_len)
{
    NoiseProtobuf pbuf;
    int err = noise_load_file(filename, &pbuf);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_load_private_key_from_buffer
        (key, &pbuf, passphrase, passphrase_len);
    noise_load_free(&pbuf);
    return err;
}

/**
 * \brief Creates a CipherState object for encrypting or decrypting a
 * private key using a passphrase.
 *
 * \param cipher Variable that returns the CipherState.
 * \param enc_key EncryptedPrivateKey object that contains the parameters
 * to use to generate the encryption key.
 * \param passphrase Points to the passphrase to use to encrypt the private key.
 * \param passphrase_len Length of the passphrase in bytes.
 *
 * \return NOISE_ERROR_NONE or an error code.
 */
static int noise_loader_create_cipherstate
    (NoiseCipherState **cipher, Noise_EncryptedPrivateKey *enc_key,
     const void *passphrase, size_t passphrase_len)
{
    // TODO
    return NOISE_ERROR_NONE;
}

/**
 * \brief Loads a private key from a protobuf.
 *
 * \param key Variable that returns the private key if one is loaded.
 * \param pbuf The protobuf to load the private key from.
 * \param passphrase Points to the passphrase to use to unlock the private key.
 * \param passphrase_len Length of the passphrase in bytes.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a key, \a pbuf, or \a passphrase
 * is NULL.
 * \return NOISE_ERROR_INVALID_FORMAT if the format of \a pbuf is not
 * as expected for a private key.
 * \return NOISE_ERROR_UNKNOWN_NAME if the algorithm that was used to
 * encrypt the private key is unknown.
 * \return NOISE_ERROR_MAC_FAILURE if the \a passphrase is incorrect.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * load the private key.
 *
 * The private key is expected to occupy the entire buffer.  Trailing
 * unknown data will be rejected as invalid.
 *
 * \sa noise_load_private_key_from_file(), noise_save_private_key_to_buffer()
 */
int noise_load_private_key_from_buffer
    (Noise_PrivateKey **key, NoiseProtobuf *pbuf,
     const void *passphrase, size_t passphrase_len)
{
    Noise_EncryptedPrivateKey *enc_key = 0;
    NoiseCipherState *cipher = 0;
    int err;

    /* Validate the parameters */
    if (!key)
        return NOISE_ERROR_INVALID_PARAM;
    *key = 0;
    if (!pbuf || !passphrase)
        return NOISE_ERROR_INVALID_PARAM;

    /* Load the encrypted version of the private key */
    err = Noise_EncryptedPrivateKey_read(pbuf, 0, &enc_key);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Decrypt the private key using the passphrase */
    err = noise_loader_create_cipherstate
        (&cipher, enc_key, passphrase, passphrase_len);
    if (err != NOISE_ERROR_NONE) {
        Noise_EncryptedPrivateKey_free(enc_key);
        return err;
    }
    // TODO

    /* Clean up and exit */
    Noise_EncryptedPrivateKey_free(enc_key);
    noise_cipherstate_free(cipher);
    return err;
}

/**
 * \brief Prototype for a protobuf object write function.
 */
typedef int (*NoiseWriteFunc)(NoiseProtobuf *pbuf, int tag, const void *obj);

/**
 * \brief Saves an object to a file.
 *
 * \param obj The object to save.
 * \param filename The name of the file to save in.
 * \param func Pointer to the write function to use to serialize the object.
 *
 * \return NOISE_ERROR_NONE on success, or an error code otherwise.
 */
static int noise_save_to_file
    (const void *obj, const char *filename, NoiseWriteFunc func)
{
    NoiseProtobuf pbuf;
    uint8_t *data = 0;
    size_t size = 0;
    int err;
    FILE *file;

    /* Validate the parameters */
    if (!data || !filename)
        return NOISE_ERROR_INVALID_PARAM;

    /* Measure the size of the serialized object */
    noise_protobuf_prepare_measure(&pbuf, NOISE_MAX_PAYLOAD_LEN);
    err = (*func)(&pbuf, 0, obj); 
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_finish_measure(&pbuf, &size);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Allocate memory to hold the serialized form temporarily */
    pbuf.data = (uint8_t *)malloc(size);
    if (!(pbuf.data))
        return NOISE_ERROR_NO_MEMORY;
    pbuf.size = size;
    pbuf.posn = 0;
    pbuf.error = NOISE_ERROR_NONE;
    err = (*func)(&pbuf, 0, obj); 
    if (err == NOISE_ERROR_NONE)
        err = noise_protobuf_finish_output(&pbuf, &data, &size);
    if (err != NOISE_ERROR_NONE) {
        noise_free(pbuf.data, pbuf.size);
        return err;
    }

    /* Write the data to the file */
    file = fopen(filename, "wb");
    if (file) {
        if (fwrite(data, 1, size, file) != size)
            err = NOISE_ERROR_SYSTEM;
        fclose(file);
    } else {
        err = NOISE_ERROR_SYSTEM;
    }

    /* Clean up and exit */
    noise_free(pbuf.data, pbuf.size);
    return err;
}

/**
 * \brief Saves a certificate to a file.
 *
 * \param cert The certificate to be saved.
 * \param filename The name of the file to save the certificate to.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a cert or \a filename is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the serialized version of the
 * certificate is more than NOISE_MAX_PAYLOAD_LEN bytes in length.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened or written,
 * with further information in the system errno variable.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory.
 *
 * \sa noise_save_certificate_to_buffer(), noise_load_certificate_from_file()
 */
int noise_save_certificate_to_file
    (const Noise_Certificate *cert, const char *filename)
{
    return noise_save_to_file
        (cert, filename, (NoiseWriteFunc)Noise_Certificate_write);
}

/**
 * \brief Saves a certificate to a protobuf.
 *
 * \param cert The certificate to be saved.
 * \param pbuf The protobuf to save the certificate to.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a cert or \a pbuf is NULL.
 *
 * \sa noise_save_certificate_to_file(), noise_load_certificate_from_buffer()
 */
int noise_save_certificate_to_buffer
    (const Noise_Certificate *cert, NoiseProtobuf *pbuf)
{
    return Noise_Certificate_write(pbuf, 0, cert);
}

/**
 * \brief Saves a certificate chain to a file.
 *
 * \param chain The certificate chain to be saved.
 * \param filename The name of the file to save the certificate chain to.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a chain or \a filename is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the serialized version of the
 * certificate chain is more than NOISE_MAX_PAYLOAD_LEN bytes in length.
 * \return NOISE_ERROR_SYSTEM if \a filename cannot be opened or written,
 * with further information in the system errno variable.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory.
 *
 * \sa noise_save_certificate_chain_to_buffer(),
 * noise_load_certificate_chain_from_file()
 */
int noise_save_certificate_chain_to_file
    (const Noise_CertificateChain *chain, const char *filename)
{
    return noise_save_to_file
        (chain, filename, (NoiseWriteFunc)Noise_CertificateChain_write);
}

/**
 * \brief Saves a certificate chain to a protobuf.
 *
 * \param chain The certificate chain to be saved.
 * \param pbuf The protobuf to save the certificate chain to.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if \a chain or \a pbuf is NULL.
 *
 * \sa noise_save_certificate_chain_to_file(),
 * noise_load_certificate_chain_from_buffer()
 */
int noise_save_certificate_chain_to_buffer
    (const Noise_CertificateChain *chain, NoiseProtobuf *pbuf)
{
    return Noise_CertificateChain_write(pbuf, 0, chain);
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
