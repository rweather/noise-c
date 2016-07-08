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
#include <noise/protocol.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/** @cond */

/**
 * \brief Version of keys and certificates supported by this library.
 */
#define NOISE_KEY_VERSION       1

/**
 * \brief Recommended length for salt values.
 */
#define NOISE_KEY_SALT_LEN      16

/**
 * \brief Recommended number of iterations for newly generated private keys.
 */
#define NOISE_KEY_ITERATIONS    20000

/**
 * \brief Number of extra bytes of overhead to allow for when allocating
 * memory to hold an EncryptedPrivateKey object.
 */
#define NOISE_ENC_KEY_OVERHEAD  128

/** @endcond */

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
 * \brief Parses an algorithm name for encrypting private keys.
 *
 * \param name The name of the algorithm; e.g. "ChaChaPoly_BLAKE2b_PBKDF2".
 * \param cipher_id Return variable for the cipher identifier.
 * \param hash_id Return variable for the hash identifier.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_UNKNOWN_NAME if the \a name is unrecognized.
 *
 * The only supported value for the KDF portion of \a name is "PBKDF2".
 */
static int noise_parse_protect_name
    (const char *name, int *cipher_id, int *hash_id)
{
    char *end;
    *cipher_id = NOISE_CIPHER_NONE;
    *hash_id = NOISE_HASH_NONE;
    end = strchr(name, '_');
    if (!end)
        return NOISE_ERROR_UNKNOWN_NAME;
    *cipher_id = noise_name_to_id(NOISE_CIPHER_CATEGORY, name, end - name);
    if (*cipher_id == NOISE_CIPHER_NONE)
        return NOISE_ERROR_UNKNOWN_NAME;
    name = end + 1;
    end = strchr(name, '_');
    if (!end)
        return NOISE_ERROR_UNKNOWN_NAME;
    *hash_id = noise_name_to_id(NOISE_HASH_CATEGORY, name, end - name);
    if (*hash_id == NOISE_HASH_NONE)
        return NOISE_ERROR_UNKNOWN_NAME;
    name = end + 1;
    if (strcmp(name, "PBKDF2") != 0)
        return NOISE_ERROR_UNKNOWN_NAME;
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
    NoiseHashState *hash = 0;
    uint8_t key_data[40];
    int cipher_id, hash_id;
    int err;
    NoiseBuffer buf;
    NoiseProtobuf pbuf2;

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

    /* Check that we have everything we need for a valid key */
    if (Noise_EncryptedPrivateKey_get_version(enc_key) != NOISE_KEY_VERSION ||
            !Noise_EncryptedPrivateKey_has_algorithm(enc_key) ||
            !Noise_EncryptedPrivateKey_has_salt(enc_key) ||
            !Noise_EncryptedPrivateKey_has_iterations(enc_key) ||
            !Noise_EncryptedPrivateKey_has_encrypted_data(enc_key)) {
        Noise_EncryptedPrivateKey_free(enc_key);
        return NOISE_ERROR_INVALID_FORMAT;
    }

    /* Is the key protection algorithm supported? */
    err = noise_parse_protect_name
        (Noise_EncryptedPrivateKey_get_algorithm(enc_key),
         &cipher_id, &hash_id);
    if (err == NOISE_ERROR_NONE) {
        err = noise_cipherstate_new_by_id(&cipher, cipher_id);
        if (err == NOISE_ERROR_NONE &&
                noise_cipherstate_get_key_length(cipher) != 32) {
            /* At the moment we only support ciphers with 256-bit keys */
            err = NOISE_ERROR_UNKNOWN_NAME;
        }
    }
    if (err == NOISE_ERROR_NONE) {
        err = noise_hashstate_new_by_id(&hash, hash_id);
    }

    /* Decrypt the private key information */
    memset(&buf, 0, sizeof(buf));
    if (err == NOISE_ERROR_NONE) {
        /* Generate the key material using PBKDF2 */
        noise_hashstate_pbkdf2
            (hash, (const uint8_t *)passphrase, passphrase_len,
             (const uint8_t *)Noise_EncryptedPrivateKey_get_salt(enc_key),
             Noise_EncryptedPrivateKey_get_size_salt(enc_key),
             Noise_EncryptedPrivateKey_get_iterations(enc_key),
             key_data, sizeof(key_data));

        /* Set the decryption key */
        noise_cipherstate_init_key(cipher, key_data, 32);

        /* Set the nonce and fast-forward the cipher */
        noise_cipherstate_set_nonce
            (cipher, (((uint64_t)(key_data[32])) << 56) |
                     (((uint64_t)(key_data[33])) << 48) |
                     (((uint64_t)(key_data[34])) << 40) |
                     (((uint64_t)(key_data[35])) << 32) |
                     (((uint64_t)(key_data[36])) << 24) |
                     (((uint64_t)(key_data[37])) << 16) |
                     (((uint64_t)(key_data[38])) <<  8) |
                      ((uint64_t)(key_data[39])));

        /* Decrypt the private key and check the MAC value.
           We decrypt the value in-place in the EncryptedPrivateKey
           object.  We will be throwing it away later so there's
           no harm in overwriting the previous value. */
        noise_buffer_set_input
            (buf, (uint8_t *)Noise_EncryptedPrivateKey_get_encrypted_data(enc_key),
             Noise_EncryptedPrivateKey_get_size_encrypted_data(enc_key));
        err = noise_cipherstate_decrypt_with_ad(cipher, 0, 0, &buf);
    }

    /* Parse the decrypted data into a PrivateKey object */
    if (err == NOISE_ERROR_NONE) {
        noise_protobuf_prepare_input(&pbuf2, buf.data, buf.size);
        err = Noise_PrivateKey_read(&pbuf2, 0, key);
    }

    /* Clean up and exit */
    Noise_EncryptedPrivateKey_free(enc_key);
    noise_cipherstate_free(cipher);
    noise_hashstate_free(hash);
    noise_clean(key_data, sizeof(key_data));
    return err;
}

/** @cond */

/**
 * \brief Prototype for a protobuf object write function.
 */
typedef int (*NoiseWriteFunc)(NoiseProtobuf *pbuf, int tag, const void *obj);

/** @endcond */

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
    if (!obj || !filename)
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
    pbuf.posn = size;
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

/**
 * \brief Saves a private key in encrypted form to a file.
 *
 * \param key The private key to be saved.
 * \param filename The name of the file to save to.
 * \param passphrase Points to the passphrase to use to encrypt the private key.
 * \param passphrase_len Length of the passphrase in bytes.
 * \param protect_name The name of the algorithm to use to protect the
 * private key; e.g. "ChaChaPoly_BLAKE2b_PBKDF2".
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a key, \a filename,
 * \a passphrase, or \a protect_name is NULL.
 * \return NOISE_ERROR_INVALID_LENGTH if the total size of the encrypted
 * private key will be larger than NOISE_MAX_PAYLOAD_LEN.
 * \return NOISE_ERROR_UNKNOWN_NAME if \a protect_name is unknown.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * save the encrypted private key data.
 * \return NOISE_ERROR_SYSTEM if there was a problem opening or writing
 * to \a filename, with the specific reason reported in the system
 * errno variable.
 *
 * \sa noise_save_private_key_to_buffer(), noise_load_private_key_from_file()
 */
int noise_save_private_key_to_file
    (const Noise_PrivateKey *key, const char *filename,
     const void *passphrase, size_t passphrase_len,
     const char *protect_name)
{
    NoiseProtobuf pbuf;
    size_t size = 0;
    int cipher_id, hash_id;
    int err;
    FILE *file;

    /* Validate the parameters */
    if (!key || !filename || !passphrase || !protect_name)
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_parse_protect_name(protect_name, &cipher_id, &hash_id);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Estimate how much memory we will need for the EncryptedPrivateKey */
    noise_protobuf_prepare_measure(&pbuf, NOISE_MAX_PAYLOAD_LEN);
    err = Noise_PrivateKey_write(&pbuf, 0, key);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_finish_measure(&pbuf, &size);
    if (err != NOISE_ERROR_NONE)
        return err;
    size += strlen(protect_name) + NOISE_ENC_KEY_OVERHEAD;

    /* Serialize the EncryptedPrivateKey into memory */
    pbuf.data = (uint8_t *)malloc(size);
    if (!(pbuf.data))
        return NOISE_ERROR_NO_MEMORY;
    pbuf.posn = size;
    pbuf.size = size;
    pbuf.error = NOISE_ERROR_NONE;
    err = noise_save_private_key_to_buffer
        (key, &pbuf, passphrase, passphrase_len, protect_name);
    if (err == NOISE_ERROR_NONE &&
            (pbuf.size - pbuf.posn) > NOISE_MAX_PAYLOAD_LEN) {
        err = NOISE_ERROR_INVALID_LENGTH;
    }

    /* Save the encrypted data to the file */
    if (err == NOISE_ERROR_NONE) {
        file = fopen(filename, "wb");
        if (file) {
            size_t len = pbuf.size - pbuf.posn;
            if (fwrite(pbuf.data + pbuf.posn, 1, len, file) != len)
                err = NOISE_ERROR_SYSTEM;
            fclose(file);
        } else {
            err = NOISE_ERROR_SYSTEM;
        }
    }

    /* Clean up and exit */
    noise_free(pbuf.data, size);
    return err;
}

/**
 * \brief Saves a private key in encrypted form to a protobuf.
 *
 * \param key The private key to be saved.
 * \param pbuf The protobuf to write the encrypted data to.
 * \param passphrase Points to the passphrase to use to encrypt the private key.
 * \param passphrase_len Length of the passphrase in bytes.
 * \param protect_name The name of the algorithm to use to protect the
 * private key; e.g. "ChaChaPoly_BLAKE2b_PBKDF2".
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_PARAM if one of \a key, \a pbuf, \a passphrase,
 * or \a protect_name is NULL.
 * \return NOISE_ERROR_UNKNOWN_NAME if \a protect_name is unknown.
 * \return NOISE_ERROR_INVALID_LENGTH if \a pbuf is not large enough to
 * contain the encrypted private key data.
 * \return NOISE_ERROR_NO_MEMORY if there is insufficient memory to
 * save the encrypted private key data.
 *
 * \sa noise_save_private_key_to_file(), noise_load_private_key_from_buffer()
 */
int noise_save_private_key_to_buffer
    (const Noise_PrivateKey *key, NoiseProtobuf *pbuf,
     const void *passphrase, size_t passphrase_len,
     const char *protect_name)
{
    Noise_EncryptedPrivateKey *enc_key = 0;
    NoiseProtobuf pcopy;
    uint8_t salt[NOISE_KEY_SALT_LEN];
    uint8_t key_data[40];
    int cipher_id, hash_id;
    NoiseCipherState *cipher = 0;
    NoiseHashState *hash = 0;
    size_t mac_len;
    NoiseBuffer buf;
    int err;
    int retry;

    /* Validate the parameters */
    if (!key || !pbuf || !passphrase || !protect_name)
        return NOISE_ERROR_INVALID_PARAM;
    err = noise_parse_protect_name(protect_name, &cipher_id, &hash_id);
    if (err != NOISE_ERROR_NONE)
        return err;

    /* Construct the cipher and hash objects to use to encrypt the key */
    err = noise_cipherstate_new_by_id(&cipher, cipher_id);
    if (err != NOISE_ERROR_NONE)
        return err;
    if (noise_cipherstate_get_key_length(cipher) != 32) {
        /* At the moment we only support ciphers with 256-bit keys */
        noise_cipherstate_free(cipher);
        return NOISE_ERROR_UNKNOWN_NAME;
    }
    err = noise_hashstate_new_by_id(&hash, hash_id);
    if (err != NOISE_ERROR_NONE) {
        noise_cipherstate_free(cipher);
        return err;
    }
    mac_len = noise_cipherstate_get_mac_length(cipher);

    /* Write the private key details to the protobuf.  The incoming
       protobuf is supposed to be large enough to hold the encrypted
       version of the key so it should be large enough to hold the
       unencrypted private key and MAC temporarily */
    pcopy = *pbuf;
    if (pcopy.posn < mac_len) {
        err = NOISE_ERROR_INVALID_LENGTH;
    } else {
        pcopy.posn -= mac_len;
        err = Noise_PrivateKey_write(&pcopy, 0, key);
    }
    if (err != NOISE_ERROR_NONE) {
        noise_clean(pcopy.data + pcopy.posn, pbuf->posn - pcopy.posn);
        noise_cipherstate_free(cipher);
        noise_hashstate_free(hash);
        return err;
    }

    /* Construct an EncryptedPrivateKey object and populate it */
    err = Noise_EncryptedPrivateKey_new(&enc_key);
    if (err == NOISE_ERROR_NONE) {
        err = Noise_EncryptedPrivateKey_set_version(enc_key, NOISE_KEY_VERSION);
    }
    if (err == NOISE_ERROR_NONE) {
        err = Noise_EncryptedPrivateKey_set_algorithm
            (enc_key, protect_name, strlen(protect_name));
    }
    if (err == NOISE_ERROR_NONE) {
        err = Noise_EncryptedPrivateKey_set_iterations
            (enc_key, NOISE_KEY_ITERATIONS);
    }

    /* Encrypt the private key information */
    noise_randstate_generate_simple(salt, sizeof(salt));
    if (err == NOISE_ERROR_NONE) {
        do {
            /* Generate the key material using PBKDF2 */
            retry = 0;
            noise_hashstate_pbkdf2
                (hash, (const uint8_t *)passphrase, passphrase_len,
                 salt, sizeof(salt), NOISE_KEY_ITERATIONS,
                 key_data, sizeof(key_data));

            /* Set the encryption key */
            noise_cipherstate_init_key(cipher, key_data, 32);

            /* Set the nonce and fast-forward the cipher */
            noise_cipherstate_set_nonce
                (cipher, (((uint64_t)(key_data[32])) << 56) |
                         (((uint64_t)(key_data[33])) << 48) |
                         (((uint64_t)(key_data[34])) << 40) |
                         (((uint64_t)(key_data[35])) << 32) |
                         (((uint64_t)(key_data[36])) << 24) |
                         (((uint64_t)(key_data[37])) << 16) |
                         (((uint64_t)(key_data[38])) <<  8) |
                          ((uint64_t)(key_data[39])));

            /* Encrypt the private key and compute the MAC value */
            noise_buffer_set_inout(buf, pcopy.data + pcopy.posn,
                                   pbuf->posn - pcopy.posn - mac_len,
                                   pbuf->posn - pcopy.posn);
            err = noise_cipherstate_encrypt_with_ad(cipher, 0, 0, &buf);
            if (err != NOISE_ERROR_NONE) {
                /* The nonce is probably the reserved value 2^64 - 1,
                   which we cannot use.  Generate a new salt and try again */
                noise_randstate_generate_simple(salt, sizeof(salt));
                retry = 1;
            }
        } while (retry);
    }

    /* Add the encrypted data to the EncryptedPrivateKey object */
    if (err == NOISE_ERROR_NONE) {
        err = Noise_EncryptedPrivateKey_set_salt(enc_key, salt, sizeof(salt));
    }
    if (err == NOISE_ERROR_NONE) {
        err = Noise_EncryptedPrivateKey_set_encrypted_data
            (enc_key, pcopy.data + pcopy.posn, pbuf->posn - pcopy.posn);
    }
    noise_clean(pcopy.data + pcopy.posn, pbuf->posn - pcopy.posn);

    /* Now write the entire EncryptedPrivateKey object to the protobuf */
    if (err == NOISE_ERROR_NONE) {
        err = Noise_EncryptedPrivateKey_write(pbuf, 0, enc_key);
    }

    /* Clean up and exit */
    Noise_EncryptedPrivateKey_free(enc_key);
    noise_cipherstate_free(cipher);
    noise_hashstate_free(hash);
    noise_clean(salt, sizeof(salt));
    noise_clean(key_data, sizeof(key_data));
    return err;
}

/**@}*/
