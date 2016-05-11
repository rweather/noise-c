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

#ifndef __NOISE_CERTIFICATE_H__
#define __NOISE_CERTIFICATE_H__

#include <noise/protobufs.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _Noise_Certificate Noise_Certificate;
typedef struct _Noise_CertificateChain Noise_CertificateChain;
typedef struct _Noise_SubjectInfo Noise_SubjectInfo;
typedef struct _Noise_PublicKeyInfo Noise_PublicKeyInfo;
typedef struct _Noise_MetaInfo Noise_MetaInfo;
typedef struct _Noise_Signature Noise_Signature;
typedef struct _Noise_ExtraSignedInfo Noise_ExtraSignedInfo;
typedef struct _Noise_EncryptedPrivateKey Noise_EncryptedPrivateKey;
typedef struct _Noise_PrivateKey Noise_PrivateKey;
typedef struct _Noise_PrivateKeyInfo Noise_PrivateKeyInfo;

int Noise_Certificate_new(Noise_Certificate **obj);
int Noise_Certificate_free(Noise_Certificate *obj);
int Noise_Certificate_write(NoiseProtobuf *pbuf, int tag, const Noise_Certificate *obj);
int Noise_Certificate_read(NoiseProtobuf *pbuf, int tag, Noise_Certificate **obj);
int Noise_Certificate_clear_version(Noise_Certificate *obj);
int Noise_Certificate_has_version(const Noise_Certificate *obj);
uint32_t Noise_Certificate_get_version(const Noise_Certificate *obj);
int Noise_Certificate_set_version(Noise_Certificate *obj, uint32_t value);
int Noise_Certificate_clear_subject(Noise_Certificate *obj);
int Noise_Certificate_has_subject(const Noise_Certificate *obj);
Noise_SubjectInfo *Noise_Certificate_get_subject(const Noise_Certificate *obj);
int Noise_Certificate_get_new_subject(Noise_Certificate *obj, Noise_SubjectInfo **value);
int Noise_Certificate_clear_signatures(Noise_Certificate *obj);
int Noise_Certificate_has_signatures(const Noise_Certificate *obj);
size_t Noise_Certificate_count_signatures(const Noise_Certificate *obj);
Noise_Signature *Noise_Certificate_get_at_signatures(const Noise_Certificate *obj, size_t index);
int Noise_Certificate_add_signatures(Noise_Certificate *obj, Noise_Signature **value);
int Noise_Certificate_insert_signatures(Noise_Certificate *obj, size_t index, Noise_Signature *value);

int Noise_CertificateChain_new(Noise_CertificateChain **obj);
int Noise_CertificateChain_free(Noise_CertificateChain *obj);
int Noise_CertificateChain_write(NoiseProtobuf *pbuf, int tag, const Noise_CertificateChain *obj);
int Noise_CertificateChain_read(NoiseProtobuf *pbuf, int tag, Noise_CertificateChain **obj);
int Noise_CertificateChain_clear_certs(Noise_CertificateChain *obj);
int Noise_CertificateChain_has_certs(const Noise_CertificateChain *obj);
size_t Noise_CertificateChain_count_certs(const Noise_CertificateChain *obj);
Noise_Certificate *Noise_CertificateChain_get_at_certs(const Noise_CertificateChain *obj, size_t index);
int Noise_CertificateChain_add_certs(Noise_CertificateChain *obj, Noise_Certificate **value);
int Noise_CertificateChain_insert_certs(Noise_CertificateChain *obj, size_t index, Noise_Certificate *value);

int Noise_SubjectInfo_new(Noise_SubjectInfo **obj);
int Noise_SubjectInfo_free(Noise_SubjectInfo *obj);
int Noise_SubjectInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_SubjectInfo *obj);
int Noise_SubjectInfo_read(NoiseProtobuf *pbuf, int tag, Noise_SubjectInfo **obj);
int Noise_SubjectInfo_clear_id(Noise_SubjectInfo *obj);
int Noise_SubjectInfo_has_id(const Noise_SubjectInfo *obj);
const char *Noise_SubjectInfo_get_id(const Noise_SubjectInfo *obj);
size_t Noise_SubjectInfo_get_size_id(const Noise_SubjectInfo *obj);
int Noise_SubjectInfo_set_id(Noise_SubjectInfo *obj, const char *value, size_t size);
int Noise_SubjectInfo_clear_name(Noise_SubjectInfo *obj);
int Noise_SubjectInfo_has_name(const Noise_SubjectInfo *obj);
const char *Noise_SubjectInfo_get_name(const Noise_SubjectInfo *obj);
size_t Noise_SubjectInfo_get_size_name(const Noise_SubjectInfo *obj);
int Noise_SubjectInfo_set_name(Noise_SubjectInfo *obj, const char *value, size_t size);
int Noise_SubjectInfo_clear_role(Noise_SubjectInfo *obj);
int Noise_SubjectInfo_has_role(const Noise_SubjectInfo *obj);
const char *Noise_SubjectInfo_get_role(const Noise_SubjectInfo *obj);
size_t Noise_SubjectInfo_get_size_role(const Noise_SubjectInfo *obj);
int Noise_SubjectInfo_set_role(Noise_SubjectInfo *obj, const char *value, size_t size);
int Noise_SubjectInfo_clear_keys(Noise_SubjectInfo *obj);
int Noise_SubjectInfo_has_keys(const Noise_SubjectInfo *obj);
size_t Noise_SubjectInfo_count_keys(const Noise_SubjectInfo *obj);
Noise_PublicKeyInfo *Noise_SubjectInfo_get_at_keys(const Noise_SubjectInfo *obj, size_t index);
int Noise_SubjectInfo_add_keys(Noise_SubjectInfo *obj, Noise_PublicKeyInfo **value);
int Noise_SubjectInfo_insert_keys(Noise_SubjectInfo *obj, size_t index, Noise_PublicKeyInfo *value);
int Noise_SubjectInfo_clear_meta(Noise_SubjectInfo *obj);
int Noise_SubjectInfo_has_meta(const Noise_SubjectInfo *obj);
size_t Noise_SubjectInfo_count_meta(const Noise_SubjectInfo *obj);
Noise_MetaInfo *Noise_SubjectInfo_get_at_meta(const Noise_SubjectInfo *obj, size_t index);
int Noise_SubjectInfo_add_meta(Noise_SubjectInfo *obj, Noise_MetaInfo **value);
int Noise_SubjectInfo_insert_meta(Noise_SubjectInfo *obj, size_t index, Noise_MetaInfo *value);

int Noise_PublicKeyInfo_new(Noise_PublicKeyInfo **obj);
int Noise_PublicKeyInfo_free(Noise_PublicKeyInfo *obj);
int Noise_PublicKeyInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_PublicKeyInfo *obj);
int Noise_PublicKeyInfo_read(NoiseProtobuf *pbuf, int tag, Noise_PublicKeyInfo **obj);
int Noise_PublicKeyInfo_clear_algorithm(Noise_PublicKeyInfo *obj);
int Noise_PublicKeyInfo_has_algorithm(const Noise_PublicKeyInfo *obj);
const char *Noise_PublicKeyInfo_get_algorithm(const Noise_PublicKeyInfo *obj);
size_t Noise_PublicKeyInfo_get_size_algorithm(const Noise_PublicKeyInfo *obj);
int Noise_PublicKeyInfo_set_algorithm(Noise_PublicKeyInfo *obj, const char *value, size_t size);
int Noise_PublicKeyInfo_clear_key(Noise_PublicKeyInfo *obj);
int Noise_PublicKeyInfo_has_key(const Noise_PublicKeyInfo *obj);
const void *Noise_PublicKeyInfo_get_key(const Noise_PublicKeyInfo *obj);
size_t Noise_PublicKeyInfo_get_size_key(const Noise_PublicKeyInfo *obj);
int Noise_PublicKeyInfo_set_key(Noise_PublicKeyInfo *obj, const void *value, size_t size);

int Noise_MetaInfo_new(Noise_MetaInfo **obj);
int Noise_MetaInfo_free(Noise_MetaInfo *obj);
int Noise_MetaInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_MetaInfo *obj);
int Noise_MetaInfo_read(NoiseProtobuf *pbuf, int tag, Noise_MetaInfo **obj);
int Noise_MetaInfo_clear_name(Noise_MetaInfo *obj);
int Noise_MetaInfo_has_name(const Noise_MetaInfo *obj);
const char *Noise_MetaInfo_get_name(const Noise_MetaInfo *obj);
size_t Noise_MetaInfo_get_size_name(const Noise_MetaInfo *obj);
int Noise_MetaInfo_set_name(Noise_MetaInfo *obj, const char *value, size_t size);
int Noise_MetaInfo_clear_value(Noise_MetaInfo *obj);
int Noise_MetaInfo_has_value(const Noise_MetaInfo *obj);
const char *Noise_MetaInfo_get_value(const Noise_MetaInfo *obj);
size_t Noise_MetaInfo_get_size_value(const Noise_MetaInfo *obj);
int Noise_MetaInfo_set_value(Noise_MetaInfo *obj, const char *value, size_t size);

int Noise_Signature_new(Noise_Signature **obj);
int Noise_Signature_free(Noise_Signature *obj);
int Noise_Signature_write(NoiseProtobuf *pbuf, int tag, const Noise_Signature *obj);
int Noise_Signature_read(NoiseProtobuf *pbuf, int tag, Noise_Signature **obj);
int Noise_Signature_clear_id(Noise_Signature *obj);
int Noise_Signature_has_id(const Noise_Signature *obj);
const char *Noise_Signature_get_id(const Noise_Signature *obj);
size_t Noise_Signature_get_size_id(const Noise_Signature *obj);
int Noise_Signature_set_id(Noise_Signature *obj, const char *value, size_t size);
int Noise_Signature_clear_name(Noise_Signature *obj);
int Noise_Signature_has_name(const Noise_Signature *obj);
const char *Noise_Signature_get_name(const Noise_Signature *obj);
size_t Noise_Signature_get_size_name(const Noise_Signature *obj);
int Noise_Signature_set_name(Noise_Signature *obj, const char *value, size_t size);
int Noise_Signature_clear_signing_key(Noise_Signature *obj);
int Noise_Signature_has_signing_key(const Noise_Signature *obj);
Noise_PublicKeyInfo *Noise_Signature_get_signing_key(const Noise_Signature *obj);
int Noise_Signature_get_new_signing_key(Noise_Signature *obj, Noise_PublicKeyInfo **value);
int Noise_Signature_clear_hash_algorithm(Noise_Signature *obj);
int Noise_Signature_has_hash_algorithm(const Noise_Signature *obj);
const char *Noise_Signature_get_hash_algorithm(const Noise_Signature *obj);
size_t Noise_Signature_get_size_hash_algorithm(const Noise_Signature *obj);
int Noise_Signature_set_hash_algorithm(Noise_Signature *obj, const char *value, size_t size);
int Noise_Signature_clear_extra_signed_info(Noise_Signature *obj);
int Noise_Signature_has_extra_signed_info(const Noise_Signature *obj);
Noise_ExtraSignedInfo *Noise_Signature_get_extra_signed_info(const Noise_Signature *obj);
int Noise_Signature_get_new_extra_signed_info(Noise_Signature *obj, Noise_ExtraSignedInfo **value);
int Noise_Signature_clear_signature(Noise_Signature *obj);
int Noise_Signature_has_signature(const Noise_Signature *obj);
const void *Noise_Signature_get_signature(const Noise_Signature *obj);
size_t Noise_Signature_get_size_signature(const Noise_Signature *obj);
int Noise_Signature_set_signature(Noise_Signature *obj, const void *value, size_t size);

int Noise_ExtraSignedInfo_new(Noise_ExtraSignedInfo **obj);
int Noise_ExtraSignedInfo_free(Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_read(NoiseProtobuf *pbuf, int tag, Noise_ExtraSignedInfo **obj);
int Noise_ExtraSignedInfo_clear_nonce(Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_has_nonce(const Noise_ExtraSignedInfo *obj);
const void *Noise_ExtraSignedInfo_get_nonce(const Noise_ExtraSignedInfo *obj);
size_t Noise_ExtraSignedInfo_get_size_nonce(const Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_set_nonce(Noise_ExtraSignedInfo *obj, const void *value, size_t size);
int Noise_ExtraSignedInfo_clear_valid_from(Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_has_valid_from(const Noise_ExtraSignedInfo *obj);
const char *Noise_ExtraSignedInfo_get_valid_from(const Noise_ExtraSignedInfo *obj);
size_t Noise_ExtraSignedInfo_get_size_valid_from(const Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_set_valid_from(Noise_ExtraSignedInfo *obj, const char *value, size_t size);
int Noise_ExtraSignedInfo_clear_valid_to(Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_has_valid_to(const Noise_ExtraSignedInfo *obj);
const char *Noise_ExtraSignedInfo_get_valid_to(const Noise_ExtraSignedInfo *obj);
size_t Noise_ExtraSignedInfo_get_size_valid_to(const Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_set_valid_to(Noise_ExtraSignedInfo *obj, const char *value, size_t size);
int Noise_ExtraSignedInfo_clear_meta(Noise_ExtraSignedInfo *obj);
int Noise_ExtraSignedInfo_has_meta(const Noise_ExtraSignedInfo *obj);
size_t Noise_ExtraSignedInfo_count_meta(const Noise_ExtraSignedInfo *obj);
Noise_MetaInfo *Noise_ExtraSignedInfo_get_at_meta(const Noise_ExtraSignedInfo *obj, size_t index);
int Noise_ExtraSignedInfo_add_meta(Noise_ExtraSignedInfo *obj, Noise_MetaInfo **value);
int Noise_ExtraSignedInfo_insert_meta(Noise_ExtraSignedInfo *obj, size_t index, Noise_MetaInfo *value);

int Noise_EncryptedPrivateKey_new(Noise_EncryptedPrivateKey **obj);
int Noise_EncryptedPrivateKey_free(Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_write(NoiseProtobuf *pbuf, int tag, const Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_read(NoiseProtobuf *pbuf, int tag, Noise_EncryptedPrivateKey **obj);
int Noise_EncryptedPrivateKey_clear_version(Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_has_version(const Noise_EncryptedPrivateKey *obj);
uint32_t Noise_EncryptedPrivateKey_get_version(const Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_set_version(Noise_EncryptedPrivateKey *obj, uint32_t value);
int Noise_EncryptedPrivateKey_clear_algorithm(Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_has_algorithm(const Noise_EncryptedPrivateKey *obj);
const char *Noise_EncryptedPrivateKey_get_algorithm(const Noise_EncryptedPrivateKey *obj);
size_t Noise_EncryptedPrivateKey_get_size_algorithm(const Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_set_algorithm(Noise_EncryptedPrivateKey *obj, const char *value, size_t size);
int Noise_EncryptedPrivateKey_clear_salt(Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_has_salt(const Noise_EncryptedPrivateKey *obj);
const void *Noise_EncryptedPrivateKey_get_salt(const Noise_EncryptedPrivateKey *obj);
size_t Noise_EncryptedPrivateKey_get_size_salt(const Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_set_salt(Noise_EncryptedPrivateKey *obj, const void *value, size_t size);
int Noise_EncryptedPrivateKey_clear_iterations(Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_has_iterations(const Noise_EncryptedPrivateKey *obj);
uint32_t Noise_EncryptedPrivateKey_get_iterations(const Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_set_iterations(Noise_EncryptedPrivateKey *obj, uint32_t value);
int Noise_EncryptedPrivateKey_clear_encrypted_data(Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_has_encrypted_data(const Noise_EncryptedPrivateKey *obj);
const void *Noise_EncryptedPrivateKey_get_encrypted_data(const Noise_EncryptedPrivateKey *obj);
size_t Noise_EncryptedPrivateKey_get_size_encrypted_data(const Noise_EncryptedPrivateKey *obj);
int Noise_EncryptedPrivateKey_set_encrypted_data(Noise_EncryptedPrivateKey *obj, const void *value, size_t size);

int Noise_PrivateKey_new(Noise_PrivateKey **obj);
int Noise_PrivateKey_free(Noise_PrivateKey *obj);
int Noise_PrivateKey_write(NoiseProtobuf *pbuf, int tag, const Noise_PrivateKey *obj);
int Noise_PrivateKey_read(NoiseProtobuf *pbuf, int tag, Noise_PrivateKey **obj);
int Noise_PrivateKey_clear_id(Noise_PrivateKey *obj);
int Noise_PrivateKey_has_id(const Noise_PrivateKey *obj);
const char *Noise_PrivateKey_get_id(const Noise_PrivateKey *obj);
size_t Noise_PrivateKey_get_size_id(const Noise_PrivateKey *obj);
int Noise_PrivateKey_set_id(Noise_PrivateKey *obj, const char *value, size_t size);
int Noise_PrivateKey_clear_name(Noise_PrivateKey *obj);
int Noise_PrivateKey_has_name(const Noise_PrivateKey *obj);
const char *Noise_PrivateKey_get_name(const Noise_PrivateKey *obj);
size_t Noise_PrivateKey_get_size_name(const Noise_PrivateKey *obj);
int Noise_PrivateKey_set_name(Noise_PrivateKey *obj, const char *value, size_t size);
int Noise_PrivateKey_clear_role(Noise_PrivateKey *obj);
int Noise_PrivateKey_has_role(const Noise_PrivateKey *obj);
const char *Noise_PrivateKey_get_role(const Noise_PrivateKey *obj);
size_t Noise_PrivateKey_get_size_role(const Noise_PrivateKey *obj);
int Noise_PrivateKey_set_role(Noise_PrivateKey *obj, const char *value, size_t size);
int Noise_PrivateKey_clear_keys(Noise_PrivateKey *obj);
int Noise_PrivateKey_has_keys(const Noise_PrivateKey *obj);
size_t Noise_PrivateKey_count_keys(const Noise_PrivateKey *obj);
Noise_PrivateKeyInfo *Noise_PrivateKey_get_at_keys(const Noise_PrivateKey *obj, size_t index);
int Noise_PrivateKey_add_keys(Noise_PrivateKey *obj, Noise_PrivateKeyInfo **value);
int Noise_PrivateKey_insert_keys(Noise_PrivateKey *obj, size_t index, Noise_PrivateKeyInfo *value);
int Noise_PrivateKey_clear_meta(Noise_PrivateKey *obj);
int Noise_PrivateKey_has_meta(const Noise_PrivateKey *obj);
size_t Noise_PrivateKey_count_meta(const Noise_PrivateKey *obj);
Noise_MetaInfo *Noise_PrivateKey_get_at_meta(const Noise_PrivateKey *obj, size_t index);
int Noise_PrivateKey_add_meta(Noise_PrivateKey *obj, Noise_MetaInfo **value);
int Noise_PrivateKey_insert_meta(Noise_PrivateKey *obj, size_t index, Noise_MetaInfo *value);

int Noise_PrivateKeyInfo_new(Noise_PrivateKeyInfo **obj);
int Noise_PrivateKeyInfo_free(Noise_PrivateKeyInfo *obj);
int Noise_PrivateKeyInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_PrivateKeyInfo *obj);
int Noise_PrivateKeyInfo_read(NoiseProtobuf *pbuf, int tag, Noise_PrivateKeyInfo **obj);
int Noise_PrivateKeyInfo_clear_algorithm(Noise_PrivateKeyInfo *obj);
int Noise_PrivateKeyInfo_has_algorithm(const Noise_PrivateKeyInfo *obj);
const char *Noise_PrivateKeyInfo_get_algorithm(const Noise_PrivateKeyInfo *obj);
size_t Noise_PrivateKeyInfo_get_size_algorithm(const Noise_PrivateKeyInfo *obj);
int Noise_PrivateKeyInfo_set_algorithm(Noise_PrivateKeyInfo *obj, const char *value, size_t size);
int Noise_PrivateKeyInfo_clear_key(Noise_PrivateKeyInfo *obj);
int Noise_PrivateKeyInfo_has_key(const Noise_PrivateKeyInfo *obj);
const void *Noise_PrivateKeyInfo_get_key(const Noise_PrivateKeyInfo *obj);
size_t Noise_PrivateKeyInfo_get_size_key(const Noise_PrivateKeyInfo *obj);
int Noise_PrivateKeyInfo_set_key(Noise_PrivateKeyInfo *obj, const void *value, size_t size);

#ifdef __cplusplus
};
#endif

#endif
