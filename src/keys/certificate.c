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

#include "certificate.h"
#include <stdlib.h>
#include <string.h>

struct _Noise_Certificate {
    uint32_t version;
    Noise_SubjectInfo *subject;
    Noise_Signature **signatures;
    size_t signatures_count_;
    size_t signatures_max_;
};

struct _Noise_CertificateChain {
    Noise_Certificate **certs;
    size_t certs_count_;
    size_t certs_max_;
};

struct _Noise_SubjectInfo {
    char *id;
    size_t id_size_;
    char *name;
    size_t name_size_;
    char *role;
    size_t role_size_;
    Noise_PublicKeyInfo **keys;
    size_t keys_count_;
    size_t keys_max_;
    Noise_MetaInfo **meta;
    size_t meta_count_;
    size_t meta_max_;
};

struct _Noise_PublicKeyInfo {
    char *algorithm;
    size_t algorithm_size_;
    void *key;
    size_t key_size_;
};

struct _Noise_MetaInfo {
    char *name;
    size_t name_size_;
    char *value;
    size_t value_size_;
};

struct _Noise_Signature {
    char *id;
    size_t id_size_;
    char *name;
    size_t name_size_;
    Noise_PublicKeyInfo *signing_key;
    char *hash_algorithm;
    size_t hash_algorithm_size_;
    Noise_ExtraSignedInfo *extra_signed_info;
    void *signature;
    size_t signature_size_;
};

struct _Noise_ExtraSignedInfo {
    void *nonce;
    size_t nonce_size_;
    char *valid_from;
    size_t valid_from_size_;
    char *valid_to;
    size_t valid_to_size_;
    Noise_MetaInfo **meta;
    size_t meta_count_;
    size_t meta_max_;
};

struct _Noise_EncryptedPrivateKey {
    uint32_t version;
    char *algorithm;
    size_t algorithm_size_;
    void *salt;
    size_t salt_size_;
    uint32_t iterations;
    void *encrypted_data;
    size_t encrypted_data_size_;
};

struct _Noise_PrivateKey {
    char *id;
    size_t id_size_;
    char *name;
    size_t name_size_;
    char *role;
    size_t role_size_;
    Noise_PrivateKeyInfo **keys;
    size_t keys_count_;
    size_t keys_max_;
    Noise_MetaInfo **meta;
    size_t meta_count_;
    size_t meta_max_;
};

struct _Noise_PrivateKeyInfo {
    char *algorithm;
    size_t algorithm_size_;
    void *key;
    size_t key_size_;
};

int Noise_Certificate_new(Noise_Certificate **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_Certificate *)calloc(1, sizeof(Noise_Certificate));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_Certificate_free(Noise_Certificate *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    Noise_SubjectInfo_free(obj->subject);
    for (index = 0; index < obj->signatures_count_; ++index)
        Noise_Signature_free(obj->signatures[index]);
    noise_protobuf_free_memory(obj->signatures, obj->signatures_max_ * sizeof(Noise_Signature *));
    noise_protobuf_free_memory(obj, sizeof(Noise_Certificate));
    return NOISE_ERROR_NONE;
}

int Noise_Certificate_write(NoiseProtobuf *pbuf, int tag, const Noise_Certificate *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->signatures_count_; index > 0; --index)
        Noise_Signature_write(pbuf, 3, obj->signatures[index - 1]);
    if (obj->subject)
        Noise_SubjectInfo_write(pbuf, 2, obj->subject);
    if (obj->version)
        noise_protobuf_write_uint32(pbuf, 1, obj->version);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_Certificate_read(NoiseProtobuf *pbuf, int tag, Noise_Certificate **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_Certificate_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_read_uint32(pbuf, 1, &((*obj)->version));
            } break;
            case 2: {
                Noise_SubjectInfo_free((*obj)->subject);
                (*obj)->subject = 0;
                Noise_SubjectInfo_read(pbuf, 2, &((*obj)->subject));
            } break;
            case 3: {
                Noise_Signature *value = 0;
                int err;
                Noise_Signature_read(pbuf, 3, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->signatures), &((*obj)->signatures_count_), &((*obj)->signatures_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_Certificate_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_Certificate_clear_version(Noise_Certificate *obj)
{
    if (obj) {
        obj->version = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Certificate_has_version(const Noise_Certificate *obj)
{
    return obj ? (obj->version != 0) : 0;
}

uint32_t Noise_Certificate_get_version(const Noise_Certificate *obj)
{
    return obj ? obj->version : 0;
}

int Noise_Certificate_set_version(Noise_Certificate *obj, uint32_t value)
{
    if (obj) {
        obj->version = value;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Certificate_clear_subject(Noise_Certificate *obj)
{
    if (obj) {
        Noise_SubjectInfo_free(obj->subject);
        obj->subject = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Certificate_has_subject(const Noise_Certificate *obj)
{
    return obj ? (obj->subject != 0) : 0;
}

Noise_SubjectInfo *Noise_Certificate_get_subject(const Noise_Certificate *obj)
{
    return obj ? obj->subject : 0;
}

int Noise_Certificate_get_new_subject(Noise_Certificate *obj, Noise_SubjectInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_SubjectInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    Noise_SubjectInfo_free(obj->subject);
    obj->subject = *value;
    return NOISE_ERROR_NONE;
}

int Noise_Certificate_clear_signatures(Noise_Certificate *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->signatures_count_; ++index)
            Noise_Signature_free(obj->signatures[index]);
        noise_protobuf_free_memory(obj->signatures, obj->signatures_max_ * sizeof(Noise_Signature *));
        obj->signatures = 0;
        obj->signatures_count_ = 0;
        obj->signatures_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Certificate_has_signatures(const Noise_Certificate *obj)
{
    return obj ? (obj->signatures_count_ != 0) : 0;
}

size_t Noise_Certificate_count_signatures(const Noise_Certificate *obj)
{
    return obj ? obj->signatures_count_ : 0;
}

Noise_Signature *Noise_Certificate_get_at_signatures(const Noise_Certificate *obj, size_t index)
{
    if (obj && index < obj->signatures_count_)
        return obj->signatures[index];
    else
        return 0;
}

int Noise_Certificate_add_signatures(Noise_Certificate *obj, Noise_Signature **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_Signature_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->signatures), &(obj->signatures_count_), &(obj->signatures_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_Signature_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_Certificate_insert_signatures(Noise_Certificate *obj, size_t index, Noise_Signature *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->signatures), &(obj->signatures_count_), &(obj->signatures_max_), index, &value, sizeof(value));
}

int Noise_CertificateChain_new(Noise_CertificateChain **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_CertificateChain *)calloc(1, sizeof(Noise_CertificateChain));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_CertificateChain_free(Noise_CertificateChain *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    for (index = 0; index < obj->certs_count_; ++index)
        Noise_Certificate_free(obj->certs[index]);
    noise_protobuf_free_memory(obj->certs, obj->certs_max_ * sizeof(Noise_Certificate *));
    noise_protobuf_free_memory(obj, sizeof(Noise_CertificateChain));
    return NOISE_ERROR_NONE;
}

int Noise_CertificateChain_write(NoiseProtobuf *pbuf, int tag, const Noise_CertificateChain *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->certs_count_; index > 0; --index)
        Noise_Certificate_write(pbuf, 8, obj->certs[index - 1]);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_CertificateChain_read(NoiseProtobuf *pbuf, int tag, Noise_CertificateChain **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_CertificateChain_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 8: {
                Noise_Certificate *value = 0;
                int err;
                Noise_Certificate_read(pbuf, 8, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->certs), &((*obj)->certs_count_), &((*obj)->certs_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_CertificateChain_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_CertificateChain_clear_certs(Noise_CertificateChain *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->certs_count_; ++index)
            Noise_Certificate_free(obj->certs[index]);
        noise_protobuf_free_memory(obj->certs, obj->certs_max_ * sizeof(Noise_Certificate *));
        obj->certs = 0;
        obj->certs_count_ = 0;
        obj->certs_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_CertificateChain_has_certs(const Noise_CertificateChain *obj)
{
    return obj ? (obj->certs_count_ != 0) : 0;
}

size_t Noise_CertificateChain_count_certs(const Noise_CertificateChain *obj)
{
    return obj ? obj->certs_count_ : 0;
}

Noise_Certificate *Noise_CertificateChain_get_at_certs(const Noise_CertificateChain *obj, size_t index)
{
    if (obj && index < obj->certs_count_)
        return obj->certs[index];
    else
        return 0;
}

int Noise_CertificateChain_add_certs(Noise_CertificateChain *obj, Noise_Certificate **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_Certificate_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->certs), &(obj->certs_count_), &(obj->certs_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_Certificate_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_CertificateChain_insert_certs(Noise_CertificateChain *obj, size_t index, Noise_Certificate *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->certs), &(obj->certs_count_), &(obj->certs_max_), index, &value, sizeof(value));
}

int Noise_SubjectInfo_new(Noise_SubjectInfo **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_SubjectInfo *)calloc(1, sizeof(Noise_SubjectInfo));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_SubjectInfo_free(Noise_SubjectInfo *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->id, obj->id_size_);
    noise_protobuf_free_memory(obj->name, obj->name_size_);
    noise_protobuf_free_memory(obj->role, obj->role_size_);
    for (index = 0; index < obj->keys_count_; ++index)
        Noise_PublicKeyInfo_free(obj->keys[index]);
    noise_protobuf_free_memory(obj->keys, obj->keys_max_ * sizeof(Noise_PublicKeyInfo *));
    for (index = 0; index < obj->meta_count_; ++index)
        Noise_MetaInfo_free(obj->meta[index]);
    noise_protobuf_free_memory(obj->meta, obj->meta_max_ * sizeof(Noise_MetaInfo *));
    noise_protobuf_free_memory(obj, sizeof(Noise_SubjectInfo));
    return NOISE_ERROR_NONE;
}

int Noise_SubjectInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_SubjectInfo *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->meta_count_; index > 0; --index)
        Noise_MetaInfo_write(pbuf, 5, obj->meta[index - 1]);
    for (index = obj->keys_count_; index > 0; --index)
        Noise_PublicKeyInfo_write(pbuf, 4, obj->keys[index - 1]);
    if (obj->role)
        noise_protobuf_write_string(pbuf, 3, obj->role, obj->role_size_);
    if (obj->name)
        noise_protobuf_write_string(pbuf, 2, obj->name, obj->name_size_);
    if (obj->id)
        noise_protobuf_write_string(pbuf, 1, obj->id, obj->id_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_SubjectInfo_read(NoiseProtobuf *pbuf, int tag, Noise_SubjectInfo **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_SubjectInfo_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->id, (*obj)->id_size_);
                (*obj)->id = 0;
                (*obj)->id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->id), 0, &((*obj)->id_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->name, (*obj)->name_size_);
                (*obj)->name = 0;
                (*obj)->name_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->name), 0, &((*obj)->name_size_));
            } break;
            case 3: {
                noise_protobuf_free_memory((*obj)->role, (*obj)->role_size_);
                (*obj)->role = 0;
                (*obj)->role_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 3, &((*obj)->role), 0, &((*obj)->role_size_));
            } break;
            case 4: {
                Noise_PublicKeyInfo *value = 0;
                int err;
                Noise_PublicKeyInfo_read(pbuf, 4, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->keys), &((*obj)->keys_count_), &((*obj)->keys_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 5: {
                Noise_MetaInfo *value = 0;
                int err;
                Noise_MetaInfo_read(pbuf, 5, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->meta), &((*obj)->meta_count_), &((*obj)->meta_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_SubjectInfo_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_SubjectInfo_clear_id(Noise_SubjectInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->id, obj->id_size_);
        obj->id = 0;
        obj->id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_has_id(const Noise_SubjectInfo *obj)
{
    return obj ? (obj->id != 0) : 0;
}

const char *Noise_SubjectInfo_get_id(const Noise_SubjectInfo *obj)
{
    return obj ? obj->id : 0;
}

size_t Noise_SubjectInfo_get_size_id(const Noise_SubjectInfo *obj)
{
    return obj ? obj->id_size_ : 0;
}

int Noise_SubjectInfo_set_id(Noise_SubjectInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->id, obj->id_size_);
        obj->id = (char *)malloc(size + 1);
        if (obj->id) {
            memcpy(obj->id, value, size);
            obj->id[size] = 0;
            obj->id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_clear_name(Noise_SubjectInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = 0;
        obj->name_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_has_name(const Noise_SubjectInfo *obj)
{
    return obj ? (obj->name != 0) : 0;
}

const char *Noise_SubjectInfo_get_name(const Noise_SubjectInfo *obj)
{
    return obj ? obj->name : 0;
}

size_t Noise_SubjectInfo_get_size_name(const Noise_SubjectInfo *obj)
{
    return obj ? obj->name_size_ : 0;
}

int Noise_SubjectInfo_set_name(Noise_SubjectInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = (char *)malloc(size + 1);
        if (obj->name) {
            memcpy(obj->name, value, size);
            obj->name[size] = 0;
            obj->name_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->name_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_clear_role(Noise_SubjectInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->role, obj->role_size_);
        obj->role = 0;
        obj->role_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_has_role(const Noise_SubjectInfo *obj)
{
    return obj ? (obj->role != 0) : 0;
}

const char *Noise_SubjectInfo_get_role(const Noise_SubjectInfo *obj)
{
    return obj ? obj->role : 0;
}

size_t Noise_SubjectInfo_get_size_role(const Noise_SubjectInfo *obj)
{
    return obj ? obj->role_size_ : 0;
}

int Noise_SubjectInfo_set_role(Noise_SubjectInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->role, obj->role_size_);
        obj->role = (char *)malloc(size + 1);
        if (obj->role) {
            memcpy(obj->role, value, size);
            obj->role[size] = 0;
            obj->role_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->role_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_clear_keys(Noise_SubjectInfo *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->keys_count_; ++index)
            Noise_PublicKeyInfo_free(obj->keys[index]);
        noise_protobuf_free_memory(obj->keys, obj->keys_max_ * sizeof(Noise_PublicKeyInfo *));
        obj->keys = 0;
        obj->keys_count_ = 0;
        obj->keys_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_has_keys(const Noise_SubjectInfo *obj)
{
    return obj ? (obj->keys_count_ != 0) : 0;
}

size_t Noise_SubjectInfo_count_keys(const Noise_SubjectInfo *obj)
{
    return obj ? obj->keys_count_ : 0;
}

Noise_PublicKeyInfo *Noise_SubjectInfo_get_at_keys(const Noise_SubjectInfo *obj, size_t index)
{
    if (obj && index < obj->keys_count_)
        return obj->keys[index];
    else
        return 0;
}

int Noise_SubjectInfo_add_keys(Noise_SubjectInfo *obj, Noise_PublicKeyInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_PublicKeyInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->keys), &(obj->keys_count_), &(obj->keys_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_PublicKeyInfo_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_SubjectInfo_insert_keys(Noise_SubjectInfo *obj, size_t index, Noise_PublicKeyInfo *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->keys), &(obj->keys_count_), &(obj->keys_max_), index, &value, sizeof(value));
}

int Noise_SubjectInfo_clear_meta(Noise_SubjectInfo *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->meta_count_; ++index)
            Noise_MetaInfo_free(obj->meta[index]);
        noise_protobuf_free_memory(obj->meta, obj->meta_max_ * sizeof(Noise_MetaInfo *));
        obj->meta = 0;
        obj->meta_count_ = 0;
        obj->meta_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_SubjectInfo_has_meta(const Noise_SubjectInfo *obj)
{
    return obj ? (obj->meta_count_ != 0) : 0;
}

size_t Noise_SubjectInfo_count_meta(const Noise_SubjectInfo *obj)
{
    return obj ? obj->meta_count_ : 0;
}

Noise_MetaInfo *Noise_SubjectInfo_get_at_meta(const Noise_SubjectInfo *obj, size_t index)
{
    if (obj && index < obj->meta_count_)
        return obj->meta[index];
    else
        return 0;
}

int Noise_SubjectInfo_add_meta(Noise_SubjectInfo *obj, Noise_MetaInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_MetaInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->meta), &(obj->meta_count_), &(obj->meta_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_MetaInfo_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_SubjectInfo_insert_meta(Noise_SubjectInfo *obj, size_t index, Noise_MetaInfo *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->meta), &(obj->meta_count_), &(obj->meta_max_), index, &value, sizeof(value));
}

int Noise_PublicKeyInfo_new(Noise_PublicKeyInfo **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_PublicKeyInfo *)calloc(1, sizeof(Noise_PublicKeyInfo));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_PublicKeyInfo_free(Noise_PublicKeyInfo *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
    noise_protobuf_free_memory(obj->key, obj->key_size_);
    noise_protobuf_free_memory(obj, sizeof(Noise_PublicKeyInfo));
    return NOISE_ERROR_NONE;
}

int Noise_PublicKeyInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_PublicKeyInfo *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->key)
        noise_protobuf_write_bytes(pbuf, 2, obj->key, obj->key_size_);
    if (obj->algorithm)
        noise_protobuf_write_string(pbuf, 1, obj->algorithm, obj->algorithm_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_PublicKeyInfo_read(NoiseProtobuf *pbuf, int tag, Noise_PublicKeyInfo **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_PublicKeyInfo_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->algorithm, (*obj)->algorithm_size_);
                (*obj)->algorithm = 0;
                (*obj)->algorithm_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->algorithm), 0, &((*obj)->algorithm_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->key, (*obj)->key_size_);
                (*obj)->key = 0;
                (*obj)->key_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 2, &((*obj)->key), 0, &((*obj)->key_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_PublicKeyInfo_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_PublicKeyInfo_clear_algorithm(Noise_PublicKeyInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
        obj->algorithm = 0;
        obj->algorithm_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PublicKeyInfo_has_algorithm(const Noise_PublicKeyInfo *obj)
{
    return obj ? (obj->algorithm != 0) : 0;
}

const char *Noise_PublicKeyInfo_get_algorithm(const Noise_PublicKeyInfo *obj)
{
    return obj ? obj->algorithm : 0;
}

size_t Noise_PublicKeyInfo_get_size_algorithm(const Noise_PublicKeyInfo *obj)
{
    return obj ? obj->algorithm_size_ : 0;
}

int Noise_PublicKeyInfo_set_algorithm(Noise_PublicKeyInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
        obj->algorithm = (char *)malloc(size + 1);
        if (obj->algorithm) {
            memcpy(obj->algorithm, value, size);
            obj->algorithm[size] = 0;
            obj->algorithm_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->algorithm_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PublicKeyInfo_clear_key(Noise_PublicKeyInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->key, obj->key_size_);
        obj->key = 0;
        obj->key_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PublicKeyInfo_has_key(const Noise_PublicKeyInfo *obj)
{
    return obj ? (obj->key != 0) : 0;
}

const void *Noise_PublicKeyInfo_get_key(const Noise_PublicKeyInfo *obj)
{
    return obj ? obj->key : 0;
}

size_t Noise_PublicKeyInfo_get_size_key(const Noise_PublicKeyInfo *obj)
{
    return obj ? obj->key_size_ : 0;
}

int Noise_PublicKeyInfo_set_key(Noise_PublicKeyInfo *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->key, obj->key_size_);
        obj->key = (void *)malloc(size ? size : 1);
        if (obj->key) {
            memcpy(obj->key, value, size);
            obj->key_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->key_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_MetaInfo_new(Noise_MetaInfo **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_MetaInfo *)calloc(1, sizeof(Noise_MetaInfo));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_MetaInfo_free(Noise_MetaInfo *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->name, obj->name_size_);
    noise_protobuf_free_memory(obj->value, obj->value_size_);
    noise_protobuf_free_memory(obj, sizeof(Noise_MetaInfo));
    return NOISE_ERROR_NONE;
}

int Noise_MetaInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_MetaInfo *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->value)
        noise_protobuf_write_string(pbuf, 2, obj->value, obj->value_size_);
    if (obj->name)
        noise_protobuf_write_string(pbuf, 1, obj->name, obj->name_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_MetaInfo_read(NoiseProtobuf *pbuf, int tag, Noise_MetaInfo **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_MetaInfo_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->name, (*obj)->name_size_);
                (*obj)->name = 0;
                (*obj)->name_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->name), 0, &((*obj)->name_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->value, (*obj)->value_size_);
                (*obj)->value = 0;
                (*obj)->value_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->value), 0, &((*obj)->value_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_MetaInfo_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_MetaInfo_clear_name(Noise_MetaInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = 0;
        obj->name_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_MetaInfo_has_name(const Noise_MetaInfo *obj)
{
    return obj ? (obj->name != 0) : 0;
}

const char *Noise_MetaInfo_get_name(const Noise_MetaInfo *obj)
{
    return obj ? obj->name : 0;
}

size_t Noise_MetaInfo_get_size_name(const Noise_MetaInfo *obj)
{
    return obj ? obj->name_size_ : 0;
}

int Noise_MetaInfo_set_name(Noise_MetaInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = (char *)malloc(size + 1);
        if (obj->name) {
            memcpy(obj->name, value, size);
            obj->name[size] = 0;
            obj->name_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->name_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_MetaInfo_clear_value(Noise_MetaInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->value, obj->value_size_);
        obj->value = 0;
        obj->value_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_MetaInfo_has_value(const Noise_MetaInfo *obj)
{
    return obj ? (obj->value != 0) : 0;
}

const char *Noise_MetaInfo_get_value(const Noise_MetaInfo *obj)
{
    return obj ? obj->value : 0;
}

size_t Noise_MetaInfo_get_size_value(const Noise_MetaInfo *obj)
{
    return obj ? obj->value_size_ : 0;
}

int Noise_MetaInfo_set_value(Noise_MetaInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->value, obj->value_size_);
        obj->value = (char *)malloc(size + 1);
        if (obj->value) {
            memcpy(obj->value, value, size);
            obj->value[size] = 0;
            obj->value_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->value_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_new(Noise_Signature **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_Signature *)calloc(1, sizeof(Noise_Signature));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_Signature_free(Noise_Signature *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->id, obj->id_size_);
    noise_protobuf_free_memory(obj->name, obj->name_size_);
    Noise_PublicKeyInfo_free(obj->signing_key);
    noise_protobuf_free_memory(obj->hash_algorithm, obj->hash_algorithm_size_);
    Noise_ExtraSignedInfo_free(obj->extra_signed_info);
    noise_protobuf_free_memory(obj->signature, obj->signature_size_);
    noise_protobuf_free_memory(obj, sizeof(Noise_Signature));
    return NOISE_ERROR_NONE;
}

int Noise_Signature_write(NoiseProtobuf *pbuf, int tag, const Noise_Signature *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->signature)
        noise_protobuf_write_bytes(pbuf, 15, obj->signature, obj->signature_size_);
    if (obj->extra_signed_info)
        Noise_ExtraSignedInfo_write(pbuf, 5, obj->extra_signed_info);
    if (obj->hash_algorithm)
        noise_protobuf_write_string(pbuf, 4, obj->hash_algorithm, obj->hash_algorithm_size_);
    if (obj->signing_key)
        Noise_PublicKeyInfo_write(pbuf, 3, obj->signing_key);
    if (obj->name)
        noise_protobuf_write_string(pbuf, 2, obj->name, obj->name_size_);
    if (obj->id)
        noise_protobuf_write_string(pbuf, 1, obj->id, obj->id_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_Signature_read(NoiseProtobuf *pbuf, int tag, Noise_Signature **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_Signature_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->id, (*obj)->id_size_);
                (*obj)->id = 0;
                (*obj)->id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->id), 0, &((*obj)->id_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->name, (*obj)->name_size_);
                (*obj)->name = 0;
                (*obj)->name_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->name), 0, &((*obj)->name_size_));
            } break;
            case 3: {
                Noise_PublicKeyInfo_free((*obj)->signing_key);
                (*obj)->signing_key = 0;
                Noise_PublicKeyInfo_read(pbuf, 3, &((*obj)->signing_key));
            } break;
            case 4: {
                noise_protobuf_free_memory((*obj)->hash_algorithm, (*obj)->hash_algorithm_size_);
                (*obj)->hash_algorithm = 0;
                (*obj)->hash_algorithm_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 4, &((*obj)->hash_algorithm), 0, &((*obj)->hash_algorithm_size_));
            } break;
            case 5: {
                Noise_ExtraSignedInfo_free((*obj)->extra_signed_info);
                (*obj)->extra_signed_info = 0;
                Noise_ExtraSignedInfo_read(pbuf, 5, &((*obj)->extra_signed_info));
            } break;
            case 15: {
                noise_protobuf_free_memory((*obj)->signature, (*obj)->signature_size_);
                (*obj)->signature = 0;
                (*obj)->signature_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 15, &((*obj)->signature), 0, &((*obj)->signature_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_Signature_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_Signature_clear_id(Noise_Signature *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->id, obj->id_size_);
        obj->id = 0;
        obj->id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_has_id(const Noise_Signature *obj)
{
    return obj ? (obj->id != 0) : 0;
}

const char *Noise_Signature_get_id(const Noise_Signature *obj)
{
    return obj ? obj->id : 0;
}

size_t Noise_Signature_get_size_id(const Noise_Signature *obj)
{
    return obj ? obj->id_size_ : 0;
}

int Noise_Signature_set_id(Noise_Signature *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->id, obj->id_size_);
        obj->id = (char *)malloc(size + 1);
        if (obj->id) {
            memcpy(obj->id, value, size);
            obj->id[size] = 0;
            obj->id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_clear_name(Noise_Signature *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = 0;
        obj->name_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_has_name(const Noise_Signature *obj)
{
    return obj ? (obj->name != 0) : 0;
}

const char *Noise_Signature_get_name(const Noise_Signature *obj)
{
    return obj ? obj->name : 0;
}

size_t Noise_Signature_get_size_name(const Noise_Signature *obj)
{
    return obj ? obj->name_size_ : 0;
}

int Noise_Signature_set_name(Noise_Signature *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = (char *)malloc(size + 1);
        if (obj->name) {
            memcpy(obj->name, value, size);
            obj->name[size] = 0;
            obj->name_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->name_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_clear_signing_key(Noise_Signature *obj)
{
    if (obj) {
        Noise_PublicKeyInfo_free(obj->signing_key);
        obj->signing_key = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_has_signing_key(const Noise_Signature *obj)
{
    return obj ? (obj->signing_key != 0) : 0;
}

Noise_PublicKeyInfo *Noise_Signature_get_signing_key(const Noise_Signature *obj)
{
    return obj ? obj->signing_key : 0;
}

int Noise_Signature_get_new_signing_key(Noise_Signature *obj, Noise_PublicKeyInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_PublicKeyInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    Noise_PublicKeyInfo_free(obj->signing_key);
    obj->signing_key = *value;
    return NOISE_ERROR_NONE;
}

int Noise_Signature_clear_hash_algorithm(Noise_Signature *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->hash_algorithm, obj->hash_algorithm_size_);
        obj->hash_algorithm = 0;
        obj->hash_algorithm_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_has_hash_algorithm(const Noise_Signature *obj)
{
    return obj ? (obj->hash_algorithm != 0) : 0;
}

const char *Noise_Signature_get_hash_algorithm(const Noise_Signature *obj)
{
    return obj ? obj->hash_algorithm : 0;
}

size_t Noise_Signature_get_size_hash_algorithm(const Noise_Signature *obj)
{
    return obj ? obj->hash_algorithm_size_ : 0;
}

int Noise_Signature_set_hash_algorithm(Noise_Signature *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->hash_algorithm, obj->hash_algorithm_size_);
        obj->hash_algorithm = (char *)malloc(size + 1);
        if (obj->hash_algorithm) {
            memcpy(obj->hash_algorithm, value, size);
            obj->hash_algorithm[size] = 0;
            obj->hash_algorithm_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->hash_algorithm_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_clear_extra_signed_info(Noise_Signature *obj)
{
    if (obj) {
        Noise_ExtraSignedInfo_free(obj->extra_signed_info);
        obj->extra_signed_info = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_has_extra_signed_info(const Noise_Signature *obj)
{
    return obj ? (obj->extra_signed_info != 0) : 0;
}

Noise_ExtraSignedInfo *Noise_Signature_get_extra_signed_info(const Noise_Signature *obj)
{
    return obj ? obj->extra_signed_info : 0;
}

int Noise_Signature_get_new_extra_signed_info(Noise_Signature *obj, Noise_ExtraSignedInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_ExtraSignedInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    Noise_ExtraSignedInfo_free(obj->extra_signed_info);
    obj->extra_signed_info = *value;
    return NOISE_ERROR_NONE;
}

int Noise_Signature_clear_signature(Noise_Signature *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->signature, obj->signature_size_);
        obj->signature = 0;
        obj->signature_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_Signature_has_signature(const Noise_Signature *obj)
{
    return obj ? (obj->signature != 0) : 0;
}

const void *Noise_Signature_get_signature(const Noise_Signature *obj)
{
    return obj ? obj->signature : 0;
}

size_t Noise_Signature_get_size_signature(const Noise_Signature *obj)
{
    return obj ? obj->signature_size_ : 0;
}

int Noise_Signature_set_signature(Noise_Signature *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->signature, obj->signature_size_);
        obj->signature = (void *)malloc(size ? size : 1);
        if (obj->signature) {
            memcpy(obj->signature, value, size);
            obj->signature_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->signature_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_new(Noise_ExtraSignedInfo **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_ExtraSignedInfo *)calloc(1, sizeof(Noise_ExtraSignedInfo));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_ExtraSignedInfo_free(Noise_ExtraSignedInfo *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->nonce, obj->nonce_size_);
    noise_protobuf_free_memory(obj->valid_from, obj->valid_from_size_);
    noise_protobuf_free_memory(obj->valid_to, obj->valid_to_size_);
    for (index = 0; index < obj->meta_count_; ++index)
        Noise_MetaInfo_free(obj->meta[index]);
    noise_protobuf_free_memory(obj->meta, obj->meta_max_ * sizeof(Noise_MetaInfo *));
    noise_protobuf_free_memory(obj, sizeof(Noise_ExtraSignedInfo));
    return NOISE_ERROR_NONE;
}

int Noise_ExtraSignedInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_ExtraSignedInfo *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->meta_count_; index > 0; --index)
        Noise_MetaInfo_write(pbuf, 4, obj->meta[index - 1]);
    if (obj->valid_to)
        noise_protobuf_write_string(pbuf, 3, obj->valid_to, obj->valid_to_size_);
    if (obj->valid_from)
        noise_protobuf_write_string(pbuf, 2, obj->valid_from, obj->valid_from_size_);
    if (obj->nonce)
        noise_protobuf_write_bytes(pbuf, 1, obj->nonce, obj->nonce_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_ExtraSignedInfo_read(NoiseProtobuf *pbuf, int tag, Noise_ExtraSignedInfo **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_ExtraSignedInfo_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->nonce, (*obj)->nonce_size_);
                (*obj)->nonce = 0;
                (*obj)->nonce_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 1, &((*obj)->nonce), 0, &((*obj)->nonce_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->valid_from, (*obj)->valid_from_size_);
                (*obj)->valid_from = 0;
                (*obj)->valid_from_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->valid_from), 0, &((*obj)->valid_from_size_));
            } break;
            case 3: {
                noise_protobuf_free_memory((*obj)->valid_to, (*obj)->valid_to_size_);
                (*obj)->valid_to = 0;
                (*obj)->valid_to_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 3, &((*obj)->valid_to), 0, &((*obj)->valid_to_size_));
            } break;
            case 4: {
                Noise_MetaInfo *value = 0;
                int err;
                Noise_MetaInfo_read(pbuf, 4, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->meta), &((*obj)->meta_count_), &((*obj)->meta_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_ExtraSignedInfo_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_ExtraSignedInfo_clear_nonce(Noise_ExtraSignedInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->nonce, obj->nonce_size_);
        obj->nonce = 0;
        obj->nonce_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_has_nonce(const Noise_ExtraSignedInfo *obj)
{
    return obj ? (obj->nonce != 0) : 0;
}

const void *Noise_ExtraSignedInfo_get_nonce(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->nonce : 0;
}

size_t Noise_ExtraSignedInfo_get_size_nonce(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->nonce_size_ : 0;
}

int Noise_ExtraSignedInfo_set_nonce(Noise_ExtraSignedInfo *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->nonce, obj->nonce_size_);
        obj->nonce = (void *)malloc(size ? size : 1);
        if (obj->nonce) {
            memcpy(obj->nonce, value, size);
            obj->nonce_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->nonce_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_clear_valid_from(Noise_ExtraSignedInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->valid_from, obj->valid_from_size_);
        obj->valid_from = 0;
        obj->valid_from_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_has_valid_from(const Noise_ExtraSignedInfo *obj)
{
    return obj ? (obj->valid_from != 0) : 0;
}

const char *Noise_ExtraSignedInfo_get_valid_from(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->valid_from : 0;
}

size_t Noise_ExtraSignedInfo_get_size_valid_from(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->valid_from_size_ : 0;
}

int Noise_ExtraSignedInfo_set_valid_from(Noise_ExtraSignedInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->valid_from, obj->valid_from_size_);
        obj->valid_from = (char *)malloc(size + 1);
        if (obj->valid_from) {
            memcpy(obj->valid_from, value, size);
            obj->valid_from[size] = 0;
            obj->valid_from_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->valid_from_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_clear_valid_to(Noise_ExtraSignedInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->valid_to, obj->valid_to_size_);
        obj->valid_to = 0;
        obj->valid_to_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_has_valid_to(const Noise_ExtraSignedInfo *obj)
{
    return obj ? (obj->valid_to != 0) : 0;
}

const char *Noise_ExtraSignedInfo_get_valid_to(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->valid_to : 0;
}

size_t Noise_ExtraSignedInfo_get_size_valid_to(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->valid_to_size_ : 0;
}

int Noise_ExtraSignedInfo_set_valid_to(Noise_ExtraSignedInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->valid_to, obj->valid_to_size_);
        obj->valid_to = (char *)malloc(size + 1);
        if (obj->valid_to) {
            memcpy(obj->valid_to, value, size);
            obj->valid_to[size] = 0;
            obj->valid_to_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->valid_to_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_clear_meta(Noise_ExtraSignedInfo *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->meta_count_; ++index)
            Noise_MetaInfo_free(obj->meta[index]);
        noise_protobuf_free_memory(obj->meta, obj->meta_max_ * sizeof(Noise_MetaInfo *));
        obj->meta = 0;
        obj->meta_count_ = 0;
        obj->meta_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_ExtraSignedInfo_has_meta(const Noise_ExtraSignedInfo *obj)
{
    return obj ? (obj->meta_count_ != 0) : 0;
}

size_t Noise_ExtraSignedInfo_count_meta(const Noise_ExtraSignedInfo *obj)
{
    return obj ? obj->meta_count_ : 0;
}

Noise_MetaInfo *Noise_ExtraSignedInfo_get_at_meta(const Noise_ExtraSignedInfo *obj, size_t index)
{
    if (obj && index < obj->meta_count_)
        return obj->meta[index];
    else
        return 0;
}

int Noise_ExtraSignedInfo_add_meta(Noise_ExtraSignedInfo *obj, Noise_MetaInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_MetaInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->meta), &(obj->meta_count_), &(obj->meta_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_MetaInfo_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_ExtraSignedInfo_insert_meta(Noise_ExtraSignedInfo *obj, size_t index, Noise_MetaInfo *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->meta), &(obj->meta_count_), &(obj->meta_max_), index, &value, sizeof(value));
}

int Noise_EncryptedPrivateKey_new(Noise_EncryptedPrivateKey **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_EncryptedPrivateKey *)calloc(1, sizeof(Noise_EncryptedPrivateKey));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_EncryptedPrivateKey_free(Noise_EncryptedPrivateKey *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
    noise_protobuf_free_memory(obj->salt, obj->salt_size_);
    noise_protobuf_free_memory(obj->encrypted_data, obj->encrypted_data_size_);
    noise_protobuf_free_memory(obj, sizeof(Noise_EncryptedPrivateKey));
    return NOISE_ERROR_NONE;
}

int Noise_EncryptedPrivateKey_write(NoiseProtobuf *pbuf, int tag, const Noise_EncryptedPrivateKey *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->encrypted_data)
        noise_protobuf_write_bytes(pbuf, 15, obj->encrypted_data, obj->encrypted_data_size_);
    if (obj->iterations)
        noise_protobuf_write_uint32(pbuf, 13, obj->iterations);
    if (obj->salt)
        noise_protobuf_write_bytes(pbuf, 12, obj->salt, obj->salt_size_);
    if (obj->algorithm)
        noise_protobuf_write_string(pbuf, 11, obj->algorithm, obj->algorithm_size_);
    if (obj->version)
        noise_protobuf_write_uint32(pbuf, 10, obj->version);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_EncryptedPrivateKey_read(NoiseProtobuf *pbuf, int tag, Noise_EncryptedPrivateKey **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_EncryptedPrivateKey_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 10: {
                noise_protobuf_read_uint32(pbuf, 10, &((*obj)->version));
            } break;
            case 11: {
                noise_protobuf_free_memory((*obj)->algorithm, (*obj)->algorithm_size_);
                (*obj)->algorithm = 0;
                (*obj)->algorithm_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 11, &((*obj)->algorithm), 0, &((*obj)->algorithm_size_));
            } break;
            case 12: {
                noise_protobuf_free_memory((*obj)->salt, (*obj)->salt_size_);
                (*obj)->salt = 0;
                (*obj)->salt_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 12, &((*obj)->salt), 0, &((*obj)->salt_size_));
            } break;
            case 13: {
                noise_protobuf_read_uint32(pbuf, 13, &((*obj)->iterations));
            } break;
            case 15: {
                noise_protobuf_free_memory((*obj)->encrypted_data, (*obj)->encrypted_data_size_);
                (*obj)->encrypted_data = 0;
                (*obj)->encrypted_data_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 15, &((*obj)->encrypted_data), 0, &((*obj)->encrypted_data_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_EncryptedPrivateKey_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_EncryptedPrivateKey_clear_version(Noise_EncryptedPrivateKey *obj)
{
    if (obj) {
        obj->version = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_has_version(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? (obj->version != 0) : 0;
}

uint32_t Noise_EncryptedPrivateKey_get_version(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->version : 0;
}

int Noise_EncryptedPrivateKey_set_version(Noise_EncryptedPrivateKey *obj, uint32_t value)
{
    if (obj) {
        obj->version = value;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_clear_algorithm(Noise_EncryptedPrivateKey *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
        obj->algorithm = 0;
        obj->algorithm_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_has_algorithm(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? (obj->algorithm != 0) : 0;
}

const char *Noise_EncryptedPrivateKey_get_algorithm(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->algorithm : 0;
}

size_t Noise_EncryptedPrivateKey_get_size_algorithm(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->algorithm_size_ : 0;
}

int Noise_EncryptedPrivateKey_set_algorithm(Noise_EncryptedPrivateKey *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
        obj->algorithm = (char *)malloc(size + 1);
        if (obj->algorithm) {
            memcpy(obj->algorithm, value, size);
            obj->algorithm[size] = 0;
            obj->algorithm_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->algorithm_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_clear_salt(Noise_EncryptedPrivateKey *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->salt, obj->salt_size_);
        obj->salt = 0;
        obj->salt_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_has_salt(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? (obj->salt != 0) : 0;
}

const void *Noise_EncryptedPrivateKey_get_salt(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->salt : 0;
}

size_t Noise_EncryptedPrivateKey_get_size_salt(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->salt_size_ : 0;
}

int Noise_EncryptedPrivateKey_set_salt(Noise_EncryptedPrivateKey *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->salt, obj->salt_size_);
        obj->salt = (void *)malloc(size ? size : 1);
        if (obj->salt) {
            memcpy(obj->salt, value, size);
            obj->salt_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->salt_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_clear_iterations(Noise_EncryptedPrivateKey *obj)
{
    if (obj) {
        obj->iterations = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_has_iterations(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? (obj->iterations != 0) : 0;
}

uint32_t Noise_EncryptedPrivateKey_get_iterations(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->iterations : 0;
}

int Noise_EncryptedPrivateKey_set_iterations(Noise_EncryptedPrivateKey *obj, uint32_t value)
{
    if (obj) {
        obj->iterations = value;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_clear_encrypted_data(Noise_EncryptedPrivateKey *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->encrypted_data, obj->encrypted_data_size_);
        obj->encrypted_data = 0;
        obj->encrypted_data_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_EncryptedPrivateKey_has_encrypted_data(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? (obj->encrypted_data != 0) : 0;
}

const void *Noise_EncryptedPrivateKey_get_encrypted_data(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->encrypted_data : 0;
}

size_t Noise_EncryptedPrivateKey_get_size_encrypted_data(const Noise_EncryptedPrivateKey *obj)
{
    return obj ? obj->encrypted_data_size_ : 0;
}

int Noise_EncryptedPrivateKey_set_encrypted_data(Noise_EncryptedPrivateKey *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->encrypted_data, obj->encrypted_data_size_);
        obj->encrypted_data = (void *)malloc(size ? size : 1);
        if (obj->encrypted_data) {
            memcpy(obj->encrypted_data, value, size);
            obj->encrypted_data_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->encrypted_data_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_new(Noise_PrivateKey **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_PrivateKey *)calloc(1, sizeof(Noise_PrivateKey));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_PrivateKey_free(Noise_PrivateKey *obj)
{
    size_t index;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->id, obj->id_size_);
    noise_protobuf_free_memory(obj->name, obj->name_size_);
    noise_protobuf_free_memory(obj->role, obj->role_size_);
    for (index = 0; index < obj->keys_count_; ++index)
        Noise_PrivateKeyInfo_free(obj->keys[index]);
    noise_protobuf_free_memory(obj->keys, obj->keys_max_ * sizeof(Noise_PrivateKeyInfo *));
    for (index = 0; index < obj->meta_count_; ++index)
        Noise_MetaInfo_free(obj->meta[index]);
    noise_protobuf_free_memory(obj->meta, obj->meta_max_ * sizeof(Noise_MetaInfo *));
    noise_protobuf_free_memory(obj, sizeof(Noise_PrivateKey));
    return NOISE_ERROR_NONE;
}

int Noise_PrivateKey_write(NoiseProtobuf *pbuf, int tag, const Noise_PrivateKey *obj)
{
    size_t end_posn;
    size_t index;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    for (index = obj->meta_count_; index > 0; --index)
        Noise_MetaInfo_write(pbuf, 5, obj->meta[index - 1]);
    for (index = obj->keys_count_; index > 0; --index)
        Noise_PrivateKeyInfo_write(pbuf, 4, obj->keys[index - 1]);
    if (obj->role)
        noise_protobuf_write_string(pbuf, 3, obj->role, obj->role_size_);
    if (obj->name)
        noise_protobuf_write_string(pbuf, 2, obj->name, obj->name_size_);
    if (obj->id)
        noise_protobuf_write_string(pbuf, 1, obj->id, obj->id_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_PrivateKey_read(NoiseProtobuf *pbuf, int tag, Noise_PrivateKey **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_PrivateKey_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->id, (*obj)->id_size_);
                (*obj)->id = 0;
                (*obj)->id_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->id), 0, &((*obj)->id_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->name, (*obj)->name_size_);
                (*obj)->name = 0;
                (*obj)->name_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 2, &((*obj)->name), 0, &((*obj)->name_size_));
            } break;
            case 3: {
                noise_protobuf_free_memory((*obj)->role, (*obj)->role_size_);
                (*obj)->role = 0;
                (*obj)->role_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 3, &((*obj)->role), 0, &((*obj)->role_size_));
            } break;
            case 4: {
                Noise_PrivateKeyInfo *value = 0;
                int err;
                Noise_PrivateKeyInfo_read(pbuf, 4, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->keys), &((*obj)->keys_count_), &((*obj)->keys_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            case 5: {
                Noise_MetaInfo *value = 0;
                int err;
                Noise_MetaInfo_read(pbuf, 5, &value);
                err = noise_protobuf_add_to_array((void **)&((*obj)->meta), &((*obj)->meta_count_), &((*obj)->meta_max_), &value, sizeof(value));
                if (err != NOISE_ERROR_NONE && pbuf->error != NOISE_ERROR_NONE)
                   pbuf->error = err;
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_PrivateKey_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_PrivateKey_clear_id(Noise_PrivateKey *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->id, obj->id_size_);
        obj->id = 0;
        obj->id_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_has_id(const Noise_PrivateKey *obj)
{
    return obj ? (obj->id != 0) : 0;
}

const char *Noise_PrivateKey_get_id(const Noise_PrivateKey *obj)
{
    return obj ? obj->id : 0;
}

size_t Noise_PrivateKey_get_size_id(const Noise_PrivateKey *obj)
{
    return obj ? obj->id_size_ : 0;
}

int Noise_PrivateKey_set_id(Noise_PrivateKey *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->id, obj->id_size_);
        obj->id = (char *)malloc(size + 1);
        if (obj->id) {
            memcpy(obj->id, value, size);
            obj->id[size] = 0;
            obj->id_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->id_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_clear_name(Noise_PrivateKey *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = 0;
        obj->name_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_has_name(const Noise_PrivateKey *obj)
{
    return obj ? (obj->name != 0) : 0;
}

const char *Noise_PrivateKey_get_name(const Noise_PrivateKey *obj)
{
    return obj ? obj->name : 0;
}

size_t Noise_PrivateKey_get_size_name(const Noise_PrivateKey *obj)
{
    return obj ? obj->name_size_ : 0;
}

int Noise_PrivateKey_set_name(Noise_PrivateKey *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->name, obj->name_size_);
        obj->name = (char *)malloc(size + 1);
        if (obj->name) {
            memcpy(obj->name, value, size);
            obj->name[size] = 0;
            obj->name_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->name_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_clear_role(Noise_PrivateKey *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->role, obj->role_size_);
        obj->role = 0;
        obj->role_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_has_role(const Noise_PrivateKey *obj)
{
    return obj ? (obj->role != 0) : 0;
}

const char *Noise_PrivateKey_get_role(const Noise_PrivateKey *obj)
{
    return obj ? obj->role : 0;
}

size_t Noise_PrivateKey_get_size_role(const Noise_PrivateKey *obj)
{
    return obj ? obj->role_size_ : 0;
}

int Noise_PrivateKey_set_role(Noise_PrivateKey *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->role, obj->role_size_);
        obj->role = (char *)malloc(size + 1);
        if (obj->role) {
            memcpy(obj->role, value, size);
            obj->role[size] = 0;
            obj->role_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->role_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_clear_keys(Noise_PrivateKey *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->keys_count_; ++index)
            Noise_PrivateKeyInfo_free(obj->keys[index]);
        noise_protobuf_free_memory(obj->keys, obj->keys_max_ * sizeof(Noise_PrivateKeyInfo *));
        obj->keys = 0;
        obj->keys_count_ = 0;
        obj->keys_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_has_keys(const Noise_PrivateKey *obj)
{
    return obj ? (obj->keys_count_ != 0) : 0;
}

size_t Noise_PrivateKey_count_keys(const Noise_PrivateKey *obj)
{
    return obj ? obj->keys_count_ : 0;
}

Noise_PrivateKeyInfo *Noise_PrivateKey_get_at_keys(const Noise_PrivateKey *obj, size_t index)
{
    if (obj && index < obj->keys_count_)
        return obj->keys[index];
    else
        return 0;
}

int Noise_PrivateKey_add_keys(Noise_PrivateKey *obj, Noise_PrivateKeyInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_PrivateKeyInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->keys), &(obj->keys_count_), &(obj->keys_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_PrivateKeyInfo_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_PrivateKey_insert_keys(Noise_PrivateKey *obj, size_t index, Noise_PrivateKeyInfo *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->keys), &(obj->keys_count_), &(obj->keys_max_), index, &value, sizeof(value));
}

int Noise_PrivateKey_clear_meta(Noise_PrivateKey *obj)
{
    size_t index;
    if (obj) {
        for (index = 0; index < obj->meta_count_; ++index)
            Noise_MetaInfo_free(obj->meta[index]);
        noise_protobuf_free_memory(obj->meta, obj->meta_max_ * sizeof(Noise_MetaInfo *));
        obj->meta = 0;
        obj->meta_count_ = 0;
        obj->meta_max_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKey_has_meta(const Noise_PrivateKey *obj)
{
    return obj ? (obj->meta_count_ != 0) : 0;
}

size_t Noise_PrivateKey_count_meta(const Noise_PrivateKey *obj)
{
    return obj ? obj->meta_count_ : 0;
}

Noise_MetaInfo *Noise_PrivateKey_get_at_meta(const Noise_PrivateKey *obj, size_t index)
{
    if (obj && index < obj->meta_count_)
        return obj->meta[index];
    else
        return 0;
}

int Noise_PrivateKey_add_meta(Noise_PrivateKey *obj, Noise_MetaInfo **value)
{
    int err;
    if (!value)
        return NOISE_ERROR_INVALID_PARAM;
    *value = 0;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_MetaInfo_new(value);
    if (err != NOISE_ERROR_NONE)
        return err;
    err = noise_protobuf_add_to_array((void **)&(obj->meta), &(obj->meta_count_), &(obj->meta_max_), value, sizeof(*value));
    if (err != NOISE_ERROR_NONE) {
        Noise_MetaInfo_free(*value);
        *value = 0;
        return err;
    }
    return NOISE_ERROR_NONE;
}

int Noise_PrivateKey_insert_meta(Noise_PrivateKey *obj, size_t index, Noise_MetaInfo *value)
{
    if (!obj || !value)
        return NOISE_ERROR_INVALID_PARAM;
    return noise_protobuf_insert_into_array((void **)&(obj->meta), &(obj->meta_count_), &(obj->meta_max_), index, &value, sizeof(value));
}

int Noise_PrivateKeyInfo_new(Noise_PrivateKeyInfo **obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = (Noise_PrivateKeyInfo *)calloc(1, sizeof(Noise_PrivateKeyInfo));
    if (!(*obj))
        return NOISE_ERROR_NO_MEMORY;
    return NOISE_ERROR_NONE;
}

int Noise_PrivateKeyInfo_free(Noise_PrivateKeyInfo *obj)
{
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
    noise_protobuf_free_memory(obj->key, obj->key_size_);
    noise_protobuf_free_memory(obj, sizeof(Noise_PrivateKeyInfo));
    return NOISE_ERROR_NONE;
}

int Noise_PrivateKeyInfo_write(NoiseProtobuf *pbuf, int tag, const Noise_PrivateKeyInfo *obj)
{
    size_t end_posn;
    if (!pbuf || !obj)
        return NOISE_ERROR_INVALID_PARAM;
    noise_protobuf_write_end_element(pbuf, &end_posn);
    if (obj->key)
        noise_protobuf_write_bytes(pbuf, 2, obj->key, obj->key_size_);
    if (obj->algorithm)
        noise_protobuf_write_string(pbuf, 1, obj->algorithm, obj->algorithm_size_);
    return noise_protobuf_write_start_element(pbuf, tag, end_posn);
}

int Noise_PrivateKeyInfo_read(NoiseProtobuf *pbuf, int tag, Noise_PrivateKeyInfo **obj)
{
    int err;
    size_t end_posn;
    if (!obj)
        return NOISE_ERROR_INVALID_PARAM;
    *obj = 0;
    if (!pbuf)
        return NOISE_ERROR_INVALID_PARAM;
    err = Noise_PrivateKeyInfo_new(obj);
    if (err != NOISE_ERROR_NONE)
        return err;
    noise_protobuf_read_start_element(pbuf, tag, &end_posn);
    while (!noise_protobuf_read_at_end_element(pbuf, end_posn)) {
        switch (noise_protobuf_peek_tag(pbuf)) {
            case 1: {
                noise_protobuf_free_memory((*obj)->algorithm, (*obj)->algorithm_size_);
                (*obj)->algorithm = 0;
                (*obj)->algorithm_size_ = 0;
                noise_protobuf_read_alloc_string(pbuf, 1, &((*obj)->algorithm), 0, &((*obj)->algorithm_size_));
            } break;
            case 2: {
                noise_protobuf_free_memory((*obj)->key, (*obj)->key_size_);
                (*obj)->key = 0;
                (*obj)->key_size_ = 0;
                noise_protobuf_read_alloc_bytes(pbuf, 2, &((*obj)->key), 0, &((*obj)->key_size_));
            } break;
            default: {
                noise_protobuf_read_skip(pbuf);
            } break;
        }
    }
    err = noise_protobuf_read_end_element(pbuf, end_posn);
    if (err != NOISE_ERROR_NONE) {
        Noise_PrivateKeyInfo_free(*obj);
        *obj = 0;
    }
    return err;
}

int Noise_PrivateKeyInfo_clear_algorithm(Noise_PrivateKeyInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
        obj->algorithm = 0;
        obj->algorithm_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKeyInfo_has_algorithm(const Noise_PrivateKeyInfo *obj)
{
    return obj ? (obj->algorithm != 0) : 0;
}

const char *Noise_PrivateKeyInfo_get_algorithm(const Noise_PrivateKeyInfo *obj)
{
    return obj ? obj->algorithm : 0;
}

size_t Noise_PrivateKeyInfo_get_size_algorithm(const Noise_PrivateKeyInfo *obj)
{
    return obj ? obj->algorithm_size_ : 0;
}

int Noise_PrivateKeyInfo_set_algorithm(Noise_PrivateKeyInfo *obj, const char *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->algorithm, obj->algorithm_size_);
        obj->algorithm = (char *)malloc(size + 1);
        if (obj->algorithm) {
            memcpy(obj->algorithm, value, size);
            obj->algorithm[size] = 0;
            obj->algorithm_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->algorithm_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKeyInfo_clear_key(Noise_PrivateKeyInfo *obj)
{
    if (obj) {
        noise_protobuf_free_memory(obj->key, obj->key_size_);
        obj->key = 0;
        obj->key_size_ = 0;
        return NOISE_ERROR_NONE;
    }
    return NOISE_ERROR_INVALID_PARAM;
}

int Noise_PrivateKeyInfo_has_key(const Noise_PrivateKeyInfo *obj)
{
    return obj ? (obj->key != 0) : 0;
}

const void *Noise_PrivateKeyInfo_get_key(const Noise_PrivateKeyInfo *obj)
{
    return obj ? obj->key : 0;
}

size_t Noise_PrivateKeyInfo_get_size_key(const Noise_PrivateKeyInfo *obj)
{
    return obj ? obj->key_size_ : 0;
}

int Noise_PrivateKeyInfo_set_key(Noise_PrivateKeyInfo *obj, const void *value, size_t size)
{
    if (obj) {
        noise_protobuf_free_memory(obj->key, obj->key_size_);
        obj->key = (void *)malloc(size ? size : 1);
        if (obj->key) {
            memcpy(obj->key, value, size);
            obj->key_size_ = size;
            return NOISE_ERROR_NONE;
        } else {
            obj->key_size_ = 0;
            return NOISE_ERROR_NO_MEMORY;
        }
    }
    return NOISE_ERROR_INVALID_PARAM;
}

