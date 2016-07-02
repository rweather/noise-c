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

#include <noise/protocol.h>
#include "internal.h"
#include "simple-handshakestate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Format information from:
// https://github.com/noiseprotocol/noise_wiki/wiki/Test-vectors

typedef struct
{
    uint8_t k25519_private[32];
    uint8_t k448_private[56];
    uint8_t k25519_public[32];
    uint8_t k448_public[56];
} Key;

// Values for populating keys, prologues, etc.
static uint8_t const prologue[] = {
    0x50, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x75, 0x65,
    0x31, 0x32, 0x33
};
static uint8_t const psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static uint8_t const ssk[] = {
    0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
    0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};
static Key const init_ephemeral = {
    {
        0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6,
        0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7,
        0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a,
        0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a
    },
    {
        0x7f, 0xd2, 0x6c, 0x8b, 0x8a, 0x0d, 0x5c, 0x98,
        0xc8, 0x5f, 0xf9, 0xca, 0x1d, 0x7b, 0xc6, 0x6d,
        0x78, 0x57, 0x8b, 0x9f, 0x2c, 0x4c, 0x17, 0x08,
        0x50, 0x74, 0x8b, 0x27, 0x99, 0x27, 0x67, 0xe6,
        0xea, 0x6c, 0xc9, 0x99, 0x2a, 0x56, 0x1c, 0x9d,
        0x19, 0xdf, 0xc3, 0x42, 0xe2, 0x60, 0xc2, 0x80,
        0xef, 0x4f, 0x3f, 0x9b, 0x8f, 0x87, 0x9d, 0x4e
    },
    {
        0xca, 0x35, 0xde, 0xf5, 0xae, 0x56, 0xce, 0xc3,
        0x3d, 0xc2, 0x03, 0x67, 0x31, 0xab, 0x14, 0x89,
        0x6b, 0xc4, 0xc7, 0x5d, 0xbb, 0x07, 0xa6, 0x1f,
        0x87, 0x9f, 0x8e, 0x3a, 0xfa, 0x4c, 0x79, 0x44
    },
    {
        0x6c, 0xfc, 0xb9, 0x8a, 0xe6, 0xb1, 0xbc, 0x56,
        0x59, 0xca, 0xdc, 0x59, 0x5b, 0xf6, 0x64, 0xe1,
        0x70, 0x94, 0x40, 0x4e, 0xae, 0x6b, 0x45, 0xfd,
        0xe6, 0xfc, 0x40, 0xca, 0x93, 0x7d, 0x1d, 0xbe,
        0x14, 0x64, 0xcb, 0x66, 0xeb, 0x21, 0xfd, 0xba,
        0xa4, 0x87, 0xcd, 0x0d, 0x11, 0xd6, 0xdc, 0xe5,
        0xaa, 0x07, 0xb8, 0x21, 0x9b, 0xfd, 0xc4, 0x9a
    }
};
static Key const resp_ephemeral = {
    {
        0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
        0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
        0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
        0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
    },
    {
        0x3f, 0xac, 0xf7, 0x50, 0x3e, 0xbe, 0xe2, 0x52,
        0x46, 0x56, 0x89, 0xf1, 0xd4, 0xe3, 0xb1, 0xdd,
        0x21, 0x96, 0x39, 0xef, 0x9d, 0xe4, 0xff, 0xd6,
        0x04, 0x9d, 0x6d, 0x71, 0xa0, 0xf6, 0x21, 0x26,
        0x84, 0x0f, 0xeb, 0xb9, 0x90, 0x42, 0x42, 0x1c,
        0xe1, 0x2a, 0xf6, 0x62, 0x6d, 0x98, 0xd9, 0x17,
        0x02, 0x60, 0x39, 0x0f, 0xbc, 0x83, 0x99, 0xa5
    },
    {
        0x95, 0xeb, 0xc6, 0x0d, 0x2b, 0x1f, 0xa6, 0x72,
        0xc1, 0xf4, 0x6a, 0x8a, 0xa2, 0x65, 0xef, 0x51,
        0xbf, 0xe3, 0x8e, 0x7c, 0xcb, 0x39, 0xec, 0x5b,
        0xe3, 0x40, 0x69, 0xf1, 0x44, 0x80, 0x88, 0x43
    },
    {
        0xf7, 0xeb, 0x9a, 0x09, 0x46, 0x8f, 0x95, 0x64,
        0x81, 0x9d, 0xe0, 0x7a, 0xda, 0x77, 0xa6, 0xcf,
        0x5d, 0x5e, 0xac, 0xd8, 0x46, 0x82, 0x06, 0x75,
        0x38, 0xbf, 0x2c, 0x4e, 0x4c, 0x90, 0x5e, 0x5c,
        0xc3, 0x5c, 0xc3, 0xff, 0x41, 0x24, 0x1e, 0x47,
        0xae, 0x3b, 0xd2, 0x96, 0x47, 0x7a, 0x23, 0x6e,
        0xf1, 0x85, 0xe5, 0xa8, 0xa0, 0xf1, 0x8d, 0x65
    }
};
static Key const init_static = {
    {
        0xe6, 0x1e, 0xf9, 0x91, 0x9c, 0xde, 0x45, 0xdd,
        0x5f, 0x82, 0x16, 0x64, 0x04, 0xbd, 0x08, 0xe3,
        0x8b, 0xce, 0xb5, 0xdf, 0xdf, 0xde, 0xd0, 0xa3,
        0x4c, 0x8d, 0xf7, 0xed, 0x54, 0x22, 0x14, 0xd1
    },
    {
        0x34, 0xd5, 0x64, 0xc4, 0xbe, 0x96, 0x3d, 0x1b,
        0x2a, 0x89, 0xfc, 0xfe, 0x83, 0xe6, 0xa7, 0x2b,
        0x5e, 0x3f, 0x5e, 0x31, 0x27, 0xf9, 0xf5, 0x96,
        0xff, 0xc7, 0x57, 0x5e, 0x41, 0x8d, 0xfc, 0x1f,
        0x4e, 0x82, 0x7c, 0xfc, 0x10, 0xc9, 0xfe, 0xd3,
        0x8e, 0x92, 0xad, 0x56, 0xdd, 0xf8, 0xf0, 0x85,
        0x71, 0x43, 0x0d, 0xf2, 0xe7, 0x6d, 0x54, 0x11
    },
    {
        0x6b, 0xc3, 0x82, 0x2a, 0x2a, 0xa7, 0xf4, 0xe6,
        0x98, 0x1d, 0x65, 0x38, 0x69, 0x2b, 0x3c, 0xdf,
        0x3e, 0x6d, 0xf9, 0xee, 0xa6, 0xed, 0x26, 0x9e,
        0xb4, 0x1d, 0x93, 0xc2, 0x27, 0x57, 0xb7, 0x5a
    },
    {
        0x30, 0x15, 0x51, 0xec, 0xa1, 0x78, 0x8f, 0x44,
        0x51, 0xc2, 0x69, 0xbe, 0xaf, 0xed, 0x11, 0x0b,
        0x51, 0xf0, 0x8c, 0x04, 0x94, 0xa8, 0xde, 0x61,
        0x4a, 0x18, 0x4f, 0xf3, 0xd4, 0x67, 0xd7, 0xde,
        0xfd, 0xfc, 0x7c, 0x13, 0x8e, 0x46, 0x69, 0x59,
        0x11, 0x08, 0xb6, 0x9a, 0x05, 0x6d, 0x25, 0xca,
        0xfd, 0xa2, 0x89, 0xf2, 0x2d, 0x1f, 0x32, 0xc0
    }
};
static Key const resp_static = {
    {
        0x4a, 0x3a, 0xcb, 0xfd, 0xb1, 0x63, 0xde, 0xc6,
        0x51, 0xdf, 0xa3, 0x19, 0x4d, 0xec, 0xe6, 0x76,
        0xd4, 0x37, 0x02, 0x9c, 0x62, 0xa4, 0x08, 0xb4,
        0xc5, 0xea, 0x91, 0x14, 0x24, 0x6e, 0x48, 0x93
    },
    {
        0xa9, 0xb4, 0x59, 0x71, 0x18, 0x08, 0x82, 0xa7,
        0x9b, 0x89, 0xa3, 0x39, 0x95, 0x44, 0xa4, 0x25,
        0xef, 0x81, 0x36, 0xd2, 0x78, 0xef, 0xa4, 0x43,
        0xed, 0x67, 0xd3, 0xff, 0x9d, 0x36, 0xe8, 0x83,
        0xbc, 0x33, 0x0c, 0x62, 0x95, 0xbb, 0xf6, 0xed,
        0x73, 0xff, 0x6f, 0xd1, 0x0c, 0xbe, 0xd7, 0x67,
        0xad, 0x05, 0xce, 0x03, 0xeb, 0xd2, 0x7c, 0x7c
    },
    {
        0x31, 0xe0, 0x30, 0x3f, 0xd6, 0x41, 0x8d, 0x2f,
        0x8c, 0x0e, 0x78, 0xb9, 0x1f, 0x22, 0xe8, 0xca,
        0xed, 0x0f, 0xbe, 0x48, 0x65, 0x6d, 0xcf, 0x47,
        0x67, 0xe4, 0x83, 0x4f, 0x70, 0x1b, 0x8f, 0x62
    },
    {
        0xbd, 0x20, 0x0f, 0xa6, 0xd5, 0x0d, 0xb3, 0xa7,
        0x43, 0x79, 0x7b, 0x00, 0xac, 0xa1, 0xb7, 0x0f,
        0x41, 0x7b, 0xfc, 0x38, 0x1b, 0x28, 0xb2, 0x1b,
        0x58, 0x35, 0xd8, 0x4c, 0xf7, 0xa6, 0xda, 0x6a,
        0xbb, 0xa1, 0x9e, 0x3b, 0xa7, 0xd4, 0x6b, 0x25,
        0x34, 0x12, 0xb7, 0x46, 0x65, 0xd4, 0x62, 0x7b,
        0x65, 0xfc, 0xef, 0x3f, 0x29, 0xc9, 0x5d, 0x3e
    }
};
static Key const resp_static_2 = {
    {
        0xc9, 0xe9, 0x7f, 0xf5, 0x46, 0x73, 0x1e, 0x9d,
        0xbe, 0x8c, 0x4e, 0x8a, 0xbc, 0x57, 0xb6, 0xdd,
        0x05, 0x95, 0x78, 0x7a, 0x52, 0xb1, 0xa5, 0x75,
        0xbc, 0x55, 0x22, 0xea, 0x43, 0xa0, 0x8d, 0x64
    },
    {
        0x78, 0xf2, 0xec, 0x74, 0xd0, 0xb0, 0xde, 0xef,
        0xad, 0xe2, 0xef, 0xba, 0xc4, 0x17, 0x2f, 0xce,
        0xb1, 0x4f, 0x03, 0x64, 0xd3, 0x3a, 0x99, 0x77,
        0xab, 0xdb, 0xf7, 0x8a, 0x2e, 0x6e, 0x4c, 0x6f,
        0x62, 0x07, 0xfe, 0xa4, 0x29, 0x39, 0xa0, 0xba,
        0xb6, 0x39, 0x8e, 0xed, 0x75, 0xf9, 0xee, 0x5b,
        0xfd, 0x99, 0x00, 0xae, 0x4e, 0xdc, 0xe5, 0x47
    },
    {
        0xf2, 0x15, 0xfe, 0x4a, 0xd5, 0x4b, 0x35, 0x45,
        0x88, 0xd3, 0xfa, 0x52, 0x16, 0x61, 0x79, 0xb7,
        0x23, 0xb9, 0xa2, 0x11, 0xec, 0x67, 0x16, 0x7b,
        0x9b, 0xf1, 0x72, 0x92, 0x60, 0x97, 0x2a, 0x23
    },
    {
        0x30, 0xab, 0xe6, 0x0d, 0xab, 0x54, 0x85, 0x1c,
        0x91, 0x89, 0x5b, 0x57, 0xfa, 0x55, 0x35, 0xd7,
        0x86, 0xc2, 0x14, 0x4d, 0x18, 0x3f, 0xf1, 0xbc,
        0xf8, 0xce, 0x24, 0x5c, 0x83, 0xa2, 0x2c, 0x60,
        0x10, 0x9b, 0x4c, 0x08, 0xfb, 0xd1, 0x5d, 0xa2,
        0x4a, 0x38, 0x84, 0xde, 0x1c, 0x91, 0x4a, 0x03,
        0xcb, 0x04, 0xcd, 0xe8, 0xd9, 0xfc, 0x4f, 0xb1
    }
};

// Payload values for successive messages.
static uint8_t const payload1[] = {
    0x4c, 0x75, 0x64, 0x77, 0x69, 0x67, 0x20, 0x76,
    0x6f, 0x6e, 0x20, 0x4d, 0x69, 0x73, 0x65, 0x73
};
static uint8_t const payload2[] = {
    0x4d, 0x75, 0x72, 0x72, 0x61, 0x79, 0x20, 0x52,
    0x6f, 0x74, 0x68, 0x62, 0x61, 0x72, 0x64
};
static uint8_t const payload3[] = {
    0x46, 0x2e, 0x20, 0x41, 0x2e, 0x20, 0x48, 0x61,
    0x79, 0x65, 0x6b
};
static uint8_t const payload4[] = {
    0x43, 0x61, 0x72, 0x6c, 0x20, 0x4d, 0x65, 0x6e,
    0x67, 0x65, 0x72
};
static uint8_t const payload5[] = {
    0x4a, 0x65, 0x61, 0x6e, 0x2d, 0x42, 0x61, 0x70,
    0x74, 0x69, 0x73, 0x74, 0x65, 0x20, 0x53, 0x61,
    0x79
};
static uint8_t const payload6[] = {
    0x45, 0x75, 0x67, 0x65, 0x6e, 0x20, 0x42, 0xf6,
    0x68, 0x6d, 0x20, 0x76, 0x6f, 0x6e, 0x20, 0x42,
    0x61, 0x77, 0x65, 0x72, 0x6b
};
static struct {
    const uint8_t *data;
    size_t len;
} const payloads[] = {
    {payload1, sizeof(payload1)},
    {payload2, sizeof(payload2)},
    {payload3, sizeof(payload3)},
    {payload4, sizeof(payload4)},
    {payload5, sizeof(payload5)},
    {payload6, sizeof(payload6)}
};
#define num_payloads    ((int)(sizeof(payloads) / sizeof(payloads[0])))

static void print_hex(const char *field, const uint8_t *data, size_t len)
{
    static char const hexchars[] = "0123456789abcdef";
    printf("\"%s\": \"", field);
    while (len > 0) {
        int ch = *data++;
        printf("%c%c", hexchars[(ch >> 4) & 0x0F], hexchars[ch & 0x0F]);
        --len;
    }
    printf("\",\n");
}

static void print_hex_no_comma(const char *field, const uint8_t *data, size_t len)
{
    static char const hexchars[] = "0123456789abcdef";
    printf("\"%s\": \"", field);
    while (len > 0) {
        int ch = *data++;
        printf("%c%c", hexchars[(ch >> 4) & 0x0F], hexchars[ch & 0x0F]);
        --len;
    }
    printf("\"\n");
}

static void print_key(const char *field, const Key *key, const NoiseProtocolId *id)
{
    if (id->dh_id == NOISE_DH_CURVE25519)
        print_hex(field, key->k25519_private, sizeof(key->k25519_private));
    else
        print_hex(field, key->k448_private, sizeof(key->k448_private));
}

static void print_public_key(const char *field, const Key *key, const NoiseProtocolId *id)
{
    if (id->dh_id == NOISE_DH_CURVE25519)
        print_hex(field, key->k25519_public, sizeof(key->k25519_public));
    else
        print_hex(field, key->k448_public, sizeof(key->k448_public));
}

static void get_key(const uint8_t **k, size_t *klen, const Key *key, const NoiseProtocolId *id)
{
    if (id->dh_id == NOISE_DH_CURVE25519) {
        *k = key->k25519_private;
        *klen = sizeof(key->k25519_private);
    } else {
        *k = key->k448_private;
        *klen = sizeof(key->k448_private);
    }
}

static void get_public_key(const uint8_t **k, size_t *klen, const Key *key, const NoiseProtocolId *id)
{
    if (id->dh_id == NOISE_DH_CURVE25519) {
        *k = key->k25519_public;
        *klen = sizeof(key->k25519_public);
    } else {
        *k = key->k448_public;
        *klen = sizeof(key->k448_public);
    }
}

static void initialize_protocol
    (HandshakeState *init, HandshakeState *resp, uint8_t flags,
     const char *protocol_name, const NoiseProtocolId *id, int with_fallback)
{
    const uint8_t *s = 0;
    size_t s_len = 0;
    const uint8_t *e = 0;
    size_t e_len = 0;
    const uint8_t *re = 0;
    size_t re_len = 0;
    const uint8_t *rs = 0;
    size_t rs_len = 0;
    const uint8_t *pk = 0;
    size_t pk_len = 0;
    if (flags & NOISE_PAT_FLAG_LOCAL_STATIC) {
        get_key(&s, &s_len, &init_static, id);
    }
    if (flags & NOISE_PAT_FLAG_LOCAL_EPHEMERAL) {
        get_key(&e, &e_len, &init_ephemeral, id);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
        /* Deliberately use the wrong remote key if we will fallback */
        if (with_fallback)
            get_public_key(&rs, &rs_len, &resp_static_2, id);
        else
            get_public_key(&rs, &rs_len, &resp_static, id);
    }
    if (id->prefix_id == NOISE_PREFIX_PSK) {
        pk = psk;
        pk_len = sizeof(psk);
    }
    Initialize(init, protocol_name, 1, prologue, sizeof(prologue),
               s, s_len, e, e_len, rs, rs_len, re, re_len, pk, pk_len);
    s = 0;
    s_len = 0;
    e = 0;
    e_len = 0;
    re = 0;
    re_len = 0;
    rs = 0;
    rs_len = 0;
    pk = 0;
    pk_len = 0;
    if (flags & NOISE_PAT_FLAG_REMOTE_STATIC) {
        get_key(&s, &s_len, &resp_static, id);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_EPHEMERAL) {
        get_key(&e, &e_len, &resp_ephemeral, id);
    }
    if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED) {
        get_public_key(&rs, &rs_len, &init_static, id);
    }
    if (id->prefix_id == NOISE_PREFIX_PSK) {
        pk = psk;
        pk_len = sizeof(psk);
    }
    Initialize(resp, protocol_name, 0, prologue, sizeof(prologue),
               s, s_len, e, e_len, rs, rs_len, re, re_len, pk, pk_len);
}

static void initialize_protocol_fallback
    (HandshakeState *init, HandshakeState *resp, uint8_t flags,
     const char *protocol_name, const NoiseProtocolId *id)
{
    const uint8_t *s = 0;
    size_t s_len = 0;
    const uint8_t *e = 0;
    size_t e_len = 0;
    const uint8_t *re = 0;
    size_t re_len = 0;
    const uint8_t *rs = 0;
    size_t rs_len = 0;
    const uint8_t *pk = 0;
    size_t pk_len = 0;
    if (flags & NOISE_PAT_FLAG_LOCAL_STATIC) {
        get_key(&s, &s_len, &resp_static, id);
    }
    if (flags & NOISE_PAT_FLAG_LOCAL_EPHEMERAL) {
        get_key(&e, &e_len, &resp_ephemeral, id);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
        get_public_key(&rs, &rs_len, &init_static, id);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) {
        get_public_key(&re, &re_len, &init_ephemeral, id);
    }
    if (id->prefix_id == NOISE_PREFIX_PSK) {
        pk = psk;
        pk_len = sizeof(psk);
    }
    Initialize(init, protocol_name, 1, prologue, sizeof(prologue),
               s, s_len, e, e_len, rs, rs_len, re, re_len, pk, pk_len);
    s = 0;
    s_len = 0;
    e = 0;
    e_len = 0;
    re = 0;
    re_len = 0;
    rs = 0;
    rs_len = 0;
    pk = 0;
    pk_len = 0;
    if (flags & NOISE_PAT_FLAG_REMOTE_STATIC) {
        get_key(&s, &s_len, &init_static, id);
    }
    if (flags & NOISE_PAT_FLAG_REMOTE_EPHEMERAL) {
        get_key(&e, &e_len, &init_ephemeral, id);
    }
    if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED) {
        get_public_key(&rs, &rs_len, &resp_static, id);
    }
    if (id->prefix_id == NOISE_PREFIX_PSK) {
        pk = psk;
        pk_len = sizeof(psk);
    }
    Initialize(resp, protocol_name, 0, prologue, sizeof(prologue),
               s, s_len, e, e_len, rs, rs_len, re, re_len, pk, pk_len);
}

static void generate_vector(const NoiseProtocolId *id, int first, int with_ssk, int with_fallback)
{
    NoiseProtocolId id2;
    char protocol_name[NOISE_MAX_PROTOCOL_NAME];
    char alt_protocol_name[NOISE_MAX_PROTOCOL_NAME];
    const uint8_t *pattern = noise_pattern_lookup(id->pattern_id);
    uint8_t flags = *pattern;
    HandshakeState init;
    HandshakeState resp;
    int payload_num;
    int speaker;
    Buffer payload;
    Buffer message;
    Buffer ad;
    int is_one_way;
    CipherState init_c1;
    CipherState init_c2;
    CipherState resp_c1;
    CipherState resp_c2;
    int fallback = with_fallback;

    /* Initialize the handshakes for each end of the communication */
    HandshakeState_new(&init);
    HandshakeState_new(&resp);

    /* Convert the identifiers into a name and print out the components */
    noise_protocol_id_to_name(protocol_name, sizeof(protocol_name), id);
    if (!first)
        printf(",\n");
    printf("{\n");
    id2 = *id;
    if (with_fallback) {
        /* The incoming pattern is "IK" - put "XXfallback" in the name
           field instead to make it clear what we are doing */
        id2.pattern_id = NOISE_PATTERN_XX_FALLBACK;
        noise_protocol_id_to_name(alt_protocol_name, sizeof(alt_protocol_name), &id2);
        printf("\"name\": \"%s%s\",\n", alt_protocol_name, with_ssk ? ":SSK" : "");
    } else {
        printf("\"name\": \"%s%s\",\n", protocol_name, with_ssk ? ":SSK" : "");
        alt_protocol_name[0] = '\0';
    }
    printf("\"pattern\": \"%s\",\n", noise_id_to_name(0, id->pattern_id));
    printf("\"dh\": \"%s\",\n", noise_id_to_name(0, id->dh_id));
    printf("\"cipher\": \"%s\",\n", noise_id_to_name(0, id->cipher_id));
    printf("\"hash\": \"%s\",\n", noise_id_to_name(0, id->hash_id));
    if (with_fallback)
        printf("\"fallback\": true,\n");
    print_hex("init_prologue", prologue, sizeof(prologue));
    if (id->prefix_id == NOISE_PREFIX_PSK)
        print_hex("init_psk", psk, sizeof(psk));
    if (with_ssk)
        print_hex("init_ssk", ssk, sizeof(ssk));
    if (flags & NOISE_PAT_FLAG_LOCAL_STATIC)
        print_key("init_static", &init_static, id);
    if (flags & NOISE_PAT_FLAG_LOCAL_EPHEMERAL)
        print_key("init_ephemeral", &init_ephemeral, id);
    if (flags & NOISE_PAT_FLAG_REMOTE_REQUIRED) {
        /* If we are going to fall back, then give the initiator the
           wrong static key for the responder */
        if (with_fallback)
            print_public_key("init_remote_static", &resp_static_2, id);
        else
            print_public_key("init_remote_static", &resp_static, id);
    }
    print_hex("resp_prologue", prologue, sizeof(prologue));
    if (id->prefix_id == NOISE_PREFIX_PSK)
        print_hex("resp_psk", psk, sizeof(psk));
    if (with_ssk)
        print_hex("resp_ssk", ssk, sizeof(ssk));
    if (flags & NOISE_PAT_FLAG_REMOTE_STATIC)
        print_key("resp_static", &resp_static, id);
    if (flags & NOISE_PAT_FLAG_REMOTE_EPHEMERAL)
        print_key("resp_ephemeral", &resp_ephemeral, id);
    if (flags & NOISE_PAT_FLAG_LOCAL_REQUIRED)
        print_public_key("resp_remote_static", &init_static, id);

    /* Initialize both ends of the communication */
    initialize_protocol(&init, &resp, flags, protocol_name, id, with_fallback);

    /* Run the handshake */
    printf("\"messages\": [\n");
    payload_num = 0;
    speaker = 0;    /* 0 = initiator, 1 = responder */
    is_one_way = (id->pattern_id == NOISE_PATTERN_N ||
                  id->pattern_id == NOISE_PATTERN_K ||
                  id->pattern_id == NOISE_PATTERN_X);
    while (init.action == ACTION_WRITE || init.action == ACTION_READ) {
        memcpy(payload.data, payloads[payload_num].data,
               payloads[payload_num].len);
        payload.size = payloads[payload_num].len;
        printf("{\n");
        print_hex("payload", payload.data, payload.size);
        if (speaker == 0) {
            WriteMessage(&init, payload, &message);
            print_hex_no_comma("ciphertext", message.data, message.size);
            if (fallback) {
                /* Switch to XXfallback and swap initiator/responder */
                pattern = noise_pattern_lookup(id2.pattern_id);
                flags = *pattern;
                initialize_protocol_fallback
                    (&init, &resp, flags, alt_protocol_name, &id2);
                fallback = 0;
                speaker = 1;
            } else if (!is_one_way) {
                ReadMessage(&resp, message, &payload);
            }
        } else {
            WriteMessage(&resp, payload, &message);
            print_hex_no_comma("ciphertext", message.data, message.size);
            if (!is_one_way)
                ReadMessage(&init, message, &payload);
        }
        printf("},\n");
        if (!is_one_way)
            speaker = !speaker;
        ++payload_num;
    }

    /* Split both ends of the communication */
    if (with_ssk) {
        memcpy(message.data, ssk, sizeof(ssk));
        message.size = sizeof(ssk);
    } else {
        message.size = 0;
    }
    Split(&(init.symmetric), message, &init_c1, &init_c2);
    Split(&(resp.symmetric), message, &resp_c1, &resp_c2);

    /* Exchange transport messages between the initiator and responder */
    while (payload_num < num_payloads) {
        printf("{\n");
        memcpy(payload.data, payloads[payload_num].data,
               payloads[payload_num].len);
        payload.size = payloads[payload_num].len;
        print_hex("payload", payload.data, payload.size);
        ad.size = 0;
        if (speaker == 0) {
            message = EncryptWithAd(&init_c1, ad, payload);
            print_hex_no_comma("ciphertext", message.data, message.size);
            DecryptWithAd(&resp_c1, ad, message, &payload);
        } else {
            message = EncryptWithAd(&resp_c2, ad, payload);
            print_hex_no_comma("ciphertext", message.data, message.size);
            DecryptWithAd(&init_c2, ad, message, &payload);
        }
        if (!is_one_way)
            speaker = !speaker;
        ++payload_num;
        if (payload_num < num_payloads)
            printf("},\n");
        else
            printf("}\n");
    }

    /* Print the footer */
    printf("],\n");
    print_hex_no_comma("handshake_hash", init.symmetric.h, init.symmetric.hash_len);
    printf("}");

    /* Clean up */
    HandshakeState_free(&init);
    HandshakeState_free(&resp);
    CipherState_free(&init_c1);
    CipherState_free(&init_c2);
    CipherState_free(&resp_c1);
    CipherState_free(&resp_c2);
}

int main(int argc, char *argv[])
{
    NoiseProtocolId id;
    int first = 1;
    int with_ssk = 0;
    int with_fallback = 0;

    while (argc > 1) {
        if (!strcmp(argv[1], "--with-ssk"))
            with_ssk = 1;
        if (!strcmp(argv[1], "--with-fallback"))
            with_fallback = 1;
        ++argv;
        --argc;
    }

    memset(&id, 0, sizeof(id));
    printf("{\n");
    printf("\"vectors\": [\n");

    if (!with_fallback) {
        /* Output all of the regular patterns */
        for (id.pattern_id = NOISE_PATTERN_N; id.pattern_id <= NOISE_PATTERN_IX; ++id.pattern_id) {
            for (id.prefix_id = NOISE_PREFIX_STANDARD; id.prefix_id <= NOISE_PREFIX_PSK; ++id.prefix_id) {
                for (id.cipher_id = NOISE_CIPHER_CHACHAPOLY; id.cipher_id <= NOISE_CIPHER_AESGCM; ++id.cipher_id) {
                    for (id.dh_id = NOISE_DH_CURVE25519; id.dh_id <= NOISE_DH_CURVE448; ++id.dh_id) {
                        for (id.hash_id = NOISE_HASH_BLAKE2s; id.hash_id <= NOISE_HASH_SHA512; ++id.hash_id) {
                            generate_vector(&id, first, with_ssk, 0);
                            first = 0;
                        }
                    }
                }
            }
        }
    } else {
        /* Output fallback patterns, starting with "IK" */
        id.pattern_id = NOISE_PATTERN_IK;
        for (id.prefix_id = NOISE_PREFIX_STANDARD; id.prefix_id <= NOISE_PREFIX_PSK; ++id.prefix_id) {
            for (id.cipher_id = NOISE_CIPHER_CHACHAPOLY; id.cipher_id <= NOISE_CIPHER_AESGCM; ++id.cipher_id) {
                for (id.dh_id = NOISE_DH_CURVE25519; id.dh_id <= NOISE_DH_CURVE448; ++id.dh_id) {
                    for (id.hash_id = NOISE_HASH_BLAKE2s; id.hash_id <= NOISE_HASH_SHA512; ++id.hash_id) {
                        generate_vector(&id, first, 0, 1);
                        first = 0;
                        if (with_ssk)
                            generate_vector(&id, first, 1, 1);
                    }
                }
            }
        }
    }

    printf("\n]\n");
    printf("}\n");
    return 0;
}
