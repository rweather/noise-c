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

#ifndef __ECHO_COMMON_H__
#define __ECHO_COMMON_H__

#include <noise/protocol.h>

/*
    Protocol byte defintions for the echo protocol from:
    https://github.com/centromere/cacophony#example-code
*/

#define ECHO_PSK_DISABLED           0x00
#define ECHO_PSK_ENABLED            0x01

#define ECHO_PATTERN_NN             0x00
#define ECHO_PATTERN_KN             0x01
#define ECHO_PATTERN_NK             0x02
#define ECHO_PATTERN_KK             0x03
#define ECHO_PATTERN_NX             0x04
#define ECHO_PATTERN_KX             0x05
#define ECHO_PATTERN_XN             0x06
#define ECHO_PATTERN_IN             0x07
#define ECHO_PATTERN_XK             0x08
#define ECHO_PATTERN_IK             0x09
#define ECHO_PATTERN_XX             0x0A
#define ECHO_PATTERN_IX             0x0B
#define ECHO_PATTERN_XR             0x0C

#define ECHO_CIPHER_CHACHAPOLY      0x00
#define ECHO_CIPHER_AESGCM          0x01

#define ECHO_DH_25519               0x00
#define ECHO_DH_448                 0x01

#define ECHO_HASH_SHA256            0x00
#define ECHO_HASH_SHA512            0x01
#define ECHO_HASH_BLAKE2s           0x02
#define ECHO_HASH_BLAKE2b           0x03

typedef struct
{
    uint8_t psk;
    uint8_t pattern;
    uint8_t cipher;
    uint8_t dh;
    uint8_t hash;

} EchoProtocolId;

#define MAX_DH_KEY_LEN 128

extern int echo_verbose;

int echo_get_protocol_id(EchoProtocolId *id, const char *name);
int echo_to_noise_protocol_id(NoiseProtocolId *nid, const EchoProtocolId *id);

int echo_load_private_key(const char *filename, uint8_t *key, size_t len);
int echo_load_public_key(const char *filename, uint8_t *key, size_t len);

int echo_connect(const char *hostname, int port);
int echo_accept(int port);

int echo_recv_exact(int fd, uint8_t *packet, size_t len);
size_t echo_recv(int fd, uint8_t *packet, size_t max_len);
int echo_send(int fd, const uint8_t *packet, size_t len);
void echo_close(int fd);

#endif
