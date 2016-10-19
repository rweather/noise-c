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
#include "json-reader.h"
#include <setjmp.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_MESSAGES 32
#define MAX_MESSAGE_SIZE 4096

/**
 * \brief Information about a single test vector.
 */
typedef struct
{
    long line_number;               /**< Line number for the "name" */
    char *name;                     /**< Full name of the test case */
    char *protocol_name;            /**< Full name of the protocol */
    char *pattern;                  /**< Name of the handshake pattern */
    char *dh;                       /**< Name of the DH algorithm */
    char *hybrid;                   /**< Name of the hybrid secrecy algorithm */
    char *cipher;                   /**< Name of the cipher algorithm */
    char *hash;                     /**< Name of the hash algorithm */
    uint8_t *init_static;           /**< Initiator's static private key */
    size_t init_static_len;         /**< Length of init_static in bytes */
    uint8_t *init_public_static;    /**< Initiator's public key known to responder */
    size_t init_public_static_len;  /**< Length of init_public_static in bytes */
    uint8_t *resp_static;           /**< Responder's static private key */
    size_t resp_static_len;         /**< Length of resp_static in bytes */
    uint8_t *resp_public_static;    /**< Responder's public key known to initiator */
    size_t resp_public_static_len;  /**< Length of resp_public_static in bytes */
    uint8_t *init_ephemeral;        /**< Initiator's ephemeral key */
    size_t init_ephemeral_len;      /**< Length of init_ephemeral in bytes */
    uint8_t *resp_ephemeral;        /**< Responder's ephemeral key */
    size_t resp_ephemeral_len;      /**< Length of resp_ephemeral in bytes */
    uint8_t *init_hybrid;           /**< Initiator's hybrid ephemeral key */
    size_t init_hybrid_len;         /**< Length of init_hybrid in bytes */
    uint8_t *resp_hybrid;           /**< Responder's hybrid ephemeral key */
    size_t resp_hybrid_len;         /**< Length of resp_hybrid in bytes */
    uint8_t *init_prologue;         /**< Initiator's prologue data */
    size_t init_prologue_len;       /**< Length of init_prologue in bytes */
    uint8_t *resp_prologue;         /**< Responder's prologue data */
    size_t resp_prologue_len;       /**< Length of resp_prologue in bytes */
    uint8_t *init_psk;              /**< Initiator's pre shared key */
    size_t init_psk_len;            /**< Length of init_psk in bytes */
    uint8_t *resp_psk;              /**< Responder's pre shared key */
    size_t resp_psk_len;            /**< Length of resp_psk in bytes */
    uint8_t *handshake_hash;        /**< Hash at the end of the handshake */
    size_t handshake_hash_len;      /**< Length of handshake_hash in bytes */
    int fail;                       /**< Failure expected on last message */
    int fallback;                   /**< Handshake involves IK to XXfallback */
    char *fallback_pattern;         /**< Name of the pattern to fall back to */
    struct {
        uint8_t *payload;           /**< Payload for this message */
        size_t payload_len;         /**< Length of payload in bytes */
        uint8_t *ciphertext;        /**< Ciphertext for this message */
        size_t ciphertext_len;      /**< Length of ciphertext in bytes */
    } messages[MAX_MESSAGES];       /**< All test messages */
    size_t num_messages;            /**< Number of test messages */

} TestVector;

/**
 * \brief Frees the memory for a test vector.
 *
 * \param vec The test vector.
 */
static void test_vector_free(TestVector *vec)
{
    size_t index;
    #define free_field(name) do { if (vec->name) free(vec->name); } while (0)
    free_field(name);
    free_field(protocol_name);
    free_field(pattern);
    free_field(dh);
    free_field(hybrid);
    free_field(cipher);
    free_field(hash);
    free_field(init_static);
    free_field(init_public_static);
    free_field(resp_static);
    free_field(resp_public_static);
    free_field(init_ephemeral);
    free_field(resp_ephemeral);
    free_field(init_hybrid);
    free_field(resp_hybrid);
    free_field(init_prologue);
    free_field(resp_prologue);
    free_field(init_psk);
    free_field(resp_psk);
    free_field(handshake_hash);
    free_field(fallback_pattern);
    for (index = 0; index < vec->num_messages; ++index) {
        if (vec->messages[index].payload)
            free(vec->messages[index].payload);
        if (vec->messages[index].ciphertext)
            free(vec->messages[index].ciphertext);
    }
    memset(vec, 0, sizeof(TestVector));
}

static jmp_buf test_jump_back;

/**
 * \brief Immediate fail of the test.
 *
 * \param message The failure message to print.
 */
#define _fail(message)   \
    do { \
        printf("%s, failed at " __FILE__ ":%d\n", (message), __LINE__); \
        longjmp(test_jump_back, 1); \
    } while (0)
#define fail(message) _fail((message))

/**
 * \brief Skips the current test.
 */
#define skip() longjmp(test_jump_back, 2)

/**
 * \brief Verifies that a condition is true, failing the test if not.
 *
 * \param condition The boolean condition to test.
 */
#define _verify(condition)   \
    do { \
        if (!(condition)) { \
            printf(#condition " failed at " __FILE__ ":%d\n", __LINE__); \
            longjmp(test_jump_back, 1); \
        } \
    } while (0)
#define verify(condition) _verify((condition))

/**
 * \brief Compares two integer values for equality, failing the test if not.
 *
 * \param actual The actual value that was computed by the code under test.
 * \param expected The value that is expected.
 */
#define compare(actual, expected) \
    do { \
        long long _actual = (long long)(actual); \
        long long _expected = (long long)(expected); \
        if (_actual != _expected) { \
            printf(#actual " != " #expected " at " __FILE__ ":%d\n", __LINE__); \
            printf("    actual  : %lld (0x%llx)\n", _actual, _actual); \
            printf("    expected: %lld (0x%llx)\n", _expected, _expected); \
            longjmp(test_jump_back, 1); \
        } \
    } while (0)

static void dump_block(uint8_t *block, size_t len)
{
    size_t index;
    if (len > 16)
        printf("\n       ");
    for (index = 0; index < len; ++index) {
        printf(" %02x", block[index]);
        if ((index % 16) == 15 && len > 16)
            printf("\n       ");
    }
    printf("\n");
}

#define compare_blocks(name, actual, actual_len, expected, expected_len)  \
    do { \
        if ((actual_len) != (expected_len) || \
                memcmp((actual), (expected), (actual_len)) != 0) { \
            printf("%s wrong at " __FILE__ ":%d\n", (name), __LINE__); \
            printf("    actual  :"); \
            dump_block((actual), (actual_len)); \
            printf("    expected:"); \
            dump_block((expected), (expected_len)); \
            longjmp(test_jump_back, 1); \
        } \
    } while (0)

/**
 * \brief Checks an identifier from a protocol name.
 *
 * \param id The identifier to check.
 * \param category The identifier category.
 * \param name The name to check against.
 */
static void check_id(int id, int category, const char *name)
{
    const char *n = noise_id_to_name(category, id);
    verify(name != 0);
    verify(n != 0);
    verify(!strcmp(name, n));
}

/**
 * \brief Tests the parsing of the protocol name into components.
 *
 * \param vec The test vector.
 *
 * \return Non-zero if the handshake pattern is one-way.
 */
static int test_name_parsing(const TestVector *vec)
{
    NoiseProtocolId id;
    compare(noise_protocol_name_to_id
                (&id, vec->protocol_name, strlen(vec->protocol_name)),
            NOISE_ERROR_NONE);
    if (vec->init_psk || vec->resp_psk)
        compare(id.prefix_id, NOISE_PREFIX_PSK);
    else
        compare(id.prefix_id, NOISE_PREFIX_STANDARD);
    check_id(id.pattern_id, NOISE_PATTERN_CATEGORY, vec->pattern);
    check_id(id.dh_id, NOISE_DH_CATEGORY, vec->dh);
    check_id(id.cipher_id, NOISE_CIPHER_CATEGORY, vec->cipher);
    check_id(id.hash_id, NOISE_HASH_CATEGORY, vec->hash);
    if (vec->hybrid)
        check_id(id.hybrid_id, NOISE_DH_CATEGORY, vec->hybrid);
    else
        compare(id.hybrid_id, 0);
    return id.pattern_id == NOISE_PATTERN_N ||
           id.pattern_id == NOISE_PATTERN_X ||
           id.pattern_id == NOISE_PATTERN_K;
}

/**
 * \brief Test a connection between an initiator and a responder.
 *
 * \param vec The test vector.
 * \param is_one_way Non-zero if the handshake pattern is one-way.
 */
static void test_connection(const TestVector *vec, int is_one_way)
{
    NoiseHandshakeState *initiator;
    NoiseHandshakeState *responder;
    NoiseHandshakeState *send;
    NoiseHandshakeState *recv;
    NoiseDHState *dh;
    NoiseCipherState *c1init;
    NoiseCipherState *c2init;
    NoiseCipherState *c1resp;
    NoiseCipherState *c2resp;
    NoiseCipherState *csend;
    NoiseCipherState *crecv;
    NoiseBuffer mbuf;
    NoiseBuffer pbuf;
    uint8_t message[MAX_MESSAGE_SIZE];
    uint8_t payload[MAX_MESSAGE_SIZE];
    size_t index;
    size_t mac_len;
    int role;
    int fallback = vec->fallback;

    /* Create the two ends of the connection */
    compare(noise_handshakestate_new_by_name
                (&initiator, vec->protocol_name, NOISE_ROLE_INITIATOR),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_new_by_name
                (&responder, vec->protocol_name, NOISE_ROLE_RESPONDER),
            NOISE_ERROR_NONE);

    /* Set all keys that we need to use */
    if (vec->init_static) {
        dh = noise_handshakestate_get_local_keypair_dh(initiator);
        compare(noise_dhstate_set_keypair_private
                    (dh, vec->init_static, vec->init_static_len),
                NOISE_ERROR_NONE);
    }
    if (vec->init_public_static) {
        dh = noise_handshakestate_get_remote_public_key_dh(responder);
        compare(noise_dhstate_set_public_key
                    (dh, vec->init_public_static, vec->init_public_static_len),
                NOISE_ERROR_NONE);
    }
    if (vec->resp_static) {
        dh = noise_handshakestate_get_local_keypair_dh(responder);
        compare(noise_dhstate_set_keypair_private
                    (dh, vec->resp_static, vec->resp_static_len),
                NOISE_ERROR_NONE);
    }
    if (vec->resp_public_static) {
        dh = noise_handshakestate_get_remote_public_key_dh(initiator);
        compare(noise_dhstate_set_public_key
                    (dh, vec->resp_public_static, vec->resp_public_static_len),
                NOISE_ERROR_NONE);
    }
    if (vec->init_ephemeral) {
        dh = noise_handshakestate_get_fixed_ephemeral_dh(initiator);
        compare(noise_dhstate_set_keypair_private
                    (dh, vec->init_ephemeral, vec->init_ephemeral_len),
                NOISE_ERROR_NONE);
    }
    if (vec->init_hybrid) {
        dh = noise_handshakestate_get_fixed_hybrid_dh(initiator);
        compare(noise_dhstate_set_keypair_private
                    (dh, vec->init_hybrid, vec->init_hybrid_len),
                NOISE_ERROR_NONE);
    }
    /* Note: The test data contains responder ephemeral keys for one-way
       patterns which doesn't actually make sense.  Ignore those keys. */
    if (vec->resp_ephemeral && strlen(vec->pattern) != 1) {
        dh = noise_handshakestate_get_fixed_ephemeral_dh(responder);
        compare(noise_dhstate_set_keypair_private
                    (dh, vec->resp_ephemeral, vec->resp_ephemeral_len),
                NOISE_ERROR_NONE);
    }
    if (vec->resp_hybrid && strlen(vec->pattern) != 1) {
        dh = noise_handshakestate_get_fixed_hybrid_dh(responder);
        compare(noise_dhstate_set_keypair_private
                    (dh, vec->resp_hybrid, vec->resp_hybrid_len),
                NOISE_ERROR_NONE);
    }

    /* Set the prologues and pre shared keys */
    if (vec->init_prologue) {
        compare(noise_handshakestate_set_prologue
                    (initiator, vec->init_prologue, vec->init_prologue_len),
                NOISE_ERROR_NONE);
    }
    if (vec->resp_prologue) {
        compare(noise_handshakestate_set_prologue
                    (responder, vec->resp_prologue, vec->resp_prologue_len),
                NOISE_ERROR_NONE);
    }
    if (vec->init_psk) {
        compare(noise_handshakestate_set_pre_shared_key
                    (initiator, vec->init_psk, vec->init_psk_len),
                NOISE_ERROR_NONE);
    }
    if (vec->resp_psk) {
        compare(noise_handshakestate_set_pre_shared_key
                    (responder, vec->resp_psk, vec->resp_psk_len),
                NOISE_ERROR_NONE);
    }

    /* Should be able to start the handshake now on both sides */
    compare(noise_handshakestate_start(initiator), NOISE_ERROR_NONE);
    compare(noise_handshakestate_start(responder), NOISE_ERROR_NONE);

    /* Work through the messages one by one until both sides "split" */
    role = NOISE_ROLE_INITIATOR;
    for (index = 0; index < vec->num_messages; ++index) {
        if (noise_handshakestate_get_action(initiator) == NOISE_ACTION_SPLIT &&
            noise_handshakestate_get_action(responder) == NOISE_ACTION_SPLIT) {
            break;
        }
        if (role == NOISE_ROLE_INITIATOR) {
            /* Send on the initiator, receive on the responder */
            send = initiator;
            recv = responder;
            if (!is_one_way)
                role = NOISE_ROLE_RESPONDER;
        } else {
            /* Send on the responder, receive on the initiator */
            send = responder;
            recv = initiator;
            role = NOISE_ROLE_INITIATOR;
        }
        compare(noise_handshakestate_get_action(send),
                NOISE_ACTION_WRITE_MESSAGE);
        compare(noise_handshakestate_get_action(recv),
                NOISE_ACTION_READ_MESSAGE);
        noise_buffer_set_output(mbuf, message, sizeof(message));
        noise_buffer_set_input(pbuf, vec->messages[index].payload,
                               vec->messages[index].payload_len);
        compare(noise_handshakestate_write_message(send, &mbuf, &pbuf),
                NOISE_ERROR_NONE);
        compare_blocks("ciphertext", mbuf.data, mbuf.size,
                       vec->messages[index].ciphertext,
                       vec->messages[index].ciphertext_len);
        if (fallback) {
            /* Look up the pattern to fall back to */
            int fallback_id = NOISE_PATTERN_XX_FALLBACK;
            if (vec->fallback_pattern) {
                fallback_id = noise_name_to_id
                    (NOISE_PATTERN_CATEGORY, vec->fallback_pattern,
                     strlen(vec->fallback_pattern));
            }

            /* Perform a read on the responder, which will fail */
            compare(noise_handshakestate_read_message(recv, &mbuf, &pbuf),
                    NOISE_ERROR_MAC_FAILURE);

            /* Initiate fallback on both sides */
            compare(noise_handshakestate_fallback_to(responder, fallback_id),
                    NOISE_ERROR_NONE);
            compare(noise_handshakestate_fallback_to(initiator, fallback_id),
                    NOISE_ERROR_NONE);

            /* Restart the protocols */
            compare(noise_handshakestate_start(initiator), NOISE_ERROR_NONE);
            compare(noise_handshakestate_start(responder), NOISE_ERROR_NONE);

            /* Only need to fallback once */
            fallback = 0;
        } else {
            noise_buffer_set_output(pbuf, payload, sizeof(payload));
            compare(noise_handshakestate_read_message(recv, &mbuf, &pbuf),
                    NOISE_ERROR_NONE);
            compare_blocks("plaintext", pbuf.data, pbuf.size,
                           vec->messages[index].payload,
                           vec->messages[index].payload_len);
        }
    }

    /* Handshake finished.  Check the handshake hash values */
    if (vec->handshake_hash_len) {
        memset(payload, 0xAA, sizeof(payload));
        compare(noise_handshakestate_get_handshake_hash
                    (initiator, payload, vec->handshake_hash_len),
                NOISE_ERROR_NONE);
        compare_blocks("handshake_hash", payload, vec->handshake_hash_len,
                       vec->handshake_hash, vec->handshake_hash_len);
        memset(payload, 0xAA, sizeof(payload));
        compare(noise_handshakestate_get_handshake_hash
                    (responder, payload, vec->handshake_hash_len),
                NOISE_ERROR_NONE);
        compare_blocks("handshake_hash", payload, vec->handshake_hash_len,
                       vec->handshake_hash, vec->handshake_hash_len);
    }

    /* Now handle the data transport */
    compare(noise_handshakestate_split(initiator, &c1init, &c2init),
            NOISE_ERROR_NONE);
    compare(noise_handshakestate_split(responder, &c2resp, &c1resp),
            NOISE_ERROR_NONE);
    mac_len = noise_cipherstate_get_mac_length(c1init);
    for (; index < vec->num_messages; ++index) {
        if (role == NOISE_ROLE_INITIATOR) {
            /* Send on the initiator, receive on the responder */
            csend = c1init;
            crecv = c1resp;
            if (!is_one_way)
                role = NOISE_ROLE_RESPONDER;
        } else {
            /* Send on the responder, receive on the initiator */
            csend = c2resp;
            crecv = c2init;
            role = NOISE_ROLE_INITIATOR;
        }
        verify(sizeof(message) >= (vec->messages[index].payload_len + mac_len));
        memcpy(message, vec->messages[index].payload,
               vec->messages[index].payload_len);
        noise_buffer_set_inout(mbuf, message, vec->messages[index].payload_len,
                               sizeof(message));
        compare(noise_cipherstate_encrypt(csend, &mbuf),
                NOISE_ERROR_NONE);
        compare_blocks("ciphertext", mbuf.data, mbuf.size,
                       vec->messages[index].ciphertext,
                       vec->messages[index].ciphertext_len);
        compare(noise_cipherstate_decrypt(crecv, &mbuf),
                NOISE_ERROR_NONE);
        compare_blocks("plaintext", mbuf.data, mbuf.size,
                       vec->messages[index].payload,
                       vec->messages[index].payload_len);
    }

    /* Clean up */
    compare(noise_handshakestate_free(initiator), NOISE_ERROR_NONE);
    compare(noise_handshakestate_free(responder), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c1init), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c2init), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c1resp), NOISE_ERROR_NONE);
    compare(noise_cipherstate_free(c2resp), NOISE_ERROR_NONE);
}

/**
 * \brief Runs a fully parsed test vector.
 *
 * \param reader The input stream, for error reporting.
 * \param vec The test vector.
 *
 * \return Non-zero if the test succeeded, zero if it failed.
 */
static int test_vector_run(JSONReader *reader, const TestVector *vec)
{
    int value;
    printf("%s ... ", vec->name);
    fflush(stdout);
    if ((value = setjmp(test_jump_back)) == 0) {
        int is_one_way = test_name_parsing(vec);
        test_connection(vec, is_one_way);
        printf("ok\n");
        return 1;
    } else if (value == 2) {
        printf("skipped\n");
        return 1;
    } else {
        printf("-> test data at %s:%ld\n", reader->filename, vec->line_number);
        return 0;
    }
}

/**
 * \brief Look for a specific token next in the input stream.
 *
 * \param reader The input stream.
 * \param token The token code.
 * \param name The token name for error reporting.
 */
static void expect_token(JSONReader *reader, JSONToken token, const char *name)
{
    if (reader->errors)
        return;
    if (reader->token == token)
        json_next_token(reader);
    else
        json_error(reader, "Expecting '%s'", name);
}

/**
 * \brief Look for a specific field name next in the input stream,
 * followed by a colon.
 *
 * \param reader The input stream.
 * \param name The field name.
 */
static void expect_name(JSONReader *reader, const char *name)
{
    if (reader->errors)
        return;
    if (json_is_name(reader, name)) {
        json_next_token(reader);
        expect_token(reader, JSON_TOKEN_COLON, ":");
    } else {
        json_error(reader, "Expecting \"%s\"", name);
    }
}

/**
 * \brief Look for a field with a string value.
 *
 * \param reader The input stream.
 * \param value The location where to place the string value.
 */
static void expect_string_field(JSONReader *reader, char **value)
{
    json_next_token(reader);
    expect_token(reader, JSON_TOKEN_COLON, ":");
    if (!reader->errors && reader->token == JSON_TOKEN_STRING) {
        *value = reader->str_value;
        reader->str_value = 0;
        json_next_token(reader);
        if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
            json_next_token(reader);
    }
}

/**
 * \brief Converts an ASCII character into a hexadecimal digit.
 *
 * \param ch The ASCII character.
 *
 * \return The digit between 0 and 15, or -1 if \a ch is not hexadecimal.
 */
static int from_hex_digit(int ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    else if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    else if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    else
        return -1;
}

/**
 * \brief Look for a field with a binary value.
 *
 * \param reader The input stream.
 * \param value The location where to place the binary value.
 *
 * \return The size of the binary value in bytes.
 */
static size_t expect_binary_field(JSONReader *reader, uint8_t **value)
{
    size_t size = 0;
    size_t posn;
    const char *hex;
    int digit1, digit2;
    json_next_token(reader);
    expect_token(reader, JSON_TOKEN_COLON, ":");
    if (!reader->errors && reader->token == JSON_TOKEN_STRING) {
        size = strlen(reader->str_value) / 2;
        *value = calloc(1, size + 1);
        if (!(*value)) {
            json_error(reader, "Out of memory");
            return 0;
        }
        hex = reader->str_value;
        for (posn = 0; posn < size; ++posn) {
            digit1 = from_hex_digit(hex[posn * 2]);
            digit2 = from_hex_digit(hex[posn * 2 + 1]);
            if (digit1 < 0 || digit2 < 0) {
                json_error(reader, "Invalid hexadecimal data");
                return 0;
            }
            (*value)[posn] = digit1 * 16 + digit2;
        }
        json_next_token(reader);
        if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
            json_next_token(reader);
    }
    return size;
}

/**
 * \brief Look for a field with a boolean value.
 *
 * \param reader The input stream.
 * \return The boolean value.
 */
static int expect_boolean_field(JSONReader *reader)
{
    int result = 0;
    json_next_token(reader);
    expect_token(reader, JSON_TOKEN_COLON, ":");
    if (!reader->errors && (reader->token == JSON_TOKEN_TRUE ||
                            reader->token == JSON_TOKEN_FALSE)) {
        result = (reader->token == JSON_TOKEN_TRUE);
        json_next_token(reader);
        if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
            json_next_token(reader);
    }
    return result;
}

/**
 * \brief Processes a single test vector from an input stream.
 *
 * \param reader The reader representing the input stream.
 *
 * \return Non-zero if the test succeeded, zero if it failed.
 */
static int process_test_vector(JSONReader *reader)
{
    TestVector vec;
    char protocol_name[NOISE_MAX_PROTOCOL_NAME];
    int retval = 1;
    memset(&vec, 0, sizeof(TestVector));
    while (!reader->errors && reader->token == JSON_TOKEN_STRING) {
        if (json_is_name(reader, "name")) {
            vec.line_number = reader->line_number;
            expect_string_field(reader, &(vec.name));
        } else if (json_is_name(reader, "pattern")) {
            expect_string_field(reader, &(vec.pattern));
        } else if (json_is_name(reader, "dh")) {
            expect_string_field(reader, &(vec.dh));
        } else if (json_is_name(reader, "hybrid")) {
            expect_string_field(reader, &(vec.hybrid));
        } else if (json_is_name(reader, "cipher")) {
            expect_string_field(reader, &(vec.cipher));
        } else if (json_is_name(reader, "hash")) {
            expect_string_field(reader, &(vec.hash));
        } else if (json_is_name(reader, "init_static")) {
            vec.init_static_len =
                expect_binary_field(reader, &(vec.init_static));
        } else if (json_is_name(reader, "init_remote_static")) {
            /* Refers to the initiator have pre-knowledge of the responder's
               public key, which is "resp_public_static" in TestVector */
            vec.resp_public_static_len =
                expect_binary_field(reader, &(vec.resp_public_static));
        } else if (json_is_name(reader, "resp_static")) {
            vec.resp_static_len =
                expect_binary_field(reader, &(vec.resp_static));
        } else if (json_is_name(reader, "resp_remote_static")) {
            /* Refers to the responder have pre-knowledge of the initiator's
               public key, which is "init_public_static" in TestVector */
            vec.init_public_static_len =
                expect_binary_field(reader, &(vec.init_public_static));
        } else if (json_is_name(reader, "init_ephemeral")) {
            vec.init_ephemeral_len =
                expect_binary_field(reader, &(vec.init_ephemeral));
        } else if (json_is_name(reader, "resp_ephemeral")) {
            vec.resp_ephemeral_len =
                expect_binary_field(reader, &(vec.resp_ephemeral));
        } else if (json_is_name(reader, "init_hybrid_ephemeral")) {
            vec.init_hybrid_len =
                expect_binary_field(reader, &(vec.init_hybrid));
        } else if (json_is_name(reader, "resp_hybrid_ephemeral")) {
            vec.resp_hybrid_len =
                expect_binary_field(reader, &(vec.resp_hybrid));
        } else if (json_is_name(reader, "init_prologue")) {
            vec.init_prologue_len =
                expect_binary_field(reader, &(vec.init_prologue));
        } else if (json_is_name(reader, "resp_prologue")) {
            vec.resp_prologue_len =
                expect_binary_field(reader, &(vec.resp_prologue));
        } else if (json_is_name(reader, "init_psk")) {
            vec.init_psk_len =
                expect_binary_field(reader, &(vec.init_psk));
        } else if (json_is_name(reader, "resp_psk")) {
            vec.resp_psk_len =
                expect_binary_field(reader, &(vec.resp_psk));
        } else if (json_is_name(reader, "handshake_hash")) {
            vec.handshake_hash_len =
                expect_binary_field(reader, &(vec.handshake_hash));
        } else if (json_is_name(reader, "fail")) {
            vec.fail = expect_boolean_field(reader);
        } else if (json_is_name(reader, "fallback")) {
            vec.fallback = expect_boolean_field(reader);
        } else if (json_is_name(reader, "fallback_pattern")) {
            expect_string_field(reader, &(vec.fallback_pattern));
        } else if (json_is_name(reader, "messages")) {
            json_next_token(reader);
            expect_token(reader, JSON_TOKEN_COLON, ":");
            expect_token(reader, JSON_TOKEN_LSQUARE, "[");
            while (!reader->errors && reader->token == JSON_TOKEN_LBRACE) {
                if (vec.num_messages >= MAX_MESSAGES) {
                    json_error(reader, "Too many messages for test vector");
                    break;
                }
                expect_token(reader, JSON_TOKEN_LBRACE, "{");
                while (!reader->errors && reader->token == JSON_TOKEN_STRING) {
                    if (json_is_name(reader, "payload")) {
                        vec.messages[vec.num_messages].payload_len =
                            expect_binary_field
                                (reader, &(vec.messages[vec.num_messages].payload));
                    } else if (json_is_name(reader, "ciphertext")) {
                        vec.messages[vec.num_messages].ciphertext_len =
                            expect_binary_field
                                (reader, &(vec.messages[vec.num_messages].ciphertext));
                    } else {
                        json_error(reader, "Unknown message field '%s'",
                                   reader->str_value);
                    }
                }
                if (!vec.messages[vec.num_messages].payload)
                    json_error(reader, "Missing payload for message");
                if (!vec.messages[vec.num_messages].ciphertext)
                    json_error(reader, "Missing ciphertext for message");
                ++(vec.num_messages);
                expect_token(reader, JSON_TOKEN_RBRACE, "}");
                if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
                    json_next_token(reader);
            }
            expect_token(reader, JSON_TOKEN_RSQUARE, "]");
            if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
                json_next_token(reader);
        } else {
            json_error(reader, "Unknown field '%s'", reader->str_value);
        }
    }
    snprintf(protocol_name, sizeof(protocol_name), "Noise%s_%s_%s%s%s_%s_%s",
             (vec.init_psk || vec.resp_psk) ? "PSK" : "",
             vec.pattern, vec.dh,
             (vec.hybrid ? "+" : ""),
             (vec.hybrid ? vec.hybrid : ""),
             vec.cipher, vec.hash);
    vec.protocol_name = strdup(protocol_name);
    if (!reader->errors) {
        retval = test_vector_run(reader, &vec);
    }
    test_vector_free(&vec);
    return retval;
}

/**
 * \brief Processes the test vectors from an input stream.
 *
 * \param reader The reader representing the input stream.
 */
static void process_test_vectors(JSONReader *reader)
{
    int ok = 1;
    printf("--------------------------------------------------------------\n");
    printf("Processing vectors from %s\n", reader->filename);
    json_next_token(reader);
    expect_token(reader, JSON_TOKEN_LBRACE, "{");
    expect_name(reader, "vectors");
    expect_token(reader, JSON_TOKEN_LSQUARE, "[");
    while (!reader->errors && reader->token != JSON_TOKEN_RSQUARE) {
        expect_token(reader, JSON_TOKEN_LBRACE, "{");
        if (!process_test_vector(reader))
            ok = 0;
        expect_token(reader, JSON_TOKEN_RBRACE, "}");
        if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
            expect_token(reader, JSON_TOKEN_COMMA, ",");
    }
    expect_token(reader, JSON_TOKEN_RSQUARE, "]");
    expect_token(reader, JSON_TOKEN_RBRACE, "}");
    expect_token(reader, JSON_TOKEN_END, "EOF");
    printf("--------------------------------------------------------------\n");
    if (!ok) {
        /* Some of the test vectors failed, so report a global failure */
        ++(reader->errors);
    }
}

static int process_file(const char *filename)
{
    int retval = 0;
    FILE *file = fopen(filename, "r");
    if (file) {
        JSONReader reader;
        json_init(&reader, filename, file);
        process_test_vectors(&reader);
        if (reader.errors > 0)
            retval = 1;
        json_free(&reader);
        fclose(file);
    } else {
        perror(filename);
        retval = 1;
    }
    return retval;
}

int main(int argc, char *argv[])
{
    if (noise_init() != NOISE_ERROR_NONE) {
        fprintf(stderr, "Noise initialization failed\n");
        return 1;
    }

    int retval = 0;
    char *srcdir = getenv("srcdir");
    if (argc <= 1 && !srcdir) {
        fprintf(stderr, "Usage: %s vectors1.txt vectors2.txt ...\n", argv[0]);
        return 1;
    } else if (argc > 1) {
        while (argc > 1) {
            retval |= process_file(argv[1]);
            --argc;
            ++argv;
        }
    } else {
        if (chdir(srcdir) < 0) {
            perror(srcdir);
            return 1;
        }
        retval |= process_file("cacophony.txt");
        retval |= process_file("noise-c-basic.txt");
        retval |= process_file("noise-c-fallback.txt");
        retval |= process_file("noise-c-hybrid.txt");
    }
    return retval;
}
