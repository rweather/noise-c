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

#define MAX_MESSAGES 32

/* Internal functions to directly supply ephemeral keys during testing */
NoiseDHState *noise_handshakestate_get_local_ephemeral_dh_
    (const NoiseHandshakeState *state);
NoiseDHState *noise_handshakestate_get_remote_ephemeral_dh_
    (const NoiseHandshakeState *state);

/**
 * \brief Information about a single test vector.
 */
typedef struct
{
    long line_number;               /**< Line number for the "name" */
    char *name;                     /**< Full name of the protocol */
    char *pattern;                  /**< Name of the handshake pattern */
    char *dh;                       /**< Name of the DH algorithm */
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
    uint8_t *resp_ephemeral;        /**< Initiator's ephemeral key */
    size_t resp_ephemeral_len;      /**< Length of resp_ephemeral in bytes */
    uint8_t *init_prologue;         /**< Initiator's prologue data */
    size_t init_prologue_len;       /**< Length of init_prologue in bytes */
    uint8_t *resp_prologue;         /**< Responder's prologue data */
    size_t resp_prologue_len;       /**< Length of resp_prologue in bytes */
    uint8_t *init_psk;              /**< Initiator's pre shared key */
    size_t init_psk_len;            /**< Length of init_psk in bytes */
    uint8_t *resp_psk;              /**< Responder's pre shared key */
    size_t resp_psk_len;            /**< Length of resp_psk in bytes */
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
    free_field(pattern);
    free_field(dh);
    free_field(cipher);
    free_field(hash);
    free_field(init_static);
    free_field(init_public_static);
    free_field(resp_static);
    free_field(resp_public_static);
    free_field(init_ephemeral);
    free_field(resp_ephemeral);
    free_field(init_prologue);
    free_field(resp_prologue);
    free_field(init_psk);
    free_field(resp_psk);
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
            printf("    actual  : %Ld (0x%Lx)\n", _actual, _actual); \
            printf("    expected: %Ld (0x%Lx)\n", _expected, _expected); \
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
 */
static void test_name_parsing(const TestVector *vec)
{
    NoiseProtocolId id;
    compare(noise_protocol_name_to_id(&id, vec->name, strlen(vec->name)),
            NOISE_ERROR_NONE);
    if (vec->init_psk || vec->resp_psk)
        compare(id.prefix_id, NOISE_PREFIX_PSK);
    else
        compare(id.prefix_id, NOISE_PREFIX_STANDARD);
    check_id(id.pattern_id, NOISE_PATTERN_CATEGORY, vec->pattern);
    check_id(id.dh_id, NOISE_DH_CATEGORY, vec->dh);
    check_id(id.cipher_id, NOISE_CIPHER_CATEGORY, vec->cipher);
    check_id(id.hash_id, NOISE_HASH_CATEGORY, vec->hash);
    compare(id.reserved_id, 0);
}

/**
 * \brief Runs a fully parsed test vector.
 *
 * \param reader The input stream, for error reporting.
 * \param vec The test vector.
 */
static void test_vector_run(JSONReader *reader, const TestVector *vec)
{
    printf("%s ... ", vec->name);
    fflush(stdout);
    if (!setjmp(test_jump_back)) {
        test_name_parsing(vec);
        // TODO
        printf("ok\n");
    } else {
        printf("-> test data at %s:%ld\n", reader->filename, vec->line_number);
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
 * \brief Processes a single test vector from an input stream.
 *
 * \param reader The reader representing the input stream.
 */
static void process_test_vector(JSONReader *reader)
{
    TestVector vec;
    memset(&vec, 0, sizeof(TestVector));
    while (!reader->errors && reader->token == JSON_TOKEN_STRING) {
        if (json_is_name(reader, "name")) {
            vec.line_number = reader->line_number;
            expect_string_field(reader, &(vec.name));
        } else if (json_is_name(reader, "pattern")) {
            expect_string_field(reader, &(vec.pattern));
        } else if (json_is_name(reader, "dh")) {
            expect_string_field(reader, &(vec.dh));
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
    if (!reader->errors) {
        test_vector_run(reader, &vec);
    }
    test_vector_free(&vec);
}

/**
 * \brief Processes the test vectors from an input stream.
 *
 * \param reader The reader representing the input stream.
 */
static void process_test_vectors(JSONReader *reader)
{
    int count = 20;     // REMOVEME
    printf("--------------------------------------------------------------\n");
    printf("Processing vectors from %s\n", reader->filename);
    json_next_token(reader);
    expect_token(reader, JSON_TOKEN_LBRACE, "{");
    expect_name(reader, "vectors");
    expect_token(reader, JSON_TOKEN_LSQUARE, "[");
    while (!reader->errors && reader->token != JSON_TOKEN_RSQUARE) {
        expect_token(reader, JSON_TOKEN_LBRACE, "{");
        process_test_vector(reader);
        expect_token(reader, JSON_TOKEN_RBRACE, "}");
        if (!reader->errors && reader->token == JSON_TOKEN_COMMA)
            expect_token(reader, JSON_TOKEN_COMMA, ",");
    if (--count <= 0)   // REMOVEME
        return;
    }
    expect_token(reader, JSON_TOKEN_RSQUARE, "]");
    expect_token(reader, JSON_TOKEN_RBRACE, "}");
    expect_token(reader, JSON_TOKEN_END, "EOF");
    printf("--------------------------------------------------------------\n");
}

int main(int argc, char *argv[])
{
    FILE *file;
    int retval = 0;
    if (argc <= 1) {
        fprintf(stderr, "Usage: %s vectors1.txt vectors2.txt ...\n", argv[0]);
        return 1;
    }
    while (argc > 1) {
        file = fopen(argv[1], "r");
        if (file) {
            JSONReader reader;
            json_init(&reader, argv[1], file);
            process_test_vectors(&reader);
            if (reader.errors > 0)
                retval = 1;
            json_free(&reader);
            fclose(file);
        } else {
            perror(argv[1]);
            retval = 1;
        }
        --argc;
        ++argv;
    }
    return retval;
}
