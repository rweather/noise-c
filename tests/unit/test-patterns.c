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

#include "test-helpers.h"
#include "protocol/internal.h"

/* Extra tokens for the unit test parser only */
#define NOISE_TOKEN_LARROW 64
#define NOISE_TOKEN_RARROW 65
#define NOISE_TOKEN_ERROR  66

/* Parses the next token from a pattern string */
static uint8_t next_token(const char **pattern)
{
    const char *pat = *pattern;
    uint8_t token = NOISE_TOKEN_END;

    /* Skip whitespace */
    while (*pat == ' ' || *pat == '\n' || *pat == ',')
        ++pat;
    if (*pat == '\0') {
        *pattern = pat;
        return token;
    }

    /* Recognize the next token */
    if (!strncmp(pat, "s", 1)) {
        pat += 1;
        token = NOISE_TOKEN_S;
    } else if (!strncmp(pat, "e", 1)) {
        pat += 1;
        token = NOISE_TOKEN_E;
    } else if (!strncmp(pat, "dhee", 4)) {
        pat += 4;
        token = NOISE_TOKEN_DHEE;
    } else if (!strncmp(pat, "dhes", 4)) {
        pat += 4;
        token = NOISE_TOKEN_DHES;
    } else if (!strncmp(pat, "dhse", 4)) {
        pat += 4;
        token = NOISE_TOKEN_DHSE;
    } else if (!strncmp(pat, "dhss", 4)) {
        pat += 4;
        token = NOISE_TOKEN_DHSS;
    } else if (!strncmp(pat, "<-", 2)) {
        pat += 2;
        token = NOISE_TOKEN_LARROW;
    } else if (!strncmp(pat, "->", 2)) {
        pat += 2;
        token = NOISE_TOKEN_RARROW;
    } else {
        token = NOISE_TOKEN_ERROR;
    }

    /* Return the token to the caller */
    *pattern = pat;
    return token;
}

/* Checks a specific pattern to verify that it matches the specification
   and that the pattern flags make sense with respect to the pattern */
static void check_pattern(int id, const char *name, const char *required,
                          const char *sequence)
{
    const uint8_t *pattern = noise_pattern_lookup(id);
    uint8_t expected_flags;
    uint8_t seen_flags = 0;
    uint8_t token;
    int role = 0;

    /* Set the name of the pattern for reporting test failures */
    data_name = name;

    /* Verify that the pattern is supported by the library */
    verify(pattern != 0);

    /* Extract the flags and then advance to the first token */
    expected_flags = *pattern++;

    /* Deal with the requirements */
    token = next_token(&required);
    while (token != NOISE_TOKEN_END) {
        if (token == NOISE_TOKEN_LARROW) {
            role = NOISE_ROLE_RESPONDER;
        } else if (token == NOISE_TOKEN_RARROW) {
            role = NOISE_ROLE_INITIATOR;
        } else if (token == NOISE_TOKEN_E) {
            verify(role == NOISE_ROLE_RESPONDER);
            seen_flags |= NOISE_PAT_FLAG_REMOTE_EMPEM_REQ |
                          NOISE_PAT_FLAG_REMOTE_EMPEMERAL;
        } else if (token == NOISE_TOKEN_S) {
            if (role == NOISE_ROLE_INITIATOR) {
                seen_flags |= NOISE_PAT_FLAG_LOCAL_REQUIRED |
                              NOISE_PAT_FLAG_LOCAL_STATIC;
            } else if (role == NOISE_ROLE_RESPONDER) {
                seen_flags |= NOISE_PAT_FLAG_REMOTE_REQUIRED |
                              NOISE_PAT_FLAG_REMOTE_STATIC;
            } else {
                fail("role is not set");
            }
        } else {
            fail("unknown pre-message token");
        }
        token = next_token(&required);
    }

    /* Deal with the token sequence */
    token = next_token(&sequence);
    role = 0;
    while (token != NOISE_TOKEN_END) {
        verify(token != NOISE_TOKEN_ERROR);
        if (role == 0) {
            /* We expect the first role to be declared */
            if (token == NOISE_TOKEN_LARROW) {
                role = NOISE_ROLE_RESPONDER;
                compare(*pattern++, NOISE_TOKEN_FLIP_DIR);
            } else if (token == NOISE_TOKEN_RARROW) {
                role = NOISE_ROLE_INITIATOR;
            } else {
                fail("first role was not declared");
            }
        } else {
            /* Check for role reversal and message pattern tokens */
            if (token == NOISE_TOKEN_LARROW) {
                compare(role, NOISE_ROLE_INITIATOR);
                compare(*pattern++, NOISE_TOKEN_FLIP_DIR);
                role = NOISE_ROLE_RESPONDER;
            } else if (token == NOISE_TOKEN_RARROW) {
                compare(role, NOISE_ROLE_RESPONDER);
                compare(*pattern++, NOISE_TOKEN_FLIP_DIR);
                role = NOISE_ROLE_INITIATOR;
            } else {
                compare(*pattern++, token);
                switch (token) {
                case NOISE_TOKEN_S:
                    if (role == NOISE_ROLE_INITIATOR)
                        seen_flags |= NOISE_PAT_FLAG_LOCAL_STATIC;
                    else
                        seen_flags |= NOISE_PAT_FLAG_REMOTE_STATIC;
                    break;
                case NOISE_TOKEN_E:
                    if (role == NOISE_ROLE_INITIATOR)
                        seen_flags |= NOISE_PAT_FLAG_LOCAL_EMPEMERAL;
                    else
                        seen_flags |= NOISE_PAT_FLAG_REMOTE_EMPEMERAL;
                    break;
                case NOISE_TOKEN_DHEE:
                    verify(seen_flags & NOISE_PAT_FLAG_LOCAL_EMPEMERAL);
                    verify(seen_flags & NOISE_PAT_FLAG_REMOTE_EMPEMERAL);
                    break;
                case NOISE_TOKEN_DHES:
                    if (role == NOISE_ROLE_INITIATOR) {
                        verify(seen_flags & NOISE_PAT_FLAG_LOCAL_EMPEMERAL);
                        verify(seen_flags & NOISE_PAT_FLAG_REMOTE_STATIC);
                    } else {
                        verify(seen_flags & NOISE_PAT_FLAG_LOCAL_STATIC);
                        verify(seen_flags & NOISE_PAT_FLAG_REMOTE_EMPEMERAL);
                    }
                    break;
                case NOISE_TOKEN_DHSE:
                    if (role == NOISE_ROLE_INITIATOR) {
                        verify(seen_flags & NOISE_PAT_FLAG_LOCAL_STATIC);
                        verify(seen_flags & NOISE_PAT_FLAG_REMOTE_EMPEMERAL);
                    } else {
                        verify(seen_flags & NOISE_PAT_FLAG_LOCAL_EMPEMERAL);
                        verify(seen_flags & NOISE_PAT_FLAG_REMOTE_STATIC);
                    }
                    break;
                case NOISE_TOKEN_DHSS:
                    verify(seen_flags & NOISE_PAT_FLAG_LOCAL_STATIC);
                    verify(seen_flags & NOISE_PAT_FLAG_REMOTE_STATIC);
                    break;
                default:
                    fail("unknown token");
                    break;
                }
            }
        }
        token = next_token(&sequence);
    }
    compare(*pattern, NOISE_TOKEN_END);

    /* Check that the seen flags match the expected flags */
    compare(seen_flags, expected_flags);
}

void test_patterns(void)
{
    check_pattern(NOISE_PATTERN_N,
                  "Noise_N(rs)",
                  "<- s\n",
                  "-> e, dhes\n");

    check_pattern(NOISE_PATTERN_X,
                  "Noise_X(s, rs)",
                  "<- s\n",
                  "-> e, dhes, s, dhss\n");

    check_pattern(NOISE_PATTERN_K,
                  "Noise_K(s, rs)",
                  "-> s\n"
                  "<- s\n",
                  "-> e, dhes, dhss\n");

    check_pattern(NOISE_PATTERN_NN,
                  "Noise_NN()",
                  "",
                  "-> e\n"
                  "<- e, dhee\n");

    check_pattern(NOISE_PATTERN_NK,
                  "Noise_NK(rs)",
                  "<- s\n",
                  "-> e, dhes\n"
                  "<- e, dhee\n");

    check_pattern(NOISE_PATTERN_NX,
                  "Noise_NX(rs)",
                  "",
                  "-> e\n"
                  "<- e, dhee, s, dhse\n");

    check_pattern(NOISE_PATTERN_XN,
                  "Noise_XN(s)",
                  "",
                  "-> e\n"
                  "<- e, dhee\n"
                  "-> s, dhse\n");

    check_pattern(NOISE_PATTERN_XK,
                  "Noise_XK(s, rs)",
                  "<- s\n",
                  "-> e, dhes\n"
                  "<- e, dhee\n"
                  "-> s, dhse\n");

    check_pattern(NOISE_PATTERN_XX,
                  "Noise_XX(s, rs)",
                  "",
                  "-> e\n"
                  "<- e, dhee, s, dhse\n"
                  "-> s, dhse\n");

    check_pattern(NOISE_PATTERN_XR,
                  "Noise_XR(s, rs)",
                  "",
                  "-> e\n"
                  "<- e, dhee\n"
                  "-> s, dhse\n"
                  "<- s, dhse\n");

    check_pattern(NOISE_PATTERN_KN,
                  "Noise_KN(s)",
                  "-> s\n",
                  "-> e\n"
                  "<- e, dhee, dhes\n");

    check_pattern(NOISE_PATTERN_KK,
                  "Noise_KK(s, rs)",
                  "-> s\n"
                  "<- s\n",
                  "-> e, dhes, dhss\n"
                  "<- e, dhee, dhes\n");

    check_pattern(NOISE_PATTERN_KX,
                  "Noise_KX(s, rs)",
                  "-> s\n",
                  "-> e\n"
                  "<- e, dhee, dhes, s, dhse\n");

    check_pattern(NOISE_PATTERN_IN,
                  "Noise_IN(s)",
                  "",
                  "-> e, s\n"
                  "<- e, dhee, dhes\n");

    check_pattern(NOISE_PATTERN_IK,
                  "Noise_IK(s, rs)",
                  "<- s\n",
                  "-> e, dhes, s, dhss\n"
                  "<- e, dhee, dhes\n");

    check_pattern(NOISE_PATTERN_IX,
                  "Noise_IX(s, rs)",
                  "",
                  "-> e, s\n"
                  "<- e, dhee, dhes, s, dhse\n");

    check_pattern(NOISE_PATTERN_XX_FALLBACK,
                  "Noise_XXfallback(s, rs, re)",
                  "<- e\n",
                  "-> e, dhee, s, dhse\n"
                  "<- s, dhse\n");
}
