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

#include "internal.h"
#include <string.h>

/**
 * \file patterns.c
 * \brief Defines the handshake message patterns.
 */

/** @cond */
#define FLAGS(x)    ((uint8_t)((x) & 0xFF)), ((uint8_t)(((x) >> 8) & 0xFF))
/** @endcond */

/**
 * \brief Token sequence for handshake pattern "N".
 *
 * @code
 * Noise_N(rs):
 *   <- s
 *   ...
 *   -> e, es
 * @endcode
 */
static uint8_t const noise_pattern_N[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "K".
 *
 * @code
 * Noise_K(s, rs):
 *   -> s
 *   <- s
 *   ...
 *   -> e, es, ss
 * @endcode
 */
static uint8_t const noise_pattern_K[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "X".
 *
 * @code
 * Noise_X(s, rs):
 *   <- s
 *   ...
 *   -> e, es, s, ss
 * @endcode
 */
static uint8_t const noise_pattern_X[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NN".
 *
 * @code
 * Noise_NN():
 *   -> e
 *   <- e, ee
 * @endcode
 */
static uint8_t const noise_pattern_NN[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NK".
 *
 * @code
 * Noise_NK(rs):
 *   <- s
 *   ...
 *   -> e, es
 *   <- e, ee
 * @endcode
 */
static uint8_t const noise_pattern_NK[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NX".
 *
 * @code
 * Noise_NX(rs):
 *   -> e
 *   <- e, ee, s, es
 * @endcode
 */
static uint8_t const noise_pattern_NX[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XN".
 *
 * @code
 * Noise_XN(s):
 *   -> e
 *   <- e, ee
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XN[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XK".
 *
 * @code
 * Noise_XK(s, rs):
 *   <- s
 *   ...
 *   -> e, es
 *   <- e, ee
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XK[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XX".
 *
 * @code
 * Noise_XX(s, rs):
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XX[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KN".
 *
 * @code
 * Noise_KN(s):
 *   -> s
 *   ...
 *   -> e
 *   <- e, ee, se
 * @endcode
 */
static uint8_t const noise_pattern_KN[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KK".
 *
 * @code
 * Noise_KK(s, rs):
 *   -> s
 *   <- s
 *   ...
 *   -> e, es, ss
 *   <- e, ee, se
 * @endcode
 */
static uint8_t const noise_pattern_KK[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KX".
 *
 * @code
 * Noise_KX(s, rs):
 *   -> s
 *   ...
 *   -> e
 *   <- e, ee, se, s, es
 * @endcode
 */
static uint8_t const noise_pattern_KX[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IN".
 *
 * @code
 * Noise_IN(s):
 *   -> e, s
 *   <- e, ee, se
 * @endcode
 */
static uint8_t const noise_pattern_IN[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IK".
 *
 * @code
 * Noise_IK(s, rs):
 *   <- s
 *   ...
 *   -> e, es, s, ss
 *   <- e, ee, se
 * @endcode
 */
static uint8_t const noise_pattern_IK[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IX".
 *
 * @code
 * Noise_IX(s, rs):
 *   -> e, s
 *   <- e, ee, se, s, es
 * @endcode
 */
static uint8_t const noise_pattern_IX[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Looks up a specific handshake pattern.
 *
 * \param id The identifier for the handshake pattern.
 *
 * \return A pointer to the pattern or NULL if \a id is unknown.
 *
 * The first byte of the returned pattern contains the pattern flags.
 * The remaining bytes are the token for the pattern, terminated by
 * NOISE_TOKEN_END.
 */
const uint8_t *noise_pattern_lookup(int id)
{
    switch (id) {
    case NOISE_PATTERN_N:               return noise_pattern_N;
    case NOISE_PATTERN_K:               return noise_pattern_K;
    case NOISE_PATTERN_X:               return noise_pattern_X;
    case NOISE_PATTERN_NN:              return noise_pattern_NN;
    case NOISE_PATTERN_NK:              return noise_pattern_NK;
    case NOISE_PATTERN_NX:              return noise_pattern_NX;
    case NOISE_PATTERN_XN:              return noise_pattern_XN;
    case NOISE_PATTERN_XK:              return noise_pattern_XK;
    case NOISE_PATTERN_XX:              return noise_pattern_XX;
    case NOISE_PATTERN_KN:              return noise_pattern_KN;
    case NOISE_PATTERN_KK:              return noise_pattern_KK;
    case NOISE_PATTERN_KX:              return noise_pattern_KX;
    case NOISE_PATTERN_IN:              return noise_pattern_IN;
    case NOISE_PATTERN_IK:              return noise_pattern_IK;
    case NOISE_PATTERN_IX:              return noise_pattern_IX;
    default:                            return 0;
    }
}

/**
 * \brief Reverses the local and remote flags for a pattern.
 *
 * \param flags The flags, assuming that the initiator is "local".
 * \return The reversed flags, with the responder now being "local".
 */
NoisePatternFlags_t noise_pattern_reverse_flags(NoisePatternFlags_t flags)
{
    return ((flags >> 8) & 0x00FF) | ((flags << 8) & 0xFF00);
}

/**
 * \brief Length of the flags in the pattern header.
 */
#define NOISE_PATTERN_HEADER_LEN 2

/**
 * \brief Puts a token into an output pattern while applying a modifier.
 */
static int noise_pattern_put_token(int err, uint8_t output[NOISE_MAX_TOKENS],
                                   unsigned *index, uint8_t token)
{
    if (err != NOISE_ERROR_NONE)
        return err;
    if (*index >= NOISE_MAX_TOKENS)
        return NOISE_ERROR_INVALID_LENGTH;
    output[(*index)++] = token;
    return NOISE_ERROR_NONE;
}

/**
 * \brief Expands a pattern using the "fallback" modifier.
 */
int noise_pattern_expand_fallback
    (uint8_t output[NOISE_MAX_TOKENS], const uint8_t input[NOISE_MAX_TOKENS],
     NoisePatternFlags_t *flags)
{
    unsigned in, out;
    int err = NOISE_ERROR_NONE;
    uint8_t token;

    /* Error out if "fallback" has already been applied to the pattern
       or if the underlying pattern is not interactive */
    if ((*flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) != 0)
        return NOISE_ERROR_UNKNOWN_NAME;
    if ((*flags & NOISE_PAT_FLAG_REMOTE_EPHEMERAL) == 0)
        return NOISE_ERROR_UNKNOWN_NAME;

    /* Reverse the flags because the initiator is now the responder */
    *flags = noise_pattern_reverse_flags(*flags);

    /* Move the contents of the first message to the pre-message flags.
       The only tokens that are allowed are "e", "f", and "s" */
    in = NOISE_PATTERN_HEADER_LEN;
    out = NOISE_PATTERN_HEADER_LEN;
    while (in < NOISE_MAX_TOKENS && input[in] != NOISE_TOKEN_END) {
        token = input[in++];
        if (token == NOISE_TOKEN_FLIP_DIR) {
            /* We have found the end of the first message */
            break;
        } else if (token == NOISE_TOKEN_E) {
            /* Remote ephemeral is required */
            *flags |= NOISE_PAT_FLAG_REMOTE_EPHEM_REQ;
        } else if (token == NOISE_TOKEN_F) {
            /* Remote hybrid ephemeral is required */
            *flags |= NOISE_PAT_FLAG_REMOTE_HYBRID_REQ;
        } else if (token == NOISE_TOKEN_S) {
            /* Remote static key is required */
            *flags |= NOISE_PAT_FLAG_REMOTE_STATIC |
                      NOISE_PAT_FLAG_REMOTE_REQUIRED;
        } else {
            /* This token is not allowed in the first message */
            return NOISE_ERROR_UNKNOWN_NAME;
        }
    }

    /* Copy the rest of the pattern while swapping "es" and "se" */
    while (in < NOISE_MAX_TOKENS && input[in] != NOISE_TOKEN_END) {
        token = input[in++];
        if (token == NOISE_TOKEN_ES)
            token = NOISE_TOKEN_SE;
        else if (token == NOISE_TOKEN_SE)
            token = NOISE_TOKEN_ES;
        err = noise_pattern_put_token(err, output, &out, token);
    }
    return noise_pattern_put_token(err, output, &out, NOISE_TOKEN_END);
}

/**
 * \brief Expands a pattern using the "hfs" modifier.
 */
int noise_pattern_expand_hfs
    (uint8_t output[NOISE_MAX_TOKENS], const uint8_t input[NOISE_MAX_TOKENS],
     NoisePatternFlags_t *flags)
{
    unsigned in, out;
    int err = NOISE_ERROR_NONE;
    uint8_t token;

    /* Error out if "hfs" has already been applied to the pattern
       or if the underlying pattern is not interactive */
    if ((*flags & NOISE_PAT_FLAG_LOCAL_HYBRID) != 0)
        return NOISE_ERROR_UNKNOWN_NAME;
    if ((*flags & NOISE_PAT_FLAG_REMOTE_EPHEMERAL) == 0)
        return NOISE_ERROR_UNKNOWN_NAME;

    /* Replace "e" with "e, f" and "ee" with "ee, ff" */
    in = NOISE_PATTERN_HEADER_LEN;
    out = NOISE_PATTERN_HEADER_LEN;
    while (in < NOISE_MAX_TOKENS && input[in] != NOISE_TOKEN_END) {
        token = input[in++];
        if (token == NOISE_TOKEN_E) {
            err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_E);
            err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_F);
        } else if (token == NOISE_TOKEN_EE) {
            err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_EE);
            err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_FF);
        } else {
            err = noise_pattern_put_token(err, output, &out, token);
        }
    }
    err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_END);

    /* Update the flags to include the required hybrid objects */
    *flags |= NOISE_PAT_FLAG_LOCAL_HYBRID | NOISE_PAT_FLAG_REMOTE_HYBRID;
    if ((*flags & NOISE_PAT_FLAG_REMOTE_EPHEM_REQ) != 0)
        *flags |= NOISE_PAT_FLAG_REMOTE_HYBRID_REQ;
    return err;
}

/**
 * \brief Expands a pattern using a "pskN" modifier.
 */
int noise_pattern_expand_psk
    (uint8_t output[NOISE_MAX_TOKENS], const uint8_t input[NOISE_MAX_TOKENS],
     NoisePatternFlags_t *flags, int psk_number)
{
    unsigned in, out;
    int err = NOISE_ERROR_NONE;
    uint8_t token;
    uint8_t prev_token = NOISE_TOKEN_END;
    int message_index = 1;

    /* Insert "psk" at the front of the pattern if necessary */
    in = NOISE_PATTERN_HEADER_LEN;
    out = NOISE_PATTERN_HEADER_LEN;
    if (psk_number == 0) {
        if (input[in] == NOISE_TOKEN_PSK) {
            /* The "psk0" modifier has already been applied to this pattern */
            return NOISE_ERROR_UNKNOWN_NAME;
        }
        err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_PSK);
    }

    /* Insert "psk" tokens at the end of the other messages */
    while (in < NOISE_MAX_TOKENS) {
        token = input[in++];
        if (token == NOISE_TOKEN_FLIP_DIR || token == NOISE_TOKEN_END) {
            if (message_index == psk_number) {
                if (prev_token == NOISE_TOKEN_PSK) {
                    /* The "pskN" modifier has already been applied */
                    return NOISE_ERROR_UNKNOWN_NAME;
                }
                err = noise_pattern_put_token
                    (err, output, &out, NOISE_TOKEN_PSK);
            }
            ++message_index;
            if (token == NOISE_TOKEN_END)
                break;
        }
        err = noise_pattern_put_token(err, output, &out, token);
        prev_token = token;
    }
    err = noise_pattern_put_token(err, output, &out, NOISE_TOKEN_END);

    /* If "pskN" is beyond the end of the pattern, then it does not apply */
    if (message_index <= psk_number)
        return NOISE_ERROR_UNKNOWN_NAME;
    return err;
}

/**
 * \brief Expands a base pattern using a set of modifiers.
 *
 * \param pattern The fully expanded pattern.
 * \param pattern_id The identifier for the base pattern.
 * \param modifiers The modifiers to apply to the base pattern.
 * \param num_modifiers The number of modifiers to apply to the base pattern.
 *
 * \return NOISE_ERROR_NONE on success.
 * \return NOISE_ERROR_INVALID_LENGTH if the fully expanded pattern is
 * too large to fit within \a pattern.
 * \return NOISE_ERROR_UNKNOWN_NAME if the pattern or modifier names
 * are not supported, or the combination of modifiers is not supported.
 */
int noise_pattern_expand
    (uint8_t pattern[NOISE_MAX_TOKENS], int pattern_id,
     const int *modifiers, size_t num_modifiers)
{
    const uint8_t *base_pattern;
    const uint8_t *pattern_end;
    size_t pattern_len;
    NoisePatternFlags_t flags;
    uint8_t temp[NOISE_MAX_TOKENS];
    size_t index;
    int err;

    /* Look up the base pattern */
    base_pattern = noise_pattern_lookup(pattern_id);
    if (!base_pattern)
        return NOISE_ERROR_UNKNOWN_NAME;

    /* Copy the base pattern into the return buffer */
    pattern_end = (const uint8_t *)memchr
        (base_pattern + 2, NOISE_TOKEN_END,
         NOISE_MAX_TOKENS - NOISE_PATTERN_HEADER_LEN);
    if (!pattern_end)
        return NOISE_ERROR_INVALID_LENGTH;
    pattern_len = pattern_end + 1 - base_pattern;
    memcpy(pattern, base_pattern, pattern_len);

    /* Fetch the starting pattern flags */
    flags = ((NoisePatternFlags_t)(pattern[0])) |
           (((NoisePatternFlags_t)(pattern[1])) << 8);

    /* Apply the modifiers to the base pattern */
    err = NOISE_ERROR_NONE;
    for (index = 0; index < num_modifiers &&
                    err == NOISE_ERROR_NONE; ++index) {
        switch (modifiers[index]) {
        case NOISE_MODIFIER_FALLBACK:
            err = noise_pattern_expand_fallback(temp, pattern, &flags);
            break;
        case NOISE_MODIFIER_HFS:
            err = noise_pattern_expand_hfs(temp, pattern, &flags);
            break;
        case NOISE_MODIFIER_PSK0:
        case NOISE_MODIFIER_PSK1:
        case NOISE_MODIFIER_PSK2:
        case NOISE_MODIFIER_PSK3:
            err = noise_pattern_expand_psk
                (temp, pattern, &flags,
                 modifiers[index] - NOISE_MODIFIER_PSK0);
            break;
        default:
            return NOISE_ERROR_UNKNOWN_NAME;
        }
        temp[0] = (uint8_t)flags;
        temp[1] = (uint8_t)(flags >> 8);
        memcpy(pattern, temp, NOISE_MAX_TOKENS);
    }
    return err;
}
