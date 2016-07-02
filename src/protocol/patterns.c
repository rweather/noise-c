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

/**
 * \file patterns.c
 * \brief Defines the handshake message patterns.
 */

/**
 * \brief Token sequence for handshake pattern "N".
 *
 * @code
 * Noise_N(rs):
 *   <- s
 *   ...
 *   -> e, dhes
 * @endcode
 */
static uint8_t const noise_pattern_N[] = {
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
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
 *   -> e, dhes, dhss
 * @endcode
 */
static uint8_t const noise_pattern_K[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_DHSS,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "X".
 *
 * @code
 * Noise_X(s, rs):
 *   <- s
 *   ...
 *   -> e, dhes, s, dhss
 * @endcode
 */
static uint8_t const noise_pattern_X[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSS,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NN".
 *
 * @code
 * Noise_NN():
 *   -> e
 *   <- e, dhee
 * @endcode
 */
static uint8_t const noise_pattern_NN[] = {
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NK".
 *
 * @code
 * Noise_NK(rs):
 *   <- s
 *   ...
 *   -> e, dhes
 *   <- e, dhee
 * @endcode
 */
static uint8_t const noise_pattern_NK[] = {
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NX".
 *
 * @code
 * Noise_NX(rs):
 *   -> e
 *   <- e, dhee, s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_NX[] = {
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XN".
 *
 * @code
 * Noise_XN(s):
 *   -> e
 *   <- e, dhee
 *   -> s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_XN[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XK".
 *
 * @code
 * Noise_XK(s, rs):
 *   <- s
 *   ...
 *   -> e, dhes
 *   <- e, dhee
 *   -> s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_XK[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XX".
 *
 * @code
 * Noise_XX(s, rs):
 *   -> e
 *   <- e, dhee, s, dhse
 *   -> s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_XX[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
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
 *   <- e, dhee, dhes
 * @endcode
 */
static uint8_t const noise_pattern_KN[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_DHES,
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
 *   -> e, dhes, dhss
 *   <- e, dhee, dhes
 * @endcode
 */
static uint8_t const noise_pattern_KK[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_DHSS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_DHES,
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
 *   <- e, dhee, dhes, s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_KX[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IN".
 *
 * @code
 * Noise_IN(s):
 *   -> e, s
 *   <- e, dhee, dhes
 * @endcode
 */
static uint8_t const noise_pattern_IN[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IK".
 *
 * @code
 * Noise_IK(s, rs):
 *   <- s
 *   ...
 *   -> e, dhes, s, dhss
 *   <- e, dhee, dhes
 * @endcode
 */
static uint8_t const noise_pattern_IK[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IX".
 *
 * @code
 * Noise_IX(s, rs):
 *   -> e, s
 *   <- e, dhee, dhes, s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_IX[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL,

    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_DHES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XXfallback".
 *
 * @code
 * Noise_XXfallback(s, rs, re):
 *   <- e
 *   ...
 *   -> e, dhee, s, dhse
 *   <- s, dhse
 * @endcode
 */
static uint8_t const noise_pattern_XXfallback[] = {
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEM_REQ,

    NOISE_TOKEN_E,
    NOISE_TOKEN_DHEE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_DHSE,
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
    case NOISE_PATTERN_N:           return noise_pattern_N;
    case NOISE_PATTERN_K:           return noise_pattern_K;
    case NOISE_PATTERN_X:           return noise_pattern_X;
    case NOISE_PATTERN_NN:          return noise_pattern_NN;
    case NOISE_PATTERN_NK:          return noise_pattern_NK;
    case NOISE_PATTERN_NX:          return noise_pattern_NX;
    case NOISE_PATTERN_XN:          return noise_pattern_XN;
    case NOISE_PATTERN_XK:          return noise_pattern_XK;
    case NOISE_PATTERN_XX:          return noise_pattern_XX;
    case NOISE_PATTERN_KN:          return noise_pattern_KN;
    case NOISE_PATTERN_KK:          return noise_pattern_KK;
    case NOISE_PATTERN_KX:          return noise_pattern_KX;
    case NOISE_PATTERN_IN:          return noise_pattern_IN;
    case NOISE_PATTERN_IK:          return noise_pattern_IK;
    case NOISE_PATTERN_IX:          return noise_pattern_IX;
    case NOISE_PATTERN_XX_FALLBACK: return noise_pattern_XXfallback;
    default:                        return 0;
    }
}

/**
 * \brief Reverses the local and remote flags for a pattern.
 *
 * \param flags The flags, assuming that the initiator is "local".
 * \return The reversed flags, with the responder now being "local".
 */
uint8_t noise_pattern_reverse_flags(uint8_t flags)
{
    return ((flags >> 4) & 0x0F) | ((flags << 4) & 0xF0);
}
