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
 * \brief Token sequence for handshake pattern "XXfallback".
 *
 * @code
 * Noise_XXfallback(s, rs, re):
 *   <- e
 *   ...
 *   -> e, ee, s, se
 *   <- s, es
 * @endcode
 */
static uint8_t const noise_pattern_XXfallback[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEM_REQ
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "Xnoidh".
 *
 * @code
 * Noise_Xnoidh(s, rs):
 *   <- s
 *   ...
 *   -> e, s, es, ss
 * @endcode
 */
static uint8_t const noise_pattern_Xnoidh[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NXnoidh".
 *
 * @code
 * Noise_NXnoidh(rs):
 *   -> e
 *   <- e, s, ee, es
 * @endcode
 */
static uint8_t const noise_pattern_NXnoidh[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XXnoidh".
 *
 * @code
 * Noise_XXnoidh(s, rs):
 *   -> e
 *   <- e, s, ee, es
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XXnoidh[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KXnoidh".
 *
 * @code
 * Noise_KXnoidh(s, rs):
 *   -> s
 *   ...
 *   -> e
 *   <- e, s, ee, se, es
 * @endcode
 */
static uint8_t const noise_pattern_KXnoidh[] = {
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
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IKnoidh".
 *
 * @code
 * Noise_IKnoidh(s, rs):
 *   <- s
 *   ...
 *   -> e, s, es, ss
 *   <- e, ee, se
 * @endcode
 */
static uint8_t const noise_pattern_IKnoidh[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IXnoidh".
 *
 * @code
 * Noise_IXnoidh(s, rs):
 *   -> e, s
 *   <- e, s, ee, se, es
 * @endcode
 */
static uint8_t const noise_pattern_IXnoidh[] = {
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
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NNhfs".
 *
 * @code
 * Noise_NNhfs():
 *   -> e, f
 *   <- e, f, ee, ff
 * @endcode
 */
static uint8_t const noise_pattern_NNhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NKhfs".
 *
 * @code
 * Noise_NKhfs(rs):
 *   <- s
 *   ...
 *   -> e, f, es
 *   <- e, f, ee, ff
 * @endcode
 */
static uint8_t const noise_pattern_NKhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NXhfs".
 *
 * @code
 * Noise_NXhfs(rs):
 *   -> e, f
 *   <- e, f, ee, ff, s, es
 * @endcode
 */
static uint8_t const noise_pattern_NXhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XNhfs".
 *
 * @code
 * Noise_XNhfs(s):
 *   -> e, f
 *   <- e, f, ee, ff
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XNhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XKhfs".
 *
 * @code
 * Noise_XKhfs(s, rs):
 *   <- s
 *   ...
 *   -> e, f, es
 *   <- e, f, ee, ff
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XKhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XXhfs".
 *
 * @code
 * Noise_XXhfs(s, rs):
 *   -> e, f
 *   <- e, f, ee, ff, s, es
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XXhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KNhfs".
 *
 * @code
 * Noise_KNhfs(s):
 *   -> s
 *   ...
 *   -> e, f
 *   <- e, f, ee, ff, se
 * @endcode
 */
static uint8_t const noise_pattern_KNhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KKhfs".
 *
 * @code
 * Noise_KKhfs(s, rs):
 *   -> s
 *   <- s
 *   ...
 *   -> e, f, es, ss
 *   <- e, f, ee, ff, se
 * @endcode
 */
static uint8_t const noise_pattern_KKhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KXhfs".
 *
 * @code
 * Noise_KXhfs(s, rs):
 *   -> s
 *   ...
 *   -> e, f
 *   <- e, f, ee, ff, se, s, es
 * @endcode
 */
static uint8_t const noise_pattern_KXhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "INhfs".
 *
 * @code
 * Noise_INhfs(s):
 *   -> e, f, s
 *   <- e, f, ee, ff, se
 * @endcode
 */
static uint8_t const noise_pattern_INhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IKhfs".
 *
 * @code
 * Noise_IKhfs(s, rs):
 *   <- s
 *   ...
 *   -> e, f, es, s, ss
 *   <- e, f, ee, ff, se
 * @endcode
 */
static uint8_t const noise_pattern_IKhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IXhfs".
 *
 * @code
 * Noise_IXhfs(s, rs):
 *   -> e, f, s
 *   <- e, f, ee, ff, se, s, es
 * @endcode
 */
static uint8_t const noise_pattern_IXhfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XXfallback+hfs".
 *
 * @code
 * Noise_XXfallback+hfs(s, rs, re):
 *   <- e, f
 *   ...
 *   -> e, f, ee, ff, s, se
 *   <- s, es
 * @endcode
 */
static uint8_t const noise_pattern_XXfallback_hfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_EPHEM_REQ |
    NOISE_PAT_FLAG_REMOTE_HYBRID |
    NOISE_PAT_FLAG_REMOTE_HYBRID_REQ
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "NXnoidh+hfs".
 *
 * @code
 * Noise_NXnoidh+hfs(rs):
 *   -> e, f
 *   <- e, f, s, ee, ff, es
 * @endcode
 */
static uint8_t const noise_pattern_NXnoidh_hfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "XXnoidh+hfs".
 *
 * @code
 * Noise_XXnoidh+hfs(s, rs):
 *   -> e, f
 *   <- e, f, s, ee, ff, es
 *   -> s, se
 * @endcode
 */
static uint8_t const noise_pattern_XXnoidh_hfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_S,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "KXnoidh+hfs".
 *
 * @code
 * Noise_KXnoidh+hfs(s, rs):
 *   -> s
 *   ...
 *   -> e, f
 *   <- e, f, s, ee, ff, se, es
 * @endcode
 */
static uint8_t const noise_pattern_KXnoidh_hfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_REQUIRED |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IKnoidh+hfs".
 *
 * @code
 * Noise_IKnoidh+hfs(s, rs):
 *   <- s
 *   ...
 *   -> e, f, s, es, ss
 *   <- e, f, ee, ff, se
 * @endcode
 */
static uint8_t const noise_pattern_IKnoidh_hfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_REQUIRED |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_ES,
    NOISE_TOKEN_SS,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
    NOISE_TOKEN_END
};

/**
 * \brief Token sequence for handshake pattern "IXnoidh+hfs".
 *
 * @code
 * Noise_IXnoidh+hfs(s, rs):
 *   -> e, f, s
 *   <- e, f, s, ee, ff, se, es
 * @endcode
 */
static uint8_t const noise_pattern_IXnoidh_hfs[] = {
    FLAGS(
    NOISE_PAT_FLAG_LOCAL_STATIC |
    NOISE_PAT_FLAG_LOCAL_EPHEMERAL |
    NOISE_PAT_FLAG_LOCAL_HYBRID |
    NOISE_PAT_FLAG_REMOTE_STATIC |
    NOISE_PAT_FLAG_REMOTE_EPHEMERAL |
    NOISE_PAT_FLAG_REMOTE_HYBRID
    ),

    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_FLIP_DIR,
    NOISE_TOKEN_E,
    NOISE_TOKEN_F,
    NOISE_TOKEN_S,
    NOISE_TOKEN_EE,
    NOISE_TOKEN_FF,
    NOISE_TOKEN_SE,
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
    case NOISE_PATTERN_XX_FALLBACK:     return noise_pattern_XXfallback;
    case NOISE_PATTERN_X_NOIDH:         return noise_pattern_Xnoidh;
    case NOISE_PATTERN_NX_NOIDH:        return noise_pattern_NXnoidh;
    case NOISE_PATTERN_XX_NOIDH:        return noise_pattern_XXnoidh;
    case NOISE_PATTERN_KX_NOIDH:        return noise_pattern_KXnoidh;
    case NOISE_PATTERN_IK_NOIDH:        return noise_pattern_IKnoidh;
    case NOISE_PATTERN_IX_NOIDH:        return noise_pattern_IXnoidh;
    case NOISE_PATTERN_NN_HFS:          return noise_pattern_NNhfs;
    case NOISE_PATTERN_NK_HFS:          return noise_pattern_NKhfs;
    case NOISE_PATTERN_NX_HFS:          return noise_pattern_NXhfs;
    case NOISE_PATTERN_XN_HFS:          return noise_pattern_XNhfs;
    case NOISE_PATTERN_XK_HFS:          return noise_pattern_XKhfs;
    case NOISE_PATTERN_XX_HFS:          return noise_pattern_XXhfs;
    case NOISE_PATTERN_KN_HFS:          return noise_pattern_KNhfs;
    case NOISE_PATTERN_KK_HFS:          return noise_pattern_KKhfs;
    case NOISE_PATTERN_KX_HFS:          return noise_pattern_KXhfs;
    case NOISE_PATTERN_IN_HFS:          return noise_pattern_INhfs;
    case NOISE_PATTERN_IK_HFS:          return noise_pattern_IKhfs;
    case NOISE_PATTERN_IX_HFS:          return noise_pattern_IXhfs;
    case NOISE_PATTERN_XX_FALLBACK_HFS: return noise_pattern_XXfallback_hfs;
    case NOISE_PATTERN_NX_NOIDH_HFS:    return noise_pattern_NXnoidh_hfs;
    case NOISE_PATTERN_XX_NOIDH_HFS:    return noise_pattern_XXnoidh_hfs;
    case NOISE_PATTERN_KX_NOIDH_HFS:    return noise_pattern_KXnoidh_hfs;
    case NOISE_PATTERN_IK_NOIDH_HFS:    return noise_pattern_IKnoidh_hfs;
    case NOISE_PATTERN_IX_NOIDH_HFS:    return noise_pattern_IXnoidh_hfs;
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
