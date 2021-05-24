/*
 * Copyright (C) 2016 Southern Storm Software, Pty Ltd.
 * Copyright (C) 2016 Topology LP.
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

#if USE_SODIUM
int crypto_aead_aes256gcm_is_available(void);
NoiseCipherState *noise_aesgcm_new_sodium(void);
#endif
#if USE_OPENSSL
NoiseCipherState *noise_aesgcm_new_openssl(void);
#else
NoiseCipherState *noise_aesgcm_new_ref(void);
#endif

/**
 * \brief Creates a new AES-GCM CipherState object.
 *
 * \return A NoiseCipherState for AES-GCM cipher use, or NULL if no such state is available.
 */
NoiseCipherState *noise_aesgcm_new(void)
{
    NoiseCipherState *state = 0;
#if USE_SODIUM
    if (crypto_aead_aes256gcm_is_available())
        state = noise_aesgcm_new_sodium();
#endif
#if USE_OPENSSL
    if (!state)
        state = noise_aesgcm_new_openssl();
#else
    if (!state)
        state = noise_aesgcm_new_ref();
#endif

    return state;
}


