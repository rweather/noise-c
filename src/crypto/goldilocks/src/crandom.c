/* Copyright (c) 2011 Stanford University.
 * Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

/* Chacha random number generator code copied from crandom */

#include "crandom.h"
#include "intrinsics.h"
#include "config.h"
#include "magic.h"

#include <stdio.h>

volatile unsigned int crandom_features = 0;

unsigned int crandom_detect_features(void) {
  unsigned int out = GEN;
  
# if (defined(__i386__) || defined(__x86_64__))
    u_int32_t a,b,c,d;
    
    a=1; __asm__("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    out |= GEN;
    if (d & 1<<26) out |= SSE2;
    if (d & 1<< 9) out |= SSSE3;
    if (c & 1<<25) out |= AESNI;
    if (c & 1<<28) out |= AVX;
    if (b & 1<<5) out  |= AVX2;
    if (c & 1<<30) out |= RDRAND;
    
    a=0x80000001; __asm__("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d));
    if (c & 1<<11) out |= XOP;
# endif
  
  return out;
}



INTRINSIC u_int64_t rdrand(int abort_on_fail) {
    uint64_t out = 0;
    int tries = 1000;
    
    if (HAVE(RDRAND)) {
    # if defined(__x86_64__)
        u_int64_t out, a=0;
        for (; tries && !a; tries--) {
            __asm__ __volatile__ (
                "rdrand %0\n\tsetc %%al"
                    : "=r"(out), "+a"(a) :: "cc"
            );
        }
    # elif (defined(__i386__))
        u_int32_t reg, a=0;
        uint64_t out;
        for (; tries && !a; tries--) {
            __asm__ __volatile__ (
                "rdrand %0\n\tsetc %%al"
                    : "=r"(reg), "+a"(a) :: "cc"
            );
        }
        out = reg; a = 0;
        for (; tries && !a; tries--) {
            __asm__ __volatile__ (
                "rdrand %0\n\tsetc %%al"
                    : "=r"(reg), "+a"(a) :: "cc"
            );
        }
        out = out << 32 | reg;
        return out;
    # else
        abort(); /* whut */
    # endif
    } else {
        tries = 0;
    }
    
    if (abort_on_fail && !tries) {
        abort();
    }
    
    return out;
}


/* ------------------------------- Vectorized code ------------------------------- */
#define shuffle(x,i) _mm_shuffle_epi32(x, \
  i + ((i+1)&3)*4 + ((i+2)&3)*16 + ((i+3)&3)*64)

#define add _mm_add_epi32
#define add64 _mm_add_epi64

#define NEED_XOP   (MIGHT_HAVE(XOP))
#define NEED_SSSE3 (MIGHT_HAVE(SSSE3) && !MUST_HAVE(XOP))
#define NEED_SSE2  (MIGHT_HAVE(SSE2)  && !MUST_HAVE(SSSE3))
#define NEED_CONV  (!MUST_HAVE(SSE2))

#if NEED_XOP
static __inline__ void
quarter_round_xop(
    ssereg *a,
    ssereg *b,
    ssereg *c,
    ssereg *d
) {
    *a = add(*a,*b); *d = xop_rotate(16, *d ^ *a);
    *c = add(*c,*d); *b = xop_rotate(12, *b ^ *c);
    *a = add(*a,*b); *d = xop_rotate(8,  *d ^ *a);
    *c = add(*c,*d); *b = xop_rotate(7,  *b ^ *c);
}
#endif

#if NEED_SSSE3
static const ssereg shuffle8  = { 0x0605040702010003ull, 0x0E0D0C0F0A09080Bull };
static const ssereg shuffle16 = { 0x0504070601000302ull, 0x0D0C0F0E09080B0Aull };
  
INTRINSIC ssereg ssse3_rotate_8(ssereg a) {
    return _mm_shuffle_epi8(a, shuffle8);
}
  
INTRINSIC ssereg ssse3_rotate_16(ssereg a) {
    return _mm_shuffle_epi8(a, shuffle16);
}
  
static __inline__ void
quarter_round_ssse3(
    ssereg *a,
    ssereg *b,
    ssereg *c,
    ssereg *d
) {
    *a = add(*a,*b); *d = ssse3_rotate_16(*d ^ *a);
    *c = add(*c,*d); *b = sse2_rotate(12, *b ^ *c);
    *a = add(*a,*b); *d = ssse3_rotate_8( *d ^ *a);
    *c = add(*c,*d); *b = sse2_rotate(7,  *b ^ *c);
}
#endif /* MIGHT_HAVE(SSSE3) && !MUST_HAVE(XOP) */

#if NEED_SSE2
static __inline__ void
quarter_round_sse2(
    ssereg *a,
    ssereg *b,
    ssereg *c,
    ssereg *d
) {
    *a = add(*a,*b); *d = sse2_rotate(16, *d ^ *a);
    *c = add(*c,*d); *b = sse2_rotate(12, *b ^ *c);
    *a = add(*a,*b); *d = sse2_rotate(8,  *d ^ *a);
    *c = add(*c,*d); *b = sse2_rotate(7,  *b ^ *c);
}
#endif

#define DOUBLE_ROUND(qrf) { \
  qrf(&a1,&b1,&c1,&d1);     \
  qrf(&a2,&b2,&c2,&d2);     \
  b1 = shuffle(b1,1);       \
  c1 = shuffle(c1,2);       \
  d1 = shuffle(d1,3);       \
  b2 = shuffle(b2,1);       \
  c2 = shuffle(c2,2);       \
  d2 = shuffle(d2,3);       \
                            \
  qrf(&a1,&b1,&c1,&d1);     \
  qrf(&a2,&b2,&c2,&d2);     \
  b1 = shuffle(b1,3);       \
  c1 = shuffle(c1,2);       \
  d1 = shuffle(d1,1);       \
  b2 = shuffle(b2,3);       \
  c2 = shuffle(c2,2);       \
  d2 = shuffle(d2,1);       \
                          }
                          
#define OUTPUT_FUNCTION   { \
  output[0] = add(a1,aa);   \
  output[1] = add(b1,bb);   \
  output[2] = add(c1,cc);   \
  output[3] = add(d1,dd);   \
  output[4] = add(a2,aa);   \
  output[5] = add(b2,bb);   \
  output[6] = add(c2,add(cc,p)); \
  output[7] = add(d2,dd);   \
                            \
  output += 8;              \
                            \
  cc = add64(add64(cc,p), p); \
  a1 = a2 = aa;             \
  b1 = b2 = bb;             \
  c1 = cc; c2 = add64(cc,p);\
  d1 = d2 = dd;             \
                          }
/* ------------------------------------------------------------------------------- */

INTRINSIC u_int32_t rotate(int r, u_int32_t a) {
    return a<<r ^ a>>(32-r);
}

static __inline__ __attribute__((unused)) void
quarter_round(u_int32_t *a, u_int32_t *b, u_int32_t *c, u_int32_t *d) {
    *a = *a + *b; *d = rotate(16, *d^*a);
    *c = *c + *d; *b = rotate(12, *b^*c);
    *a = *a + *b; *d = rotate(8,  *d^*a);
    *c = *c + *d; *b = rotate(7,  *b^*c);
}

static void
crandom_chacha_expand(u_int64_t iv,
                         u_int64_t ctr,
                         int nr,
                         int output_size,
                         const unsigned char *key_,
                         unsigned char *output_) {
# if MIGHT_HAVE_SSE2
    if (HAVE(SSE2)) {
        ssereg *key = (ssereg *)key_;
        ssereg *output = (ssereg *)output_;
                 
        ssereg a1 = key[0], a2 = a1, aa = a1,
               b1 = key[1], b2 = b1, bb = b1,
               c1 = {iv, ctr}, c2 = {iv, ctr+1}, cc = c1,
               d1 = {0x3320646e61707865ull, 0x6b20657479622d32ull},
               d2 = d1, dd = d1,
               p = {0, 1};
 
        int i,r;
#   if (NEED_XOP)
        if (HAVE(XOP)) {
            for (i=0; i<output_size; i+=128) {
                for (r=nr; r>0; r-=2)
                    DOUBLE_ROUND(quarter_round_xop);
                OUTPUT_FUNCTION;
            }
            return;
        }
#   endif
#   if (NEED_SSSE3)
        if (HAVE(SSSE3)) {
            for (i=0; i<output_size; i+=128) {
                for (r=nr; r>0; r-=2)
                    DOUBLE_ROUND(quarter_round_ssse3);
                OUTPUT_FUNCTION;
            }
            return;
        }
#   endif
#   if (NEED_SSE2)
        if (HAVE(SSE2)) {
            for (i=0; i<output_size; i+=128) {
                for (r=nr; r>0; r-=2)
                    DOUBLE_ROUND(quarter_round_sse2);
                OUTPUT_FUNCTION;
            }
            return;
        }
#   endif
    }
# endif

# if NEED_CONV
    {
        const u_int32_t *key = (const u_int32_t *)key_;
        u_int32_t
        x[16],
        input[16] = {
            key[0], key[1], key[2], key[3],
            key[4], key[5], key[6], key[7],
            iv, iv>>32, ctr, ctr>>32,
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
        },
        *output = (u_int32_t *)output_;
        int i, r;

        for (i=0; i<output_size; i+= 64) {
            for (r=0; r<16; r++) {
                x[r] = input[r];
            }
                for (r=nr; r>0; r-=2) {
                quarter_round(&x[0], &x[4],  &x[8], &x[12]);
                quarter_round(&x[1], &x[5],  &x[9], &x[13]);
                quarter_round(&x[2], &x[6], &x[10], &x[14]);
                quarter_round(&x[3], &x[7], &x[11], &x[15]);

                quarter_round(&x[0], &x[5], &x[10], &x[15]);
                quarter_round(&x[1], &x[6], &x[11], &x[12]);
                quarter_round(&x[2], &x[7],  &x[8], &x[13]);
                quarter_round(&x[3], &x[4],  &x[9], &x[14]);
            }
            for (r=0; r<16; r++) {
                output[r] = x[r] + input[r];
            }

            output += 16;
            input[11] ++;
            if (!input[11]) input[12]++;
        }
    }
  
#endif /* NEED_CONV */
}

int
crandom_init_from_file(
    crandom_state_a_t state,
    const char *filename,
    int reseed_interval,
    int reseeds_mandatory
) {
    state->fill = 0;
    state->reseed_countdown = reseed_interval;
    state->reseed_interval = reseed_interval;
    state->ctr = 0;

    state->randomfd = open(filename, O_RDONLY);
    if (state->randomfd == -1) {
        int err = errno;
        return err ? err : -1;
    }

    ssize_t offset = 0, red;
    do {
        red = read(state->randomfd, state->seedBuffer + offset, 32 - offset);
        if (red > 0) offset += red;
    } while (red > 0 && offset < 32);

    if (offset < 32) {
        int err = errno;
        return err ? err : -1;
    }

    memset(state->seedBuffer+32, 0, 96);

    state->magic = CRANDOM_MAGIC;
    state->reseeds_mandatory = reseeds_mandatory;

    return 0;
}

void
crandom_init_from_buffer(
    crandom_state_a_t state,
    const char initial_seed[32]
) {
    memcpy(state->seedBuffer, initial_seed, 32);
    memset(state->seedBuffer+32, 0, 96);
    state->reseed_countdown = state->reseed_interval = state->fill = state->ctr = state->reseeds_mandatory = 0;
    state->randomfd = -1;
    state->magic = CRANDOM_MAGIC;
}

int
crandom_generate(
    crandom_state_a_t state,
    unsigned char *output,
    unsigned long long length
) {
    /* the generator isn't seeded; maybe they ignored the return value of init_from_file */
    if (unlikely(state->magic != CRANDOM_MAGIC)) {
        abort();
    }

    int ret = 0;

    /* 
     * Addition 5/21/2014.
     *
     * If this is used in an application inside a VM, and the VM
     * is snapshotted and restored, then crandom_generate() would
     * produce the same output.
     * 
     * Of course, the real defense against this is "don't do that",
     * but we mitigate it by the RDRAND and/or rdtsc() in the refilling
     * code.  Since chacha is pseudorandom, when the attacker doesn't
     * know the state, it's good enough if RDRAND/rdtsc() return
     * different results.  However, if (part of) the request is filled
     * from the buffer, this won't help.
     *
     * So, add a flag EXPERIMENT_CRANDOM_BUFFER_CUTOFF_BYTES which
     * disables the buffer for requests larger than this size.
     *
     * Suggest EXPERIMENT_CRANDOM_BUFFER_CUTOFF_BYTES = 0, which
     * disables the buffer.  But instead you can set it to say 16,
     * so that pulls of at least 128 bits will be stirred.  This
     * could still be a problem for eg 64-bit nonces, but those
     * aren't entirely collision-resistant anyway.
     *
     * Heuristic: large requests are more likely to be 
     * cryptographically important, and the buffer doesn't impact
     * their performance as much.  So if the request is bigger
     * than a certain size, just drop the buffer on the floor.
     *
     * This code isn't activated if state->reseed_interval == 0,
     * because then the PRNG is deterministic anyway.
     *
     * TODO: sample 128 bits out of RDRAND() instead of 64 bits.
     * TODO: option to completely remove the buffer and fill?
     * FUTURE: come up with a less band-aid-y solution to this problem.
     */
#ifdef EXPERIMENT_CRANDOM_BUFFER_CUTOFF_BYTES
    if (state->reseed_interval
#if EXPERIMENT_CRANDOM_CUTOFF_BYTES > 0
        /* #if'd to a warning from -Wtype-limits in GCC when it's zero */
        && length >= EXPERIMENT_CRANDOM_BUFFER_CUTOFF_BYTES
#endif
    ) {
        state->fill = 0;
    }
#endif
    
    while (length) {
        if (unlikely(state->fill <= 0)) {
            uint64_t iv = 0;
            if (state->reseed_interval) {
                /* it's nondeterministic, stir in some rdrand() or rdtsc() */
                if (HAVE(RDRAND)) {
                    iv = rdrand(0);
                    if (!iv) iv = rdtsc();
                } else {
                    iv = rdtsc();
                }

                state->reseed_countdown--;
                if (unlikely(state->reseed_countdown <= 0)) {
                    /* reseed by xoring in random state */
                    state->reseed_countdown = state->reseed_interval;
                    ssize_t offset = 0, red;
                    do {
                        red = read(state->randomfd, state->seedBuffer + 32 + offset, 32 - offset);
                        if (red > 0) offset += red;
                    } while (red > 0 && offset < 32);

                    if (offset < 32) {
                        /* The read failed.  Signal an error with the return code.
                         *
                         * If reseeds are mandatory, crash.
                         *
                         * If not, the generator is still probably safe to use, because reseeding
                         * is basically over-engineering for caution.  Also, the user might ignore
                         * the return code, so we still need to fill the request.
                         *
                         * Set reseed_countdown = 1 so we'll try again later.  If the user's
                         * performance sucks as a result of ignoring the error code while calling
                         * us in a loop, well, that's life.
                         */
                        if (state->reseeds_mandatory) {
                            abort();
                        }

                        ret = errno;
                        if (ret == 0) ret = -1;
                        state->reseed_countdown = 1;
                    }

                    int i;
                    for (i=0; i<32; i++) {
                        /* Stir in the buffer.  If somehow the read failed, it'll be zeros. */
                        state->seedBuffer[i] ^= state->seedBuffer[i+32];
                    }
                }
            }
            crandom_chacha_expand(iv,state->ctr,20,128,state->seedBuffer,state->seedBuffer);
            state->ctr++;
            state->fill = sizeof(state->seedBuffer)-32;
        }

        unsigned long long copy = (length > state->fill) ? state->fill : length;
        state->fill -= copy;
        memcpy(output, state->seedBuffer + 32 + state->fill, copy);
        really_memset(state->seedBuffer + 32 + state->fill, 0, copy);
        output += copy; length -= copy;
    }

    return ret;
}

void
crandom_destroy(
    crandom_state_a_t state
) { 
    if (state->magic == CRANDOM_MAGIC && state->randomfd) {
        (void) close(state->randomfd);
        /* Ignore the return value from close(), because what would it mean?
         * "Your random device, which you were reading over NFS, lost some data"?
         */
    }

    really_memset(state, 0, sizeof(*state));
}
