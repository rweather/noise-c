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

#include "curve448.h"

/* Include the field arithmetic from Ed448-Goldilocks */
#include <field.h>

/*
The public Ed448-Goldilocks functions don't quite do what we want.
So we instead call the internal field arithmetic functions directly
to implement the requirements from RFC 7748.

Reference: https://tools.ietf.org/html/rfc7748
*/

/**
 * \brief Conditional swap of two values in constant time.
 *
 * \param swap Set to 1 to swap the values or 0 to leave them as-is.
 * \param x The first value to swap.
 * \param y The second value to swap.
 *
 * Reference: http://tools.ietf.org/html/rfc7748
 */
static void cswap(unsigned char swap, field_t *x, field_t *y)
{
#if WORD_BITS == 64
    uint64_t sel, dummy;
#else
    uint32_t sel, dummy;
#endif
    unsigned char posn;
    sel = (uint64_t)(-((int64_t)swap));
    for (posn = 0; posn < (sizeof(x->limb) / sizeof(x->limb[0])); ++posn) {
        dummy = sel & (x->limb[posn] ^ y->limb[posn]);
        x->limb[posn] ^= dummy;
        y->limb[posn] ^= dummy;
    }
}

/**
 * \brief Evaluates the Curve448 function.
 *
 * \param mypublic Final output public key, 56 bytes.
 * \param secret Secret value; i.e. the private key, 56 bytes.
 * \param basepoint The input base point, 56 bytes.
 *
 * \return Returns 1 if the evaluation was successful, 0 if the inputs
 * were invalid in some way.
 *
 * Reference: http://tools.ietf.org/html/rfc7748
 */
int curve448_eval(unsigned char mypublic[56], const unsigned char secret[56], const unsigned char basepoint[56])
{
    /* Implementation details from RFC 7748, section 5 */
    field_t x_1, x_2, z_2, x_3, z_3;
    field_t A, AA, B, BB, E, C, D, DA, CB;
    unsigned char swap = 0;
    unsigned char byte_val;
    unsigned char k_t;
    unsigned char bit = 7;
    unsigned char posn = 55;

    /* Initialize working variables */
    mask_t success = field_deserialize(&x_1, basepoint);    /* x_1 = u */
    field_set_ui(&x_2, 1);                                  /* x_2 = 1 */
    field_set_ui(&z_2, 0);                                  /* z_2 = 0 */
    field_copy(&x_3, &x_1);                                 /* x_3 = u */
    field_set_ui(&z_3, 1);                                  /* z_3 = 1 */

    /* Loop on all bits of the secret from highest to lowest.
       We perform the required masking from RFC 7748 as we go */
    byte_val = secret[posn] | 0x80;
    for (;;) {
        /* Get the next bit of the secret and conditionally swap */
        k_t = (byte_val >> bit) & 1;
        swap ^= k_t;
        cswap(swap, &x_2, &x_3);
        cswap(swap, &z_2, &z_3);
        swap = k_t;

        /* Double and add for this bit */
        field_add(&A, &x_2, &z_2);          /* A = x_2 + z_2 */
        field_sqr(&AA, &A);                 /* AA = A^2 */
        field_sub(&B, &x_2, &z_2);          /* B = x_2 - z_2 */
        field_sqr(&BB, &B);                 /* BB = B^2 */
        field_sub(&E, &AA, &BB);            /* E = AA - BB */
        field_add(&C, &x_3, &z_3);          /* C = x_3 + z_3 */
        field_sub(&D, &x_3, &z_3);          /* D = x_3 - z_3 */
        field_mul(&DA, &D, &A);             /* DA = D * A */
        field_mul(&CB, &C, &B);             /* CB = C * B */
        field_add(&z_2, &DA, &CB);          /* x_3 = (DA + CB)^2 */
        field_sqr(&x_3, &z_2);
        field_sub(&z_2, &DA, &CB);          /* z_3 = x_1 * (DA - CB)^2 */
        field_sqr(&x_2, &z_2);
        field_mul(&z_3, &x_1, &x_2);
        field_mul(&x_2, &AA, &BB);          /* x_2 = AA * BB */
        field_mulw(&z_2, &E, 39081);        /* z_2 = E * (AA + a24 * E) */
        field_add(&A, &AA, &z_2);
        field_mul(&z_2, &E, &A);

        /* Move onto the next lower bit of the secret */
        if (bit) {
            --bit;
        } else if (posn > 1) {
            bit = 7;
            byte_val = secret[--posn];
        } else if (posn == 1) {
            bit = 7;
            byte_val = secret[--posn] & 0xFC;
        } else {
            break;
        }
    }

    /* Final conditional swap */
    cswap(swap, &x_2, &x_3);
    cswap(swap, &z_2, &z_3);

    /* Compute x_2 * z_2 ^ (p - 2)

       The value p - 2 is: FF...FEFF...FD, which from highest to lowest is
       223 one bits, followed by a zero bit, followed by 222 one bits,
       followed by another zero bit, and a final one bit.

       The naive implementation that squares for every bit and multiplies
       for every 1 bit requires 893 multiplications.  The following can
       do the same operation in 483 multiplications.  The basic idea is to
       create bit patterns and then "shift" them into position.  We start
       with a 4 bit pattern 1111, which we can square 4 times to get
       11110000 and then multiply by the 1111 pattern to get 11111111.
       We then repeat that to turn 11111111 into 1111111111111111, etc.
    */
    field_sqr(&B, &z_2);                /* Set A to a 4 bit pattern */
    field_mul(&A, &B, &z_2);
    field_sqr(&B, &A);
    field_mul(&A, &B, &z_2);
    field_sqr(&B, &A);
    field_mul(&A, &B, &z_2);
    field_sqr(&B, &A);                  /* Set C to a 6 bit pattern */
    field_mul(&C, &B, &z_2);
    field_sqr(&B, &C);
    field_mul(&C, &B, &z_2);
    field_sqr(&B, &C);                  /* Set A to a 8 bit pattern */
    field_mul(&A, &B, &z_2);
    field_sqr(&B, &A);
    field_mul(&A, &B, &z_2);
    field_sqr(&E, &A);                  /* Set E to a 16 bit pattern */
    field_sqr(&B, &E);
    for (posn = 1; posn < 4; ++posn) {
        field_sqr(&E, &B);
        field_sqr(&B, &E);
    }
    field_mul(&E, &B, &A);
    field_sqr(&AA, &E);                 /* Set AA to a 32 bit pattern */
    field_sqr(&B, &AA);
    for (posn = 1; posn < 8; ++posn) {
        field_sqr(&AA, &B);
        field_sqr(&B, &AA);
    }
    field_mul(&AA, &B, &E);
    field_sqr(&BB, &AA);                /* Set BB to a 64 bit pattern */
    field_sqr(&B, &BB);
    for (posn = 1; posn < 16; ++posn) {
        field_sqr(&BB, &B);
        field_sqr(&B, &BB);
    }
    field_mul(&BB, &B, &AA);
    field_sqr(&DA, &BB);                /* Set DA to a 128 bit pattern */
    field_sqr(&B, &DA);
    for (posn = 1; posn < 32; ++posn) {
        field_sqr(&DA, &B);
        field_sqr(&B, &DA);
    }
    field_mul(&DA, &B, &BB);
    field_sqr(&CB, &DA);                /* Set CB to a 192 bit pattern */
    field_sqr(&B, &CB);                 /* 192 = 128 + 64 */
    for (posn = 1; posn < 32; ++posn) {
        field_sqr(&CB, &B);
        field_sqr(&B, &CB);
    }
    field_mul(&CB, &B, &BB);
    field_sqr(&DA, &CB);                /* Set DA to a 208 bit pattern */
    field_sqr(&B, &DA);                 /* 208 = 128 + 64 + 16 */
    for (posn = 1; posn < 8; ++posn) {
        field_sqr(&DA, &B);
        field_sqr(&B, &DA);
    }
    field_mul(&DA, &B, &E);
    field_sqr(&CB, &DA);                /* Set CB to a 216 bit pattern */
    field_sqr(&B, &CB);                 /* 216 = 128 + 64 + 16 + 8 */
    for (posn = 1; posn < 4; ++posn) {
        field_sqr(&CB, &B);
        field_sqr(&B, &CB);
    }
    field_mul(&CB, &B, &A);
    field_sqr(&DA, &CB);                /* Set DA to a 222 bit pattern */
    field_sqr(&B, &DA);                 /* 222 = 128 + 64 + 16+ 8 + 6 */
    for (posn = 1; posn < 3; ++posn) {
        field_sqr(&DA, &B);
        field_sqr(&B, &DA);
    }
    field_mul(&DA, &B, &C);
    field_sqr(&CB, &DA);                /* Set CB to a 224 bit pattern */
    field_mul(&B, &CB, &z_2);           /* CB = DA|1|0 */
    field_sqr(&CB, &B);
    field_sqr(&BB, &CB);                /* Set BB to a 446 bit pattern */
    field_sqr(&B, &BB);                 /* BB = DA|1|0|DA */
    for (posn = 1; posn < 111; ++posn) {
        field_sqr(&BB, &B);
        field_sqr(&B, &BB);
    }
    field_mul(&BB, &B, &DA);
    field_sqr(&B, &BB);                 /* Set B to a 448 bit pattern */
    field_sqr(&BB, &B);                 /* B = DA|1|0|DA|01 */
    field_mul(&B, &BB, &z_2);
    field_mul(&BB, &x_2, &B);           /* Set BB to x_2 * B */

    /* Serialize the result into the return buffer */
    field_serialize(mypublic, &BB);

    /* If the original base point was out of range, then fail now */
    return (int)(1 & success);
}
