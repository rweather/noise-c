/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "word.h"

#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "intrinsics.h"
#include "scalarmul.h"
#include "barrett_field.h"
#include "constant_time.h"

mask_t
montgomery_ladder (
    field_a_t out,
    const field_a_t in,
    const word_t *scalar,
    unsigned int nbits,
    unsigned int n_extra_doubles
) { 
    montgomery_a_t mont;
    deserialize_montgomery(mont, in);
    
    int i,j,n=(nbits-1)%WORD_BITS;
    mask_t pflip = 0;
    for (j=(nbits+WORD_BITS-1)/WORD_BITS-1; j>=0; j--) {
        word_t w = scalar[j];
        for (i=n; i>=0; i--) {
            mask_t flip = -((w>>i)&1);
            constant_time_cond_swap(mont->xa,mont->xd,sizeof(mont->xd),flip^pflip);
            constant_time_cond_swap(mont->za,mont->zd,sizeof(mont->xd),flip^pflip);
            montgomery_step(mont);
            pflip = flip;
        }
        n = WORD_BITS-1;
    }
    constant_time_cond_swap(mont->xa,mont->xd,sizeof(mont->xd),pflip);
    constant_time_cond_swap(mont->za,mont->zd,sizeof(mont->xd),pflip);
    
    assert(n_extra_doubles < INT_MAX);
    for (j=0; j<(int)n_extra_doubles; j++) {
        montgomery_step(mont);
    }
    
    return serialize_montgomery(out, mont, in);
}

static __inline__ void
__attribute__((unused,always_inline))
constant_time_lookup_tw_pniels (
    tw_pniels_a_t out,
    const tw_pniels_a_t *in,
    int nin,
    int idx
) {
    constant_time_lookup(out,in,sizeof(*out),nin,idx);
}

static __inline__ void
__attribute__((unused,always_inline))
constant_time_lookup_tw_niels (
    tw_niels_a_t out,
    const tw_niels_a_t *in,
    int nin,
    int idx
) {
    constant_time_lookup(out,in,sizeof(*out),nin,idx);
}

static void
convert_to_signed_window_form (
    word_t *out,
    const word_t *scalar,
    int nwords_scalar,
    const word_t *prepared_data,
    int nwords_pd
) {
    assert(nwords_pd <= nwords_scalar);
    mask_t mask = -(scalar[0]&1);

    word_t carry = add_nr_ext_packed(out, scalar, nwords_scalar, prepared_data, nwords_pd, ~mask);
    carry += add_nr_ext_packed(out, out, nwords_scalar, prepared_data+nwords_pd, nwords_pd, mask);
    
    assert(!(out[0]&1));
    
    int i;
    for (i=0; i<nwords_scalar; i++) {
        out[i] >>= 1;
        if (i<nwords_scalar-1) {
            out[i] |= out[i+1]<<(WORD_BITS-1);
        } else {
            out[i] |= carry<<(WORD_BITS-1);
        }
    }
}

void
scalarmul (
    tw_extensible_a_t working,
    const word_t scalar[SCALAR_WORDS]
) {
    const int WINDOW = SCALARMUL_FIXED_WINDOW_SIZE,
        WINDOW_MASK = (1<<WINDOW)-1, WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1),
        nbits = ROUND_UP(SCALAR_BITS,WINDOW);
    
    word_t scalar2[SCALAR_WORDS];
    convert_to_signed_window_form (
        scalar2, scalar, SCALAR_WORDS,
        SCALARMUL_FIXED_WINDOW_ADJUSTMENT, SCALAR_WORDS
    );

    tw_extensible_a_t tabulator;
    copy_tw_extensible(tabulator, working);
    double_tw_extensible(tabulator);

    tw_pniels_a_t
	  pn VECTOR_ALIGNED,
	  multiples[NTABLE] VECTOR_ALIGNED;
    convert_tw_extensible_to_tw_pniels(pn, tabulator);
    convert_tw_extensible_to_tw_pniels(multiples[0], working);

    int i,j;
    for (i=1; i<NTABLE; i++) {
        add_tw_pniels_to_tw_extensible(working, pn);
        convert_tw_extensible_to_tw_pniels(multiples[i], working);
    }

    i = nbits - WINDOW;
    int bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS) & WINDOW_MASK,
        inv = (bits>>(WINDOW-1))-1;
    bits ^= inv;
    
    constant_time_lookup_tw_pniels(pn, (const tw_pniels_a_t*)multiples, NTABLE, bits & WINDOW_T_MASK);
    cond_negate_tw_pniels(pn, inv);
    convert_tw_pniels_to_tw_extensible(working, pn);
		

    for (i-=WINDOW; i>=0; i-=WINDOW) {
        for (j=0; j<WINDOW; j++) {
            double_tw_extensible(working);
        }

        bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS);
        
        if (i/WORD_BITS < SCALAR_WORDS-1 && i%WORD_BITS >= WORD_BITS-WINDOW) {
            bits ^= scalar2[i/WORD_BITS+1] << (WORD_BITS - (i%WORD_BITS));
        }
                
        bits &= WINDOW_MASK;
        inv = (bits>>(WINDOW-1))-1;
        bits ^= inv;
    
        constant_time_lookup_tw_pniels(pn, (const tw_pniels_a_t*)multiples, NTABLE, bits & WINDOW_T_MASK);
        cond_negate_tw_pniels(pn, inv);
        add_tw_pniels_to_tw_extensible(working, pn);
    }
}

void
scalarmul_vlook (
    tw_extensible_a_t working,
    const word_t scalar[SCALAR_WORDS]
) {    
    const int WINDOW = SCALARMUL_FIXED_WINDOW_SIZE,
        WINDOW_MASK = (1<<WINDOW)-1, WINDOW_T_MASK = WINDOW_MASK >> 1,
        NTABLE = 1<<(WINDOW-1),
        nbits = ROUND_UP(SCALAR_BITS,WINDOW);
    
    word_t scalar2[SCALAR_WORDS];
    convert_to_signed_window_form(
        scalar2, scalar, SCALAR_WORDS,
        SCALARMUL_FIXED_WINDOW_ADJUSTMENT, SCALAR_WORDS
    );


    tw_extensible_a_t tabulator;
    copy_tw_extensible(tabulator, working);
    double_tw_extensible(tabulator);

    tw_pniels_a_t
	  pn VECTOR_ALIGNED,
	  multiples[NTABLE] VECTOR_ALIGNED;
    convert_tw_extensible_to_tw_pniels(pn, tabulator);
    convert_tw_extensible_to_tw_pniels(multiples[0], working);

    int i,j;
    for (i=1; i<NTABLE; i++) {
        add_tw_pniels_to_tw_extensible(working, pn);
        convert_tw_extensible_to_tw_pniels(multiples[i], working);
    }

    i = nbits - WINDOW;
    int bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS) & WINDOW_MASK,
        inv = (bits>>(WINDOW-1))-1;
    bits ^= inv;

    copy_tw_pniels(pn, multiples[bits & WINDOW_T_MASK]);
    cond_negate_tw_pniels(pn, inv);
    convert_tw_pniels_to_tw_extensible(working, pn);
		

    for (i-=WINDOW; i>=0; i-=WINDOW) {
        for (j=0; j<WINDOW; j++) {
            double_tw_extensible(working);
        }

        bits = scalar2[i/WORD_BITS] >> (i%WORD_BITS);
        
        if (i/WORD_BITS < SCALAR_WORDS-1 && i%WORD_BITS >= WORD_BITS-WINDOW) {
            bits ^= scalar2[i/WORD_BITS+1] << (WORD_BITS - (i%WORD_BITS));
        }
                
        bits &= WINDOW_MASK;
        inv = (bits>>(WINDOW-1))-1;
        bits ^= inv;
    
        copy_tw_pniels(pn, multiples[bits & WINDOW_T_MASK]);
        cond_negate_tw_pniels(pn, inv);
        add_tw_pniels_to_tw_extensible(working, pn);
    }
}

static mask_t
schedule_scalar_for_combs (
    word_t *scalar2,
    const word_t *scalar,
    unsigned int nbits,
    const struct fixed_base_table_t* table
) {
    unsigned int i;
    unsigned int n = table->n, t = table->t, s = table->s;
    
    if (n*t*s < nbits || n < 1 || t < 1 || s < 1) {
        return MASK_FAILURE;
    }
    
    unsigned int scalar_words = (nbits + WORD_BITS - 1)/WORD_BITS,
        scalar2_words = scalar_words;
    if (scalar2_words < SCALAR_WORDS)
        scalar2_words = SCALAR_WORDS;
    word_t scalar3[scalar2_words];
    
    /* Copy scalar to scalar3, but clear its high bits (if there are any) */
    for (i=0; i<scalar_words; i++) {
        scalar3[i] = scalar[i];
    }
    if (likely(i) && (nbits % WORD_BITS)) {
        scalar3[i-1] &= (((word_t)1) << (nbits%WORD_BITS)) - 1;
    }
    for (; i<scalar2_words; i++) {
        scalar3[i] = 0;
    }
    
    convert_to_signed_window_form (
        scalar2,
        scalar3, scalar2_words,
        table->scalar_adjustments , SCALAR_WORDS
    );
    
    return MASK_SUCCESS;
}

mask_t
scalarmul_fixed_base (
    tw_extensible_a_t out,
    const word_t scalar[SCALAR_WORDS],
    unsigned int nbits,
    const struct fixed_base_table_t* table
) {
    unsigned int i,j,k;
    unsigned int n = table->n, t = table->t, s = table->s;
    
    unsigned int scalar2_words = (nbits + WORD_BITS - 1)/WORD_BITS;
    if (scalar2_words < SCALAR_WORDS) scalar2_words = SCALAR_WORDS;
    
    word_t scalar2[scalar2_words];

    mask_t succ = schedule_scalar_for_combs(scalar2, scalar, nbits, table);
    if (!succ) return MASK_FAILURE;
    
#ifdef __clang_analyzer__
    assert(t >= 1);
#endif
    
    tw_niels_a_t ni;
    
    for (i=0; i<s; i++) {
        if (i) double_tw_extensible(out);
        
        for (j=0; j<n; j++) {
            int tab = 0;
			
			/*
             * PERF: This computation takes about 1.5µs on SBR, i.e. 2-3% of the
			 * time of a keygen or sign op.  Surely it is possible to speed it up.
             */
            for (k=0; k<t; k++) {
                unsigned int bit = (s-1-i) + k*s + j*(s*t);
                if (bit < scalar2_words * WORD_BITS) {
                    tab |= (scalar2[bit/WORD_BITS] >> (bit%WORD_BITS) & 1) << k;
                }
            }
            
            mask_t invert = (tab>>(t-1))-1;
            tab ^= invert;
            tab &= (1<<(t-1)) - 1;
            
            constant_time_lookup_tw_niels(ni, (const tw_niels_a_t*)table->table + (j<<(t-1)), 1<<(t-1), tab);
            cond_negate_tw_niels(ni, invert);
            if (i||j) {
                add_tw_niels_to_tw_extensible(out, ni);
            } else {
                convert_tw_niels_to_tw_extensible(out, ni);
            }
        }
    }
    
    return MASK_SUCCESS;
}

mask_t
linear_combo_combs_vt (
    tw_extensible_a_t out,
    const word_t scalar1[SCALAR_WORDS],
    unsigned int nbits1,
    const struct fixed_base_table_t* table1,
    const word_t scalar2[SCALAR_WORDS],
    unsigned int nbits2,
    const struct fixed_base_table_t* table2
) { 
    unsigned int i,j,k,sc;
    unsigned int s1 = table1->s, s2 = table2->s, smax = (s1 > s2) ? s1 : s2;
    
    unsigned int scalar1b_words = (nbits1 + WORD_BITS - 1)/WORD_BITS;
    if (scalar1b_words < SCALAR_WORDS) scalar1b_words = SCALAR_WORDS;
    
    unsigned int scalar2b_words = (nbits2 + WORD_BITS - 1)/WORD_BITS;
    if (scalar2b_words < SCALAR_WORDS) scalar2b_words = SCALAR_WORDS;
    
    word_t scalar1b[scalar1b_words], scalar2b[scalar2b_words];

    /* Schedule the scalars */
    mask_t succ;
    succ = schedule_scalar_for_combs(scalar1b, scalar1, nbits1, table1);
    if (!succ) return MASK_FAILURE;
  
    succ = schedule_scalar_for_combs(scalar2b, scalar2, nbits2, table2);
    if (!succ) return MASK_FAILURE;

#ifdef __clang_analyzer__
    assert(table1->t >= 1);
    assert(table2->t >= 1);
#endif
  
    const struct tw_niels_t *ni;
    
    unsigned int swords[2] = {scalar1b_words, scalar2b_words};
    word_t *scalars[2] = {scalar1b,scalar2b};
    
    set_identity_tw_extensible(out);
    
    for (i=0; i<smax; i++) {
        if (i) double_tw_extensible(out);
            
        for (sc=0; sc<2; sc++) {
            const struct fixed_base_table_t* table = sc ? table2 : table1;
            
            int ii = i-smax+table->s;
            if (ii < 0) continue;
            assert(ii < (int)table->s);
        
            for (j=0; j<table->n; j++) {
            
                int tab = 0;

                for (k=0; k<table->t; k++) {
                    unsigned int bit = (table->s-1-ii) + k*table->s + j*(table->s*table->t);
                    if (bit < swords[sc] * WORD_BITS) {
                        tab |= (scalars[sc][bit/WORD_BITS] >> (bit%WORD_BITS) & 1) << k;
                    }
                }
            
                mask_t invert = (tab>>(table->t-1))-1;
                tab ^= invert;
                tab &= (1<<(table->t-1)) - 1;
            
                ni = table->table[tab + (j<<(table->t-1))];
                
                if (invert) sub_tw_niels_from_tw_extensible(out, ni);
                else add_tw_niels_to_tw_extensible(out, ni);
            }
        }
    }
    
    return MASK_SUCCESS;
}


mask_t
precompute_fixed_base (
  struct fixed_base_table_t* out,
  const tw_extensible_a_t base,
  unsigned int n,
  unsigned int t,
  unsigned int s,
  tw_niels_a_t *prealloc
) {
    if (s < 1 || t < 1 || n < 1 || n*t*s < SCALAR_BITS) {
        really_memset(out, 0, sizeof(*out));
        return 0;
    }
    
    out->n = n;
    out->t = t;
    out->s = s;
  
    tw_extensible_a_t working, start;
    copy_tw_extensible(working, base);
    tw_pniels_a_t pn_tmp;
  
    tw_pniels_a_t *doubles = (tw_pniels_a_t *) malloc_vector(sizeof(*doubles) * (t-1));
    field_a_t *zs  = (field_a_t *) malloc_vector(sizeof(*zs) * (n<<(t-1)));
    field_a_t *zis = (field_a_t *) malloc_vector(sizeof(*zis) * (n<<(t-1)));
    
    tw_niels_a_t *table = prealloc;
    if (prealloc) {
        out->own_table = 0;
    } else {
        table = (tw_niels_a_t *) malloc_vector(sizeof(*table) * (n<<(t-1)));
        out->own_table = 1;
    }
    out->table = table;
  
    if (!doubles || !zs || !zis || !table) {
        free(doubles);
        free(zs);
        free(zis);
        really_memset(out, 0, sizeof(*out));
        really_memset(table, 0, sizeof(*table) * (n<<(t-1)));
        if (!prealloc) free(table);
        return 0;
    }
  
    unsigned int i,j,k;
    
    /* Compute the scalar adjustments, equal to 2^nbits-1 mod q */
    unsigned int adjustment_size = (n*t*s)/WORD_BITS + 1;
    assert(adjustment_size >= SCALAR_WORDS);
    word_t adjustment[adjustment_size];
    for (i=0; i<adjustment_size; i++) {
        adjustment[i] = -1;
    }
    
    adjustment[(n*t*s) / WORD_BITS] += ((word_t)1) << ((n*t*s) % WORD_BITS);
    
    /* The low adjustment is 2^nbits - 1 mod q */
    barrett_reduce(adjustment, adjustment_size, 0, &curve_prime_order);
    word_t *low_adjustment = &out->scalar_adjustments[(SCALAR_WORDS)*(adjustment[0] & 1)],
        *high_adjustment = &out->scalar_adjustments[(SCALAR_WORDS)*((~adjustment[0]) & 1)];
    for (i=0; i<SCALAR_WORDS; i++) {
        low_adjustment[i] = adjustment[i];
    }
    
    /* The high adjustment is low + q = low - q_lo + 2^big */
    (void)
    sub_nr_ext_packed(
        high_adjustment,
        adjustment, SCALAR_WORDS,
        curve_prime_order.p_lo, curve_prime_order.nwords_lo,
        -1
    );
    if (curve_prime_order.p_shift) {
        high_adjustment[curve_prime_order.nwords_p - 1] += ((word_t)1)<<curve_prime_order.p_shift;
    }
    
    /* OK, now compute the tables */
    for (i=0; i<n; i++) {

        /* doubling phase */
        for (j=0; j<t; j++) {
            if (j) {
                convert_tw_extensible_to_tw_pniels(pn_tmp, working);
                add_tw_pniels_to_tw_extensible(start, pn_tmp);
            } else {
                copy_tw_extensible(start, working);
            }

            if (j==t-1 && i==n-1) {
                break;
            }

            double_tw_extensible(working);
            if (j<t-1) {
                convert_tw_extensible_to_tw_pniels(doubles[j], working);
            }

            for (k=0; k<s-1; k++) {
                double_tw_extensible(working);
            }
        }

        /* Gray-code phase */
        for (j=0;; j++) {
            int gray = j ^ (j>>1);
            int idx = (((i+1)<<(t-1))-1) ^ gray;

            convert_tw_extensible_to_tw_pniels(pn_tmp, start);
            copy_tw_niels(table[idx], pn_tmp->n);
            field_copy(zs[idx], pn_tmp->z);
			
            if (j >= (1u<<(t-1)) - 1) break;
            int delta = (j+1) ^ ((j+1)>>1) ^ gray;

            for (k=0; delta>1; k++)
                delta >>=1;
            
            if (gray & (1<<k)) {
                /* start += doubles[k] */
                add_tw_pniels_to_tw_extensible(start, doubles[k]);
            } else {
                /* start -= doubles[k] */
                sub_tw_pniels_from_tw_extensible(start, doubles[k]);
            }
            
            
        }
    }
	
    field_simultaneous_invert(zis, (const field_a_t*)zs, n<<(t-1));

    field_a_t product;
    for (i=0; i<n<<(t-1); i++) {
        field_mul(product, table[i]->a, zis[i]);
        field_strong_reduce(product);
        field_copy(table[i]->a, product);
        
        field_mul(product, table[i]->b, zis[i]);
        field_strong_reduce(product);
        field_copy(table[i]->b, product);
        
        field_mul(product, table[i]->c, zis[i]);
        field_strong_reduce(product);
        field_copy(table[i]->c, product);
    }
	
	mask_t ret = ~field_is_zero(zis[0]);

    free(doubles);
    free(zs);
    free(zis);

    if (unlikely(!ret)) {
        really_memset(table, 0, sizeof(*table) * (n<<(t-1)));
        if (!prealloc) free(table);
        really_memset(out, 0, sizeof(*out));
        return 0;
    }

    return ret;
}

void
destroy_fixed_base (
    struct fixed_base_table_t* table
) {
    if (table->table) {
        really_memset(table->table,0,sizeof(*table->table)*(table->n<<(table->t-1)));
    }
    if (table->own_table) {
        free(table->table);
    }
    really_memset(table,0,sizeof(*table));
}

mask_t
precompute_fixed_base_wnaf (
    tw_niels_a_t *out,
    const tw_extensible_a_t const_base,
    unsigned int tbits
) {
    int i;
    field_a_t *zs  = (field_a_t *) malloc_vector(sizeof(*zs)<<tbits);
    field_a_t *zis = (field_a_t *) malloc_vector(sizeof(*zis)<<tbits);

    if (!zs || !zis) {
        free(zs);
        free(zis);
        return 0;
    }

    tw_extensible_a_t base;
    copy_tw_extensible(base,const_base);
    
    tw_pniels_a_t twop, tmp;
    
    convert_tw_extensible_to_tw_pniels(tmp, base);
    field_copy(zs[0], tmp->z);
    copy_tw_niels(out[0], tmp->n);

    if (tbits > 0) {
        double_tw_extensible(base);
        convert_tw_extensible_to_tw_pniels(twop, base);
        add_tw_pniels_to_tw_extensible(base, tmp);
        
        convert_tw_extensible_to_tw_pniels(tmp, base);
        field_copy(zs[1], tmp->z);
        copy_tw_niels(out[1], tmp->n);

        for (i=2; i < 1<<tbits; i++) {
            add_tw_pniels_to_tw_extensible(base, twop);
            convert_tw_extensible_to_tw_pniels(tmp, base);
            field_copy(zs[i], tmp->z);
            copy_tw_niels(out[i], tmp->n);
        }
    }
    
    field_simultaneous_invert(zis, (const field_a_t *)zs, 1<<tbits);

    field_a_t product;
    for (i=0; i<1<<tbits; i++) {
        field_mul(product, out[i]->a, zis[i]);
        field_strong_reduce(product);
        field_copy(out[i]->a, product);
        
        field_mul(product, out[i]->b, zis[i]);
        field_strong_reduce(product);
        field_copy(out[i]->b, product);
        
        field_mul(product, out[i]->c, zis[i]);
        field_strong_reduce(product);
        field_copy(out[i]->c, product);
    }

    free(zs);
    free(zis);

    return -1;
}

/**
 * @cond internal
 * Control for variable-time scalar multiply algorithms.
 */
struct smvt_control {
  int power, addend;
};

static int
recode_wnaf(
    struct smvt_control *control, /* [nbits/(tableBits+1) + 3] */
    const word_t *scalar,
    unsigned int nbits,
    unsigned int tableBits)
{
    int current = 0, i, j;
    unsigned int position = 0;

    /* PERF: negate scalar if it's large
     * PERF: this is a pretty simplistic algorithm.  I'm sure there's a faster one...
     */
    for (i=nbits-1; i >= 0; i--) {
        int bit = (scalar[i/WORD_BITS] >> (i%WORD_BITS)) & 1;
        current = 2*current + bit;

        /*
         * Sizing: |current| >= 2^(tableBits+1) -> |current| = 2^0
         * So current loses (tableBits+1) bits every time.  It otherwise gains
         * 1 bit per iteration.  The number of iterations is
         * (nbits + 2 + tableBits), and an additional control word is added at
         * the end.  So the total number of control words is at most
         * ceil((nbits+1) / (tableBits+1)) + 2 = floor((nbits)/(tableBits+1)) + 2.
         * There's also the stopper with power -1, for a total of +3.
         */
        if (current >= (2<<tableBits) || current <= -1 - (2<<tableBits)) {
            int delta = (current + 1) >> 1; /* |delta| < 2^tablebits */
            current = -(current & 1);

            for (j=i; (delta & 1) == 0; j++) {
                delta >>= 1;
            }
            control[position].power = j+1;
            control[position].addend = delta;
            position++;
            assert(position <= nbits/(tableBits+1) + 2);
        }
    }
    
    if (current) {
        for (j=0; (current & 1) == 0; j++) {
            current >>= 1;
        }
        control[position].power = j;
        control[position].addend = current;
        position++;
        assert(position <= nbits/(tableBits+1) + 2);
    }
    
  
    control[position].power = -1;
    control[position].addend = 0;
    return position;
}


static void
prepare_wnaf_table(
    tw_pniels_a_t *output,
    tw_extensible_a_t working,
    unsigned int tbits
) {
    int i;
    convert_tw_extensible_to_tw_pniels(output[0], working);

    if (tbits == 0) return;

    double_tw_extensible(working);
    tw_pniels_a_t twop;
    convert_tw_extensible_to_tw_pniels(twop, working);

    add_tw_pniels_to_tw_extensible(working, output[0]);
    convert_tw_extensible_to_tw_pniels(output[1], working);

    for (i=2; i < 1<<tbits; i++) {
        add_tw_pniels_to_tw_extensible(working, twop);
        convert_tw_extensible_to_tw_pniels(output[i], working);
    }
}

void
scalarmul_vt (
    tw_extensible_a_t working,
    const word_t scalar[SCALAR_WORDS],
    unsigned int nbits
) {
    const int table_bits = SCALARMUL_WNAF_TABLE_BITS;
    struct smvt_control control[nbits/(table_bits+1)+3];
    
    int control_bits = recode_wnaf(control, scalar, nbits, table_bits);
  
    tw_pniels_a_t precmp[1<<table_bits];
    prepare_wnaf_table(precmp, working, table_bits);
  
    if (control_bits > 0) {
        assert(control[0].addend > 0);
        assert(control[0].power >= 0);
        convert_tw_pniels_to_tw_extensible(working, precmp[control[0].addend >> 1]);
    } else {
        set_identity_tw_extensible(working);
        return;
    }
  
    int conti = 1, i;
    for (i = control[0].power - 1; i >= 0; i--) {
        double_tw_extensible(working);

        if (i == control[conti].power) {
            assert(control[conti].addend);

            if (control[conti].addend > 0) {
                add_tw_pniels_to_tw_extensible(working, precmp[control[conti].addend >> 1]);
            } else {
                sub_tw_pniels_from_tw_extensible(working, precmp[(-control[conti].addend) >> 1]);
            }
            conti++;
            assert(conti <= control_bits);
        }
    }
}

void
scalarmul_fixed_base_wnaf_vt (
    tw_extensible_a_t working,
    const word_t scalar[SCALAR_WORDS],
    unsigned int nbits,
    const tw_niels_a_t *precmp,
    unsigned int table_bits
) {
    struct smvt_control control[nbits/(table_bits+1)+3];
    
    int control_bits = recode_wnaf(control, scalar, nbits, table_bits);
  
    if (control_bits > 0) {
        assert(control[0].addend > 0);
        assert(control[0].power >= 0);
        convert_tw_niels_to_tw_extensible(working, precmp[control[0].addend >> 1]);
    } else {
        set_identity_tw_extensible(working);
        return;
    }
  
    int conti = 1, i;
    for (; control[conti].power >= 0; conti++) {
        assert(conti <= control_bits);
        for (i = control[conti-1].power - control[conti].power; i; i--) {
            double_tw_extensible(working);
        }
        
        assert(control[conti].addend);
        if (control[conti].addend > 0) {
            add_tw_niels_to_tw_extensible(working, precmp[control[conti].addend >> 1]);
        } else {
            sub_tw_niels_from_tw_extensible(working, precmp[(-control[conti].addend) >> 1]);
        }
    }

    for (i = control[conti-1].power; i; i--) {
        double_tw_extensible(working);
    }
}

void
linear_combo_var_fixed_vt(
    tw_extensible_a_t working,
    const word_t scalar_var[SCALAR_WORDS],
    unsigned int nbits_var,
    const word_t scalar_pre[SCALAR_WORDS],
    unsigned int nbits_pre,
    const tw_niels_a_t *precmp,
    unsigned int table_bits_pre
) {
    const int table_bits_var = SCALARMUL_WNAF_COMBO_TABLE_BITS;
    struct smvt_control control_var[nbits_var/(table_bits_var+1)+3];
    struct smvt_control control_pre[nbits_pre/(table_bits_pre+1)+3];
    
    int ncb_var = recode_wnaf(control_var, scalar_var, nbits_var, table_bits_var);
    int ncb_pre = recode_wnaf(control_pre, scalar_pre, nbits_pre, table_bits_pre);
    (void)ncb_var;
    (void)ncb_pre;
  
    tw_pniels_a_t precmp_var[1<<table_bits_var];
    prepare_wnaf_table(precmp_var, working, table_bits_var);
  
    int contp=0, contv=0, i;
  
    i = control_var[0].power;
    if (i > control_pre[0].power) {
        convert_tw_pniels_to_tw_extensible(working, precmp_var[control_var[0].addend >> 1]);
        contv++;
    } else if (i == control_pre[0].power && i >=0 ) {
        convert_tw_pniels_to_tw_extensible(working, precmp_var[control_var[0].addend >> 1]);
        add_tw_niels_to_tw_extensible(working, precmp[control_pre[0].addend >> 1]);
        contv++; contp++;
    } else {
        i = control_pre[0].power;
        convert_tw_niels_to_tw_extensible(working, precmp[control_pre[0].addend >> 1]);
        contp++;
    }
    
    if (i < 0) {
        set_identity_tw_extensible(working);
        return;
    }
    
    for (i--; i >= 0; i--) {
        double_tw_extensible(working);

        if (i == control_var[contv].power) {
            assert(control_var[contv].addend);

            if (control_var[contv].addend > 0) {
                add_tw_pniels_to_tw_extensible(working, precmp_var[control_var[contv].addend >> 1]);
            } else {
                sub_tw_pniels_from_tw_extensible(working, precmp_var[(-control_var[contv].addend) >> 1]);
            }
            contv++;
        }

        if (i == control_pre[contp].power) {
            assert(control_pre[contp].addend);

            if (control_pre[contp].addend > 0) {
                add_tw_niels_to_tw_extensible(working, precmp[control_pre[contp].addend >> 1]);
            } else {
                sub_tw_niels_from_tw_extensible(working, precmp[(-control_pre[contp].addend) >> 1]);
            }
            contp++;
        }
    }
    
    assert(contv == ncb_var);
    assert(contp == ncb_pre);
}



