/**
 * @cond internal
 * @file ec_point.c
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @warning This file was automatically generated.
 *     Then it was edited by hand.  Good luck, have fun.
 */

#include "ec_point.h"
#include "magic.h"

void
add_tw_niels_to_tw_extensible (
    tw_extensible_a_t  d,
    const tw_niels_a_t e
) {
    ANALYZE_THIS_ROUTINE_CAREFULLY;
    field_a_t L0, L1;
    field_sub ( L1, d->y, d->x );
    field_mul ( L0, e->a, L1 );
    field_add_nr ( L1, d->x, d->y );
    field_mul ( d->y, e->b, L1 );
    field_mul ( L1, d->u, d->t );
    field_mul ( d->x, e->c, L1 );
    field_add_nr ( d->u, L0, d->y );
    field_subx_nr ( d->t, d->y, L0 );
    field_subx_nr ( d->y, d->z, d->x );
    field_add_nr ( L0, d->x, d->z );
    field_mul ( d->z, L0, d->y );
    field_mul ( d->x, d->y, d->t );
    field_mul ( d->y, L0, d->u );
}

void
sub_tw_niels_from_tw_extensible (
    tw_extensible_a_t  d,
    const tw_niels_a_t e
) {
    ANALYZE_THIS_ROUTINE_CAREFULLY;
    field_a_t L0, L1;
    field_subx_nr ( L1, d->y, d->x );
    field_mul ( L0, e->b, L1 );
    field_add_nr ( L1, d->x, d->y );
    field_mul ( d->y, e->a, L1 );
    field_mul ( L1, d->u, d->t );
    field_mul ( d->x, e->c, L1 );
    field_add_nr ( d->u, L0, d->y );
    field_subx_nr ( d->t, d->y, L0 );
    field_add_nr ( d->y, d->x, d->z );
    field_subx_nr ( L0, d->z, d->x );
    field_mul ( d->z, L0, d->y );
    field_mul ( d->x, d->y, d->t );
    field_mul ( d->y, L0, d->u );
}

void
add_tw_pniels_to_tw_extensible (
    tw_extensible_a_t   e,
    const tw_pniels_a_t a
) {
    field_a_t L0;
    field_mul ( L0, e->z, a->z );
    field_copy ( e->z, L0 );
    add_tw_niels_to_tw_extensible( e, a->n );
}

void
sub_tw_pniels_from_tw_extensible (
    tw_extensible_a_t   e,
    const tw_pniels_a_t a
) {
    field_a_t L0;
    field_mul ( L0, e->z, a->z );
    field_copy ( e->z, L0 );
    sub_tw_niels_from_tw_extensible( e, a->n );
}

void
double_tw_extensible (
    tw_extensible_a_t a
) {
    ANALYZE_THIS_ROUTINE_CAREFULLY;
    field_a_t L0, L1, L2;
    field_sqr ( L2, a->x );
    field_sqr ( L0, a->y );
    field_add_nr ( a->u, L2, L0 );
    field_add_nr ( a->t, a->y, a->x );
    field_sqr ( L1, a->t );
    field_sub_nr ( a->t, L1, a->u );
    field_bias ( a->t, 3 );
    IF32( field_weak_reduce( a->t ) );
    field_subx_nr ( L1, L0, L2 );
    field_sqr ( a->x, a->z );
    field_bias ( a->x, 2-is32 /*is32 ? 1 : 2*/ );
    field_add_nr ( a->z, a->x, a->x );
    field_sub_nr ( L0, a->z, L1 );
    IF32( field_weak_reduce( L0 ) );
    field_mul ( a->z, L1, L0 );
    field_mul ( a->x, L0, a->t );
    field_mul ( a->y, L1, a->u );
}

void
double_extensible (
    extensible_a_t a
) {
    ANALYZE_THIS_ROUTINE_CAREFULLY;
    field_a_t L0, L1, L2;
    field_sqr ( L2, a->x );
    field_sqr ( L0, a->y );
    field_add_nr ( L1, L2, L0 );
    field_add_nr ( a->t, a->y, a->x );
    field_sqr ( a->u, a->t );
    field_sub_nr ( a->t, a->u, L1 );
    field_bias ( a->t, 3 );
    IF32( field_weak_reduce( a->t ) );
    field_subx_nr ( a->u, L0, L2 );
    field_sqr ( a->x, a->z );
    field_bias ( a->x, 2 );
    field_add_nr ( a->z, a->x, a->x );
    field_sub_nr ( L0, a->z, L1 );
    IF32( field_weak_reduce( L0 ) );
    field_mul ( a->z, L1, L0 );
    field_mul ( a->x, L0, a->t );
    field_mul ( a->y, L1, a->u );
}

void
twist_and_double (
    tw_extensible_a_t    b,
    const extensible_a_t a
) {
    field_a_t L0;
    field_sqr ( b->x, a->x );
    field_sqr ( b->z, a->y );
    field_add ( b->u, b->x, b->z );
    field_add ( b->t, a->y, a->x );
    field_sqr ( L0, b->t );
    field_sub ( b->t, L0, b->u );
    field_sub ( L0, b->z, b->x );
    field_sqr ( b->x, a->z );
    field_add ( b->z, b->x, b->x );
    field_sub ( b->y, b->z, b->u );
    field_mul ( b->z, L0, b->y );
    field_mul ( b->x, b->y, b->t );
    field_mul ( b->y, L0, b->u );
}

void
untwist_and_double (
    extensible_a_t          b,
    const tw_extensible_a_t a
) {
    field_a_t L0;
    field_sqr ( b->x, a->x );
    field_sqr ( b->z, a->y );
    field_add ( L0, b->x, b->z );
    field_add ( b->t, a->y, a->x );
    field_sqr ( b->u, b->t );
    field_sub ( b->t, b->u, L0 );
    field_sub ( b->u, b->z, b->x );
    field_sqr ( b->x, a->z );
    field_add ( b->z, b->x, b->x );
    field_sub ( b->y, b->z, b->u );
    field_mul ( b->z, L0, b->y );
    field_mul ( b->x, b->y, b->t );
    field_mul ( b->y, L0, b->u );
}

void
convert_tw_affine_to_tw_pniels (
    tw_pniels_a_t       b,
    const tw_affine_a_t a
) {
    field_sub ( b->n->a, a->y, a->x );
    field_add ( b->n->b, a->x, a->y );
    field_mul ( b->z, a->y, a->x );
    field_mulw_scc_wr ( b->n->c, b->z, 2*EDWARDS_D-2 );
    field_set_ui( b->z, 2 );
}

void
convert_tw_affine_to_tw_extensible (
    tw_extensible_a_t   b,
    const tw_affine_a_t a
) {
    field_copy ( b->x, a->x );
    field_copy ( b->y, a->y );
    field_set_ui( b->z, 1 );
    field_copy ( b->t, a->x );
    field_copy ( b->u, a->y );
}

void
convert_affine_to_extensible (
    extensible_a_t   b,
    const affine_a_t a
) {
    field_copy ( b->x, a->x );
    field_copy ( b->y, a->y );
    field_set_ui( b->z, 1 );
    field_copy ( b->t, a->x );
    field_copy ( b->u, a->y );
}

void
convert_tw_extensible_to_tw_pniels (
    tw_pniels_a_t           b,
    const tw_extensible_a_t a
) {
    field_sub ( b->n->a, a->y, a->x );
    field_add ( b->n->b, a->x, a->y );
    field_mul ( b->z, a->u, a->t );
    field_mulw_scc_wr ( b->n->c, b->z, 2*EDWARDS_D-2 );
    field_add ( b->z, a->z, a->z );
}

void
convert_tw_pniels_to_tw_extensible (
    tw_extensible_a_t   e,
    const tw_pniels_a_t d
) {
    field_add ( e->u, d->n->b, d->n->a );
    field_sub ( e->t, d->n->b, d->n->a );
    field_mul ( e->x, d->z, e->t );
    field_mul ( e->y, d->z, e->u );
    field_sqr ( e->z, d->z );
}

void
convert_tw_niels_to_tw_extensible (
    tw_extensible_a_t  e,
    const tw_niels_a_t d
) {
    field_add ( e->y, d->b, d->a );
    field_sub ( e->x, d->b, d->a );
    field_set_ui( e->z, 1 );
    field_copy ( e->t, e->x );
    field_copy ( e->u, e->y );
}

void
montgomery_step (
    montgomery_a_t a
) {
    ANALYZE_THIS_ROUTINE_CAREFULLY;
    field_a_t L0, L1;
    field_add_nr ( L0, a->zd, a->xd );
    field_subx_nr ( L1, a->xd, a->zd );
    field_subx_nr ( a->zd, a->xa, a->za );
    field_mul ( a->xd, L0, a->zd );
    field_add_nr ( a->zd, a->za, a->xa );
    field_mul ( a->za, L1, a->zd );
    field_add_nr ( a->xa, a->za, a->xd );
    field_sqr ( a->zd, a->xa );
    field_mul ( a->xa, a->z0, a->zd );
    field_subx_nr ( a->zd, a->xd, a->za );
    field_sqr ( a->za, a->zd );
    field_sqr ( a->xd, L0 );
    field_sqr ( L0, L1 );
    field_mulw_scc ( a->zd, a->xd, 1-EDWARDS_D ); /* FIXME PERF MULW */
    field_subx_nr ( L1, a->xd, L0 );
    field_mul ( a->xd, L0, a->zd );
    field_sub_nr ( L0, a->zd, L1 );
    field_bias ( L0, 4 - 2*is32 /*is32 ? 2 : 4*/ );
    IF32( field_weak_reduce( L0 ) );
    field_mul ( a->zd, L0, L1 );
}

void
deserialize_montgomery (
    montgomery_a_t a,
    const field_a_t sbz
) {
    field_sqr ( a->z0, sbz );
    field_set_ui( a->xd, 1 );
    field_set_ui( a->zd, 0 );
    field_set_ui( a->xa, 1 );
    field_copy ( a->za, a->z0 );
}

mask_t
serialize_montgomery (
    field_a_t             b,
    const montgomery_a_t a,
    const field_a_t       sbz
) {
    mask_t L4, L5, L6;
    field_a_t L0, L1, L2, L3;
    field_mul ( L3, a->z0, a->zd );
    field_sub ( L1, L3, a->xd );
    field_mul ( L3, a->za, L1 );
    field_mul ( L2, a->z0, a->xd );
    field_sub ( L1, L2, a->zd );
    field_mul ( L0, a->xa, L1 );
    field_add ( L2, L0, L3 );
    field_sub ( L1, L3, L0 );
    field_mul ( L3, L1, L2 );
    field_copy ( L2, a->z0 );
    field_addw ( L2, 1 );
    field_sqr ( L0, L2 );
    field_mulw_scc_wr ( L1, L0, EDWARDS_D-1 );
    field_add ( L2, a->z0, a->z0 );
    field_add ( L0, L2, L2 );
    field_add ( L2, L0, L1 );
    field_mul ( L0, a->xd, L2 );
    L5 = field_is_zero( a->zd );
    L6 = -   L5;
    constant_time_mask ( L1, L0, sizeof(L1), L5 );
    field_add ( L2, L1, a->zd );
    L4 = ~   L5;
    field_mul ( L1, sbz, L3 );
    field_addw ( L1, L6 );
    field_mul ( L3, L2, L1 );
    field_mul ( L1, L3, L2 );
    field_mul ( L2, L3, a->xd );
    field_mul ( L3, L1, L2 );
    field_isr ( L0, L3 );
    field_mul ( L2, L1, L0 );
    field_sqr ( L1, L0 );
    field_mul ( L0, L3, L1 );
    constant_time_mask ( b, L2, sizeof(L1), L4 );
    field_subw( L0, 1 );
    L5 = field_is_zero( L0 );
    L4 = field_is_zero( sbz );
    return    L5 |    L4;
}

void
serialize_extensible (
    field_a_t             b,
    const extensible_a_t a
) {
    field_a_t L0, L1, L2;
    field_sub ( L0, a->y, a->z );
    field_add ( b, a->z, a->y );
    field_mul ( L1, a->z, a->x );
    field_mul ( L2, L0, L1 );
    field_mul ( L1, L2, L0 );
    field_mul ( L0, L2, b );
    field_mul ( L2, L1, L0 );
    field_isr ( L0, L2 );
    field_mul ( b, L1, L0 );
    field_sqr ( L1, L0 );
    field_mul ( L0, L2, L1 );
}

void
untwist_and_double_and_serialize (
    field_a_t                b,
    const tw_extensible_a_t a
) {
    field_a_t L0, L1, L2, L3;
    field_mul ( L3, a->y, a->x );
    field_add ( b, a->y, a->x );
    field_sqr ( L1, b );
    field_add ( L2, L3, L3 );
    field_sub ( b, L1, L2 );
    field_sqr ( L2, a->z );
    field_sqr ( L1, L2 );
    field_add ( b, b, b );
    field_mulw_scc ( L2, b, EDWARDS_D-1 );
    field_mulw_scc ( b, L2, EDWARDS_D-1 );
    field_mul ( L0, L2, L1 );
    field_mul ( L2, b, L0 );
    field_isr ( L0, L2 );
    field_mul ( L1, b, L0 );
    field_sqr ( b, L0 );
    field_mul ( L0, L2, b );
    field_mul ( b, L1, L3 );
}

void
twist_even (
    tw_extensible_a_t    b,
    const extensible_a_t a
) {
    field_sqr ( b->y, a->z );
    field_sqr ( b->z, a->x );
    field_sub ( b->u, b->y, b->z );
    field_sub ( b->z, a->z, a->x );
    field_mul ( b->y, b->z, a->y );
    field_sub ( b->z, a->z, a->y );
    field_mul ( b->x, b->z, b->y );
    field_mul ( b->t, b->x, b->u );
    field_mul ( b->y, b->x, b->t );
    field_isr ( b->t, b->y );
    field_mul ( b->u, b->x, b->t );
    field_sqr ( b->x, b->t );
    field_mul ( b->t, b->y, b->x );
    field_mul ( b->x, a->x, b->u );
    field_mul ( b->y, a->y, b->u );
    field_addw ( b->y, -field_is_zero( b->z ) );
    field_set_ui( b->z, 1 );
    field_copy ( b->t, b->x );
    field_copy ( b->u, b->y );
}

void
test_only_twist (
    tw_extensible_a_t    b,
    const extensible_a_t a
) {
    field_a_t L0, L1;
    field_sqr ( b->u, a->z );
    field_sqr ( b->y, a->x );
    field_sub ( b->z, b->u, b->y );
    field_add ( b->y, b->z, b->z );
    field_add ( b->u, b->y, b->y );
    field_sub ( b->y, a->z, a->x );
    field_mul ( b->x, b->y, a->y );
    field_sub ( b->z, a->z, a->y );
    field_mul ( b->t, b->z, b->x );
    field_mul ( L1, b->t, b->u );
    field_mul ( b->x, b->t, L1 );
    field_isr ( L0, b->x );
    field_mul ( b->u, b->t, L0 );
    field_sqr ( L1, L0 );
    field_mul ( b->t, b->x, L1 );
    field_add ( L1, a->y, a->x );
    field_sub ( L0, a->x, a->y );
    field_mul ( b->x, b->t, L0 );
    field_add ( L0, b->x, L1 );
    field_sub ( b->t, L1, b->x );
    field_mul ( b->x, L0, b->u );
    field_addw ( b->x, -field_is_zero( b->y ) );
    field_mul ( b->y, b->t, b->u );
    field_addw ( b->y, -field_is_zero( b->z ) );
    field_set_ui( b->z, 1+field_is_zero( a->y ) );
    field_copy ( b->t, b->x );
    field_copy ( b->u, b->y );
}

mask_t
is_even_pt (
    const extensible_a_t a
) {
    field_a_t L0, L1, L2;
    field_sqr ( L2, a->z );
    field_sqr ( L1, a->x );
    field_sub ( L0, L2, L1 );
    return field_is_square ( L0 );
}

mask_t
is_even_tw (
    const tw_extensible_a_t a
) {
    field_a_t L0, L1, L2;
    field_sqr ( L2, a->z );
    field_sqr ( L1, a->x );
    field_add ( L0, L1, L2 );
    return field_is_square ( L0 );
}

mask_t
deserialize_affine (
    affine_a_t     a,
    const field_a_t sz
) {
    field_a_t L0, L1, L2, L3;
    field_sqr ( L1, sz );
    field_copy ( L3, L1 );
    field_addw ( L3, 1 );
    field_sqr ( L2, L3 );
    field_mulw_scc ( a->x, L2, EDWARDS_D-1 ); /* PERF MULW */
    field_add ( L3, L1, L1 ); /* FIXME: i adjusted the bias here, was it right? */
    field_add ( a->y, L3, L3 );
    field_add ( L3, a->y, a->x );
    field_copy ( a->y, L1 );
    field_neg ( a->x, a->y );
    field_addw ( a->x, 1 );
    field_mul ( a->y, a->x, L3 );
    field_sqr ( L2, a->x );
    field_mul ( L0, L2, a->y );
    field_mul ( a->y, a->x, L0 );
    field_isr ( L3, a->y );
    field_mul ( a->y, L2, L3 );
    field_sqr ( L2, L3 );
    field_mul ( L3, L0, L2 );
    field_mul ( L0, a->x, L3 );
    field_add ( L2, a->y, a->y );
    field_mul ( a->x, sz, L2 );
    field_addw ( L1, 1 );
    field_mul ( a->y, L1, L3 );
    field_subw( L0, 1 );
    return field_is_zero( L0 );
}

mask_t
deserialize_and_twist_approx (
    tw_extensible_a_t a,
    const field_a_t    sz
) {
    field_a_t L0, L1;
    field_sqr ( a->z, sz );
    field_copy ( a->y, a->z );
    field_addw ( a->y, 1 );
    field_sqr ( L0, a->y );
    field_mulw_scc ( a->x, L0, EDWARDS_D-1 );
    field_add ( a->y, a->z, a->z );
    field_add ( a->u, a->y, a->y );
    field_add ( a->y, a->u, a->x );
    field_sqr ( a->x, a->z );
    field_neg ( a->u, a->x );
    field_addw ( a->u, 1 );
    field_mul ( a->x, sqrt_d_minus_1, a->u );
    field_mul ( L0, a->x, a->y );
    field_mul ( a->t, L0, a->y );
    field_mul ( a->u, a->x, a->t );
    field_mul ( a->t, a->u, L0 );
    field_mul ( a->y, a->x, a->t );
    field_isr ( L0, a->y );
    field_mul ( a->y, a->u, L0 );
    field_sqr ( L1, L0 );
    field_mul ( a->u, a->t, L1 );
    field_mul ( a->t, a->x, a->u );
    field_add ( a->x, sz, sz );
    field_mul ( L0, a->u, a->x );
    field_copy ( a->x, a->z );
    field_neg ( L1, a->x );
    field_addw ( L1, 1 );
    field_mul ( a->x, L1, L0 );
    field_mul ( L0, a->u, a->y );
    field_addw ( a->z, 1 );
    field_mul ( a->y, a->z, L0 );
    field_subw( a->t, 1 );
    mask_t ret = field_is_zero( a->t );
    field_set_ui( a->z, 1 );
    field_copy ( a->t, a->x );
    field_copy ( a->u, a->y );
    return ret;
}

void
set_identity_extensible (
    extensible_a_t a
) {
    field_set_ui( a->x, 0 );
    field_set_ui( a->y, 1 );
    field_set_ui( a->z, 1 );
    field_set_ui( a->t, 0 );
    field_set_ui( a->u, 0 );
}

void
set_identity_tw_extensible (
    tw_extensible_a_t a
) {
    field_set_ui( a->x, 0 );
    field_set_ui( a->y, 1 );
    field_set_ui( a->z, 1 );
    field_set_ui( a->t, 0 );
    field_set_ui( a->u, 0 );
}

void
set_identity_affine (
    affine_a_t a
) {
    field_set_ui( a->x, 0 );
    field_set_ui( a->y, 1 );
}

mask_t
eq_affine (
    const affine_a_t a,
    const affine_a_t b
) {
    mask_t L1, L2;
    field_a_t L0;
    field_sub ( L0, a->x, b->x );
    L2 = field_is_zero( L0 );
    field_sub ( L0, a->y, b->y );
    L1 = field_is_zero( L0 );
    return    L2 &    L1;
}

mask_t
eq_extensible (
    const extensible_a_t a,
    const extensible_a_t b
) {
    mask_t L3, L4;
    field_a_t L0, L1, L2;
    field_mul ( L2, b->z, a->x );
    field_mul ( L1, a->z, b->x );
    field_sub ( L0, L2, L1 );
    L4 = field_is_zero( L0 );
    field_mul ( L2, b->z, a->y );
    field_mul ( L1, a->z, b->y );
    field_sub ( L0, L2, L1 );
    L3 = field_is_zero( L0 );
    return    L4 &    L3;
}

mask_t
eq_tw_extensible (
    const tw_extensible_a_t a,
    const tw_extensible_a_t b
) {
    mask_t L3, L4;
    field_a_t L0, L1, L2;
    field_mul ( L2, b->z, a->x );
    field_mul ( L1, a->z, b->x );
    field_sub ( L0, L2, L1 );
    L4 = field_is_zero( L0 );
    field_mul ( L2, b->z, a->y );
    field_mul ( L1, a->z, b->y );
    field_sub ( L0, L2, L1 );
    L3 = field_is_zero( L0 );
    return    L4 &    L3;
}

void
elligator_2s_inject (
    affine_a_t     a,
    const field_a_t r
) {
    field_a_t L2, L3, L4, L5, L6, L7, L8;
    field_sqr ( a->x, r );
    field_sqr ( L3, a->x );
    field_copy ( a->y, L3 );
    field_neg ( L4, a->y );
    field_addw ( L4, 1 );
    field_sqr ( L2, L4 );
    field_mulw ( L7, L2, (EDWARDS_D-1)*(EDWARDS_D-1) );
    field_mulw ( L8, L3, 4*(EDWARDS_D+1)*(EDWARDS_D+1) );
    field_add ( a->y, L8, L7 );
    field_mulw ( L8, L2, 4*(EDWARDS_D)*(EDWARDS_D-1) );
    field_sub ( L7, a->y, L8 );
    field_mulw_scc ( L6, a->y, -2-2*EDWARDS_D );
    field_mul ( L5, L7, L6 );
        /* FIXME Stability problem (API stability, not crash) / possible bug.
         * change to: p448_mul ( L5, L7, L4 ); ?
         * This isn't a deep change: it's for sign adjustment.
         * Need to check which one leads to the correct sign, probably by writig
         * the invert routine.
         *
         * Also, the tool doesn't produce the optimal route to this.
         * Let incoming L6 = a, L7 = e, L4 = b.
         *
         * Could compute be, (be)^2, (be)^3, a b^3 e^3, a b^3 e^4. = 4M+S
         * instead of 6M.
         */
    field_mul ( L8, L5, L4 );
    field_mul ( L4, L5, L6 );
    field_mul ( L5, L7, L8 );
    field_mul ( L8, L5, L4 );
    field_mul ( L4, L7, L8 );
    field_isr ( L6, L4 );
    field_mul ( L4, L5, L6 );
    field_sqr ( L5, L6 );
    field_mul ( L6, L8, L5 );
    field_mul ( L8, L7, L6 );
    field_mul ( L7, L8, L6 );
    field_copy ( L6, a->x );
    field_addw ( a->x, 1 );
    field_mul ( L5, a->x, L8 );
    field_addw ( L5, 1 );
    field_sub ( a->x, L6, L5 );
    field_mul ( L5, L4, a->x );
    field_mulw_scc_wr ( a->x, L5, -2-2*EDWARDS_D );
    field_add ( L4, L3, L3 );
    field_add ( L3, L4, L2 );
    field_subw( L3, 2 );
    field_mul ( L2, L3, L8 );
    field_mulw ( L3, L2, 2*(EDWARDS_D+1)*(EDWARDS_D-1) );
    field_add ( L2, L3, a->y );
    field_mul ( a->y, L7, L2 );
    field_addw ( a->y, -field_is_zero( L8 ) );
}

mask_t
validate_affine (
    const affine_a_t a
) {
    field_a_t L0, L1, L2, L3;
    field_sqr ( L0, a->y );
    field_sqr ( L1, a->x );
    field_add ( L3, L1, L0 );
    field_mulw_scc ( L2, L1, EDWARDS_D );
    field_mul ( L1, L0, L2 );
    field_addw ( L1, 1 );
    field_sub ( L0, L3, L1 );
    return field_is_zero( L0 );
}

mask_t
validate_tw_extensible (
    const tw_extensible_a_t ext
) {
    mask_t L4, L5;
    field_a_t L0, L1, L2, L3;
    /*
     * Check invariant:
     * 0 = -x*y + z*t*u
     */
    field_mul ( L1, ext->t, ext->u );
    field_mul ( L2, ext->z, L1 );
    field_mul ( L0, ext->x, ext->y );
    field_neg ( L1, L0 );
    field_add ( L0, L1, L2 );
    L5 = field_is_zero( L0 );
    /*
     * Check invariant:
     * 0 = d*t^2*u^2 + x^2 - y^2 + z^2 - t^2*u^2
     */
    field_sqr ( L2, ext->y );
    field_neg ( L1, L2 );
    field_sqr ( L0, ext->x );
    field_add ( L2, L0, L1 );
    field_sqr ( L3, ext->u );
    field_sqr ( L0, ext->t );
    field_mul ( L1, L0, L3 );
    field_mulw_scc ( L3, L1, EDWARDS_D );
    field_add ( L0, L3, L2 );
    field_neg ( L3, L1 );
    field_add ( L2, L3, L0 );
    field_sqr ( L1, ext->z );
    field_add ( L0, L1, L2 );
    L4 = field_is_zero( L0 );
    return    L5 & L4 &~ field_is_zero(ext->z);
}

mask_t
validate_extensible (
    const extensible_a_t ext
) {
    mask_t L4, L5;
    field_a_t L0, L1, L2, L3;
    /*
     * Check invariant:
     * 0 = d*t^2*u^2 - x^2 - y^2 + z^2
     */
    field_sqr ( L2, ext->y );
    field_neg ( L1, L2 );
    field_sqr ( L0, ext->z );
    field_add ( L2, L0, L1 );
    field_sqr ( L3, ext->u );
    field_sqr ( L0, ext->t );
    field_mul ( L1, L0, L3 );
    field_mulw_scc ( L0, L1, EDWARDS_D );
    field_add ( L1, L0, L2 );
    field_sqr ( L0, ext->x );
    field_neg ( L2, L0 );
    field_add ( L0, L2, L1 );
    L5 = field_is_zero( L0 );
    /*
     * Check invariant:
     * 0 = -x*y + z*t*u
     */
    field_mul ( L1, ext->t, ext->u );
    field_mul ( L2, ext->z, L1 );
    field_mul ( L0, ext->x, ext->y );
    field_neg ( L1, L0 );
    field_add ( L0, L1, L2 );
    L4 = field_is_zero( L0 );
    return L5 & L4 &~ field_is_zero(ext->z);
}
