/**
 * @file ec_point.h
 * @copyright
 *   Copyright (c) 2014 Cryptography Research, Inc.  \n
 *   Released under the MIT License.  See LICENSE.txt for license information.
 * @author Mike Hamburg
 * @warning This file was automatically generated.
 */

#ifndef __CC_INCLUDED_EC_POINT_H__
#define __CC_INCLUDED_EC_POINT_H__

#include "field.h"
#include "constant_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Affine point on an Edwards curve.
 */
typedef struct affine_t {
    field_a_t x, y;
} affine_a_t[1];

/**
 * Affine point on a twisted Edwards curve.
 */
typedef struct tw_affine_t {
    field_a_t x, y;
} tw_affine_a_t[1];

/**
 * Montgomery buffer.
 */
typedef struct montgomery_t {
    field_a_t z0, xd, zd, xa, za;
} montgomery_a_t[1];

/**
 * Extensible coordinates for Edwards curves, suitable for
 * accumulators.
 * 
 * Represents the point (x/z, y/z).  The extra coordinates
 * t,u satisfy xy = tuz, allowing for conversion to Extended
 * form by multiplying t and u.
 * 
 * The idea is that you don't have to do this multiplication
 * when doubling the accumulator, because the t-coordinate
 * isn't used there.  At the same time, as long as you only
 * have one point in extensible form, additions don't cost
 * extra.
 * 
 * This is essentially a lazier version of Hisil et al's
 * lookahead trick.  It might be worth considering that trick
 * instead.
 */
typedef struct extensible_t {
    field_a_t x, y, z, t, u;
} extensible_a_t[1];

/**
 * Extensible coordinates for twisted Edwards curves,
 * suitable for accumulators.
 */
typedef struct tw_extensible_t {
    field_a_t x, y, z, t, u;
} tw_extensible_a_t[1];

/**
 * Niels coordinates for twisted Edwards curves.
 * 
 * Good for mixed readdition; suitable for fixed tables.
 */
typedef struct tw_niels_t {
    field_a_t a, b, c;
} tw_niels_a_t[1];

/**
 * Projective niels coordinates for twisted Edwards curves.
 * 
 * Good for readdition; suitable for temporary tables.
 */
typedef struct tw_pniels_t {
    tw_niels_a_t n;
    field_a_t z;
} tw_pniels_a_t[1];


/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_affine (
    affine_a_t       a,
    const affine_a_t ds
) __attribute__((unused,always_inline));

/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_affine (
    tw_affine_a_t       a,
    const tw_affine_a_t ds
) __attribute__((unused,always_inline));

/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_montgomery (
    montgomery_a_t       a,
    const montgomery_a_t ds
) __attribute__((unused,always_inline));

/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_extensible (
    extensible_a_t       a,
    const extensible_a_t ds
) __attribute__((unused,always_inline));

/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_extensible (
    tw_extensible_a_t       a,
    const tw_extensible_a_t ds
) __attribute__((unused,always_inline));

/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_niels (
    tw_niels_a_t       a,
    const tw_niels_a_t ds
) __attribute__((unused,always_inline));

/**
 * Auto-generated copy method.
 */
static __inline__ void
copy_tw_pniels (
    tw_pniels_a_t       a,
    const tw_pniels_a_t ds
) __attribute__((unused,always_inline));

/**
 * Add two points on a twisted Edwards curve, one in Extensible form
 * and the other in half-Niels form.
 */
void
add_tw_niels_to_tw_extensible (
    tw_extensible_a_t  d,
    const tw_niels_a_t e
);

/**
 * Add two points on a twisted Edwards curve, one in Extensible form
 * and the other in half-Niels form.
 */
void
sub_tw_niels_from_tw_extensible (
    tw_extensible_a_t  d,
    const tw_niels_a_t e
);

/**
 * Add two points on a twisted Edwards curve, one in Extensible form
 * and the other in projective Niels form.
 */
void
add_tw_pniels_to_tw_extensible (
    tw_extensible_a_t   e,
    const tw_pniels_a_t a
);

/**
 * Add two points on a twisted Edwards curve, one in Extensible form
 * and the other in projective Niels form.
 */
void
sub_tw_pniels_from_tw_extensible (
    tw_extensible_a_t   e,
    const tw_pniels_a_t a
);

/**
 * Double a point on a twisted Edwards curve, in "extensible" coordinates.
 */
void
double_tw_extensible (
    tw_extensible_a_t a
);

/**
 * Double a point on an Edwards curve, in "extensible" coordinates.
 */
void
double_extensible (
    extensible_a_t a
);

/**
 * Double a point, and transfer it to the twisted curve.
 * 
 * That is, apply the 4-isogeny.
 */
void
twist_and_double (
    tw_extensible_a_t    b,
    const extensible_a_t a
);

/**
 * Double a point, and transfer it to the untwisted curve.
 * 
 * That is, apply the dual isogeny.
 */
void
untwist_and_double (
    extensible_a_t          b,
    const tw_extensible_a_t a
);

void
convert_tw_affine_to_tw_pniels (
    tw_pniels_a_t       b,
    const tw_affine_a_t a
);

void
convert_tw_affine_to_tw_extensible (
    tw_extensible_a_t   b,
    const tw_affine_a_t a
);

void
convert_affine_to_extensible (
    extensible_a_t   b,
    const affine_a_t a
);

void
convert_tw_extensible_to_tw_pniels (
    tw_pniels_a_t           b,
    const tw_extensible_a_t a
);

void
convert_tw_pniels_to_tw_extensible (
    tw_extensible_a_t   e,
    const tw_pniels_a_t d
);

void
convert_tw_niels_to_tw_extensible (
    tw_extensible_a_t  e,
    const tw_niels_a_t d
);

void
montgomery_step (
    montgomery_a_t a
);

void
deserialize_montgomery (
    montgomery_a_t a,
    const field_a_t sbz
);

mask_t
serialize_montgomery (
    field_a_t             b,
    const montgomery_a_t a,
    const field_a_t       sbz
);

/**
 * Serialize a point on an Edwards curve.
 * 
 * The serialized form would be sqrt((z-y)/(z+y)) with sign of xz.
 * 
 * It would be on 4y^2/(1-d) = x^3 + 2(1+d)/(1-d) * x^2 + x.
 * 
 * But 4/(1-d) isn't square, so we need to twist it:
 * 
 * -x is on 4y^2/(d-1) = x^3 + 2(d+1)/(d-1) * x^2 + x
 */
void
serialize_extensible (
    field_a_t             b,
    const extensible_a_t a
);

/**
 * 
 */
void
untwist_and_double_and_serialize (
    field_a_t                b,
    const tw_extensible_a_t a
);

/**
 * Expensive transfer from untwisted to twisted.  Roughly equivalent to halve and isogeny.
 * Correctly transfers point of order 2.
 * 
 * Can't have x=+1 (it's not even).  There is code to fix the exception that would otherwise
 * occur at (0,1).
 * 
 * Input point must be even.
 */
void
twist_even (
    tw_extensible_a_t    b,
    const extensible_a_t a
);

/**
 * Expensive transfer from untwisted to twisted.  Roughly equivalent to halve and isogeny.
 * 
 * This function is for testing purposes only, because it can return odd points on the
 * twist.  This can cause exceptions in the point addition formula.  What's more, this
 * function should be able to return points of order 4, which are at infinity.
 * 
 * This function probably doesn't properly handle special cases, such as the point at
 * infinity (FUTURE).
 * 
 * This function probably isn't a homomorphism, in that it probably doesn't consistently
 * handle adjustments by the point of order 2 when the input is odd.    (FUTURE)
 */
void
test_only_twist (
    tw_extensible_a_t    b,
    const extensible_a_t a
);

mask_t
field_is_square (
    const field_a_t x
);

mask_t
is_even_pt (
    const extensible_a_t a
);

mask_t
is_even_tw (
    const tw_extensible_a_t a
);

/**
 * Deserialize a point to an untwisted affine curve.
 */
mask_t
deserialize_affine (
    affine_a_t     a,
    const field_a_t sz
);

/**
 * Deserialize a point and transfer it to the twist.
 * 
 * Not guaranteed to preserve the 4-torsion component.
 * 
 * Refuses to deserialize +-1, which are the points of order 2.
 */
mask_t
deserialize_and_twist_approx (
    tw_extensible_a_t a,
    const field_a_t    sz
);

void
set_identity_extensible (
    extensible_a_t a
);

void
set_identity_tw_extensible (
    tw_extensible_a_t a
);

void
set_identity_affine (
    affine_a_t a
);

mask_t
eq_affine (
    const affine_a_t a,
    const affine_a_t b
);

mask_t
eq_extensible (
    const extensible_a_t a,
    const extensible_a_t b
);

mask_t
eq_tw_extensible (
    const tw_extensible_a_t a,
    const tw_extensible_a_t b
);

void
elligator_2s_inject (
    affine_a_t     a,
    const field_a_t r
);

mask_t
validate_affine (
    const affine_a_t a
);

/**
 * Check the invariants for struct tw_extensible_t.
 * NOTE: This function was automatically generated
 * with no regard for speed.
 */
mask_t
validate_tw_extensible (
    const tw_extensible_a_t ext
);

/**
 * Check the invariants for struct extensible_t.
 * NOTE: This function was automatically generated
 * with no regard for speed.
 */
mask_t
validate_extensible (
    const extensible_a_t ext
);

/**
 * If doNegate, then negate a twisted niels point.
 */
static __inline__ void
__attribute__((unused))
cond_negate_tw_niels (
    tw_niels_a_t n,
    mask_t doNegate
) {
    constant_time_cond_swap(n->a, n->b, sizeof(n->a), doNegate);
    field_cond_neg(n->c, doNegate);
}

/**
 * If doNegate, then negate a twisted projective niels point.
 */
static __inline__ void
__attribute__((unused))
cond_negate_tw_pniels (
    tw_pniels_a_t n,
    mask_t doNegate
) {
    cond_negate_tw_niels(n->n, doNegate);
}

void
copy_affine (
    affine_a_t       a,
    const affine_a_t ds
) {
    field_copy ( a->x, ds->x );
    field_copy ( a->y, ds->y );
}

void
copy_tw_affine (
    tw_affine_a_t       a,
    const tw_affine_a_t ds
) {
    field_copy ( a->x, ds->x );
    field_copy ( a->y, ds->y );
}

void
copy_montgomery (
    montgomery_a_t       a,
    const montgomery_a_t ds
) {
    field_copy ( a->z0, ds->z0 );
    field_copy ( a->xd, ds->xd );
    field_copy ( a->zd, ds->zd );
    field_copy ( a->xa, ds->xa );
    field_copy ( a->za, ds->za );
}

void
copy_extensible (
    extensible_a_t       a,
    const extensible_a_t ds
) {
    field_copy ( a->x, ds->x );
    field_copy ( a->y, ds->y );
    field_copy ( a->z, ds->z );
    field_copy ( a->t, ds->t );
    field_copy ( a->u, ds->u );
}

void
copy_tw_extensible (
    tw_extensible_a_t       a,
    const tw_extensible_a_t ds
) {
    field_copy ( a->x, ds->x );
    field_copy ( a->y, ds->y );
    field_copy ( a->z, ds->z );
    field_copy ( a->t, ds->t );
    field_copy ( a->u, ds->u );
}

void
copy_tw_niels (
    tw_niels_a_t       a,
    const tw_niels_a_t ds
) {
    field_copy ( a->a, ds->a );
    field_copy ( a->b, ds->b );
    field_copy ( a->c, ds->c );
}

void
copy_tw_pniels (
    tw_pniels_a_t       a,
    const tw_pniels_a_t ds
) {
    copy_tw_niels( a->n, ds->n );
    field_copy ( a->z, ds->z );
}

#ifdef __cplusplus
}; /* extern "C" */
#endif

#endif /* __CC_INCLUDED_EC_POINT_H__ */
