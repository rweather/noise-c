#ifndef __GOLDILOCKS_TEST_H__
#define __GOLDILOCKS_TEST_H__ 1

#include "word.h"
#include "field.h"

int
hexdecode (
    unsigned char *bytes,
    const char *hex,
    unsigned int nbytes
);

void
hexprint (
    const char *descr,
    const unsigned char *bytes,
    unsigned int nbytes
);
    
void field_print (
    const char *descr,
    const field_a_t a
);
    
void scalar_print (
    const char *descr,
    const word_t *scalar,
    int nwords
);

void youfail(void);

int test_sha512_monte_carlo(void);

int test_linear_combo (void);

int test_scalarmul_compatibility (void);

int test_scalarmul_commutativity (void);

int test_arithmetic (void);

int test_goldilocks (void);

int test_pointops (void);

#endif // __GOLDILOCKS_TEST_H__
