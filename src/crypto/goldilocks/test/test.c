#include "test.h"

#include <stdio.h>
#include <string.h>

#ifndef LIMBPERM
#define LIMBPERM(x) (x)
#endif

int failed_tests, n_tests, failed_this_test, running_a_test;

static void end_test(void) {
    if (!failed_this_test) {
        printf("[PASS]\n");
    }
    n_tests ++;
    running_a_test = 0;
}

static void begin_test(const char *name) {
    if (running_a_test) end_test();
    printf("%s...%*s",name,(int)(30-strlen(name)),"");
    fflush(stdout);
    failed_this_test = 0;
    running_a_test = 1;
}

void youfail(void) {
    if (failed_this_test) return;
    failed_this_test = 1;
    failed_tests ++;
    printf("[FAIL]\n");   
}

static int
hexchar (char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return 10 + c - 'a';
    } else if (c >= 'A' && c <= 'F') {
        return 10 + c - 'A';
    } else {
        return -1;
    }
}

int
hexdecode (
    unsigned char *bytes,
    const char *hex,
    unsigned int nbytes
) {
    if (strlen(hex) != nbytes*2) {
        return -1;
    }
    
    unsigned int i;
    for (i=0; i<nbytes; i++) {
        int hi = hexchar(hex[2*i]),
            lo = hexchar(hex[2*i+1]);
        if (hi<0 || lo<0) return -1;
        bytes[i] = hi*16 + lo;
    }
    
    return 0;
}

void
hexprint (
    const char *descr,
    const unsigned char *bytes,
    unsigned int nbytes
) {
    if (descr) printf("%s = ", descr);
    unsigned int i;
    for (i=0; i<nbytes; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void field_print (
    const char *descr,
    const field_a_t a
) {
    int j;
    unsigned char ser[FIELD_BYTES];
    field_serialize(ser,a);
    printf("%s = 0x", descr);
    for (j=FIELD_BYTES - 1; j>=0; j--) {
        printf("%02x", ser[j]);
    }
    printf("\n");
}

void scalar_print (
    const char *descr,
    const word_t *scalar,
    int nwords
) {
    int j;
    printf("%s = 0x", descr);
    for (j=nwords-1; j>=0; j--) {
        printf(PRIxWORDfull, scalar[j]);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    
    n_tests = running_a_test = failed_tests = 0;

    begin_test("Arithmetic");
    test_arithmetic();

    begin_test("EC point operations");
    test_pointops();
    
    begin_test("Scalarmul compatibility");
    test_scalarmul_compatibility();
    
    begin_test("Scalarmul commutativity");
    test_scalarmul_commutativity();
    
    begin_test("Linear combo");
    test_linear_combo();
    
    begin_test("SHA-512 NIST Monte Carlo");
    test_sha512_monte_carlo();
    
    begin_test("Goldilocks complete system");
    test_goldilocks();
    
    if (running_a_test) end_test();
    printf("\n");
    if (failed_tests) {
        printf("Failed %d / %d tests.\n", failed_tests, n_tests);
    } else {
        printf("Passed all %d tests.\n", n_tests);
    }
    
    return failed_tests ? 1 : 0;
}
