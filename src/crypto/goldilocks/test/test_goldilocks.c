#include "test.h"
#include "goldilocks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_goldilocks (void) {
    const char *message1 = "hello world";
    const char *message2 = "Jello world";
    
    unsigned char signature[GOLDI_SIGNATURE_BYTES];
    
    unsigned char
        ss12[GOLDI_SHARED_SECRET_BYTES],
        ss21[GOLDI_SHARED_SECRET_BYTES],
        ss21p[GOLDI_SHARED_SECRET_BYTES],
        proto[GOLDI_SYMKEY_BYTES];
    
    struct goldilocks_public_key_t  pub, pub2;
    struct goldilocks_private_key_t priv, priv2;
    struct goldilocks_precomputed_public_key_t *pre = NULL;
    
    int i, ret, good = 1;
    
    ret = goldilocks_init();
    if (ret) {
        youfail();
        printf("    Failed init.\n");
    }
    
    for (i=0; i<1000 && good; i++) {
        
        ret = goldilocks_keygen(&priv, &pub);
        if (ret) {
            youfail();
            printf("    Failed keygen trial %d.\n", i);
            good = 0;
        }
        
        goldilocks_destroy_precomputed_public_key( pre );
        pre = goldilocks_precompute_public_key ( &pub );
        if (!pre) {
            youfail();
            printf("    Failed precomp-public trial %d.\n", i);
            return -1;
        }
        
        ret = goldilocks_sign(
            signature,
            (const unsigned char *)message1,
            strlen(message1),
            &priv
        );
        if (ret) {
            youfail();
            printf("    Failed sign trial %d.\n", i);
            good = 0;
        }
        
        ret = goldilocks_verify(
            signature,
            (const unsigned char *)message1,
            strlen(message1),
            &pub
        );
        if (ret) {
            youfail();
            printf("    Failed verify trial %d.\n", i);
            good = 0;
        }

        ret = goldilocks_verify_precomputed (
            signature,
            (const unsigned char *)message1,
            strlen(message1),
            pre
        );
        if (ret) {
            youfail();
            printf("    Failed verify-pre trial %d.\n", i);
            good = 0;
        }
        
        /* terrible negative test */
        ret = goldilocks_verify(
            signature,
            (const unsigned char *)message2,
            strlen(message1),
            &pub
        );
        if (ret != GOLDI_EINVAL) {
            youfail();
            printf("    Failed nega-verify trial %d.\n", i);
            good = 0;
        }
        ret = goldilocks_verify_precomputed(
            signature,
            (const unsigned char *)message2,
            strlen(message1),
            pre
        );
        if (ret != GOLDI_EINVAL) {
            youfail();
            printf("    Failed nega-verify-pre trial %d.\n", i);
            good = 0;
        }
        
        /* honestly a slightly better negative test */
        memset(signature,0,sizeof(signature));
        ret = goldilocks_verify(
            signature,
            (const unsigned char *)message1,
            strlen(message1),
            &pub
        );
        if (ret != GOLDI_EINVAL) {
            youfail();
            printf("    Failed nega-verify-0 trial %d.\n", i);
            good = 0;
        }
        ret = goldilocks_verify_precomputed(
            signature,
            (const unsigned char *)message1,
            strlen(message1),
            pre
        );
        if (ret != GOLDI_EINVAL) {
            youfail();
            printf("    Failed nega-verify-pre-0 trial %d.\n", i);
            good = 0;
        }
        
        /* ecdh */
        ret = goldilocks_keygen(&priv2, &pub2);
        if (ret) {
            youfail();
            printf("    Failed keygen2 trial %d.\n", i);
            good = 0;
        }
        
        ret = goldilocks_shared_secret ( ss12, &priv, &pub2 );
        if (ret) {
            youfail();
            printf("    Failed ss12 trial %d.\n", i);
            good = 0;
        }
        
        ret = goldilocks_shared_secret ( ss21, &priv2, &pub );
        if (ret) {
            youfail();
            printf("    Failed ss21 trial %d.\n", i);
            good = 0;
        }
        
        ret = goldilocks_shared_secret_precomputed ( ss21p, &priv2, pre );
        if (ret) {
            youfail();
            printf("    Failed ss21p trial %d.\n", i);
            good = 0;
        }
        
        if (memcmp(ss12,ss21,sizeof(ss12))) {
            youfail();
            printf("    Failed shared-secret trial %d.\n", i);
            good = 0;
        }
        
        if (memcmp(ss21,ss21p,sizeof(ss21))) {
            youfail();
            printf("    Failed shared-secret precomp trial %d.\n", i);
            good = 0;
        }
        
        /* test derive / underive / priv to pub */
        goldilocks_underive_private_key ( proto, &priv );
        ret = goldilocks_derive_private_key ( &priv2, proto );
        if (ret || memcmp(&priv,&priv2,sizeof(priv))) {
            youfail();    
            printf("    Failed derive round-trip trial %d.\n", i);
            good = 0;
        }
        
        ret = goldilocks_private_to_public ( &pub2, &priv );
        if (ret || memcmp(&pub,&pub2,sizeof(pub))) {
            youfail();
            printf("    Failed private-to-public trial %d.\n", i);
            good = 0;
        }
        
    }
    
    goldilocks_destroy_precomputed_public_key( pre );
    
    return good ? 0 : -1;
}
