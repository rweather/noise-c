/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key 
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: functions for validation of public keys
*           
* SECURITY NOTE: these functions run in variable time because it is assumed that they are
*                used over public data.
*
*********************************************************************************************/ 

#include "SIDH_internal.h"


static bool is_equal_fp(felm_t a, felm_t b)
{ // Return true if a = b in GF(p751). Otherwise, return false
    unsigned int i;

    for (i = 0; i < NWORDS_FIELD; i++) {
        if (a[i] != b[i]) {
            return false; 
        }
    }

    return true;
}


static bool is_equal_fp2(f2elm_t a, f2elm_t b)
{ // Return true if a = b in GF(p751^2). Otherwise, return false

    return (is_equal_fp(a[0], b[0]) && is_equal_fp(a[1], b[1]));
}


CRYPTO_STATUS random_fp2(f2elm_t f2value, PCurveIsogenyStruct pCurveIsogeny)
{ // Output random value in GF(p751). It makes requests of random values to the "random_bytes" function. 
  // If successful, the output is given in "f2value".
  // The "random_bytes" function, which is passed through the curve isogeny structure PCurveIsogeny, should be set up in advance using SIDH_curve_initialize().
  // The caller is responsible of providing the "random_bytes" function passing random values as octets.
    unsigned int ntry = 0, nbytes;    
    felm_t t1, p751;
    unsigned char mask;
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;
    
    clear_words((void*)f2value, 2*NWORDS_FIELD);    
    fpcopy751(pCurveIsogeny->prime, p751);
    nbytes = (pCurveIsogeny->pbits+7)/8;                       // Number of random bytes to be requested 
    mask = (unsigned char)(8*nbytes - pCurveIsogeny->pbits);
    mask = ((unsigned char)-1 >> mask);                        // Value for masking last random byte

    do {
        ntry++;
        if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, p751-1] 
            return CRYPTO_ERROR_TOO_MANY_ITERATIONS;
        }
        Status = (pCurveIsogeny->RandomBytesFunction)(nbytes, (unsigned char*)&f2value[0]);
        if (Status != CRYPTO_SUCCESS) {
            return Status;
        }
        ((unsigned char*)&f2value[0])[nbytes-1] &= mask;       // Masking last byte 
    } while (mp_sub(p751, f2value[0], t1, NWORDS_FIELD) == 1);

    ntry = 0;
    do {
        ntry++;
        if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, p751-1] 
            return CRYPTO_ERROR_TOO_MANY_ITERATIONS;
        }
        Status = (pCurveIsogeny->RandomBytesFunction)(nbytes, (unsigned char*)&f2value[1]);
        if (Status != CRYPTO_SUCCESS) {
            return Status;
        }
        ((unsigned char*)&f2value[1])[nbytes-1] &= mask;       // Masking last byte 
    } while (mp_sub(p751, f2value[1], t1, NWORDS_FIELD) == 1);

// Cleanup
    clear_words((void*)t1, NWORDS_FIELD);

    return CRYPTO_SUCCESS;
}


static bool test_curve(f2elm_t A, f2elm_t rvalue, PCurveIsogenyStruct CurveIsogeny) 
{
    f2elm_t t0, t1, C, one = {0}, zero = {0};
    point_proj_t rP, P1;
    bool valid_curve;
    
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, one[0]);

    // Test j invariant in Fp2\Fp
    fp2sqr751_mont(A, t0);                             // t0 = a^2
    fp2sub751(t0, one, t0);             
    fp2sub751(t0, one, t0);             
    fp2sub751(t0, one, t0);                            // t0 = t0-3
    fp2sqr751_mont(t0, t1);                            // t1 = t0^2
    fp2mul751_mont(t0, t1, t1);                        // t1 = t1*t0
    fp2sub751(t0, one, t0);                            // t0 = t0-1
    fpmul751_mont(t1[0], t0[1], t1[0]);
    fpmul751_mont(t1[1], t0[0], t1[1]);

    valid_curve = !is_equal_fp(t1[0], t1[1]);
        
    // Test supersingular
    fp2copy751(rvalue, rP->X);
    fp2copy751(one, rP->Z);
    fp2copy751(one, C);

    xDBLe(rP, rP, A, C, 1);
    xDBLe(rP, P1, A, C, 371);    
    xTPLe(P1, P1, A, C, 239);    
    fp2mul751_mont(rP->X, P1->Z, rP->X);               // X = X*Z1
    fp2mul751_mont(rP->Z, P1->X, rP->Z);               // Z = Z*X1
    fp2sub751(rP->X, rP->Z, rP->X);                    // X = X-Z
    fp2mul751_mont(rP->X, P1->Z, rP->X);               // X = X*Z1

   return (valid_curve && is_equal_fp2(rP->X, zero));
}


static void cube_indeterminant(f2elm_t a, f2elm_t b, f2elm_t sq)
{ // Computes a*y+b <-- (a*y+b)^3 where y^2=sq
    f2elm_t t0, t1, t2, t3;

    fp2copy751(a, t0); 
    fp2sqr751_mont(b, t1);    
    fp2sqr751_mont(t0, t2);    
    fp2mul751_mont(sq, t2, t2);    
    fp2add751(t1, t2, t3);        
    fp2add751(t1, t3, a);        
    fp2add751(t1, a, a);        
    fp2mul751_mont(t0, a, a);    
    fp2add751(t2, t3, t1);        
    fp2add751(t2, t1, t1);        
    fp2mul751_mont(b, t1, b);    
}


static void line_indeterminant_TPL(f2elm_t a, f2elm_t b, f2elm_t c, f2elm_t d, f2elm_t sq)
{ // Computes a*y+b <-- (a*y+b)*(c*y+d) where y^2=sq
    f2elm_t t0, t1;

    fp2mul751_mont(a, c, t0);   
    fp2mul751_mont(a, d, a);  
    fp2mul751_mont(b, c, t1);  
    fp2add751(a, t1, a); 
    fp2mul751_mont(b, d, t1);  
    fp2mul751_mont(t0, sq, b);  
    fp2add751(b, t1, b);  
}


static void TPLline(point_proj_t P, point_proj_t Q, publickey_t PK, point_proj_t UP, point_proj_t UQ, f2elm_t alpha_numer, f2elm_t beta_numer, f2elm_t alpha_denom, f2elm_t beta_denom)   /// x,z,X,Z,xP,xQ,A 
{
    f2elm_t x, z, X, Z;
    f2elm_t t0, t1, t2, t3, t4, t5, t6, l0P, l1P, l2P, l0Q, l1Q, l2Q;

    fp2copy751(P->X, x);
    fp2copy751(P->Z, z);
    fp2copy751(Q->X, X);
    fp2copy751(Q->Z, Z);
      
    fp2sqr751_mont(x, t0);                             // t0 = x^2
    fp2sqr751_mont(z, t1);                             // t1 = z^2
    fp2mul751_mont(x, z, t2);                          // t2 = x*z
    fp2mul751_mont(PK[0], t2, t3);                     // t3 = A*t2
    fp2add751(t0, t1, t4);                             // t4 = t0+t1
    fp2add751(t3, t4, t5);                             // t5 = t4+t3
    fp2add751(t3, t5, t3);                             // t3 = t3+t5
    fp2add751(t5, t5, t5);                             // t5 = t5+t5
    fp2add751(t1, t1, l2P);                            // l2P = t1+t1
    fp2add751(t1, l2P, l2P);                           // l2P = l2P+t1
    fp2add751(t3, l2P, l2P);                           // l2P = l2P+t3
    fp2add751(t5, l2P, l2P);                           // l2P = l2P+t5
    fp2mul751_mont(t0, l2P, l2P);                      // l2P = l2P*t0
    fp2sqr751_mont(t1, alpha_numer);                   // alpha_numer = t1^2
    fp2sub751(l2P, alpha_numer, l2P);                  // l2P = l2P-alpha_numer
    fp2add751(t0, t3, l1P);                            // l1P = t0+t3
    fp2add751(t0, l1P, l1P);                           // l1P = l1P+t0
    fp2mul751_mont(t5, l1P, l1P);                      // l1P = t5*l1P
    fp2sub751(l1P, l2P, l1P);                          // l1P = l1P-l2P
    fp2add751(l1P, l1P, l1P);                          // l1P = l1P+l1P
    fp2sub751(t0, t1, l0P);                            // l0P = t0-t1
    fp2mul751_mont(t5, l0P, l0P);                      // l0P = l0P*t5
    fp2add751(l0P, l0P, l0P);                          // l0P = l0P+l0P
    fp2sub751(l2P, l0P, l0P);                          // l0P = l2P-l0P
    fp2sqr751_mont(l0P, P->X);                         // X3 = l0P^2
    fp2sqr751_mont(l2P, P->Z);                         // Z3 = l2P^2
    fp2mul751_mont(x, t5, alpha_numer);                // alpha_numer = x*t5
    fp2add751(alpha_numer, alpha_numer, alpha_numer);  // alpha_numer = alpha_numer+alpha_numer
    fp2add751(alpha_numer, alpha_numer, alpha_numer);  // alpha_numer = alpha_numer+alpha_numer
    fp2mul751_mont(t0, l0P, t0);                       // t0 = t0*l0P
    fp2mul751_mont(l2P, PK[2], t5);                    // t5 = l2P*xQ
    fp2mul751_mont(t1, t5, t5);                        // t5 = t5*t1
    fp2mul751_mont(l1P, t2, beta_numer);               // beta_numer = l1P*t2
    fp2add751(t5, beta_numer, beta_numer);             // beta_numer = beta_numer+t5
    fp2mul751_mont(PK[2], beta_numer, beta_numer);     // beta_numer = beta_numer*xQ
    fp2add751(t0, beta_numer, beta_numer);             // beta_numer = beta_numer+t0
    fp2neg751(beta_numer);                             // beta_numer = -beta_numer
    fp2mul751_mont(PK[0], t4, t5);                     // t5 = A*t4
    fp2sqr751_mont(t4, t4);                            // t4 = t4^2
    fp2add751(t2, t2, t2);                             // t2 = t2+t2
    fp2add751(t2, t5, UP->X);                          // UP = t5+t2
    fp2sub751(t5, t2, t5);                             // t5 = t5-t2
    fp2mul751_mont(t2, UP->X, UP->X);                  // UP = t2*UP
    fp2add751(t4, UP->X, UP->X);                       // UP = UP+t4
    fp2mul751_mont(t2, t5, t2);                        // t2 = t2*t5
    fp2add751(t2, t4, t2);                             // t2 = t2+t4
    fp2add751(t4, t4, t4);                             // t4 = t4+t4
    fp2add751(t2, t4, t2);                             // t2 = t2+t4
    fp2mul751_mont(UP->X, t2, UP->X);                  // UP = UP*t2
    fp2add751(UP->X, UP->X, UP->X);                    // UP = UP+UP
    fp2add751(UP->X, UP->X, UP->X);                    // UP = UP+UP
    fp2sub751(UP->X, P->X, UP->X);                     // UP = UP-X3
    fp2mul751_mont(P->X, x, P->X);                     // X3 = x*X3
    fp2sub751(UP->X, P->Z, UP->X);                     // UP = UP-Z3
    fp2neg751(UP->X);                                  // UP = -UP
    fp2mul751_mont(l0P, UP->X, UP->X);                 // UP = UP*l0P
    fp2mul751_mont(P->Z, l2P, UP->Z);                  // UPZ = Z3*l2P
    fp2add751(UP->Z, UP->Z, UP->Z);                    // UPZ = UPZ+UPZ
    fp2mul751_mont(P->Z, z, P->Z);                     // Z3 = z*Z3 
    fp2sqr751_mont(X, t0);                             // t0 = X^2
    fp2sqr751_mont(Z, t6);                             // t6 = Z^2
    fp2mul751_mont(X, Z, t2);                          // t2 = X*Z
    fp2mul751_mont(PK[0], t2, t3);                     // t3 = A*t2
    fp2add751(t0, t6, t4);                             // t4 = t0+t6
    fp2add751(t3, t4, t5);                             // t5 = t4+t3
    fp2add751(t3, t5, t3);                             // t3 = t3+t5
    fp2add751(t5, t5, t5);                             // t5 = t5+t5
    fp2add751(t6, t6, l2Q);                            // l2Q = t6+t6
    fp2add751(t6, l2Q, l2Q);                           // l2Q = l2Q+t6
    fp2add751(t3, l2Q, l2Q);                           // l2Q = l2Q+t3
    fp2add751(t5, l2Q, l2Q);                           // l2Q = l2Q+t5
    fp2mul751_mont(t0, l2Q, l2Q);                      // l2Q = l2Q*t0
    fp2sqr751_mont(t6, alpha_denom);                   // alpha_denom = t6^2
    fp2sub751(l2Q, alpha_denom, l2Q);                  // l2Q = l2Q-alpha_denom
    fp2add751(t0, t3, l1Q);                            // l1Q = t0+t3
    fp2add751(t0, l1Q, l1Q);                           // l1Q = l1Q+t0
    fp2mul751_mont(t5, l1Q, l1Q);                      // l1Q = t5*l1Q
    fp2sub751(l1Q, l2Q, l1Q);                          // l1Q = l1Q-l2Q
    fp2add751(l1Q, l1Q, l1Q);                          // l1Q = l1Q+l1Q
    fp2sub751(t0, t6, l0Q);                            // l0Q = t0-t6
    fp2mul751_mont(t5, l0Q, l0Q);                      // l0Q = l0Q*t5
    fp2add751(l0Q, l0Q, l0Q);                          // l0Q = l0Q+l0Q
    fp2sub751(l2Q, l0Q, l0Q);                          // l0Q = l2Q-l0Q
    fp2sqr751_mont(l0Q, Q->X);                         // X4 = l0Q^2
    fp2sqr751_mont(l2Q, Q->Z);                         // Z4 = l2Q^2
    fp2mul751_mont(X, t5, alpha_denom);                // alpha_denom = X*t5
    fp2add751(alpha_denom, alpha_denom, alpha_denom);  // alpha_denom = alpha_denom+alpha_denom
    fp2add751(alpha_denom, alpha_denom, alpha_denom);  // alpha_denom = alpha_denom+alpha_denom
    fp2mul751_mont(t0, l0Q, t0);                       // t0 = t0*l0Q
    fp2mul751_mont(l2Q, PK[1], t5);                    // t5 = l2Q*xP
    fp2mul751_mont(t6, t5, t5);                        // t5 = t5*t6
    fp2mul751_mont(l1Q, t2, beta_denom);               // beta_denom = l1Q*t2
    fp2add751(t5, beta_denom, beta_denom);             // beta_denom = beta_denom+t5
    fp2mul751_mont(PK[1], beta_denom, beta_denom);     // beta_denom = beta_denom*xP
    fp2add751(t0, beta_denom, beta_denom);             // beta_denom = beta_denom+t0
    fp2neg751(beta_denom);                             // beta_denom = -beta_denom
    fp2mul751_mont(PK[0], t4, t5);                     // t5 = A*t4
    fp2sqr751_mont(t4, t4);                            // t4 = t4^2
    fp2add751(t2, t2, t2);                             // t2 = t2+t2
    fp2add751(t5, t2, UQ->X);                          // UQ = t5+t2
    fp2sub751(t5, t2, t5);                             // t5 = t5-t2
    fp2mul751_mont(UQ->X, t2, UQ->X);                  // UQ = t2*UQ
    fp2add751(UQ->X, t4, UQ->X);                       // UQ = UQ+t4
    fp2mul751_mont(t2, t5, t2);                        // t2 = t2*t5
    fp2add751(t4, t2, t2);                             // t2 = t2+t4
    fp2add751(t4, t4, t4);                             // t4 = t4+t4
    fp2add751(t2, t4, t2);                             // t2 = t2+t4
    fp2mul751_mont(UQ->X, t2, UQ->X);                  // UQ = UQ*t2
    fp2add751(UQ->X, UQ->X, UQ->X);                    // UQ = UQ+UQ
    fp2add751(UQ->X, UQ->X, UQ->X);                    // UQ = UQ+UQ
    fp2sub751(UQ->X, Q->X, UQ->X);                     // UQ = UQ-X4
    fp2mul751_mont(Q->X, X, Q->X);                     // X4 = X*X4
    fp2sub751(UQ->X, Q->Z, UQ->X);                     // UQ = UQ-Z4
    fp2neg751(UQ->X);                                  // UQ = -UQ
    fp2mul751_mont(l0Q, UQ->X, UQ->X);                 // UQ = UQ*l0Q
    fp2mul751_mont(Q->Z, l2Q, UQ->Z);                  // UQZ = Z4*l2Q
    fp2add751(UQ->Z, UQ->Z, UQ->Z);                    // UQZ = UQZ+UQZ
    fp2mul751_mont(Q->Z, Z, Q->Z);                     // Z4 = Z*Z4 
    fp2mul751_mont(t1, t6, t2);                        // t2:=t1*t6;
    fp2mul751_mont(t6, P->Z, t6);                      // t6:=t6*Z3;
    fp2mul751_mont(t1, Q->Z, t1);                      // t1:=t1*Z4;
    fp2mul751_mont(alpha_denom, Z, alpha_denom);       // alpha_denom:=alpha_denom*Z;
    fp2mul751_mont(alpha_denom, Q->Z, alpha_denom);    // alpha_denom:=alpha_denom*Z4;
    fp2mul751_mont(alpha_numer, z, alpha_numer);       // alpha_numer:=alpha_numer*z;
    fp2mul751_mont(alpha_numer, P->Z, alpha_numer);    // alpha_numer:=alpha_numer*Z3;
    fp2mul751_mont(PK[1], Q->Z, t3);                   // t3:=xP*Z4;
    fp2sub751(t3, Q->X, t3);                           // t3:=t3-X4;
    fp2mul751_mont(t3, l2Q, t3);                       // t3:=t3*l2Q;
    fp2mul751_mont(PK[2], P->Z, t5);                   // t5:=xQ*Z3;
    fp2sub751(t5, P->X, t5);                           // t5:=t5-X3;
    fp2mul751_mont(t5, l2P, t5);                       // t5:=t5*l2P;
    fp2mul751_mont(alpha_numer, t3, alpha_numer);      // alpha_numer:=alpha_numer*t3;
    fp2mul751_mont(t2, alpha_numer, alpha_numer);      // alpha_numer:=alpha_numer*t2;
    fp2mul751_mont(beta_numer, t3, beta_numer);        // beta_numer:=beta_numer*t3;
    fp2mul751_mont(t6, beta_numer, beta_numer);        // beta_numer:=beta_numer*t6;
    fp2mul751_mont(alpha_denom, t5, alpha_denom);      // alpha_denom:=alpha_denom*t5;
    fp2mul751_mont(t2, alpha_denom, alpha_denom);      // alpha_denom:=alpha_denom*t2;
    fp2mul751_mont(beta_denom, t5, beta_denom);        // beta_denom:=beta_denom*t5;
    fp2mul751_mont(t1, beta_denom, beta_denom);        // beta_denom:=beta_denom*t1;
}


CRYPTO_STATUS Validate_PKA(unsigned char* pPublicKeyA, bool* valid, PCurveIsogenyStruct CurveIsogeny)
{ // Bob validating Alice's public key
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    f2elm_t PKA[4];
    f2elm_t t0, t1, t2, t3, t4, t5, t6, t7, lambdaP, lambdaQ, lnQ, lnP, ldQ, ldP, uP = {0}, uQ = {0}, uPD = {0}, uQD = {0}, sqP, sqQ, sq;
    f2elm_t rvalue, alphan, betan, alphad, betad, alpha_numer = {0}, alpha_denom = {0}, beta_numer = {0}, beta_denom = {0}, one = {0}, zero = {0};
    point_proj_t P = {0}, Q = {0}, UP, UQ; 
    unsigned int j, e = CurveIsogeny->eB; 
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    // Choose a random element in GF(p751^2), assume that it is in Montgomery representation
    Status = random_fp2(rvalue, CurveIsogeny);    
    if (Status != CRYPTO_SUCCESS) {
        clear_words((void*)rvalue, 2*NWORDS_FIELD);
        return Status;
    }
                      
    to_fp2mont(((f2elm_t*)pPublicKeyA)[0], PKA[0]);    // Conversion of Alice's public key to Montgomery representation
    to_fp2mont(((f2elm_t*)pPublicKeyA)[1], PKA[1]);
    to_fp2mont(((f2elm_t*)pPublicKeyA)[2], PKA[2]);
    to_fp2mont(((f2elm_t*)pPublicKeyA)[3], PKA[3]);

    fp2copy751(PKA[1], P->X);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, P->Z[0]);
    fp2copy751(PKA[2], Q->X);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, Q->Z[0]);
    
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, one[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, uP[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, uQ[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, uPD[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, uQD[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, beta_numer[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, beta_denom[0]);

    fp2add751(PKA[0], PKA[1], sqP);                    // sqP = xP+A
    fp2mul751_mont(PKA[1], sqP, sqP);                  // sqP = xP*sqP
    fp2add751(one, sqP, sqP);                          // sqP = sqP+1
    fp2add751(PKA[0], PKA[2], sqQ);                    // sqQ = xQ+A
    fp2mul751_mont(PKA[2], sqQ, sqQ);                  // sqQ = xQ*sqQ
    fp2add751(one, sqQ, sqQ);                          // sqQ = sqQ+1
    fp2mul751_mont(PKA[2], sqQ, sqQ);                  // sqQ = xQ*sqQ
    fp2mul751_mont(PKA[1], sqP, sqP);                  // sqP = xP*sqP
    fp2mul751_mont(sqQ, sqP, sq);                      // sq = sqP*sqQ

    for (j = 1; j < e; j++) {
        cube_indeterminant(alpha_numer, beta_numer, sq);
        cube_indeterminant(alpha_denom, beta_denom, sq);
        TPLline(P, Q, PKA, UP, UQ, alphan, betan, alphad, betad);

        fp2mul751_mont(uP, alphan, alphan);            // alphan = alphan*uP
        fp2mul751_mont(uQD, alphan, alphan);           // alphan = alphan*uQD 
        fp2mul751_mont(uQ, alphad, alphad);            // alphad = alphad*uQ 
        fp2mul751_mont(uPD, alphad, alphad);           // alphad = alphad*uPD
        fp2mul751_mont(uQD, uPD, t0);                  // t0 = uQD*uPD
        fp2mul751_mont(betan, t0, betan);              // betan = betan*t0
        fp2mul751_mont(betad, t0, betad);              // betad = betad*t0
        fp2mul751_mont(uP, UP->X, uP);                 // uP = uP*UP
        fp2mul751_mont(uPD, UP->Z, uPD);               // uPD = uPD*UPZ
        fp2mul751_mont(uQ, UQ->X, uQ);                 // uQ = uQ*UQ
        fp2mul751_mont(uQD, UQ->Z, uQD);               // uQD = uQD*UQZ

        line_indeterminant_TPL(alpha_numer, beta_numer, alphan, betan, sq);
        line_indeterminant_TPL(alpha_denom, beta_denom, alphad, betad, sq);
    }

    cube_indeterminant(alpha_numer, beta_numer, sq);
    cube_indeterminant(alpha_denom, beta_denom, sq);
    
    fp2mul751_mont(PKA[0], P->Z, t0);                  // t0 = A*ZP
    fp2add751(P->X, P->X, t1);                         // t1 = XP+XP
    fp2add751(P->X, t1, t1);                           // t1 = t1+XP
    fp2add751(t0, t1, t2);                             // t2 = t1+t0
    fp2add751(t0, t2, t1);                             // t1 = t2+t0
    fp2mul751_mont(P->X, t1, lambdaP);                 // lambdaP = t1*XP
    fp2sqr751_mont(P->Z, t1);                          // t1 = ZP^2
    fp2add751(lambdaP, t1, lambdaP);                   // lambdaP = lambdaP+t1
    fp2mul751_mont(t1, P->Z, t1);                      // t1 = t1*ZP
    fp2mul751_mont(sqP, t1, t0);                       // t0 = t1*sqP
    fp2mul751_mont(t1, uPD, t1);                       // t1 = t1*uPD
    fp2sqr751_mont(uP, t3);                            // t3 = uP^2
    fp2mul751_mont(t0, t3, t0);                        // t0 = t0*t3
    fp2add751(t0, t0, t0);                             // t0 = t0+t0
    fp2mul751_mont(t2, t0, t2);                        // t2 = t2*t0
    fp2add751(t2, t2, t2);                             // t2 = t2+t2
    fp2mul751_mont(lambdaP, uPD, t3);                  // t3 = lambdaP*uPD
    fp2sqr751_mont(t3, t4);                            // t4 = t3^2

    *valid = is_equal_fp2(t2, t4);                     // Checks order P by
    *valid = *valid & !is_equal_fp2(t2, zero);         // asserting that 3^238*P has order 3
        
    fp2mul751_mont(PKA[0], Q->Z, t5);                  // t5 = A*ZQ
    fp2add751(Q->X, Q->X, t6);                         // t6 = XQ+XQ
    fp2add751(Q->X, t6, t6);                           // t6 = t6+XQ
    fp2add751(t5, t6, t2);                             // t2 = t6+t5
    fp2add751(t2, t5, t6);                             // t6 = t2+t5
    fp2mul751_mont(Q->X, t6, lambdaQ);                 // lambdaQ = t6*XQ
    fp2sqr751_mont(Q->Z, t6);                          // t6 = ZQ^2
    fp2add751(lambdaQ, t6, lambdaQ);                   // lambdaQ = lambdaQ+t6
    fp2mul751_mont(Q->Z, t6, t6);                      // t6 = t6*ZQ
    fp2mul751_mont(sqQ, t6, t5);                       // t5 = t6*sqQ
    fp2mul751_mont(t6, uQD, t6);                       // t6 = t6*uQD
    fp2sqr751_mont(uQ, t7);                            // t7 = uQ^2
    fp2mul751_mont(t5, t7, t5);                        // t5 = t5*t7
    fp2add751(t5, t5, t5);                             // t5 = t5+t5
    fp2mul751_mont(t2, t5, t2);                        // t2 = t2*t5
    fp2add751(t2, t2, t2);                             // t2 = t2+t2
    fp2mul751_mont(lambdaQ, uQD, t7);                  // t7 = lambdaQ*uQD
    fp2sqr751_mont(t7, t4);                            // t4 = t7^2

    *valid = *valid & is_equal_fp2(t2, t4);            // Checks order Q by
    *valid = *valid & !is_equal_fp2(t2, zero);         // asserting that 3^238*Q has order 3

    fp2mul751_mont(PKA[2], P->Z, lnQ);                 // lnQ = xQ*ZP
    fp2sub751(P->X, lnQ, lnQ);                         // lnQ = XP-lnQ
    fp2mul751_mont(t3, lnQ, lnQ);                      // lnQ = t3*lnQ
    fp2mul751_mont(uPD, lnQ, lnQ);                     // lnQ = lnQ*uPD
    fp2sub751(lnQ, t0, lnQ);                           // lnQ = lnQ-t0
    fp2mul751_mont(PKA[1], Q->Z, ldP);                 // ldP = xP*ZQ
    fp2sub751(Q->X, ldP, ldP);                         // ldP = XQ-ldP
    fp2mul751_mont(t7, ldP, ldP);                      // ldP = t7*ldP
    fp2mul751_mont(uQD, ldP, ldP);                     // ldP = uQD*ldP
    fp2sub751(ldP, t5, ldP);                           // ldP = ldP-t5
    fp2mul751_mont(uP, uQ, lnP);                       // lnP = uP*uQ
    fp2add751(lnP, lnP, lnP);                          // lnP = lnP+lnP
    fp2mul751_mont(sqP, lnP, ldQ);                     // ldQ = lnP*sqP
    fp2mul751_mont(lnP, sqQ, lnP);                     // lnP = lnP*sqQ
    fp2mul751_mont(ldP, uP, ldP);                      // ldP = ldP*uP
    fp2mul751_mont(t1, ldP, ldP);                      // ldP = ldP*t1
    fp2mul751_mont(lnQ, uQ, lnQ);                      // lnQ = lnQ*uQ
    fp2mul751_mont(t6, lnQ, lnQ);                      // lnQ = lnQ*t6
    fp2mul751_mont(t1, t6, t1);                        // t1 = t1*t6
    fp2mul751_mont(lnP, t1, lnP);                      // lnP = lnP*t1    
    fp2mul751_mont(ldQ, t1, ldQ);                      // ldQ = ldQ*t1
    fp2copy751(alpha_numer, t0);                       // t0 = alpha_numer
    fp2mul751_mont(lnP, t0, alpha_numer);              // alpha_numer = lnP*t0
    fp2mul751_mont(sqP, alpha_numer, alpha_numer);     // alpha_numer = alpha_numer*sqP
    fp2mul751_mont(lnQ, beta_numer, t1);               // t1 = lnQ*beta_numer
    fp2add751(alpha_numer, t1, alpha_numer);           // alpha_numer = t1+alpha_numer
    fp2mul751_mont(t0, sqQ, t1);                       // t1 = t0*sqQ
    fp2mul751_mont(t1, lnQ, t1);                       // t1 = t1*lnQ
    fp2mul751_mont(lnP, beta_numer, beta_numer);       // beta_numer = lnP*beta_numer
    fp2add751(t1, beta_numer, beta_numer);             // beta_numer = beta_numer+t1
    fp2copy751(alpha_denom, t0);                       // t0 = alpha_denom
    fp2mul751_mont(ldP, t0, t1);                       // t1 = ldP*t0
    fp2mul751_mont(sqP, t1, t1);                       // t1 = t1*sqP
    fp2mul751_mont(beta_denom, ldQ, alpha_denom);      // alpha_denom = ldQ*beta_denom
    fp2add751(t1, alpha_denom, alpha_denom);           // alpha_denom = alpha_denom+t1
    fp2mul751_mont(t0, sqQ, t1);                       // t1 = t0*sqQ
    fp2mul751_mont(ldQ, t1, t1);                       // t1 = ldQ*t1
    fp2mul751_mont(beta_denom, ldP, beta_denom);       // beta_denom = ldP*beta_denom
    fp2add751(t1, beta_denom, beta_denom);             // beta_denom = beta_denom+t1    
    fp2add751(alpha_numer, alpha_denom, t2);           // t2 = alpha_numer+alpha_denom
    fp2sqr751_mont(t2, t2);                            // t2 = t2^2
    fp2mul751_mont(sqQ, t2, t2);                       // t2 = t2*sqQ
    fp2add751(beta_numer, beta_denom, t4);             // t4 = beta_numer+beta_denom
    fp2sqr751_mont(t4, t4);                            // t4 = t4^2
    fp2mul751_mont(sqP, t4, t4);                       // t4 = t4*sqP
    
    *valid = *valid & !is_equal_fp2(t2, t4);           // iff weil pairing != 1

    fp2add751(PKA[1], PKA[2], t0);                     // t0 = xP+xQ
    fp2mul751_mont(PKA[3], t0, t1);                    // t1 = xQP*t0
    fp2sub751(t1, one, t1);                            // t1 = t1-1
    fp2mul751_mont(PKA[1], PKA[2], t2);                // t2 = xP*xQ
    fp2add751(t1, t2, t1);                             // t1 = t2+t1
    fp2sqr751_mont(t1, t1);                            // t1 = t1^2
    fp2add751(t0, PKA[3], t0);                         // t0 = t0+xQP
    fp2add751(PKA[0], t0, t0);                         // t0 = t0+A
    fp2mul751_mont(t2, PKA[3], t2);                    // t2 = t2*xQP
    fp2mul751_mont(t0, t2, t0);                        // t0 = t0*t2
    fp2add751(t0, t0, t0);                             // t0 = t0+t0
    fp2add751(t0, t0, t0);                             // t0 = t0+t0
    
    *valid = *valid & is_equal_fp2(t0, t1);            // Third point is difference
    *valid = *valid & test_curve(PKA[0], rvalue, CurveIsogeny); 

    return CRYPTO_SUCCESS;
}


CRYPTO_STATUS Validate_PKB(unsigned char* pPublicKeyB, bool* valid, PCurveIsogenyStruct CurveIsogeny)
{ // Bob validating Alice's public key
  // CurveIsogeny must be set up in advance using SIDH_curve_initialize().
    f2elm_t PKB[4];
    f2elm_t t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, fP = {0}, fQ = {0}, UP = {0}, UQ = {0}, VP = {0}, VQ = {0};
    f2elm_t rvalue, cP, cQ, alphaQi, betaPi, alphaPi, betaQi, alphaP = {0}, alphaQ = {0}, betaP = {0}, betaQ = {0}, one = {0}, zero = {0};
    point_proj_t P = {0}, Q = {0}; 
    unsigned int i, e = CurveIsogeny->oAbits; 
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN; 

    // Choose a random element in GF(p751^2), assume that it is in Montgomery representation
    Status = random_fp2(rvalue, CurveIsogeny);    
    if (Status != CRYPTO_SUCCESS) {
        clear_words((void*)rvalue, 2*NWORDS_FIELD);
        return Status;
    }
                      
    to_fp2mont(((f2elm_t*)pPublicKeyB)[0], PKB[0]);    // Conversion of Bob's public key to Montgomery representation
    to_fp2mont(((f2elm_t*)pPublicKeyB)[1], PKB[1]);
    to_fp2mont(((f2elm_t*)pPublicKeyB)[2], PKB[2]);
    to_fp2mont(((f2elm_t*)pPublicKeyB)[3], PKB[3]);

    fp2copy751(PKB[1], P->X);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, P->Z[0]);
    fp2copy751(PKB[2], Q->X);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, Q->Z[0]);
    fp2copy751(PKB[1], t0);
    fp2copy751(PKB[2], t1);
    
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, one[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, fP[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, fQ[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, UP[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, UQ[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, VP[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, VQ[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, betaP[0]);
    fpcopy751((digit_t*)CurveIsogeny->Montgomery_one, betaQ[0]);
    
    fp2add751(PKB[0], PKB[2], cQ);                     // cQ = xQ+A
    fp2add751(PKB[0], PKB[1], cP);                     // cP = xP+A
    fp2mul751_mont(cQ, PKB[2], cQ);                    // cQ = cQ*xQ 
    fp2mul751_mont(cP, PKB[1], cP);                    // cP = cP*xP 
    fp2add751(cQ, one, cQ);                            // cQ = cQ+1
    fp2add751(cP, one, cP);                            // cP = cP+1
    fp2mul751_mont(cQ, PKB[2], cQ);                    // cQ = cQ*xQ
    fp2mul751_mont(cP, PKB[1], cP);                    // cP = cP*xP

    for (i = 1; i < e; i++) {             
        fp2sqr751_mont(P->X, t2);                      // t2 = XP^2
        fp2sqr751_mont(P->Z, t11);                     // t11 = ZP^2
        fp2sqr751_mont(Q->X, t4);                      // t4 = XQ^2
        fp2sqr751_mont(Q->Z, t10);                     // t10 = ZQ^2
        fp2sub751(t2, t11, t6);                        // t6 = t2-t11
        fp2add751(t2, t2, betaPi);                     // betaPi = t2+t2
        fp2add751(t2, t11, t2);                        // t2 = t2+t11
        fp2sub751(t4, t10, t7);                        // t7 = t4-t10
        fp2add751(t4, t4, alphaQi);                    // alphaQi = t4+t4
        fp2add751(t4, t10, t4);                        // t4 = t4+t10
        fp2mul751_mont(P->X, P->Z, t3);                // t3 = XP*ZP 
        fp2mul751_mont(Q->X, Q->Z, t5);                // t5 = XQ*ZQ 
        fp2mul751_mont(PKB[0], t3, t8);                // t8 = A*t3
        fp2mul751_mont(PKB[0], t5, t9);                // t9 = A*t5
        fp2add751(t3, t3, t3);                         // t3 = t3+t3
        fp2add751(t5, t5, t5);                         // t5 = t5+t5
        fp2add751(betaPi, t8, betaPi);                 // betaPi = betaPi+t8
        fp2add751(t2, t8, t8);                         // t8 = t8+t2
        fp2add751(alphaQi, t9, alphaQi);               // alphaQi = alphaQi+t9
        fp2add751(t4, t9, t9);                         // t9 = t9+t4
        fp2mul751_mont(PKB[0], t2, t2);                // t2 = A*t2
        fp2mul751_mont(PKB[0], t4, t4);                // t4 = A*t4
        fp2add751(betaPi, t8, betaPi);                 // betaPi = betaPi+t8
        fp2add751(alphaQi, t9, alphaQi);               // alphaQi = alphaQi+t9
        fp2mul751_mont(betaPi, t1, betaPi);            // betaPi = betaPi*t1
        fp2mul751_mont(alphaQi, t0, alphaQi);          // alphaQi = alphaQi*t0
        fp2mul751_mont(P->X, t6, t1);                  // t1 = XP*t6
        fp2mul751_mont(Q->X, t7, t0);                  // t0 = XQ*t7
        fp2sub751(t1, betaPi, t1);                     // t1 = t1-betaPi
        fp2sub751(t0, alphaQi, t0);                    // t0 = t0-alphaQi
        fp2mul751_mont(VP, t1, betaPi);                // betaPi = VP*t1
        fp2mul751_mont(VQ, t0, alphaQi);               // alphaQi = VQ*t0
        fp2mul751_mont(Q->Z, t10, t10);                // t10 = t10*ZQ
        fp2mul751_mont(P->Z, t11, t11);                // t11 = t11*ZP
        fp2mul751_mont(t10, UQ, t10);                  // t10 = t10*UQ
        fp2mul751_mont(t11, UP, t11);                  // t11 = t11*UP
        fp2mul751_mont(betaPi, t10, betaPi);           // betaPi = betaPi*t10
        fp2mul751_mont(alphaQi, t11, alphaQi);         // alphaQi = alphaQi*t11
        fp2mul751_mont(t10, t11, t10);                 // t10 = t10*t11
        fp2add751(t10, t10, t10);                      // t10 = t10+t10
        fp2mul751_mont(cQ, t10, alphaPi);              // alphaPi = cQ*t10
        fp2mul751_mont(cP, t10, betaQi);               // betaQi = cP*t10
        fp2mul751_mont(UQ, t7, UQ);                    // UQ = UQ*t7
        fp2mul751_mont(UP, t6, UP);                    // UP = UP*t6
        fp2add751(t8, t8, t8);                         // t8 = t8+t8
        fp2add751(t9, t9, t9);                         // t9 = t9+t9
        fp2mul751_mont(t3, t8, P->Z);                  // ZP = t3*t8
        fp2mul751_mont(t5, t9, Q->Z);                  // ZQ = t5*t9
        fp2mul751_mont(t8, P->X, t8);                  // t8 = t8*XP
        fp2mul751_mont(t9, Q->X, t9);                  // t9 = t9*XQ
        fp2sqr751_mont(t6, P->X);                      // XP = t6^2
        fp2sqr751_mont(t7, Q->X);                      // XQ = t7^2
        fp2add751(t4, t5, t4);                         // t4 = t4+t5
        fp2add751(t5, t4, t4);                         // t4 = t4+t5
        fp2add751(t2, t3, t2);                         // t2 = t2+t3
        fp2add751(t3, t2, t2);                         // t2 = t2+t3
        fp2mul751_mont(t4, t5, t4);                    // t4 = t4*t5
        fp2mul751_mont(t2, t3, t2);                    // t2 = t2*t3
        fp2add751(t4, Q->X, t4);                       // t4 = t4+XQ
        fp2add751(t2, P->X, t2);                       // t2 = t2+XP
        fp2mul751_mont(UQ, t4, UQ);                    // UQ = UQ*t4
        fp2mul751_mont(UP, t2, UP);                    // UP = UP*t2
        fp2sqr751_mont(t9, t9);                        // t9 = t9^2
        fp2sqr751_mont(t8, t8);                        // t8 = t8^2
        fp2mul751_mont(VQ, t9, VQ);                    // VQ = VQ*t9
        fp2mul751_mont(VP, t8, VP);                    // VP = VP*t8
        fp2add751(VQ, VQ, VQ);                         // VQ = VQ+VQ
        fp2add751(VP, VP, VP);                         // VP = VP+VP
        fp2sqr751_mont(alphaP, t4);                    // t4 = alphaP^2
        fp2sqr751_mont(betaP, t5);                     // t5 = betaP^2
        fp2mul751_mont(alphaP, betaP, t6);             // t6 = alphaP*betaP
        fp2add751(t6, t6, t6);                         // t6 = t6+t6 
        fp2mul751_mont(t4, cP, t4);                    // t4 = t4*cP
        fp2mul751_mont(t5, cQ, t5);                    // t5 = t5*cQ
        fp2add751(t4, t5, t4);                         // t4 = t4+t5
        fp2mul751_mont(alphaPi, t4, alphaP);           // alphaP = alphaPi*t4
        fp2mul751_mont(betaPi, t4, betaP);             // betaP = betaPi*t4
        fp2mul751_mont(betaPi, t6, t4);                // t4 = t6*betaPi
        fp2mul751_mont(t4, cQ, t4);                    // t4 = t4*cQ
        fp2mul751_mont(t6, alphaPi, t6);               // t6 = t6*alphaPi
        fp2mul751_mont(cP, t6, t6);                    // t6 = t6*cP
        fp2add751(alphaP, t4, alphaP);                 // alphaP = alphaP+t4
        fp2add751(betaP, t6, betaP);                   // betaP = betaP+t6
        fp2sqr751_mont(alphaQ, t4);                    // t4 = alphaQ^2
        fp2sqr751_mont(betaQ, t5);                     // t5 = betaQ^2
        fp2mul751_mont(alphaQ, betaQ, t6);             // t6 = alphaQ*betaQ
        fp2add751(t6, t6, t6);                         // t6 = t6+t6
        fp2mul751_mont(t4, cP, t4);                    // t4 = t4*cP
        fp2mul751_mont(t5, cQ, t5);                    // t5 = t5*cQ
        fp2add751(t4, t5, t4);                         // t4 = t4+t5
        fp2mul751_mont(alphaQi, t4, alphaQ);           // alphaQ = alphaQi*t4
        fp2mul751_mont(betaQi, t4, betaQ);             // betaQ = betaQi*t4
        fp2mul751_mont(betaPi, t6, t4);                // t4 = t6*betaPi
        fp2mul751_mont(cQ, t4, t4);                    // t4 = t4*cQ
        fp2mul751_mont(t6, betaQi, t5);                // t5 = t6*betaQi
        fp2mul751_mont(t5, cQ, t5);                    // t5 = t5*cQ
        fp2add751(alphaQ, t5, alphaQ);                 // alphaQ = alphaQ+t5
        fp2mul751_mont(t6, alphaQi, t5);               // t5 = t6*alphaQi
        fp2mul751_mont(cP, t5, t5);                    // t5 = t5*cP
        fp2add751(betaQ, t5, betaQ);                   // betaQ = betaQ+t5
        fp2mul751_mont(PKB[1], Q->Z, t0);              // t0 = xP*ZQ 
        fp2mul751_mont(PKB[2], P->Z, t1);              // t1 = xQ*ZP 
        fp2sub751(Q->X, t0, t2);                       // t2 = XQ-t0
        fp2sub751(P->X, t1, t3);                       // t3 = XP-t1
        fp2mul751_mont(t2, P->Z, t2);                  // t2 = t2*ZP
        fp2mul751_mont(t3, Q->Z, t3);                  // t3 = t3*ZQ
        fp2mul751_mont(alphaP, t2, alphaP);            // alphaP = alphaP*t2
        fp2mul751_mont(betaP, t2, betaP);              // betaP = betaP*t2
        fp2mul751_mont(alphaQ, t3, alphaQ);            // alphaQ = alphaQ*t3
        fp2mul751_mont(betaQ, t3, betaQ);              // betaQ = betaQ*t3
    }

    fp2mul751_mont(PKB[2], P->Z, t2);                  // t2 = xQ*ZP
    fp2mul751_mont(PKB[1], Q->Z, t3);                  // t3 = xP*ZQ
    fp2sub751(P->X, t2, t2);                           // t2 = XP-t2
    fp2sub751(Q->X, t3, t3);                           // t3 = XQ-t3
    fp2mul751_mont(t2, Q->Z, t2);                      // t2 = t2*ZQ
    fp2mul751_mont(t3, P->Z, t3);                      // t3 = t3*ZP
    fp2sqr751_mont(alphaP, t4);                        // t4 = alphaP^2
    fp2sqr751_mont(betaP, t5);                         // t5 = betaP^2
    fp2mul751_mont(alphaP, betaP, t6);                 // t6 = alphaP*betaP
    fp2add751(t6, t6, t6);                             // t6 = t6+t6
    fp2sqr751_mont(alphaQ, t7);                        // t7 = alphaQ^2
    fp2sqr751_mont(betaQ, t8);                         // t8 = betaQ^2
    fp2mul751_mont(alphaQ, betaQ, t9);                 // t9 = alphaQ*betaQ
    fp2add751(t9, t9, t9);                             // t9 = t9+t9
    fp2mul751_mont(t4, cP, t4);                        // t4 = t4*cP
    fp2mul751_mont(t5, cQ, t5);                        // t5 = t5*cQ
    fp2mul751_mont(t7, cP, t7);                        // t7 = t7*cP
    fp2mul751_mont(t8, cQ, t8);                        // t8 = t8*cQ
    fp2add751(t4, t5, t4);                             // t4 = t4+t5
    fp2add751(t7, t8, t7);                             // t7 = t7+t8
    fp2mul751_mont(t2, t4, t4);                        // t4 = t2*t4
    fp2mul751_mont(t3, t7, t7);                        // t7 = t3*t7
    fp2sub751(t4, t7, t7);                             // t7 = t4-t7
    fp2sqr751_mont(t7, t7);                            // t7 = t7^2
    fp2mul751_mont(t3, t9, t3);                        // t3 = t3*t9
    fp2mul751_mont(t2, t6, t2);                        // t2 = t2*t6
    fp2sub751(t3, t2, t3);                             // t3 = t3-t2
    fp2sqr751_mont(t3, t3);                            // t3 = t3^2
    fp2mul751_mont(cP, t3, t3);                        // t3 = t3*cP
    fp2mul751_mont(cQ, t3, t3);                        // t3 = t3*cQ
    fp2add751(one, one, t10);                          
    fp2add751(t10, t10, t11);                          // t11 = 4
    fp2add751(t10, PKB[0], t10);                       // t10 = A+2
    
    *valid = !is_equal_fp2(Q->Z, zero);                // Checks order Q
    xDBL(Q, Q, t10, t11);                              // xDBL(XQ,ZQ,A+2,4);    
    *valid = *valid & is_equal_fp2(Q->Z, zero);  
    
    *valid = *valid & !is_equal_fp2(P->Z, zero);       // Checks order P
    xDBL(P, P, t10, t11);                              // xDBL(XP,ZP,A+2,4); 
    *valid = *valid & is_equal_fp2(P->Z, zero);  
    *valid = *valid & !is_equal_fp2(t3, t7);           // Checks Weil pairing non trivial 

    fp2add751(PKB[1], PKB[2], t0);                     // t0 = xP+xQ
    fp2mul751_mont(PKB[3], t0, t1);                    // t1 = xQP*t0
    fp2sub751(t1, one, t1);                            // t1 = t1-1
    fp2mul751_mont(PKB[1], PKB[2], t2);                // t2 = xP*xQ
    fp2add751(t1, t2, t1);                             // t1 = t2+t1
    fp2sqr751_mont(t1, t1);                            // t1 = t1^2
    fp2add751(t0, PKB[3], t0);                         // t0 = t0+xQP
    fp2add751(PKB[0], t0, t0);                         // t0 = t0+A
    fp2mul751_mont(PKB[3], t2, t2);                    // t2 = t2*xQP
    fp2mul751_mont(t0, t2, t0);                        // t0 = t0*t2
    fp2add751(t0, t0, t0);                             // t0 = t0+t0
    fp2add751(t0, t0, t0);                             // t0 = t0+t0

    *valid = *valid & is_equal_fp2(t0, t1); 
    *valid = *valid & test_curve(PKB[0], rvalue, CurveIsogeny); 

    return CRYPTO_SUCCESS;
}