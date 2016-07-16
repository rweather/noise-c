/********************************************************************************************
* SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key 
*       exchange providing 128 bits of quantum security and 192 bits of classical security.
*
*    Copyright (c) Microsoft Corporation. All rights reserved.
*
*
* Abstract: functions for initialization and getting randomness
*
*********************************************************************************************/ 

#include "SIDH_internal.h"
#include <malloc.h>


CRYPTO_STATUS SIDH_curve_initialize(PCurveIsogenyStruct pCurveIsogeny, RandomBytes RandomBytesFunction, PCurveIsogenyStaticData pCurveIsogenyData)
{ // Initialize curve isogeny structure pCurveIsogeny with static data extracted from pCurveIsogenyData.
  // This needs to be called after allocating memory for "pCurveIsogeny" using SIDH_curve_allocate().
    unsigned int i, pwords, owords;

    if (is_CurveIsogenyStruct_null(pCurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    for (i = 0; i < 8; i++) {    // Copy 8-character identifier
        pCurveIsogeny->CurveIsogeny[i] = pCurveIsogenyData->CurveIsogeny[i];
    }
    pCurveIsogeny->pwordbits = pCurveIsogenyData->pwordbits;
    pCurveIsogeny->owordbits = pCurveIsogenyData->owordbits;
    pCurveIsogeny->pbits = pCurveIsogenyData->pbits;
    pCurveIsogeny->oAbits = pCurveIsogenyData->oAbits;
    pCurveIsogeny->oBbits = pCurveIsogenyData->oBbits;
    pCurveIsogeny->eB = pCurveIsogenyData->eB;
    pCurveIsogeny->BigMont_A24 = pCurveIsogenyData->BigMont_A24;
    pCurveIsogeny->RandomBytesFunction = RandomBytesFunction;

    pwords = (pCurveIsogeny->pwordbits + RADIX - 1)/RADIX;
    owords = (pCurveIsogeny->owordbits + RADIX - 1)/RADIX;
    copy_words((digit_t*)pCurveIsogenyData->prime, pCurveIsogeny->prime, pwords);
    copy_words((digit_t*)pCurveIsogenyData->A, pCurveIsogeny->A, pwords);
    copy_words((digit_t*)pCurveIsogenyData->C, pCurveIsogeny->C, pwords);
    copy_words((digit_t*)pCurveIsogenyData->Aorder, pCurveIsogeny->Aorder, owords);
    copy_words((digit_t*)pCurveIsogenyData->Border, pCurveIsogeny->Border, owords);
    copy_words((digit_t*)pCurveIsogenyData->PA, pCurveIsogeny->PA, 2*pwords);
    copy_words((digit_t*)pCurveIsogenyData->PB, pCurveIsogeny->PB, 2*pwords);
    copy_words((digit_t*)pCurveIsogenyData->BigMont_order, pCurveIsogeny->BigMont_order, pwords);
    copy_words((digit_t*)pCurveIsogenyData->Montgomery_R2, pCurveIsogeny->Montgomery_R2, pwords);
    copy_words((digit_t*)pCurveIsogenyData->Montgomery_pp, pCurveIsogeny->Montgomery_pp, pwords);
    copy_words((digit_t*)pCurveIsogenyData->Montgomery_one, pCurveIsogeny->Montgomery_one, pwords);
    
    return CRYPTO_SUCCESS;
}


PCurveIsogenyStruct SIDH_curve_allocate(PCurveIsogenyStaticData CurveData)
{ // Dynamic allocation of memory for curve isogeny structure.
  // Returns NULL on error.
    digit_t pbytes = (CurveData->pwordbits + 7)/8;
    digit_t obytes = (CurveData->owordbits + 7)/8;
    PCurveIsogenyStruct pCurveIsogeny = NULL;

    pCurveIsogeny = (PCurveIsogenyStruct)calloc(1, sizeof(CurveIsogenyStruct));
    pCurveIsogeny->prime = (digit_t*)calloc(1, pbytes);
    pCurveIsogeny->A = (digit_t*)calloc(1, pbytes);
    pCurveIsogeny->C = (digit_t*)calloc(1, pbytes);
    pCurveIsogeny->Aorder = (digit_t*)calloc(1, obytes);
    pCurveIsogeny->Border = (digit_t*)calloc(1, obytes);
    pCurveIsogeny->PA = (digit_t*)calloc(1, 2*pbytes);
    pCurveIsogeny->PB = (digit_t*)calloc(1, 2*pbytes);
    pCurveIsogeny->BigMont_order = (digit_t*)calloc(1, pbytes);
    pCurveIsogeny->Montgomery_R2 = (digit_t*)calloc(1, pbytes);
    pCurveIsogeny->Montgomery_pp = (digit_t*)calloc(1, pbytes);
    pCurveIsogeny->Montgomery_one = (digit_t*)calloc(1, pbytes);

    if (is_CurveIsogenyStruct_null(pCurveIsogeny)) {
        return NULL;
    }
    return pCurveIsogeny;
}


void SIDH_curve_free(PCurveIsogenyStruct pCurveIsogeny)
{ // Free memory for curve isogeny structure

    if (pCurveIsogeny != NULL)
    {
        if (pCurveIsogeny->prime != NULL) 
            free(pCurveIsogeny->prime);
        if (pCurveIsogeny->A != NULL) 
            free(pCurveIsogeny->A);
        if (pCurveIsogeny->C != NULL) 
            free(pCurveIsogeny->C);
        if (pCurveIsogeny->Aorder != NULL) 
            free(pCurveIsogeny->Aorder);
        if (pCurveIsogeny->Border != NULL) 
            free(pCurveIsogeny->Border);
        if (pCurveIsogeny->PA != NULL) 
            free(pCurveIsogeny->PA);
        if (pCurveIsogeny->PB != NULL) 
            free(pCurveIsogeny->PB);
        if (pCurveIsogeny->BigMont_order != NULL) 
            free(pCurveIsogeny->BigMont_order);
        if (pCurveIsogeny->Montgomery_R2 != NULL) 
             free(pCurveIsogeny->Montgomery_R2);
        if (pCurveIsogeny->Montgomery_pp != NULL) 
             free(pCurveIsogeny->Montgomery_pp);
        if (pCurveIsogeny->Montgomery_one != NULL) 
             free(pCurveIsogeny->Montgomery_one);

        free(pCurveIsogeny);
    }
}


bool is_CurveIsogenyStruct_null(PCurveIsogenyStruct pCurveIsogeny)
{ // Check if curve isogeny structure is NULL

    if (pCurveIsogeny == NULL || pCurveIsogeny->prime == NULL || pCurveIsogeny->A == NULL || pCurveIsogeny->C == NULL || pCurveIsogeny->Aorder == NULL || pCurveIsogeny->Border == NULL || 
        pCurveIsogeny->PA == NULL || pCurveIsogeny->PB == NULL || pCurveIsogeny->BigMont_order == NULL || pCurveIsogeny->Montgomery_R2 == NULL || pCurveIsogeny->Montgomery_pp == NULL || 
        pCurveIsogeny->Montgomery_one == NULL)
    {
        return true;
    }
    return false;
}


const char* SIDH_get_error_message(CRYPTO_STATUS Status)
{ // Output error/success message for a given CRYPTO_STATUS
    struct error_mapping {
        unsigned int index;
        char*        string;
    } mapping[CRYPTO_STATUS_TYPE_SIZE] = {
        {CRYPTO_SUCCESS, CRYPTO_MSG_SUCCESS},
        {CRYPTO_ERROR, CRYPTO_MSG_ERROR},
        {CRYPTO_ERROR_DURING_TEST, CRYPTO_MSG_ERROR_DURING_TEST},
        {CRYPTO_ERROR_UNKNOWN, CRYPTO_MSG_ERROR_UNKNOWN},
        {CRYPTO_ERROR_NOT_IMPLEMENTED, CRYPTO_MSG_ERROR_NOT_IMPLEMENTED},
        {CRYPTO_ERROR_NO_MEMORY, CRYPTO_MSG_ERROR_NO_MEMORY},
        {CRYPTO_ERROR_INVALID_PARAMETER, CRYPTO_MSG_ERROR_INVALID_PARAMETER},
        {CRYPTO_ERROR_SHARED_KEY, CRYPTO_MSG_ERROR_SHARED_KEY},
        {CRYPTO_ERROR_PUBLIC_KEY_VALIDATION, CRYPTO_MSG_ERROR_PUBLIC_KEY_VALIDATION},
        {CRYPTO_ERROR_TOO_MANY_ITERATIONS, CRYPTO_MSG_ERROR_TOO_MANY_ITERATIONS}
    };

    if (Status >= CRYPTO_STATUS_TYPE_SIZE || mapping[Status].string == NULL) {
        return "Unrecognized CRYPTO_STATUS";
    } else {
        return mapping[Status].string;
    }
};


const uint64_t Border_div3[NWORDS_ORDER] = { 0xEDCD718A828384F9, 0x733B35BFD4427A14, 0xF88229CF94D7CF38, 0x63C56C990C7C2AD6, 0xB858A87E8F4222C7, 0x254C9C6B525EAF5 }; 


CRYPTO_STATUS random_mod_order(digit_t* random_digits, unsigned int AliceOrBob, PCurveIsogenyStruct pCurveIsogeny)
{ // Output random values in the range [1, order-1] in little endian format that can be used as private keys.
  // It makes requests of random values with length "oAbits" (when AliceOrBob = 0) or "oBbits" (when AliceOrBob = 1) to the "random_bytes" function. 
  // The process repeats until random value is in [0, Aorder-2]  ([0, Border-2], resp.). 
  // If successful, the output is given in "random_digits" in the range [1, Aorder-1] ([1, Border-1], resp.).
  // The "random_bytes" function, which is passed through the curve isogeny structure PCurveIsogeny, should be set up in advance using SIDH_curve_initialize().
  // The caller is responsible of providing the "random_bytes" function passing random values as octets.
    unsigned int ntry = 0, nbytes, nwords;    
    digit_t t1[MAXWORDS_ORDER] = {0}, order2[MAXWORDS_ORDER] = {0};
    unsigned char mask;
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (random_digits == NULL || is_CurveIsogenyStruct_null(pCurveIsogeny) || AliceOrBob > 1) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    clear_words((void*)random_digits, MAXWORDS_ORDER);     
    t1[0] = 2;
    if (AliceOrBob == ALICE) {
        nbytes = (pCurveIsogeny->oAbits+7)/8;                  // Number of random bytes to be requested 
        nwords = NBITS_TO_NWORDS(pCurveIsogeny->oAbits);
        mask = 0x07;                                           // Value for masking last random byte
        copy_words(pCurveIsogeny->Aorder, order2, nwords);
        mp_shiftr1(order2, nwords);                            // order/2
        mp_sub(order2, t1, order2, nwords);                    // order2 = order/2-2
    } else {
        nbytes = (pCurveIsogeny->oBbits+7)/8;                    
        nwords = NBITS_TO_NWORDS(pCurveIsogeny->oBbits);
        mask = 0x03;                                           // Value for masking last random byte
        mp_sub((digit_t*)Border_div3, t1, order2, nwords);     // order2 = order/3-2
    }

    do {
        ntry++;
        if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, order-2] 
            return CRYPTO_ERROR_TOO_MANY_ITERATIONS;
        }
        Status = (pCurveIsogeny->RandomBytesFunction)(nbytes, (unsigned char*)random_digits);
        if (Status != CRYPTO_SUCCESS) {
            return Status;
        }
        ((unsigned char*)random_digits)[nbytes-1] &= mask;     // Masking last byte 
    } while (mp_sub(order2, random_digits, t1, nwords) == 1);
    
    clear_words((void*)t1, MAXWORDS_ORDER);  
    t1[0] = 1;
    mp_add(random_digits, t1, random_digits, nwords);          
    copy_words(random_digits, t1, nwords);
    mp_shiftl1(random_digits, nwords);                         // Alice's output in the range [2, order-2]
    if (AliceOrBob == BOB) {
        mp_add(random_digits, t1, random_digits, nwords);      // Bob's output in the range [3, order-3]
    }

    return Status;
}


CRYPTO_STATUS random_BigMont_mod_order(digit_t* random_digits, PCurveIsogenyStruct pCurveIsogeny)
{ // Output random values in the range [1, BigMont_order-1] in little endian format that can be used as private keys to compute scalar multiplications 
  // using the elliptic curve BigMont.
  // It makes requests of random values with length "BIGMONT_NBITS_ORDER" to the "random_bytes" function. 
  // The process repeats until random value is in [0, BigMont_order-2] 
  // If successful, the output is given in "random_digits" in the range [1, BigMont_order-1].
  // The "random_bytes" function, which is passed through the curve isogeny structure PCurveIsogeny, should be set up in advance using SIDH_curve_initialize().
  // The caller is responsible of providing the "random_bytes" function passing random values as octets.
    unsigned int ntry = 0, nbytes = (BIGMONT_NBITS_ORDER+7)/8, nwords = NBITS_TO_NWORDS(BIGMONT_NBITS_ORDER);    
    digit_t t1[BIGMONT_MAXWORDS_ORDER] = {0}, order2[BIGMONT_MAXWORDS_ORDER] = {0};
    unsigned char mask;
    CRYPTO_STATUS Status = CRYPTO_ERROR_UNKNOWN;

    if (random_digits == NULL || is_CurveIsogenyStruct_null(pCurveIsogeny)) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    clear_words((void*)random_digits, BIGMONT_MAXWORDS_ORDER);     
    t1[0] = 2;
    mask = (unsigned char)(8*nbytes - BIGMONT_NBITS_ORDER);
    mp_sub(pCurveIsogeny->BigMont_order, t1, order2, nwords);  // order2 = order-2
    mask = ((unsigned char)-1 >> mask);                        // Value for masking last random byte

    do {
        ntry++;
        if (ntry > 100) {                                      // Max. 100 iterations to obtain random value in [0, order-2] 
            return CRYPTO_ERROR_TOO_MANY_ITERATIONS;
        }
        Status = (pCurveIsogeny->RandomBytesFunction)(nbytes, (unsigned char*)random_digits);
        if (Status != CRYPTO_SUCCESS) {
            return Status;
        }
        ((unsigned char*)random_digits)[nbytes-1] &= mask;     // Masking last byte 
    } while (mp_sub(order2, random_digits, t1, nwords) == 1);
    
    clear_words((void*)t1, BIGMONT_MAXWORDS_ORDER);  
    t1[0] = 1;
    mp_add(random_digits, t1, random_digits, nwords);          // Output in the range [1, order-1]

    return Status;
}


void clear_words(void* mem, digit_t nwords)
{ // Clear digits from memory. "nwords" indicates the number of digits to be zeroed.
  // This function uses the volatile type qualifier to inform the compiler not to optimize out the memory clearing.
    unsigned int i;
    volatile digit_t *v = mem; 

    for (i = 0; i < nwords; i++) {
        v[i] = 0;
    }
}






