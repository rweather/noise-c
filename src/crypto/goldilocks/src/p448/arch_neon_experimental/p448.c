/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "word.h"
#include "p448.h"

static inline mask_t __attribute__((always_inline))
is_zero (
    word_t x
) {
    dword_t xx = x;
    xx--;
    return xx >> WORD_BITS;
}

static __inline__ uint64x2_t __attribute__((gnu_inline,always_inline,unused))
xx_vaddup_u64(uint64x2_t x) {
    __asm__ ("vadd.s64 %f0, %e0" : "+w"(x));
    return x;
}

static __inline__ int64x2_t __attribute__((gnu_inline,always_inline,unused))
vrev128_s64(int64x2_t x) {
    __asm__ ("vswp.s64 %e0, %f0" : "+w"(x));
    return x;
}

static __inline__ uint64x2_t __attribute__((gnu_inline,always_inline))
vrev128_u64(uint64x2_t x) {
    __asm__ ("vswp.s64 %e0, %f0" : "+w"(x));
    return x;
}

static inline void __attribute__((gnu_inline,always_inline,unused))
smlal (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
    *acc += (int64_t)(int32_t)a * (int64_t)(int32_t)b;
}

static inline void __attribute__((gnu_inline,always_inline,unused))
smlal2 (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
    *acc += (int64_t)(int32_t)a * (int64_t)(int32_t)b * 2;
}

static inline void __attribute__((gnu_inline,always_inline,unused))
smull (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
    *acc = (int64_t)(int32_t)a * (int64_t)(int32_t)b;
}

static inline void __attribute__((gnu_inline,always_inline,unused))
smull2 (
    uint64_t *acc,
    const uint32_t a,
    const uint32_t b
) {
    *acc = (int64_t)(int32_t)a * (int64_t)(int32_t)b * 2;
}

void
p448_mul (
    p448_t *__restrict__ cs,
    const p448_t *as,
    const p448_t *bs
) {
    #define _bl0 "q0"
    #define _bl0_0 "d0"
    #define _bl0_1 "d1"
    #define _bh0 "q1"
    #define _bh0_0 "d2"
    #define _bh0_1 "d3"
    #define _bs0 "q2"
    #define _bs0_0 "d4"
    #define _bs0_1 "d5"
    #define _bl2 "q3"
    #define _bl2_0 "d6"
    #define _bl2_1 "d7"
    #define _bh2 "q4"
    #define _bh2_0 "d8"
    #define _bh2_1 "d9"
    #define _bs2 "q5"
    #define _bs2_0 "d10"
    #define _bs2_1 "d11"

    #define _as0 "q6"
    #define _as0_0 "d12"
    #define _as0_1 "d13"
    #define _as2 "q7"
    #define _as2_0 "d14"
    #define _as2_1 "d15"
    #define _al0 "q8"
    #define _al0_0 "d16"
    #define _al0_1 "d17"
    #define _ah0 "q9"
    #define _ah0_0 "d18"
    #define _ah0_1 "d19"
    #define _al2 "q10"
    #define _al2_0 "d20"
    #define _al2_1 "d21"
    #define _ah2 "q11"
    #define _ah2_0 "d22"
    #define _ah2_1 "d23"

    #define _a0a "q12"
    #define _a0a_0 "d24"
    #define _a0a_1 "d25"
    #define _a0b "q13"
    #define _a0b_0 "d26"
    #define _a0b_1 "d27"
    #define _a1a "q14"
    #define _a1a_0 "d28"
    #define _a1a_1 "d29"
    #define _a1b "q15"
    #define _a1b_0 "d30"
    #define _a1b_1 "d31"
    #define VMAC(op,result,a,b,n) #op" "result", "a", "b"[" #n "]\n\t"
    #define VOP3(op,result,a,b)   #op" "result", "a", "b"\n\t"
    #define VOP2(op,result,a)     #op" "result", "a"\n\t"

    int32x2_t *vc = (int32x2_t*) cs->limb;

    __asm__ __volatile__(
        
        "vld2.32 {"_al0_0","_al0_1","_ah0_0","_ah0_1"}, [%[a],:128]!" "\n\t"
        VOP3(vadd.i32,_as0,_al0,_ah0)
        
        "vld2.32 {"_bl0_0","_bl0_1","_bh0_0","_bh0_1"}, [%[b],:128]!" "\n\t"
        VOP3(vadd.i32,_bs0_1,_bl0_1,_bh0_1)
        VOP3(vsub.i32,_bs0_0,_bl0_0,_bh0_0)
            
        "vld2.32 {"_bl2_0","_bl2_1","_bh2_0","_bh2_1"}, [%[b],:128]!" "\n\t"
        VOP3(vadd.i32,_bs2,_bl2,_bh2)
            
        "vld2.32 {"_al2_0","_al2_1","_ah2_0","_ah2_1"}, [%[a],:128]!" "\n\t"
        VOP3(vadd.i32,_as2,_al2,_ah2)
        
        VMAC(vmull.s32,_a0b,_as0_1,_bs2_1,0)
        VMAC(vmlal.s32,_a0b,_as2_0,_bs2_0,0)
        VMAC(vmlal.s32,_a0b,_as2_1,_bs0_1,0)
        VMAC(vmlal.s32,_a0b,_as0_0,_bh0_0,0)
            
        VMAC(vmull.s32,_a1b,_as0_1,_bs2_1,1)
        VMAC(vmlal.s32,_a1b,_as2_0,_bs2_0,1)
        VMAC(vmlal.s32,_a1b,_as2_1,_bs0_1,1)
        VMAC(vmlal.s32,_a1b,_as0_0,_bh0_0,1)
            
        VOP2(vmov,_a0a,_a0b)
        VMAC(vmlal.s32,_a0a,_ah0_1,_bh2_1,0)
        VMAC(vmlal.s32,_a0a,_ah2_0,_bh2_0,0)
        VMAC(vmlal.s32,_a0a,_ah2_1,_bh0_1,0)
        VMAC(vmlal.s32,_a0a,_ah0_0,_bl0_0,0)
            
        VMAC(vmlsl.s32,_a0b,_al0_1,_bl2_1,0)
        VMAC(vmlsl.s32,_a0b,_al2_0,_bl2_0,0)
        VMAC(vmlsl.s32,_a0b,_al2_1,_bl0_1,0)
        VMAC(vmlal.s32,_a0b,_al0_0,_bs0_0,0)
            
        VOP2(vmov,_a1a,_a1b)
        VMAC(vmlal.s32,_a1a,_ah0_1,_bh2_1,1)
        VMAC(vmlal.s32,_a1a,_ah2_0,_bh2_0,1)
        VMAC(vmlal.s32,_a1a,_ah2_1,_bh0_1,1)
        VMAC(vmlal.s32,_a1a,_ah0_0,_bl0_0,1)
            
            VOP2(vswp,_a0b_1,_a0a_0)
            
        VMAC(vmlsl.s32,_a1b,_al0_1,_bl2_1,1)
        VMAC(vmlsl.s32,_a1b,_al2_0,_bl2_0,1)
        VMAC(vmlsl.s32,_a1b,_al2_1,_bl0_1,1)
        VMAC(vmlal.s32,_a1b,_al0_0,_bs0_0,1)
                
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP3(vsub.i32,_bs0_1,_bl0_1,_bh0_1)
            VOP2(vmovn.i64,_a0b_0,_a0b)
                
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a1b,_a0a,_a1b)
                    
                    
        VMAC(vmull.s32,_a0a,_as2_0,_bs2_1,0)
            VOP2(vmovn.i64,_a0b_1,_a1b)
        VMAC(vmlal.s32,_a0a,_as2_1,_bs2_0,0)
            VOP3(vsra.u64,_a1a,_a1b,"#28")
        VMAC(vmlal.s32,_a0a,_as0_0,_bh0_1,0)
            VOP2(vbic.i32,_a0b,"#0xf0000000")
        VMAC(vmlal.s32,_a0a,_as0_1,_bh0_0,0)
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"
                    
        VMAC(vmull.s32,_a1b,_as2_0,_bs2_1,1)
        VMAC(vmlal.s32,_a1b,_as2_1,_bs2_0,1)
        VMAC(vmlal.s32,_a1b,_as0_0,_bh0_1,1)
        VMAC(vmlal.s32,_a1b,_as0_1,_bh0_0,1)

        VOP2(vmov,_a0b_1,_a0a_1)
        VOP3(vadd.i64,_a0b_0,_a0a_0,_a1a_0)
        VOP3(vadd.i64,_a0a_0,_a0a_0,_a1a_1)
        VMAC(vmlal.s32,_a0a,_ah2_0,_bh2_1,0)
        VMAC(vmlal.s32,_a0a,_ah2_1,_bh2_0,0)
        VMAC(vmlal.s32,_a0a,_ah0_0,_bl0_1,0)
        VMAC(vmlal.s32,_a0a,_ah0_1,_bl0_0,0)

        VMAC(vmlsl.s32,_a0b,_al2_0,_bl2_1,0)
        VMAC(vmlsl.s32,_a0b,_al2_1,_bl2_0,0)
        VMAC(vmlal.s32,_a0b,_al0_0,_bs0_1,0)
        VMAC(vmlal.s32,_a0b,_al0_1,_bs0_0,0)

        VOP2(vmov,_a1a,_a1b)
        VMAC(vmlal.s32,_a1a,_ah2_0,_bh2_1,1)
        VMAC(vmlal.s32,_a1a,_ah2_1,_bh2_0,1)
        VMAC(vmlal.s32,_a1a,_ah0_0,_bl0_1,1)
        VMAC(vmlal.s32,_a1a,_ah0_1,_bl0_0,1)

            VOP2(vswp,_a0b_1,_a0a_0)

        VMAC(vmlsl.s32,_a1b,_al2_0,_bl2_1,1)
        VMAC(vmlsl.s32,_a1b,_al2_1,_bl2_0,1)
        VMAC(vmlal.s32,_a1b,_al0_0,_bs0_1,1)
        VMAC(vmlal.s32,_a1b,_al0_1,_bs0_0,1)
                                        
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP3(vsub.i32,_bs2_0,_bl2_0,_bh2_0)
            VOP2(vmovn.i64,_a0b_0,_a0b)
                        
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a1b,_a0a,_a1b)

        VMAC(vmull.s32,_a0a,_as2_1,_bs2_1,0)
            VOP2(vmovn.i64,_a0b_1,_a1b)
        VMAC(vmlal.s32,_a0a,_as0_0,_bh2_0,0)
            VOP3(vsra.u64,_a1a,_a1b,"#28")
        VMAC(vmlal.s32,_a0a,_as0_1,_bh0_1,0)
            VOP2(vbic.i32,_a0b,"#0xf0000000")
        VMAC(vmlal.s32,_a0a,_as2_0,_bh0_0,0)
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"

        VMAC(vmull.s32,_a1b,_as2_1,_bs2_1,1)
        VMAC(vmlal.s32,_a1b,_as0_0,_bh2_0,1)
        VMAC(vmlal.s32,_a1b,_as0_1,_bh0_1,1)
        VMAC(vmlal.s32,_a1b,_as2_0,_bh0_0,1)

        VOP2(vmov,_a0b_1,_a0a_1)
        VOP3(vadd.i64,_a0b_0,_a0a_0,_a1a_0)
        VOP3(vadd.i64,_a0a_0,_a0a_0,_a1a_1)
        VMAC(vmlal.s32,_a0a,_ah2_1,_bh2_1,0)
        VMAC(vmlal.s32,_a0a,_ah0_0,_bl2_0,0)
        VMAC(vmlal.s32,_a0a,_ah0_1,_bl0_1,0)
        VMAC(vmlal.s32,_a0a,_ah2_0,_bl0_0,0)

        VMAC(vmlsl.s32,_a0b,_al2_1,_bl2_1,0)
        VMAC(vmlal.s32,_a0b,_al0_0,_bs2_0,0)
        VMAC(vmlal.s32,_a0b,_al0_1,_bs0_1,0)
        VMAC(vmlal.s32,_a0b,_al2_0,_bs0_0,0)

        VOP2(vmov,_a1a,_a1b)
        VMAC(vmlal.s32,_a1a,_ah2_1,_bh2_1,1)
        VMAC(vmlal.s32,_a1a,_ah0_0,_bl2_0,1)
        VMAC(vmlal.s32,_a1a,_ah0_1,_bl0_1,1)
        VMAC(vmlal.s32,_a1a,_ah2_0,_bl0_0,1)

            VOP2(vswp,_a0b_1,_a0a_0)

        VMAC(vmlsl.s32,_a1b,_al2_1,_bl2_1,1)
        VMAC(vmlal.s32,_a1b,_al0_0,_bs2_0,1)
        VMAC(vmlal.s32,_a1b,_al0_1,_bs0_1,1)
        VMAC(vmlal.s32,_a1b,_al2_0,_bs0_0,1)
                                                                
            VOP3(vsub.i32,_bs2_1,_bl2_1,_bh2_1)
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP2(vmovn.i64,_a0b_0,_a0b)
                        
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a1b,_a0a,_a1b)

        VMAC(vmull.s32,_a0a,_as0_0,_bh2_1,0)
            VOP2(vmovn.i64,_a0b_1,_a1b)
        VMAC(vmlal.s32,_a0a,_as0_1,_bh2_0,0)
            VOP3(vsra.u64,_a1a,_a1b,"#28")
        VMAC(vmlal.s32,_a0a,_as2_0,_bh0_1,0)
            VOP2(vbic.i32,_a0b,"#0xf0000000")
        VMAC(vmlal.s32,_a0a,_as2_1,_bh0_0,0)
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"

        VMAC(vmull.s32,_a1b,_as0_0,_bh2_1,1)
        VMAC(vmlal.s32,_a1b,_as0_1,_bh2_0,1)
        VMAC(vmlal.s32,_a1b,_as2_0,_bh0_1,1)
        VMAC(vmlal.s32,_a1b,_as2_1,_bh0_0,1)

        VOP2(vmov,_a0b_1,_a0a_1)
        VOP3(vadd.i64,_a0b_0,_a0a_0,_a1a_0)
        VOP3(vadd.i64,_a0a_0,_a0a_0,_a1a_1)
        VMAC(vmlal.s32,_a0a,_ah0_0,_bl2_1,0)
        VMAC(vmlal.s32,_a0a,_ah0_1,_bl2_0,0)
        VMAC(vmlal.s32,_a0a,_ah2_0,_bl0_1,0)
        VMAC(vmlal.s32,_a0a,_ah2_1,_bl0_0,0)

        VMAC(vmlal.s32,_a0b,_al0_0,_bs2_1,0)
        VMAC(vmlal.s32,_a0b,_al0_1,_bs2_0,0)
        VMAC(vmlal.s32,_a0b,_al2_0,_bs0_1,0)
        VMAC(vmlal.s32,_a0b,_al2_1,_bs0_0,0)

        VOP2(vmov,_a1a,_a1b)
        VMAC(vmlal.s32,_a1a,_ah0_0,_bl2_1,1)
        VMAC(vmlal.s32,_a1a,_ah0_1,_bl2_0,1)
        VMAC(vmlal.s32,_a1a,_ah2_0,_bl0_1,1)
        VMAC(vmlal.s32,_a1a,_ah2_1,_bl0_0,1)

            VOP2(vswp,_a0b_1,_a0a_0)

        VMAC(vmlal.s32,_a1b,_al0_0,_bs2_1,1)
        VMAC(vmlal.s32,_a1b,_al0_1,_bs2_0,1)
        VMAC(vmlal.s32,_a1b,_al2_0,_bs0_1,1)
        VMAC(vmlal.s32,_a1b,_al2_1,_bs0_0,1)
                        
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP2(vmovn.i64,_a0b_0,_a0b)
                                                                                            
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a0a,_a0a,_a1b)

            VOP2(vmovn.i64,_a0b_1,_a0a)
            VOP3(vsra.u64,_a1a,_a0a,"#28")
                                                                                            
            VOP2(vbic.i32,_a0b,"#0xf0000000") 
                                                                                            
        VOP2(vswp,_a1a_0,_a1a_1)
                                                                                            
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"  
            "sub %[c], #64" "\n\t"
                                                                                                
        VOP3(vadd.i64,_a1a_1,_a1a_1,_a1a_0)
        
            "vldmia %[c], {"_a0a_0", "_a0a_1", "_a0b_0"}" "\n\t"
            VOP2(vaddw.s32,_a1a,_a0a_0)
            VOP2(vmovn.i64,_a0a_0,_a1a)
            VOP2(vshr.s64,_a1a,"#28")
                                                
            VOP2(vaddw.s32,_a1a,_a0a_1)
            VOP2(vmovn.i64,_a0a_1,_a1a)
            VOP2(vshr.s64,_a1a,"#28")
                                                                                                    
            VOP2(vbic.i32,_a0a,"#0xf0000000")
                                                
            VOP2(vaddw.s32,_a1a,_a0b_0) 
            VOP2(vmovn.i64,_a0b_0,_a1a)
            
            "vstmia %[c], {"_a0a_0", "_a0a_1", "_a0b_0"}" "\n\t"
        
        : [a]"+r"(as)
        , [b]"+r"(bs)
        , [c]"+r"(vc)
                            
        :: "q0","q1","q2","q3",
            "q4","q5","q6","q7",
            "q8","q9","q10","q11",
            "q12","q13","q14","q15",
            "memory"
    );
}

void
p448_sqr (
    p448_t *__restrict__ cs,
    const p448_t *bs
) {
    int32x2_t *vc = (int32x2_t*) cs->limb;

    __asm__ __volatile__ (
        "vld2.32 {"_bl0_0","_bl0_1","_bh0_0","_bh0_1"}, [%[b],:128]!" "\n\t"
        VOP3(vadd.i32,_bs0_1,_bl0_1,_bh0_1) /* 0 .. 2^30 */
        VOP3(vsub.i32,_bs0_0,_bl0_0,_bh0_0) /* +- 2^29 */
        VOP3(vadd.i32,_as0,_bl0,_bh0)       /* 0 .. 2^30 */
            
        "vld2.32 {"_bl2_0","_bl2_1","_bh2_0","_bh2_1"}, [%[b],:128]!" "\n\t"
        VOP3(vadd.i32,_bs2,_bl2,_bh2)       /* 0 .. 2^30 */
        VOP2(vmov,_as2,_bs2)
        
        VMAC(vqdmull.s32,_a0b,_as0_1,_bs2_1,0) /* 0 .. 8 * 2^58.  danger for vqdmlal is 32 */
        VMAC(vmlal.s32,_a0b,_as2_0,_bs2_0,0)   /* 0 .. 12 */
        VMAC(vmlal.s32,_a0b,_as0_0,_bh0_0,0)   /* 0 .. 14 */
            
        VMAC(vqdmull.s32,_a1b,_as0_1,_bs2_1,1) /* 0 .. 8 */
        VMAC(vmlal.s32,_a1b,_as2_0,_bs2_0,1)   /* 0 .. 14 */
        VMAC(vmlal.s32,_a1b,_as0_0,_bh0_0,1)   /* 0 .. 16 */
            
        VOP2(vmov,_a0a,_a0b)                   /* 0 .. 14 */
        VMAC(vqdmlal.s32,_a0a,_bh0_1,_bh2_1,0) /* 0 .. 16 */
        VMAC(vmlal.s32,_a0a,_bh2_0,_bh2_0,0)   /* 0 .. 17 */
        VMAC(vmlal.s32,_a0a,_bh0_0,_bl0_0,0)   /* 0 .. 18 */
            
        VMAC(vqdmlsl.s32,_a0b,_bl0_1,_bl2_1,0) /*-2 .. 14 */
        VMAC(vmlsl.s32,_a0b,_bl2_0,_bl2_0,0)   /*-3 .. 14 */
        VMAC(vmlal.s32,_a0b,_bl0_0,_bs0_0,0)   /*-4 .. 15 */
            
        VOP2(vmov,_a1a,_a1b)
        VMAC(vqdmlal.s32,_a1a,_bh0_1,_bh2_1,1) /* 0 .. 18 */
        VMAC(vmlal.s32,_a1a,_bh2_0,_bh2_0,1)   /* 0 .. 19 */
        VMAC(vmlal.s32,_a1a,_bh0_0,_bl0_0,1)   /* 0 .. 20 */
            
            VOP2(vswp,_a0b_1,_a0a_0)
            
        VMAC(vqdmlsl.s32,_a1b,_bl0_1,_bl2_1,1) /*-2 .. 16 */
        VMAC(vmlsl.s32,_a1b,_bl2_0,_bl2_0,1)   /*-3 .. 16 */
        VMAC(vmlal.s32,_a1b,_bl0_0,_bs0_0,1)   /*-4 .. 17 */
                
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP3(vsub.i32,_bs0_1,_bl0_1,_bh0_1)
            VOP2(vmovn.i64,_a0b_0,_a0b)
                
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a1b,_a0a,_a1b)
                    
                    
        VMAC(vqdmull.s32,_a0a,_as2_0,_bs2_1,0) /* 0 .. 8 */
            VOP2(vmovn.i64,_a0b_1,_a1b)
            VOP3(vsra.u64,_a1a,_a1b,"#28")
        VMAC(vqdmlal.s32,_a0a,_as0_0,_bh0_1,0) /* 0 .. 12 */
            VOP2(vbic.i32,_a0b,"#0xf0000000")
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"
                    
        VMAC(vqdmull.s32,_a1b,_as2_0,_bs2_1,1) /* 0 .. 8 */
        VMAC(vqdmlal.s32,_a1b,_as0_0,_bh0_1,1) /* 0 .. 12 */

        VOP2(vmov,_a0b,_a0a)               /* 0 .. 12 */
        VMAC(vqdmlal.s32,_a0a,_bh2_0,_bh2_1,0) /* 0 .. 14 */
        VMAC(vqdmlal.s32,_a0a,_bh0_0,_bl0_1,0) /* 0 .. 16 */

        VMAC(vqdmlsl.s32,_a0b,_bl2_0,_bl2_1,0) /*-2 .. 12 */
        VMAC(vqdmlal.s32,_a0b,_bl0_0,_bs0_1,0) /*-4 .. 14 */
        VOP3(vadd.i64,_a0a_0,_a0a_0,_a1a_1)
        VOP3(vadd.i64,_a0b_0,_a0b_0,_a1a_0)

        VOP2(vmov,_a1a,_a1b)                   /* 0 .. 12 */
        VMAC(vqdmlal.s32,_a1a,_bh2_0,_bh2_1,1) /* 0 .. 14 */
        VMAC(vqdmlal.s32,_a1a,_bh0_0,_bl0_1,1) /* 0 .. 16 */

            VOP2(vswp,_a0b_1,_a0a_0)

        VMAC(vqdmlsl.s32,_a1b,_bl2_0,_bl2_1,1) /*-2 .. 12 */
        VMAC(vqdmlal.s32,_a1b,_bl0_0,_bs0_1,1) /*-4 .. 14 */
                                        
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP3(vsub.i32,_bs2_0,_bl2_0,_bh2_0)
            VOP2(vmovn.i64,_a0b_0,_a0b)
                        
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a1b,_a0a,_a1b)

        VMAC(vmull.s32,_a0a,_as2_1,_bs2_1,0)
            VOP2(vmovn.i64,_a0b_1,_a1b)
        VMAC(vqdmlal.s32,_a0a,_as0_0,_bh2_0,0)
            VOP3(vsra.u64,_a1a,_a1b,"#28")
        VMAC(vmlal.s32,_a0a,_as0_1,_bh0_1,0)
            VOP2(vbic.i32,_a0b,"#0xf0000000")
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"

        VMAC(vmull.s32,_a1b,_as2_1,_bs2_1,1)
        VMAC(vqdmlal.s32,_a1b,_as0_0,_bh2_0,1)
        VMAC(vmlal.s32,_a1b,_as0_1,_bh0_1,1)

        VOP2(vmov,_a0b_1,_a0a_1)
        VOP3(vadd.i64,_a0b_0,_a0a_0,_a1a_0)
        VOP3(vadd.i64,_a0a_0,_a0a_0,_a1a_1)
        VMAC(vmlal.s32,_a0a,_bh2_1,_bh2_1,0)
        VMAC(vqdmlal.s32,_a0a,_bh0_0,_bl2_0,0)
        VMAC(vmlal.s32,_a0a,_bh0_1,_bl0_1,0)

        VMAC(vmlsl.s32,_a0b,_bl2_1,_bl2_1,0)
        VMAC(vqdmlal.s32,_a0b,_bl0_0,_bs2_0,0)
        VMAC(vmlal.s32,_a0b,_bl0_1,_bs0_1,0)

        VOP2(vmov,_a1a,_a1b)
        VMAC(vmlal.s32,_a1a,_bh2_1,_bh2_1,1)
        VMAC(vqdmlal.s32,_a1a,_bh0_0,_bl2_0,1)
        VMAC(vmlal.s32,_a1a,_bh0_1,_bl0_1,1)

            VOP2(vswp,_a0b_1,_a0a_0)

        VMAC(vmlsl.s32,_a1b,_bl2_1,_bl2_1,1)
        VMAC(vqdmlal.s32,_a1b,_bl0_0,_bs2_0,1)
        VMAC(vmlal.s32,_a1b,_bl0_1,_bs0_1,1)
                                                                
            VOP3(vsub.i32,_bs2_1,_bl2_1,_bh2_1)
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP2(vmovn.i64,_a0b_0,_a0b)
                        
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a1b,_a0a,_a1b)

        VMAC(vqdmull.s32,_a0a,_as0_0,_bh2_1,0)
            VOP2(vmovn.i64,_a0b_1,_a1b)
            VOP3(vsra.u64,_a1a,_a1b,"#28")
        VMAC(vqdmlal.s32,_a0a,_as2_0,_bh0_1,0)
            VOP2(vbic.i32,_a0b,"#0xf0000000")
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"

        VMAC(vqdmull.s32,_a1b,_as0_0,_bh2_1,1)
        VMAC(vqdmlal.s32,_a1b,_as2_0,_bh0_1,1)

        VOP2(vmov,_a0b_1,_a0a_1)
        VOP3(vadd.i64,_a0b_0,_a0a_0,_a1a_0)
        VOP3(vadd.i64,_a0a_0,_a0a_0,_a1a_1)
        VMAC(vqdmlal.s32,_a0a,_bh0_0,_bl2_1,0)
        VMAC(vqdmlal.s32,_a0a,_bh2_0,_bl0_1,0)

        VMAC(vqdmlal.s32,_a0b,_bl0_0,_bs2_1,0)
        VMAC(vqdmlal.s32,_a0b,_bl2_0,_bs0_1,0)

        VOP2(vmov,_a1a,_a1b)
        VMAC(vqdmlal.s32,_a1a,_bh0_0,_bl2_1,1)
        VMAC(vqdmlal.s32,_a1a,_bh2_0,_bl0_1,1)

            VOP2(vswp,_a0b_1,_a0a_0)

        VMAC(vqdmlal.s32,_a1b,_bl0_0,_bs2_1,1)
        VMAC(vqdmlal.s32,_a1b,_bl2_0,_bs0_1,1)
                        
            VOP3(vsra.u64,_a0a,_a0b,"#28")
            VOP2(vmovn.i64,_a0b_0,_a0b)
                                                                                            
            VOP2(vswp,_a1b_1,_a1a_0)
            VOP3(vadd.i64,_a0a,_a0a,_a1b)

            VOP2(vmovn.i64,_a0b_1,_a0a)
            VOP3(vsra.u64,_a1a,_a0a,"#28")
                                                                                            
            VOP2(vbic.i32,_a0b,"#0xf0000000") 
                                                                                            
        VOP2(vswp,_a1a_0,_a1a_1)
                                                                                            
            "vstmia %[c]!, {"_a0b_0", "_a0b_1"}" "\n\t"  
            "sub %[c], #64" "\n\t"
                                                                                                
        VOP3(vadd.i64,_a1a_1,_a1a_1,_a1a_0)
        
            "vldmia %[c], {"_a0a_0", "_a0a_1", "_a0b_0"}" "\n\t"
            VOP2(vaddw.s32,_a1a,_a0a_0)
            VOP2(vmovn.i64,_a0a_0,_a1a)
            VOP2(vshr.s64,_a1a,"#28")
                                                
            VOP2(vaddw.s32,_a1a,_a0a_1)
            VOP2(vmovn.i64,_a0a_1,_a1a)
            VOP2(vshr.s64,_a1a,"#28")
                                                                                                    
            VOP2(vbic.i32,_a0a,"#0xf0000000")
                                                
            VOP2(vaddw.s32,_a1a,_a0b_0) 
            VOP2(vmovn.i64,_a0b_0,_a1a)
            
            "vstmia %[c], {"_a0a_0", "_a0a_1", "_a0b_0"}" "\n\t"
        
        : [b]"+r"(bs)
        , [c]"+r"(vc)
                            
        :: "q0","q1","q2","q3",
            "q4","q5","q6","q7",
            "q12","q13","q14","q15",
            "memory"
    );
}

void
p448_mulw (
    p448_t *__restrict__ cs,
    const p448_t *as,
    uint64_t b
) { 
    uint32x2_t vmask = {(1<<28) - 1, (1<<28)-1};
    
    uint64x2_t accum;
    const uint32x2_t *va = (const uint32x2_t *) as->limb;
    uint32x2_t *vo = (uint32x2_t *) cs->limb;
    uint32x2_t vc, vn;
    uint32x2_t vb = {b & ((1<<28)-1), b>>28};
    
    accum = vmull_lane_u32(va[7], vb, 1);
    accum = xx_vaddup_u64(vrev128_u64(accum));
    
    vc = va[0];
    accum = vmlal_lane_u32(accum, vc, vb, 0);
    vo[0] = vmovn_u64(accum) & vmask;
    accum = vshrq_n_u64(accum,28);
    
    /* PERF: the right way to do this is to reduce behind, i.e.
     * vmull + vmlal round 0
     * vmull + vmlal round 1
     * vmull + vmlal round 2
     * vsraq round 0, 1
     * vmull + vmlal round 3
     * vsraq round 1, 2
     * ...
     */
    
    int i;
    for (i=1; i<8; i++) {
        vn = va[i];
        accum = vmlal_lane_u32(accum, vc, vb, 1);
        accum = vmlal_lane_u32(accum, vn, vb, 0);
        vo[i] = vmovn_u64(accum) & vmask;
        accum = vshrq_n_u64(accum,28);
        vc = vn;
    }
        
    accum = xx_vaddup_u64(vrev128_u64(accum));
    accum = vaddw_u32(accum, vo[0]);
    vo[0] = vmovn_u64(accum) & vmask;
    
    accum = vshrq_n_u64(accum,28);
    vo[1] += vmovn_u64(accum);
}

/* TODO: vectorize? */
void
p448_strong_reduce (
    p448_t *a
) { 
    word_t mask = (1ull<<28)-1;

    /* first, clear high */
    a->limb[1] += a->limb[15]>>28;
    a->limb[0] += a->limb[15]>>28;
    a->limb[15] &= mask;

    /* now the total is less than 2^448 - 2^(448-56) + 2^(448-56+8) < 2p */

    /* compute total_value - p.  No need to reduce mod p. */

    dsword_t scarry = 0;
    int i;
    for (i=0; i<16; i++) {
        scarry = scarry + a->limb[LIMBPERM(i)] - ((i==8)?mask-1:mask);
        a->limb[LIMBPERM(i)] = scarry & mask;
        scarry >>= 28;
    }

    /* uncommon case: it was >= p, so now scarry = 0 and this = x
    * common case: it was < p, so now scarry = -1 and this = x - p + 2^448
    * so let's add back in p.  will carry back off the top for 2^448.
    */

    assert(is_zero(scarry) | is_zero(scarry+1));

    word_t scarry_mask = scarry & mask;
    dword_t carry = 0;

    /* add it back */
    for (i=0; i<16; i++) {
        carry = carry + a->limb[LIMBPERM(i)] + ((i==8)?(scarry_mask&~1):scarry_mask);
        a->limb[LIMBPERM(i)] = carry & mask;
        carry >>= 28;
    }

    assert(is_zero(carry + scarry));
}

mask_t
p448_is_zero (
    const struct p448_t *a
) {
    struct p448_t b;
    p448_copy(&b,a);
    p448_strong_reduce(&b);

    uint32_t any = 0;
    int i;
    for (i=0; i<16; i++) {
        any |= b.limb[i];
    }
    return is_zero(any);
}

void
p448_serialize (
    uint8_t *serial,
    const struct p448_t *x
) {
    int i,j;
    p448_t red;
    p448_copy(&red, x);
    p448_strong_reduce(&red);
    
    for (i=0; i<8; i++) {
        uint64_t limb = red.limb[LIMBPERM(2*i)] + (((uint64_t)red.limb[LIMBPERM(2*i+1)])<<28);
        for (j=0; j<7; j++) {
            serial[7*i+j] = limb;
            limb >>= 8;
        }
        assert(limb == 0);
    }
}

mask_t
p448_deserialize (
    p448_t *x,
    const uint8_t serial[56]
) {
    int i,j;
    for (i=0; i<8; i++) {
        uint64_t out = 0;
        for (j=0; j<7; j++) {
            out |= ((uint64_t)serial[7*i+j])<<(8*j);
        }
        x->limb[LIMBPERM(2*i)] = out & ((1ull<<28)-1);
        x->limb[LIMBPERM(2*i+1)] = out >> 28;
    }
    
    /* Check for reduction.
     *
     * The idea is to create a variable ge which is all ones (rather, 56 ones)
     * if and only if the low $i$ words of $x$ are >= those of p.
     *
     * Remember p = little_endian(1111,1111,1111,1111,1110,1111,1111,1111)
     */
    uint32_t ge = -1, mask = (1ull<<28)-1;
    for (i=0; i<8; i++) {
        ge &= x->limb[LIMBPERM(i)];
    }
    
    /* At this point, ge = 1111 iff bottom are all 1111.  Now propagate if 1110, or set if 1111 */
    ge = (ge & (x->limb[LIMBPERM(8)] + 1)) | is_zero(x->limb[LIMBPERM(8)] ^ mask);
    
    /* Propagate the rest */
    for (i=9; i<16; i++) {
        ge &= x->limb[LIMBPERM(i)];
    }
    
    return ~is_zero(ge ^ mask);
}

