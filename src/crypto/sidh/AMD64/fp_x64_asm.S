//*******************************************************************************************
// SIDH: an efficient supersingular isogeny-based cryptography library for Diffie-Hellman key 
//       exchange providing 128 bits of quantum security and 192 bits of classical security.
//
//    Copyright (c) Microsoft Corporation. All rights reserved.
//
//
// Abstract: field arithmetic in x64 assembly for Linux 
//
//*******************************************************************************************  

.intel_syntax noprefix 

// Registers that are used for parameter passing:
#define reg_p1  rdi
#define reg_p2  rsi
#define reg_p3  rdx

// p751 + 1
#define p751p1_5   0xEEB0000000000000
#define p751p1_6   0xE3EC968549F878A8
#define p751p1_7   0xDA959B1A13F7CC76
#define p751p1_8   0x084E9867D6EBE876
#define p751p1_9   0x8562B5045CB25748
#define p751p1_10  0x0E12909F97BADC66
#define p751p1_11  0x00006FE5D541F71C

#define p751_0     0xFFFFFFFFFFFFFFFF
#define p751_5     0xEEAFFFFFFFFFFFFF
#define p751_6     0xE3EC968549F878A8
#define p751_7     0xDA959B1A13F7CC76
#define p751_8     0x084E9867D6EBE876
#define p751_9     0x8562B5045CB25748
#define p751_10    0x0E12909F97BADC66
#define p751_11    0x00006FE5D541F71C


.text
//***********************************************************************
//  Field addition
//  Operation: c [reg_p3] = a [reg_p1] + b [reg_p2]
//*********************************************************************** 
.global fpadd751_asm
fpadd751_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rcx, [reg_p1+64]
  add    r8, [reg_p2] 
  adc    r9, [reg_p2+8] 
  adc    r10, [reg_p2+16] 
  adc    r11, [reg_p2+24] 
  adc    r12, [reg_p2+32] 
  adc    r13, [reg_p2+40] 
  adc    r14, [reg_p2+48] 
  adc    r15, [reg_p2+56]
  adc    rcx, [reg_p2+64] 
  mov    rax, [reg_p1+72]
  adc    rax, [reg_p2+72] 
  mov    [reg_p3+72], rax
  mov    rax, [reg_p1+80]
  adc    rax, [reg_p2+80] 
  mov    [reg_p3+80], rax
  mov    rax, [reg_p1+88]
  adc    rax, [reg_p2+88] 
  mov    [reg_p3+88], rax

  movq   rax, p751_0
  sub    r8, rax
  sbb    r9, rax
  sbb    r10, rax
  sbb    r11, rax
  sbb    r12, rax
  movq   rax, p751_5
  sbb    r13, rax
  movq   rax, p751_6
  sbb    r14, rax
  movq   rax, p751_7
  sbb    r15, rax
  movq   rax, p751_8
  sbb    rcx, rax
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rcx
  mov    r8, [reg_p3+72]
  mov    r9, [reg_p3+80]
  mov    r10, [reg_p3+88]
  movq   rax, p751_9
  sbb    r8, rax
  movq   rax, p751_10
  sbb    r9, rax
  movq   rax, p751_11
  sbb    r10, rax
  mov    [reg_p3+72], r8
  mov    [reg_p3+80], r9
  mov    [reg_p3+88], r10
  movq   rax, 0
  sbb    rax, 0
  
  mov    r8, p751_0
  and    r8, rax
  movq   r9, p751_5
  and    r9, rax
  movq   r10, p751_6
  and    r10, rax
  movq   r11, p751_7
  and    r11, rax
  movq   r12, p751_8
  and    r12, rax
  movq   r13, p751_9
  and    r13, rax
  movq   r14, p751_10
  and    r14, rax
  movq   r15, p751_11
  and    r15, rax
  
  mov    rax, [reg_p3]
  add    rax, r8  
  mov    [reg_p3], rax
  mov    rax, [reg_p3+8]
  adc    rax, r8 
  mov    [reg_p3+8], rax  
  mov    rax, [reg_p3+16]
  adc    rax, r8 
  mov    [reg_p3+16], rax  
  mov    rax, [reg_p3+24]  
  adc    rax, r8 
  mov    [reg_p3+24], rax 
  mov    rax, [reg_p3+32]  
  adc    rax, r8 
  mov    [reg_p3+32], rax 
  mov    rax, [reg_p3+40]    
  adc    rax, r9 
  mov    [reg_p3+40], rax 
  mov    rax, [reg_p3+48]   
  adc    rax, r10 
  mov    [reg_p3+48], rax 
  mov    rax, [reg_p3+56]   
  adc    rax, r11  
  mov    [reg_p3+56], rax 
  mov    rax, [reg_p3+64]  
  adc    rax, r12 
  mov    [reg_p3+64], rax 
  mov    rax, [reg_p3+72]   
  adc    rax, r13 
  mov    [reg_p3+72], rax 
  mov    rax, [reg_p3+80]   
  adc    rax, r14 
  mov    [reg_p3+80], rax 
  mov    rax, [reg_p3+88]   
  adc    rax, r15
  mov    [reg_p3+88], rax 
  
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret


//***********************************************************************
//  Field subtraction
//  Operation: c [reg_p3] = a [reg_p1] - b [reg_p2]
//*********************************************************************** 
.global fpsub751_asm
fpsub751_asm:
  push   r12
  push   r13
  push   r14
  push   r15
  
  mov    r8, [reg_p1]
  mov    r9, [reg_p1+8]
  mov    r10, [reg_p1+16]
  mov    r11, [reg_p1+24]
  mov    r12, [reg_p1+32]
  mov    r13, [reg_p1+40]
  mov    r14, [reg_p1+48]
  mov    r15, [reg_p1+56] 
  mov    rcx, [reg_p1+64]
  sub    r8, [reg_p2] 
  sbb    r9, [reg_p2+8] 
  sbb    r10, [reg_p2+16] 
  sbb    r11, [reg_p2+24] 
  sbb    r12, [reg_p2+32] 
  sbb    r13, [reg_p2+40] 
  sbb    r14, [reg_p2+48] 
  sbb    r15, [reg_p2+56]
  sbb    rcx, [reg_p2+64] 
  mov    [reg_p3], r8
  mov    [reg_p3+8], r9
  mov    [reg_p3+16], r10
  mov    [reg_p3+24], r11
  mov    [reg_p3+32], r12
  mov    [reg_p3+40], r13
  mov    [reg_p3+48], r14
  mov    [reg_p3+56], r15
  mov    [reg_p3+64], rcx
  mov    rax, [reg_p1+72]
  sbb    rax, [reg_p2+72] 
  mov    [reg_p3+72], rax
  mov    rax, [reg_p1+80]
  sbb    rax, [reg_p2+80] 
  mov    [reg_p3+80], rax
  mov    rax, [reg_p1+88]
  sbb    rax, [reg_p2+88] 
  mov    [reg_p3+88], rax
  movq   rax, 0
  sbb    rax, 0
  
  mov    r8, p751_0
  and    r8, rax
  movq   r9, p751_5
  and    r9, rax
  movq   r10, p751_6
  and    r10, rax
  movq   r11, p751_7
  and    r11, rax
  movq   r12, p751_8
  and    r12, rax
  movq   r13, p751_9
  and    r13, rax
  movq   r14, p751_10
  and    r14, rax
  movq   r15, p751_11
  and    r15, rax
  
  mov    rax, [reg_p3]
  add    rax, r8  
  mov    [reg_p3], rax
  mov    rax, [reg_p3+8]
  adc    rax, r8 
  mov    [reg_p3+8], rax  
  mov    rax, [reg_p3+16]
  adc    rax, r8 
  mov    [reg_p3+16], rax  
  mov    rax, [reg_p3+24]  
  adc    rax, r8 
  mov    [reg_p3+24], rax 
  mov    rax, [reg_p3+32]  
  adc    rax, r8 
  mov    [reg_p3+32], rax 
  mov    rax, [reg_p3+40]    
  adc    rax, r9 
  mov    [reg_p3+40], rax 
  mov    rax, [reg_p3+48]   
  adc    rax, r10 
  mov    [reg_p3+48], rax 
  mov    rax, [reg_p3+56]   
  adc    rax, r11  
  mov    [reg_p3+56], rax 
  mov    rax, [reg_p3+64]  
  adc    rax, r12 
  mov    [reg_p3+64], rax 
  mov    rax, [reg_p3+72]   
  adc    rax, r13 
  mov    [reg_p3+72], rax 
  mov    rax, [reg_p3+80]   
  adc    rax, r14 
  mov    [reg_p3+80], rax 
  mov    rax, [reg_p3+88]   
  adc    rax, r15
  mov    [reg_p3+88], rax 
  
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret


//***********************************************************************
//  Integer multiplication
//  Based on comba method
//  Operation: c [reg_p3] = a [reg_p1] * b [reg_p2]
//  NOTE: a=c or b=c are not allowed
//*********************************************************************** 
.global mul751_asm
mul751_asm:
  push   r12
  push   r13
  mov    rcx, reg_p3 

  mov    r11, [reg_p1]
  mov    rax, [reg_p2] 
  mul    r11
  xor    r9, r9
  mov    [rcx], rax       // c0
  mov    r8, rdx

  mov    rax, [reg_p2+8]
  mul    r11
  xor    r10, r10
  add    r8, rax
  adc    r9, rdx

  mov    r12, [reg_p1+8] 
  mov    rax, [reg_p2] 
  mul    r12
  add    r8, rax
  mov    [rcx+8], r8      // c1 
  adc    r9, rdx
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+16] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p2] 
  mov    rax, [reg_p1+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+8] 
  mul    r12
  add    r9, rax
  mov    [rcx+16], r9     // c2 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+24] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p1+24] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+16] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r10, rax
  mov    [rcx+24], r10    // c3 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+32] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p2] 
  mov    rax, [reg_p1+32] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+24] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r8, rax
  mov    [rcx+32], r8     // c4 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+40] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p2] 
  mov    rax, [reg_p1+40] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+32] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r9, rax
  mov    [rcx+40], r9     // c5 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+48] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+8] 
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p2+8] 
  mov    rax, [reg_p1+40] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r10, rax
  mov    [rcx+48], r10    // c6 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+56] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+40] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p2+8] 
  mov    rax, [reg_p1+48] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+48] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2] 
  mul    r13
  add    r8, rax
  mov    [rcx+56], r8     // c7 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+64] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+56] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+40] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+32]
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+64] 
  mov    rax, [reg_p2] 
  mul    r13
  add    r9, rax
  mov    [rcx+64], r9     // c8 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+72] 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+64] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+40]
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+72] 
  mov    rax, [reg_p2] 
  mul    r13
  add    r10, rax
  mov    [rcx+72], r10    // c9 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+80] 
  mul    r11
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    rax, [reg_p2+72] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+64] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+48]
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+40]
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2] 
  mul    r13
  add    r8, rax
  mov    [rcx+80], r8     // c10 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+88] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    rax, [reg_p2+80] 
  mul    r12
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+72] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+64] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+56]
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+40]
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+48]
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2] 
  mul    r13
  add    r9, rax
  mov    [rcx+88], r9     // c11 
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+8] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p2+88] 
  mul    r12
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+72] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+64]
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+40]
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+56]
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r10, rax
  mov    [rcx+96], r10    // c12 
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+16] 
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+16] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p2+32] 
  mov    rax, [reg_p1+72] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p2+72]
  mov    rax, [reg_p1+32] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+40]
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+64]
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r8, rax
  mov    [rcx+104], r8    // c13 
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+24] 
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+24] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+40] 
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+72]
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+48]
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+64]
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r9, rax
  mov    [rcx+112], r9    // c14
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+32] 
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+32] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+40] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+72]
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p2+64] 
  mov    rax, [reg_p1+56]
  mul    r13
  add    r10, rax
  mov    [rcx+120], r10   // c15
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p1+64] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+40] 
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+40] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+72]
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r8, rax
  mov    [rcx+128], r8    // c16
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+48] 
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+48] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r13, [reg_p2+72] 
  mov    rax, [reg_p1+64] 
  mul    r13
  add    r9, rax
  mov    [rcx+136], r9    // c17
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, [reg_p1+72] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+56] 
  mov    rax, [reg_p2+88] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+56] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+64] 
  mov    rax, [reg_p2+80] 
  mul    r13
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    r13, [reg_p1+80] 
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r10, rax
  mov    [rcx+144], r10   // c18
  adc    r8, rdx 
  adc    r9, 0
  
  xor    r10, r10
  mov    rax, [reg_p2+72] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r12, [reg_p2+88] 
  mov    rax, [reg_p1+64] 
  mul    r12
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p1+88] 
  mov    rax, [reg_p2+64] 
  mul    r13
  add    r8, rax
  adc    r9, rdx 
  adc    r10, 0
  
  mov    r13, [reg_p2+80] 
  mov    rax, [reg_p1+72] 
  mul    r13
  add    r8, rax
  mov    [rcx+152], r8    // c19
  adc    r9, rdx 
  adc    r10, 0
  
  xor    r8, r8
  mov    rax, [reg_p1+80] 
  mul    r13
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r11, [reg_p1+72] 
  mov    rax, [reg_p2+88] 
  mul    r11
  add    r9, rax
  adc    r10, rdx 
  adc    r8, 0
  
  mov    r11, [reg_p1+88] 
  mov    rax, [reg_p2+72] 
  mul    r11
  add    r9, rax
  mov    [rcx+160], r9    // c20
  adc    r10, rdx 
  adc    r8, 0
  
  xor    r9, r9
  mov    rax, r13 
  mul    r11
  add    r10, rax
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, [reg_p1+80] 
  mul    r12
  add    r10, rax
  mov    [rcx+168], r10   // c21
  adc    r8, rdx 
  adc    r9, 0
  
  mov    rax, r12 
  mul    r11
  add    r8, rax
  mov    [rcx+176], r8    // c22
  adc    r9, rdx 
  mov    [rcx+184], r9    // c23

  pop    r13
  pop    r12
  ret

  
//***********************************************************************
//  Montgomery reduction
//  Based on comba method
//  Operation: c [reg_p2] = a [reg_p1]
//  NOTE: a=c is not allowed
//*********************************************************************** 
.global rdc751_asm
rdc751_asm:
  push   r12
  push   r13 
  push   r14 
  push   r15 

  mov    r11, [reg_p1]
  movq   rax, p751p1_5 
  mul    r11
  xor    r8, r8
  add    rax, [reg_p1+40]
  mov    [reg_p2+40], rax    // z5
  adc    r8, rdx
  
  xor    r9, r9
  movq   rax, p751p1_6 
  mul    r11
  xor    r10, r10
  add    r8, rax
  adc    r9, rdx

  mov    r12, [reg_p1+8]
  movq   rax, p751p1_5 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+48]
  mov    [reg_p2+48], r8    // z6
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_7 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_6 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    r13, [reg_p1+16]
  movq   rax, p751p1_5 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+56]
  mov    [reg_p2+56], r9    // z7
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_8 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r14, [reg_p1+24]
  movq   rax, p751p1_5 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+64]
  mov    [reg_p2+64], r10   // z8
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_9 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_6 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r15, [reg_p1+32]
  movq   rax, p751p1_5 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+72]
  mov    [reg_p2+72], r8    // z9
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_10 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_9 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_8 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_7 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_6 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rcx, [reg_p2+40]
  movq   rax, p751p1_5 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+80]
  mov    [reg_p2+80], r9    // z10
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_8 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r11, [reg_p2+48]
  movq   rax, p751p1_5 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+88]
  mov    [reg_p2+88], r10    // z11
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_10 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_9 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_6 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r12, [reg_p2+56]
  movq   rax, p751p1_5 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+96]
  mov    [reg_p2], r8        // z0
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_11 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_10 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_9
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_8
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_7
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0

  movq   rax, p751p1_6
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    r13, [reg_p2+64]
  movq   rax, p751p1_5
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+104]
  mov    [reg_p2+8], r9      // z1
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_8 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  mov    r14, [reg_p2+72]
  movq   rax, p751p1_5 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+112]
  mov    [reg_p2+16], r10    // z2
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_10 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_9 
  mul    r11
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_6 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  mov    r15, [reg_p2+80]
  movq   rax, p751p1_5 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+120]
  mov    [reg_p2+24], r8     // z3
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_11 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_10 
  mul    r11
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_9 
  mul    r12
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_8 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_7 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_6 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  mov    rcx, [reg_p2+88]
  movq   rax, p751p1_5 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+128]
  mov    [reg_p2+32], r9     // z4
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r11
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r12
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    r13
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_8 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_7 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_6 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+136]
  mov    [reg_p2+40], r10    // z5
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r12
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_10 
  mul    r13
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_9 
  mul    r14
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_8 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  
  movq   rax, p751p1_7 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+144]
  mov    [reg_p2+48], r8     // z6
  adc    r9, 0
  adc    r10, 0
  
  xor    r8, r8
  movq   rax, p751p1_11 
  mul    r13
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_10 
  mul    r14
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_9 
  mul    r15
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  
  movq   rax, p751p1_8 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  adc    r8, 0
  add    r9, [reg_p1+152]
  mov    [reg_p2+56], r9     // z7
  adc    r10, 0
  adc    r8, 0
  
  xor    r9, r9
  movq   rax, p751p1_11 
  mul    r14
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_10 
  mul    r15
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  
  movq   rax, p751p1_9 
  mul    rcx
  add    r10, rax
  adc    r8, rdx
  adc    r9, 0
  add    r10, [reg_p1+160]
  mov    [reg_p2+64], r10    // z8
  adc    r8, 0
  adc    r9, 0
  
  xor    r10, r10
  movq   rax, p751p1_11 
  mul    r15
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0

  movq   rax, p751p1_10 
  mul    rcx
  add    r8, rax
  adc    r9, rdx
  adc    r10, 0
  add    r8, [reg_p1+168]    // z9
  adc    r9, 0
  adc    r10, 0
  
  movq   rax, p751p1_11 
  mul    rcx
  add    r9, rax
  adc    r10, rdx
  add    r9, [reg_p1+176]    // z10
  adc    r10, 0  
  add    r10, [reg_p1+184]   // z11

// Final, constant-time correction
  mov    rax, [reg_p2]
  movq   rcx, p751_0  
  sub    rax, rcx 
  mov    [reg_p2], rax
  mov    rax, [reg_p2+8]
  sbb    rax, rcx 
  mov    [reg_p2+8], rax
  mov    rax, [reg_p2+16]
  sbb    rax, rcx
  mov    [reg_p2+16], rax
  mov    r12, [reg_p2+24]
  sbb    r12, rcx
  mov    r13, [reg_p2+32]
  sbb    r13, rcx
  mov    r14, [reg_p2+40]
  movq   rcx, p751_5  
  sbb    r14, rcx
  mov    r15, [reg_p2+48]
  movq   rcx, p751_6  
  sbb    r15, rcx
  mov    rax, [reg_p2+56]
  movq   rcx, p751_7  
  sbb    rax, rcx
  mov    rdx, [reg_p2+64]
  movq   rcx, p751_8  
  sbb    rdx, rcx
  movq   rcx, p751_9  
  sbb    r8, rcx
  movq   rcx, p751_10  
  sbb    r9, rcx
  movq   rcx, p751_11  
  sbb    r10, rcx
  movq   rcx, 0
  sbb    rcx, 0
  
  movq   r11, p751_0  
  and    rcx, r11
  mov    r11, [reg_p2]
  add    r11, rcx  
  mov    [reg_p2], r11  
  mov    r11, [reg_p2+8]
  adc    r11, rcx  
  mov    [reg_p2+8], r11  
  mov    r11, [reg_p2+16]
  adc    r11, rcx  
  mov    [reg_p2+16], r11  
  adc    r12, rcx  
  mov    [reg_p2+24], r12   
  adc    r13, rcx  
  mov    [reg_p2+32], r13 
  movq   r11, 0
  adc    r11, 0 
  movq   r12, p751_5   
  and    r12, rcx
  shr    r11, 1
  adc    r14, r12
  mov    [reg_p2+40], r14 
  adc    r11, 0 
  movq   r12, p751_6   
  and    r12, rcx
  shr    r11, 1
  adc    r15, r12
  mov    [reg_p2+48], r15 
  adc    r11, 0 
  movq   r12, p751_7   
  and    r12, rcx
  shr    r11, 1
  adc    rax, r12
  mov    [reg_p2+56], rax  
  adc    r11, 0 
  movq   r12, p751_8   
  and    r12, rcx
  shr    r11, 1
  adc    rdx, r12
  mov    [reg_p2+64], rdx  
  adc    r11, 0 
  movq   r12, p751_9   
  and    r12, rcx
  shr    r11, 1
  adc    r8, r12
  mov    [reg_p2+72], r8  
  adc    r11, 0 
  movq   r12, p751_10   
  and    r12, rcx
  shr    r11, 1
  adc    r9, r12
  mov    [reg_p2+80], r9  
  adc    r11, 0 
  movq   r12, p751_11   
  and    r12, rcx
  shr    r11, 1
  adc    r10, r12
  mov    [reg_p2+88], r10 
  
  pop    r15
  pop    r14
  pop    r13
  pop    r12
  ret