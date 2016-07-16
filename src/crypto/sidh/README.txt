                                        SIDH v1.0 (C Edition)
                                       =======================

The SIDH v1.0 library (C Edition) is a supersingular isogeny-based cryptography library that implements 
a post-quantum resistant Diffie-Hellman key exchange scheme. This scheme provides approximately 128 bits 
of quantum security and 192 bits of classical security. 

The library was developed by Microsoft Research for experimentation purposes. 


1. CONTENTS:
   --------

Visual Studio/SIDH/SIDH.sln    - Visual Studio 2013 solution file for compilation in Windows
Visual Studio/kex_tests/       - Test project for the key exchange
makefile                       - Makefile for compilation using the GNU GCC or clang compilers on Linux 
/                              - Library C and header files                                     
AMD64/                         - Optimized implementation of the field arithmetic for x64 platforms
generic/                       - Implementation of the field arithmetic in portable C
tests/                         - Test files
SIDH-Magma/                    - Magma files
README.txt                     - This readme file


2. MAIN FEATURES:
   -------------
   
- Support key exchange providing 128 bits of quantum security and 192 bits of classical security.
- Support a peace-of-mind hybrid key exchange mode that adds a classical elliptic curve Diffie-Hellman 
  key exchange on a high-security Montgomery curve providing 384 bits of classical ECDH security.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of 
  all operations on secret key material.
- Support for public key validation in static key exchange when private keys are used more than once.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC and clang.     
- Basic implementation of the underlying arithmetic functions using portable C to enable support on
  a wide range of platforms including x64, x86 and ARM. 
- Optimized implementation of the underlying arithmetic functions for x64 platforms with optional, 
  high-performance x64 assembly for Linux.
- Testing and benchmarking code for key exchange. See kex_tests.c.


3. SUPPORTED PLATFORMS:
   -------------------

SIDH v1.0 is supported on a wide range of platforms including x64, x86 and ARM devices running Windows 
or Linux OS. We have tested the library with Microsoft Visual Studio 2013 and 2015, GNU GCC v4.7, v4.8 
and v4.9, and clang v3.6 and v3.8. See instructions below to choose an implementation option and compile 
on one of the supported platforms.


4. USER-PROVIDED FUNCTIONS:
   -----------------------

SIDH requires the user to provide a pseudo-random generator passing random values as octets to generate 
private keys during a key exchange (see how the PRNG function, called RandomBytesFunction, is used in 
random_mod_order() in SIDH_setup.c). This function should be provided to SIDH_curve_initialize() function 
during initialization. Follow kex_tests.c (see cryptotest_kex()) as an example on how to perform this 
initialization. 

An (unsafe) example function is provided in test_extras.c for testing purposes (see random_bytes_test()). 
NOTE THAT THIS SHOULD NOT BE USED IN PRODUCTION CODE. 

Finally, the outputs of the shared secret functions are not processed by a key derivation function (e.g., 
a hash). The user is responsible for post-processing to derive cryptographic keys from the shared secret 
(e.g., see NIST Special Publication 800-108).     


5. IMPLEMENTATION OPTIONS:
   ----------------------

The following implementation options are available:

- The library contains a portable implementation (enabled by the "GENERIC" option) and an optimized
  x64 implementation. Note that non-x64 platforms are only supported by the generic implementation. 

- Optimized x64 assembly implementations enabled by the "ASM" option in Linux.

Follow the instructions in Section 6 - INSTRUCTIONS FOR WINDOWS OS or Section 7 - "INSTRUCTIONS FOR 
LINUX OS" to configure these different options.


6. INSTRUCTIONS FOR WINDOWS OS:
   ---------------------------

BUILDING THE LIBRARY WITH VISUAL STUDIO:
---------------------------------------

Open the solution file (SIDH.sln) in Visual Studio, and select one of the supported platforms as 
Platform. Then choose a configuration from the configuration menu: for x64, one can select either 
"Release" (faster) or "Generic"; for other platforms, choose "Generic".

Finally, select "Build Solution" from the "Build" menu. 

RUNNING THE TESTS:
-----------------

After building the solution file, there should be an executable file available: kex_tests.exe, to run 
tests for the key exchange. 

USING THE LIBRARY:
-----------------

After building the solution file, add the generated SIDH.lib file to the set of References for a project,
and add SIDH.h to the list of Header Files of a project.


7. INSTRUCTIONS FOR LINUX OS:
   -------------------------

BUILDING THE LIBRARY AND EXECUTING THE TESTS WITH GNU GCC OR CLANG:
------------------------------------------------------------------

To compile on Linux using GNU GCC or clang, execute the following command from the command prompt:

make ARCH=[x64/x86/ARM] CC=[gcc/clang] ASM=[TRUE/FALSE] GENERIC=[TRUE/FALSE]

After compilation, run kex_text.

For example, to compile the key exchange tests using clang and the fully optimized x64 implementation 
in assembly, execute:

make CC=clang ARCH=x64 ASM=TRUE

Whenever an unsupported configuration is applied, the following message will be displayed: #error -- 
"Unsupported configuration". For example, the use of assembly is not supported when selecting the portable 
implementation (i.e., if GENERIC=TRUE). Similarly, x86 and ARM are only supported when GENERIC=TRUE.