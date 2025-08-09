cmake_minimum_required(VERSION 3.10)
project(noise-c)
set(CMAKE_C_STANDARD 99)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

message(STATUS "Source directory is " ${CMAKE_SOURCE_DIR})
message(STATUS "Build directory is " ${CMAKE_CURRENT_BINARY_DIR})

include_directories(include)
include_directories(src)
include_directories(src/protocol)
include_directories(src/crypto/goldilocks/src/include)

#//////////////////////////
# sources 
#//////////////////////////

set(src_pro ${src_pro})
set(src_pro ${src_pro} include/noise/protocol.h)
set(src_pro ${src_pro} include/noise/protocol/constants.h)
set(src_pro ${src_pro} include/noise/protocol/names.h)
set(src_pro ${src_pro} include/noise/protocol/handshakestate.h)
set(src_pro ${src_pro} include/noise/protocol/cipherstate.h)
set(src_pro ${src_pro} include/noise/protocol/symmetricstate.h)
set(src_pro ${src_pro} include/noise/protocol/errors.h)
set(src_pro ${src_pro} include/noise/protocol/buffer.h)
set(src_pro ${src_pro} include/noise/protocol/hashstate.h)
set(src_pro ${src_pro} include/noise/protocol/dhstate.h)
set(src_pro ${src_pro} include/noise/protocol/signstate.h)
set(src_pro ${src_pro} include/noise/protocol/randstate.h)
set(src_pro ${src_pro} include/noise/protocol/util.h)

#//////////////////////////
# protocol core  
#//////////////////////////

set(src_pro ${src_pro} src/protocol/names.c)
set(src_pro ${src_pro} src/protocol/errors.c)
set(src_pro ${src_pro} src/protocol/util.c)
set(src_pro ${src_pro} src/protocol/cipherstate.c)
set(src_pro ${src_pro} src/protocol/handshakestate.c)
set(src_pro ${src_pro} src/protocol/dhstate.c)
set(src_pro ${src_pro} src/protocol/internal.c)
set(src_pro ${src_pro} src/protocol/hashstate.c)
set(src_pro ${src_pro} src/protocol/symmetricstate.c)
set(src_pro ${src_pro} src/protocol/patterns.c)
set(src_pro ${src_pro} src/protocol/rand_os.c)
set(src_pro ${src_pro} src/protocol/randstate.c)

#//////////////////////////
# reference implementation
#//////////////////////////

set(src_ref ${src_ref})
set(src_ref ${src_ref} src/backend/ref/cipher-chachapoly.c)
set(src_ref ${src_ref} src/backend/ref/dh-curve25519.c)
set(src_ref ${src_ref} src/backend/ref/dh-curve448.c)
set(src_ref ${src_ref} src/backend/ref/dh-newhope.c)
set(src_ref ${src_ref} src/backend/ref/hash-blake2s.c)
set(src_ref ${src_ref} src/backend/ref/hash-blake2b.c)
set(src_ref ${src_ref} src/backend/ref/hash-sha256.c)
set(src_ref ${src_ref} src/backend/ref/hash-sha512.c)

set(src_ref ${src_ref} src/backend/ref/cipher-aesgcm.c)

#//////////////////////////
# cryptographic backend 
#//////////////////////////

set(src_cry ${src_cry})

set(src_cry ${src_cry} src/crypto/sha2/sha256.c)
set(src_cry ${src_cry} src/crypto/sha2/sha256.h)

set(src_cry ${src_cry} src/crypto/sha2/sha512.c)
set(src_cry ${src_cry} src/crypto/sha2/sha512.h)

set(src_cry ${src_cry} src/crypto/blake2/blake2b.c)
set(src_cry ${src_cry} src/crypto/blake2/blake2b.h)
set(src_cry ${src_cry} src/crypto/blake2/blake2s.c)
set(src_cry ${src_cry} src/crypto/blake2/blake2s.h)

set(src_cry ${src_cry} src/crypto/chacha/chacha.c)
set(src_cry ${src_cry} src/crypto/chacha/chacha.h)

set(src_cry ${src_cry} src/crypto/donna/poly1305-donna-16.h)
set(src_cry ${src_cry} src/crypto/donna/poly1305-donna-32.h)
set(src_cry ${src_cry} src/crypto/donna/poly1305-donna-64.h)
set(src_cry ${src_cry} src/crypto/donna/poly1305-donna-8.h)
set(src_cry ${src_cry} src/crypto/donna/poly1305-donna.c)
set(src_cry ${src_cry} src/crypto/donna/poly1305-donna.h)

set(src_cry ${src_cry} src/crypto/aes/rijndael-alg-fst.h)
set(src_cry ${src_cry} src/crypto/aes/rijndael-alg-fst.c)

set(src_cry ${src_cry} src/crypto/ghash/ghash.c)
set(src_cry ${src_cry} src/crypto/ghash/ghash.h)

set(src_cry ${src_cry} src/crypto/newhope/newhope.h)
set(src_cry ${src_cry} src/crypto/newhope/newhope.c)
set(src_cry ${src_cry} src/crypto/newhope/poly.h)
set(src_cry ${src_cry} src/crypto/newhope/poly.c)
set(src_cry ${src_cry} src/crypto/newhope/ntt.h)
set(src_cry ${src_cry} src/crypto/newhope/ntt.c)
set(src_cry ${src_cry} src/crypto/newhope/reduce.h)
set(src_cry ${src_cry} src/crypto/newhope/reduce.c)
set(src_cry ${src_cry} src/crypto/newhope/fips202.h)
set(src_cry ${src_cry} src/crypto/newhope/fips202.c)
set(src_cry ${src_cry} src/crypto/newhope/crypto_stream_chacha20.h)
set(src_cry ${src_cry} src/crypto/newhope/crypto_stream_chacha20.c)
set(src_cry ${src_cry} src/crypto/newhope/batcher.h)
set(src_cry ${src_cry} src/crypto/newhope/batcher.c)
set(src_cry ${src_cry} src/crypto/newhope/precomp.c)
set(src_cry ${src_cry} src/crypto/newhope/error_correction.h)
set(src_cry ${src_cry} src/crypto/newhope/error_correction.c)


add_library(noise ${src_pro} ${src_ref} ${src_cry})


set_target_properties(noise PROPERTIES FOLDER "noise")
source_group("protocol" FILES ${src_pro})
source_group("ref" FILES ${src_ref})
source_group("crypto" FILES ${src_cry})


#//////////////////////////
# examples  
#//////////////////////////

include_directories(examples/echo)

set(src_srv ${src_srv})
set(src_srv ${src_srv} examples/echo/echo-server/echo-common.c)
set(src_srv ${src_srv} examples/echo/echo-server/echo-common.h)
set(src_srv ${src_srv} examples/echo/echo-server/echo-server.c)
if (MSVC)
  set(src_srv ${src_srv} examples/echo/getopt.c)
  set(src_srv ${src_srv} examples/echo/getopt.h)
endif()
add_executable(echo-server ${src_srv}) 

target_link_libraries(echo-server noise)
if(WIN32)
  target_link_libraries(echo-server ws2_32 wsock32)
endif()

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT echo-server)
