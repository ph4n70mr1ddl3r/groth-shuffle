cmake_minimum_required( VERSION 3.10 )

project( shuffle 
  VERSION 0.1
  DESCRIPTION "simple implementation of a cryptographic Shuffle" )

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -pedantic -Werror")

# Relic library path
set(RELIC_LIB "${CMAKE_SOURCE_DIR}/thirdparty/lib/librelic_s.a")

set(SOURCE_FILES
    src/cipher.cc
    src/commit.cc
    src/curve.cc
    src/hash.cc
    src/prg.cc
    src/shuffler.cc
    src/zkp.cc)

set(TEST_SOURCE_FILES
    test/test_main.cc
    test/test_security.cc)

include_directories(src)
include_directories(thirdparty)

set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g" )

# Mediated Demo Executable
add_executable( mediated_demo.x ${SOURCE_FILES} demo/mediated_demo.cc )
target_link_libraries( mediated_demo.x
  ${RELIC_LIB}
  gmp
  pthread )

add_executable( tests.x ${SOURCE_FILES} ${TEST_SOURCE_FILES} )
target_link_libraries( tests.x
  ${RELIC_LIB}
  gmp
  pthread )