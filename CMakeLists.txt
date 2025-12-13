cmake_minimum_required( VERSION 3.10 )

project( shuffle 
  VERSION 0.1
  DESCRIPTION "simple implementation of a cryptographic Shuffle" )

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -pedantic -Werror")

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
    test/test_curve.cc
    test/test_hash.cc
    test/test_zkp.cc
    test/test_shuffler.cc)

include_directories(src)
include_directories(thirdparty)

set(TEST_EXEC tests.x)
set(DEMO_EXEC holdem_demo.x)

set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g" )
add_compile_definitions( TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/test/data/" )
include( CTest )

find_package( Catch2 QUIET )
if(Catch2_FOUND)
  set(CATCH2_TARGET Catch2::Catch2)
  include(Catch OPTIONAL)
else()
  add_library(catch2_header INTERFACE)
  add_library(Catch2::Catch2 ALIAS catch2_header)
  target_include_directories(catch2_header INTERFACE "${CMAKE_SOURCE_DIR}/thirdparty")
  set(CATCH2_TARGET Catch2::Catch2)
endif()

add_executable( ${TEST_EXEC} ${SOURCE_FILES} ${TEST_SOURCE_FILES} )
add_executable( ${DEMO_EXEC} ${SOURCE_FILES} demo/holdem_demo.cc )
add_executable( server_demo.x ${SOURCE_FILES} demo/server_demo.cc )
target_link_libraries( ${TEST_EXEC}
  ${CATCH2_TARGET}
  ${RELIC_LIB}
  gmp
  pthread )
target_link_libraries( ${DEMO_EXEC}
  ${RELIC_LIB}
  gmp
  pthread )
target_link_libraries( server_demo.x
  ${RELIC_LIB}
  gmp
  pthread )
if(COMMAND catch_discover_tests)
  catch_discover_tests( ${TEST_EXEC} )
else()
  add_test(NAME shuffle_tests COMMAND ${TEST_EXEC})
endif()
