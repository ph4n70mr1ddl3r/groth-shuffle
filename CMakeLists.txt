cmake_minimum_required( VERSION 3.10 )

project( shuffle 
  VERSION 0.1
  DESCRIPTION "simple implementation of a cryptographic Shuffle" )

set(CMAKE_CXX_STANDARD 17)
include(CTest)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -pedantic -Werror")

# --- Relic Configuration ---
# We configure Relic BEFORE adding the subdirectory so it picks up our preferences.

set(MULTI "PTHREAD" CACHE STRING "Multi-threading support")
set(WSIZE "64" CACHE STRING "Word size")
set(ALLOC "AUTO" CACHE STRING "Allocation method")

# Arithmetic backend: Use "easy" for portability (no GMP dependency).
set(ARITH "easy" CACHE STRING "Arithmetic backend")

# Curve support
set(FP_PRIME "256" CACHE STRING "Prime field size")
set(EC_METHD "PRIME" CACHE STRING "Elliptic curve method")
# Required for P-256 support
set(EC_PLAIN ON CACHE BOOL "Enable ordinary elliptic curves") 

# Misc
set(QUIET ON CACHE BOOL "Quiet build")
set(TESTS OFF CACHE BOOL "Disable Relic tests")
set(BENCH OFF CACHE BOOL "Disable Relic benchmarks")

# Add Relic source
# Assumes 'thirdparty/relic' contains the source code
add_subdirectory(thirdparty/relic)

# Relic include directories are exposed by the target, but sometimes we need explicit access
include_directories(thirdparty/relic/include)
include_directories(${CMAKE_BINARY_DIR}/thirdparty/relic/include) # generated headers

# --- Project Source ---

set(SOURCE_FILES
    src/cipher.cc
    src/commit.cc
    src/curve.cc
    src/hash.cc
    src/parallel.cc
    src/prg.cc
    src/shuffler.cc
    src/zkp.cc)

set(TEST_SOURCE_FILES
    test/test_main.cc
    test/test_security.cc)

include_directories(src)
# include_directories(thirdparty) # No longer needed for pre-built libs

# --- Targets ---

# Detailed Mediated Demo
add_executable( shuffle_simulation.x ${SOURCE_FILES} demo/server_mediated_detailed.cc )
target_link_libraries( shuffle_simulation.x
  relic_s
  pthread )

# Tests
add_executable( tests.x ${SOURCE_FILES} ${TEST_SOURCE_FILES} )
target_link_libraries( tests.x
  relic_s
  pthread )
if(BUILD_TESTING)
  add_test(NAME shuffle_tests COMMAND tests.x)
endif()


