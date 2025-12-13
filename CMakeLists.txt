cmake_minimum_required( VERSION 3.10 )

project( shuffle 
  VERSION 0.1
  DESCRIPTION "simple implementation of a cryptographic Shuffle" )

set(CMAKE_CXX_STANDARD 17)
if(EMSCRIPTEN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Werror")
  set(ARITH "easy" CACHE STRING "Arithmetic backend" FORCE)
  set(MULTI "" CACHE STRING "Multi-threading support" FORCE)
  set(WSIZE 32 CACHE INTEGER "Word size" FORCE)
  set(OPSYS "NONE" CACHE STRING "Operating system" FORCE)
  set(ARCH "NONE" CACHE STRING "Architecture" FORCE)
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -pedantic -Werror")
endif()

# --- Relic Configuration ---
# We configure Relic BEFORE adding the subdirectory so it picks up our preferences.

set(MULTI "PTHREAD" CACHE STRING "Multi-threading support")
set(WSIZE 64 CACHE INTEGER "Word size")
set(ALLOC "AUTO" CACHE STRING "Allocation method")

# Arithmetic backend: Use "easy" for portability/Wasm (no GMP dependency).
set(ARITH "easy" CACHE STRING "Arithmetic backend")

# Curve support
set(FP_PRIME 256 CACHE INTEGER "Prime field size")
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
    src/prg.cc
    src/shuffler.cc
    src/zkp.cc)

set(TEST_SOURCE_FILES
    test/test_main.cc
    test/test_security.cc)

include_directories(src)
# include_directories(thirdparty) # No longer needed for pre-built libs

# --- Targets ---

# Mediated Demo
add_executable( mediated_demo.x ${SOURCE_FILES} demo/mediated_demo.cc )
# Link against the 'relic_s' static library target defined by Relic's CMake
target_link_libraries( mediated_demo.x
  relic_s
  pthread )

# Tests
add_executable( tests.x ${SOURCE_FILES} ${TEST_SOURCE_FILES} )
target_link_libraries( tests.x
  relic_s
  pthread )

if(EMSCRIPTEN)
    add_executable( groth_shuffle_js src/js_bindings.cc ${SOURCE_FILES} )
    target_link_libraries( groth_shuffle_js relic_s )
    set_target_properties(groth_shuffle_js PROPERTIES LINK_FLAGS 
        "--bind -sMODULARIZE=1 -sEXPORT_NAME='GrothShuffle' -sALLOW_MEMORY_GROWTH=1 -sWASM=1 -sDISABLE_EXCEPTION_CATCHING=0 -g0 -O3 -Wno-limited-postlink-optimizations"
    )
endif()
