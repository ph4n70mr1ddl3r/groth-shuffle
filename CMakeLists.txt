cmake_minimum_required( VERSION 3.10 )

project( shuffle 
  VERSION 0.1
  DESCRIPTION "server-based poker simulation with cryptographic shuffle" )

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

include_directories(src)
include_directories(thirdparty)

add_executable(bg12_poker_server bg12_poker_server.cc ${SOURCE_FILES})
target_link_libraries(bg12_poker_server ${RELIC_LIB} gmp pthread)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g")
