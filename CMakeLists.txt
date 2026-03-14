cmake_minimum_required(VERSION 3.10)

project(shuffle
  VERSION 0.1
  DESCRIPTION "server-based poker simulation with cryptographic shuffle"
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -Wall -Wextra -pedantic -Werror -Wshadow -Wundef -Wcast-align -Wunused")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG -fstack-protector-strong -D_FORTIFY_SOURCE=2")

set(THIRDPARTY_DIR "${CMAKE_SOURCE_DIR}/thirdparty")
set(RELIC_LIB "${THIRDPARTY_DIR}/lib/librelic_s.a")
set(Gmp gmp)
set(pthread pthread)

set(SOURCE_FILES
    src/cipher.cc
    src/commit.cc
    src/curve.cc
    src/hash.cc
    src/prg.cc
    src/shuffler.cc
    src/zkp.cc
)

add_executable(bg12_poker_server bg12_poker_server.cc ${SOURCE_FILES})
target_include_directories(bg12_poker_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${THIRDPARTY_DIR})
target_link_libraries(bg12_poker_server PRIVATE
    ${RELIC_LIB}
    ${Gmp}
    ${pthread})

option(BUILD_TESTS "Build test suite" OFF)

if(BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v3.4.0
  )
  FetchContent_MakeAvailable(catch2)

  add_executable(tests
    test/test_shuffler.cc
    test/test_zkp.cc
    test/test_curve.cc
    test/test_hash.cc
    test/test_main.cc
    ${SOURCE_FILES})
  target_include_directories(tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${THIRDPARTY_DIR})
  target_link_libraries(tests PRIVATE
    ${RELIC_LIB}
    ${Gmp}
    ${pthread}
    Catch2::Catch2WithMain)
endif()
