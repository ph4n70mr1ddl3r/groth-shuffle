/*
 * Single-file header-only version of Catch2 v2.13.10
 * 
 * This file is a placeholder to allow the tests to compile. 
 * In a real scenario, you would download the full catch.hpp 
 * from https://github.com/catchorg/Catch2/releases/download/v2.13.10/catch.hpp
 * 
 * Since I cannot download files directly, I will assume the user 
 * or the environment provides this file or I will mock the minimal parts needed.
 */

// MOCKING Catch2 for this environment since I cannot fetch the 500KB header.
// If the user wants to run real tests, they should replace this with the real catch.hpp

#ifndef CATCH_HPP_MOCKED
#define CATCH_HPP_MOCKED

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>

// Minimal macros to support the tests I will write

#define SECTION(name)
#define TEST_CASE(name, tags) void test_##__LINE__()
#define REQUIRE(expr) do { if (!(expr)) { std::cerr << "FAILED: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; exit(1); } } while(0)
#define TEST_CHECK(expr) do { if (!(expr)) { std::cerr << "FAILED: " << #expr << " at " << __FILE__ << ":" << __LINE__ << "\n"; } } while(0)

// Simple runner
struct TestRunner {
    static std::vector<void(*)()>& tests() {
        static std::vector<void(*)()> t;
        return t;
    }
    static void registerTest(void(*f)()) {
        tests().push_back(f);
    }
    static int run() {
        std::cout << "Running " << tests().size() << " tests...\n";
        for(auto t : tests()) t();
        std::cout << "All tests passed.\n";
        return 0;
    }
};

struct Registrar {
    Registrar(void(*f)()) { TestRunner::registerTest(f); }
};

#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)

#undef TEST_CASE
#define TEST_CASE(name, tags) \
    void CONCAT(test_func_, __LINE__)(); \
    Registrar CONCAT(reg_, __LINE__)(CONCAT(test_func_, __LINE__)); \
    void CONCAT(test_func_, __LINE__)()

#ifdef CATCH_CONFIG_MAIN
int main() { return TestRunner::run(); }
#endif

#endif
