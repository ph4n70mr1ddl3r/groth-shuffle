#include "parallel.h"
#include <thread>
#include <vector>
#include <algorithm>

namespace shf {

std::size_t ParallelChunks(std::size_t start, std::size_t end, std::function<void(std::size_t, std::size_t, std::size_t)> func) {
    std::size_t count = end - start;
    if (count == 0) return 0;

    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;
    if (num_threads > count) num_threads = count;

    std::vector<std::thread> threads;
    threads.reserve(num_threads);
    
    std::size_t block_size = count / num_threads;
    std::size_t remainder = count % num_threads;

    std::size_t current_start = start;

    for (unsigned int t = 0; t < num_threads; ++t) {
        std::size_t current_end = current_start + block_size + (t < remainder ? 1 : 0);
        threads.emplace_back([current_start, current_end, t, &func]() {
            func(current_start, current_end, t);
        });
        current_start = current_end;
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    return num_threads;
}

}