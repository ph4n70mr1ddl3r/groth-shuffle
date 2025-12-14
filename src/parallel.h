#pragma once
#include <functional>
#include <cstddef>

namespace shf {
    // Executes func in parallel over range [start, end).
    // func receives (start_index, end_index, thread_index).
    // thread_index is 0 to num_threads-1.
    // returns number of threads used.
    std::size_t ParallelChunks(std::size_t start, std::size_t end, std::function<void(std::size_t, std::size_t, std::size_t)> func);
}