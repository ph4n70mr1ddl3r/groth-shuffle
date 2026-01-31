#ifndef SHF_UTILS_H
#define SHF_UTILS_H

#include <cstdio>

namespace shf {

struct FileGuard {
    std::FILE* file;
    explicit FileGuard(std::FILE* f) : file(f) {}
    ~FileGuard() { if (file) std::fclose(file); }
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;
};

}
#endif
