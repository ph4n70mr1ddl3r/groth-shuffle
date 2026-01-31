#ifndef SHF_PRG_H
#define SHF_PRG_H

#include <cstring>
#include <wmmintrin.h>

#include <cstdint>
#include <vector>

namespace shf {

void secure_clear(void* ptr, std::size_t size);

class Prg {
 public:
  static constexpr std::size_t BlockSize() { return sizeof(__m128i); };

  static constexpr std::size_t SeedSize() { return BlockSize(); };

  Prg();

  Prg(const uint8_t* seed);

  void Fill(uint8_t* dest, std::size_t n);

  template <typename T>
  void Fill(std::vector<T>& to_fill) {
    const auto n = to_fill.size();
    const auto data_size = sizeof(T) * n;
    std::vector<uint8_t> data(data_size);
    Fill(data.data(), data_size);
    for (std::size_t i = 0; i < n; ++i) {
      std::memcpy(&to_fill[i], data.data() + i * sizeof(T), sizeof(T));
    }
  }

 private:
  void Update();
  void Init();

  uint8_t m_seed[sizeof(__m128i)] = {0};
  long m_counter = 0;
  __m128i m_state[11];
};

}  // namespace shf

#endif  // SHF_PRG_H
