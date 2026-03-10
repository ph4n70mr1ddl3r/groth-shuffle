#ifndef SHF_PRG_H
#define SHF_PRG_H

#include <cstring>
#include <type_traits>
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

  ~Prg() { secure_clear(m_seed, SeedSize()); }

  Prg(const uint8_t* seed);

  void Fill(uint8_t* dest, std::size_t n);

  template <typename T>
  void Fill(std::vector<T>& to_fill) {
    static_assert(std::is_trivially_copyable<T>::value, "T must be trivially copyable");
    Fill(reinterpret_cast<uint8_t*>(to_fill.data()), sizeof(T) * to_fill.size());
  }

 private:
  void Update();
  void Init();

  uint8_t m_seed[sizeof(__m128i)] = {0};
  uint64_t m_counter = 0;
  __m128i m_state[11];
};

}  // namespace shf

#endif  // SHF_PRG_H
