#ifndef SHF_PRG_H
#define SHF_PRG_H

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

namespace shf {

class Prg {
 public:
  static constexpr std::size_t BlockSize() { return 16; };

  static constexpr std::size_t SeedSize() { return BlockSize(); };

  Prg();

  Prg(const uint8_t* seed);

  void Fill(uint8_t* dest, std::size_t n);

  template <typename T>
  void Fill(std::vector<T>& to_fill) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Prg::Fill(std::vector<T>&) requires trivially copyable T");
    const auto data_size = sizeof(T) * to_fill.size();
    Fill(reinterpret_cast<uint8_t*>(to_fill.data()), data_size);
  }

 private:
  void Update();
  void Init();

  uint8_t m_seed[16] = {0};
  long m_counter = 0;
  alignas(16) uint8_t m_state[11 * 16];
};

}  // namespace shf

#endif  // SHF_PRG_H
