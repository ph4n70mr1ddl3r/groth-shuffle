#include "prg.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <cpuid.h>
#define HAS_CPUID 1
#else
#define HAS_CPUID 0
#endif

namespace {
bool CheckAesNiSupport() {
#if HAS_CPUID
    uint32_t eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AES) != 0;
    }
#endif
    return false;
}

bool g_aes_ni_available = CheckAesNiSupport();
}

void shf::secure_clear(void* ptr, std::size_t size) {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) *p++ = 0;
}

/* https://github.com/sebastien-riou/aes-brute-force */

#define DO_ENC_BLOCK(m, k)              \
  do {                                  \
    m = _mm_xor_si128(m, k[0]);         \
    m = _mm_aesenc_si128(m, k[1]);      \
    m = _mm_aesenc_si128(m, k[2]);      \
    m = _mm_aesenc_si128(m, k[3]);      \
    m = _mm_aesenc_si128(m, k[4]);      \
    m = _mm_aesenc_si128(m, k[5]);      \
    m = _mm_aesenc_si128(m, k[6]);      \
    m = _mm_aesenc_si128(m, k[7]);      \
    m = _mm_aesenc_si128(m, k[8]);      \
    m = _mm_aesenc_si128(m, k[9]);      \
    m = _mm_aesenclast_si128(m, k[10]); \
  } while (0)

#define AES_128_key_exp(k, rcon) \
  aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

inline static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

inline static void aes128_load_key(const uint8_t* enc_key, __m128i* key_schedule) {
  key_schedule[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc_key));
  key_schedule[1] = AES_128_key_exp(key_schedule[0], 0x01);
  key_schedule[2] = AES_128_key_exp(key_schedule[1], 0x02);
  key_schedule[3] = AES_128_key_exp(key_schedule[2], 0x04);
  key_schedule[4] = AES_128_key_exp(key_schedule[3], 0x08);
  key_schedule[5] = AES_128_key_exp(key_schedule[4], 0x10);
  key_schedule[6] = AES_128_key_exp(key_schedule[5], 0x20);
  key_schedule[7] = AES_128_key_exp(key_schedule[6], 0x40);
  key_schedule[8] = AES_128_key_exp(key_schedule[7], 0x80);
  key_schedule[9] = AES_128_key_exp(key_schedule[8], 0x1B);
  key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

inline static void aes128_enc(__m128i* key_schedule, const uint8_t* pt, uint8_t* ct) {
  __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pt));
  DO_ENC_BLOCK(m, key_schedule);
  _mm_storeu_si128(reinterpret_cast<__m128i*>(ct), m);
}

shf::Prg::Prg() {
  if (!g_aes_ni_available) {
    throw std::runtime_error("AES-NI instruction set not available on this CPU");
  }
  std::random_device rd;
  for (std::size_t i = 0; i < SeedSize(); ++i) {
    m_seed[i] = static_cast<uint8_t>(rd());
  }
  Init();
}

shf::Prg::Prg(const uint8_t* seed) {
  if (!g_aes_ni_available) {
    throw std::runtime_error("AES-NI instruction set not available on this CPU");
  }
  if (seed == nullptr) {
    throw std::invalid_argument("seed cannot be null");
  }
  std::memcpy(m_seed, seed, SeedSize());
  Init();
}

static constexpr uint64_t kMaskPrefix = 0x0123456789ABCDEFULL;

static inline __m128i CreateMask(const uint64_t counter) {
  return _mm_set_epi64x(kMaskPrefix, counter);
}

void shf::Prg::Fill(uint8_t* dest, std::size_t n) {
  if (!n) return;
  if (dest == nullptr) {
    throw std::invalid_argument("dest cannot be null when n > 0");
  }

  std::size_t offset = 0;
  while (offset < n) {
    __m128i mask = CreateMask(m_counter);
    alignas(16) uint8_t block[16];
    aes128_enc(m_state, reinterpret_cast<uint8_t*>(&mask), block);

    std::size_t to_copy = std::min(n - offset, BlockSize());
    std::memcpy(dest + offset, block, to_copy);

    offset += to_copy;
    Update();
  }
}

void shf::Prg::Update() { 
  // Note: Counter overflow at 2^64 is not handled. At 1 billion 
  // operations/second, this would take ~585 years.
  m_counter++; 
}

void shf::Prg::Init() {
  aes128_load_key(m_seed, m_state);
  secure_clear(m_seed, SeedSize());
}
