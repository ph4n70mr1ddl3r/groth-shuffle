#include "prg.h"

#include <wmmintrin.h>

#include <cstring>
#include <random>

#if defined(__linux__) || defined(__unix__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/random.h>
#include <cstdio>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

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

inline static void aes128_load_key(uint8_t* enc_key, __m128i* key_schedule) {
  key_schedule[0] = _mm_loadu_si128((const __m128i*)enc_key);
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

inline static void aes128_enc(__m128i* key_schedule, uint8_t* pt, uint8_t* ct) {
  __m128i m = _mm_loadu_si128((__m128i*)pt);
  DO_ENC_BLOCK(m, key_schedule);
  _mm_storeu_si128((__m128i*)ct, m);
}

shf::Prg::Prg() {
#if defined(__linux__) || defined(__unix__)
  // Use getrandom syscall for cryptographic randomness
  if (getrandom(m_seed, SeedSize(), 0) != static_cast<ssize_t>(SeedSize())) {
    // Fallback to /dev/urandom
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) {
      if (fread(m_seed, 1, SeedSize(), f) != SeedSize()) {
        // Last resort: std::random_device (may be insecure)
        std::random_device rd;
        for (std::size_t i = 0; i < SeedSize(); ++i) {
          m_seed[i] = static_cast<uint8_t>(rd());
        }
      }
      fclose(f);
    } else {
      std::random_device rd;
      for (std::size_t i = 0; i < SeedSize(); ++i) {
        m_seed[i] = static_cast<uint8_t>(rd());
      }
    }
  }
#else
  // Platform without getrandom; use /dev/urandom or CryptoAPI etc.
  // For simplicity, fallback to std::random_device (may be insecure on some platforms)
  std::random_device rd;
  for (std::size_t i = 0; i < SeedSize(); ++i) {
    m_seed[i] = static_cast<uint8_t>(rd());
  }
#endif
  Init();
}

shf::Prg::Prg(const uint8_t* seed) {
  std::memcpy(m_seed, seed, SeedSize());
  Init();
}

static inline __m128i CreateMask(const long counter) {
  return _mm_set_epi64x(0x0123456789ABCDEF, counter);
}

void shf::Prg::Fill(uint8_t* dest, std::size_t n) {
  if (!n) return;

  std::size_t remaining = n;
  uint8_t* out = dest;
  __m128i* state = reinterpret_cast<__m128i*>(m_state);

  while (remaining >= BlockSize()) {
    __m128i mask = CreateMask(m_counter);
    aes128_enc(state, reinterpret_cast<uint8_t*>(&mask), out);
    Update();
    out += BlockSize();
    remaining -= BlockSize();
  }

  if (remaining) {
    alignas(16) uint8_t block[BlockSize()];
    __m128i mask = CreateMask(m_counter);
    aes128_enc(state, reinterpret_cast<uint8_t*>(&mask), block);
    Update();
    std::memcpy(out, block, remaining);
  }
}

void shf::Prg::Update() { m_counter++; }

void shf::Prg::Init() { aes128_load_key(m_seed, reinterpret_cast<__m128i*>(m_state)); }
