#include "prg.h"

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <stdexcept>

#if defined(__linux__) || defined(__APPLE__) || defined(__unix__)
#include <strings.h>
void shf::secure_clear(void* ptr, std::size_t size) {
    explicit_bzero(ptr, size);
}
#elif defined(_WIN32) || defined(_WIN64)
#include <windows.h>
void shf::secure_clear(void* ptr, std::size_t size) {
    SecureZeroMemory(ptr, size);
}
#else
void shf::secure_clear(void* ptr, std::size_t size) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    for (std::size_t i = 0; i < size; ++i) p[i] = 0;
}
#endif

// Security note: This PRG implementation uses AES in counter mode with AES-NI
// acceleration for high-performance cryptographically secure pseudorandom
// generation. The implementation securely wipes sensitive data from memory.
/* https://github.com/sebastien-riou/aes-brute-force */

static constexpr uint64_t PRG_DOMAIN_SEPARATOR = 0x0123456789ABCDEFULL;

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
#if defined(_WIN32) || defined(_WIN64)
  std::uint8_t seed[SeedSize()];
  HCRYPTPROV hProv = 0;
  if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
    throw std::runtime_error("Failed to acquire cryptographic context for PRG seed");
  }

  if (!CryptGenRandom(hProv, static_cast<DWORD>(SeedSize()), seed)) {
    CryptReleaseContext(hProv, 0);
    throw std::runtime_error("Failed to generate random seed");
  }

  std::memcpy(m_seed, seed, SeedSize());
  secure_clear(seed, SeedSize());
  CryptReleaseContext(hProv, 0);
#else
  struct FileGuard {
    std::FILE* file;
    explicit FileGuard(std::FILE* f) : file(f) {}
    ~FileGuard() { if (file) std::fclose(file); }
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;
  };

  std::uint8_t seed[SeedSize()];
  std::FILE* urandom = std::fopen("/dev/urandom", "rb");
  if (!urandom) {
    throw std::runtime_error("Failed to open /dev/urandom for PRG seed");
  }
  FileGuard guard(urandom);

  std::size_t total_read = 0;
  while (total_read < SeedSize()) {
    std::size_t bytes_read = std::fread(seed + total_read, 1, SeedSize() - total_read, urandom);
    if (std::ferror(urandom)) {
      throw std::runtime_error("Error reading from /dev/urandom");
    }
    if (bytes_read == 0) {
      throw std::runtime_error("Unexpected EOF while reading from /dev/urandom");
    }
    total_read += bytes_read;
  }

  std::memcpy(m_seed, seed, SeedSize());
  secure_clear(seed, SeedSize());
#endif
  Init();
}

shf::Prg::Prg(const uint8_t* seed) {
  if (!seed) {
    throw std::invalid_argument("seed cannot be null");
  }
  std::memcpy(m_seed, seed, SeedSize());
  Init();
}

static inline __m128i CreateMask(const long counter) {
  if (counter < 0) {
    throw std::runtime_error("PRG counter overflow detected");
  }
  return _mm_set_epi64x(PRG_DOMAIN_SEPARATOR, counter);
}

void shf::Prg::Fill(uint8_t* dest, std::size_t n) {
  if (!dest) {
    throw std::invalid_argument("destination cannot be null");
  }
  if (!n) return;

  std::size_t nblocks = n / BlockSize();

  if (n % BlockSize()) nblocks++;

  __m128i mask = CreateMask(m_counter);
  std::vector<uint8_t> out(nblocks * BlockSize());
  uint8_t* p = out.data();

  for (std::size_t i = 0; i < nblocks; ++i) {
    aes128_enc(m_state, (uint8_t*)(&mask), p);
    Update();
    mask = CreateMask(m_counter);
    p += BlockSize();
  }

  std::memcpy(dest, out.data(), n);
  secure_clear(out.data(), out.size());
}

void shf::Prg::Update() { m_counter++; }

void shf::Prg::Init() {
#if defined(__AES__) || defined(_MSC_VER)
  aes128_load_key(m_seed, m_state);
#else
  throw std::runtime_error("AES-NI not supported on this platform");
#endif
}
