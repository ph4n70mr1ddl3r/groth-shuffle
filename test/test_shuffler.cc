#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <catch2/catch.hpp>
#include <vector>

#include "shuffler.h"

#define ENABLE_BENCHMARKS 0

TEST_CASE("shuffle") {
  shf::CurveInit();

  std::size_t n = 150;

  const auto ck = shf::CreateCommitKey(n);
  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);

  std::vector<shf::Point> messages;
  std::vector<shf::Ctxt> ctxts;
  for (std::size_t i = 0; i < n; ++i) {
    const auto m = shf::Point::CreateRandom();
    ctxts.emplace_back(shf::Encrypt(pk, m));
    messages.emplace_back(m);
  }

  shf::Prg prg;
  shf::Shuffler shuffler(pk, ck, prg);

  shf::ShuffleP shuffle_proof;

#if ENABLE_BENCHMARKS
  BENCHMARK("prove") {
#endif
    shf::Hash hp;
    shuffle_proof = shuffler.Shuffle(ctxts, hp);
#if ENABLE_BENCHMARKS
    return shuffle_proof;
  };
#endif

  auto shuffled = shuffle_proof.permuted;
  REQUIRE(shuffled.size() == ctxts.size());

  // brute-force check that all permuted ciphertexts are also re-randomized.
  bool good = true;
  for (std::size_t i = 0; i < ctxts.size(); i++) {
    for (std::size_t j = i + 1; j < shuffled.size(); j++) {
      good &= ctxts[i].V != shuffled[j].V;
      good &= ctxts[i].U != shuffled[j].U;
    }
  }

  bool correct = false;
#if ENABLE_BENCHMARKS
  BENCHMARK("verify") {
#endif
    shf::Hash hv;
    correct = shuffler.VerifyShuffle(ctxts, shuffle_proof, hv);
#if ENABLE_BENCHMARKS
    return correct;
  };
#endif
  REQUIRE(correct);
}

TEST_CASE("shuffle edge cases") {
  shf::CurveInit();

  SECTION("empty ciphertext vector throws") {
    const auto ck = shf::CreateCommitKey(1);
    const auto sk = shf::CreateSecretKey();
    const auto pk = shf::CreatePublicKey(sk);
    shf::Prg prg;
    shf::Shuffler shuffler(pk, ck, prg);
    std::vector<shf::Ctxt> empty;
    shf::Hash hash;
    REQUIRE_THROWS_AS(shuffler.Shuffle(empty, hash), std::invalid_argument);
  }

  SECTION("size mismatch between commitment key and ciphertexts throws") {
    const auto ck = shf::CreateCommitKey(5);
    const auto sk = shf::CreateSecretKey();
    const auto pk = shf::CreatePublicKey(sk);
    shf::Prg prg;
    shf::Shuffler shuffler(pk, ck, prg);
    std::vector<shf::Ctxt> ctxts(10);
    shf::Hash hash;
    REQUIRE_THROWS_AS(shuffler.Shuffle(ctxts, hash), std::invalid_argument);
  }

  SECTION("verification fails with tampered proof") {
    const std::size_t n = 50;
    const auto ck = shf::CreateCommitKey(n);
    const auto sk = shf::CreateSecretKey();
    const auto pk = shf::CreatePublicKey(sk);
    std::vector<shf::Ctxt> ctxts;
    for (std::size_t i = 0; i < n; ++i) {
      ctxts.emplace_back(shf::Encrypt(pk, shf::Point::CreateRandom()));
    }
    shf::Prg prg;
    shf::Shuffler shuffler(pk, ck, prg);
    shf::Hash hash;
    auto proof = shuffler.Shuffle(ctxts, hash);
    proof.permuted[0].U = shf::Point::CreateRandom();
    shf::Hash hash2;
    REQUIRE_FALSE(shuffler.VerifyShuffle(ctxts, proof, hash2));
  }

  SECTION("large shuffle (1000 ciphertexts)") {
    const std::size_t n = 1000;
    const auto ck = shf::CreateCommitKey(n);
    const auto sk = shf::CreateSecretKey();
    const auto pk = shf::CreatePublicKey(sk);
    std::vector<shf::Ctxt> ctxts;
    for (std::size_t i = 0; i < n; ++i) {
      ctxts.emplace_back(shf::Encrypt(pk, shf::Point::CreateRandom()));
    }
    shf::Prg prg;
    shf::Shuffler shuffler(pk, ck, prg);
    shf::Hash hash;
    auto proof = shuffler.Shuffle(ctxts, hash);
    shf::Hash hash2;
    REQUIRE(shuffler.VerifyShuffle(ctxts, proof, hash2));
  }

  SECTION("verification fails with empty ciphertext vector") {
    const auto ck = shf::CreateCommitKey(1);
    const auto sk = shf::CreateSecretKey();
    const auto pk = shf::CreatePublicKey(sk);
    shf::Prg prg;
    shf::Shuffler shuffler(pk, ck, prg);
    std::vector<shf::Ctxt> empty;
    shf::ShuffleP proof;
    shf::Hash hash;
    REQUIRE_FALSE(shuffler.VerifyShuffle(empty, proof, hash));
  }
}