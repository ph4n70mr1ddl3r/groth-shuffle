#define CATCH_CONFIG_ENABLE_BENCHMARKING
#include <catch2/catch_all.hpp>
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

  // Verify that ciphertexts are properly re-randomized (no identical U or V values)
  bool re_randomized = true;
  for (std::size_t i = 0; i < ctxts.size(); i++) {
    for (std::size_t j = i + 1; j < shuffled.size(); j++) {
      re_randomized &= (ctxts[i].V != shuffled[j].V);
      re_randomized &= (ctxts[i].U != shuffled[j].U);
    }
  }
  REQUIRE(re_randomized);

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

  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);

  shf::Prg prg;

  // Test with minimum supported size (3) - product proof requires at least 3 elements
  const auto ck3 = shf::CreateCommitKey(3);
  shf::Shuffler shuffler3(pk, ck3, prg);
  std::vector<shf::Ctxt> three_ctxts;
  for (int i = 0; i < 3; ++i) {
    three_ctxts.emplace_back(shf::Encrypt(pk, shf::Point::CreateRandom()));
  }
  shf::Hash hash3;
  REQUIRE_NOTHROW(shuffler3.Shuffle(three_ctxts, hash3));

  // Test with small deck (5 cards)
  const auto ck5 = shf::CreateCommitKey(5);
  shf::Shuffler shuffler5(pk, ck5, prg);
  shf::Hash hash5;
  std::vector<shf::Ctxt> small_ctxts;
  for (int i = 0; i < 5; ++i) {
    small_ctxts.emplace_back(shf::Encrypt(pk, shf::Point::CreateRandom()));
  }

  auto proof = shuffler5.Shuffle(small_ctxts, hash5);
  REQUIRE(proof.permuted.size() == 5);
}

TEST_CASE("shuffle minimum size enforced") {
  shf::CurveInit();

  const auto ck = shf::CreateCommitKey(2);
  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);

  shf::Prg prg;
  shf::Shuffler shuffler(pk, ck, prg);
  shf::Hash hash;

  // Shuffle requires at least 3 ciphertexts for the product proof
  std::vector<shf::Ctxt> two_ctxts;
  for (int i = 0; i < 2; ++i) {
    two_ctxts.emplace_back(shf::Encrypt(pk, shf::Point::CreateRandom()));
  }
  REQUIRE_THROWS_AS(shuffler.Shuffle(two_ctxts, hash), std::invalid_argument);
}

TEST_CASE("shuffle verification failure cases") {
  shf::CurveInit();

  const auto ck = shf::CreateCommitKey(10);
  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);

  shf::Prg prg;
  shf::Shuffler shuffler(pk, ck, prg);
  shf::Hash hash;

  std::vector<shf::Ctxt> ctxts;
  for (int i = 0; i < 10; ++i) {
    ctxts.emplace_back(shf::Encrypt(pk, shf::Point::CreateRandom()));
  }

  auto proof = shuffler.Shuffle(ctxts, hash);

  // Test verification with wrong input ciphertexts
  std::vector<shf::Ctxt> wrong_ctxts = ctxts;
  wrong_ctxts[0] = shf::Encrypt(pk, shf::Point::CreateRandom());
  shf::Hash hash1;
  REQUIRE_FALSE(shuffler.VerifyShuffle(wrong_ctxts, proof, hash1));

  // Test verification with tampered proof
  auto tampered_proof = proof;
  tampered_proof.permuted[0] = shf::Encrypt(pk, shf::Point::CreateRandom());
  shf::Hash hash2;
  REQUIRE_FALSE(shuffler.VerifyShuffle(ctxts, tampered_proof, hash2));
}

TEST_CASE("shuffle empty throws") {
  shf::CurveInit();

  const auto ck = shf::CreateCommitKey(1);
  const auto sk = shf::CreateSecretKey();
  const auto pk = shf::CreatePublicKey(sk);

  shf::Prg prg;
  shf::Shuffler shuffler(pk, ck, prg);
  shf::Hash hash;

  std::vector<shf::Ctxt> empty_ctxts;
  REQUIRE_THROWS_AS(shuffler.Shuffle(empty_ctxts, hash), std::invalid_argument);
}
