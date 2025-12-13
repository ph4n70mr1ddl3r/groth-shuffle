#include "catch.hpp"
#include "shuffler.h"
#include "curve.h"
#include "prg.h"

using namespace shf;

// Helper to create a deterministic PRG for testing
Prg CreateTestPrg(uint8_t seed_byte) {
    std::vector<uint8_t> seed(Prg::SeedSize(), seed_byte);
    return Prg(seed.data());
}

TEST_CASE("Security: Verifier rejects invalid proofs", "[security]") {
    CurveInit();
    
    // Setup
    Prg prg = CreateTestPrg(0x42);
    size_t n = 5;
    CommitKey ck = CreateCommitKey(n);
    SecretKey sk = Scalar::CreateRandom(prg);
    PublicKey pk = CreatePublicKey(sk);
    
    // Create Deck
    std::vector<Ctxt> deck;
    for(size_t i=0; i<n; ++i) {
        deck.push_back(Encrypt(pk, Point::Generator())); // Encrypting G for simplicity
    }
    
    // Honest Shuffle
    Shuffler shuffler(pk, ck, prg);
    Hash hash_gen;
    ShuffleP valid_proof = shuffler.Shuffle(deck, hash_gen);
    
    Hash hash_ver;
    REQUIRE(shuffler.VerifyShuffle(deck, valid_proof, hash_ver));

    // Attack 1: Tamper with the permuted ciphertexts
    {
        ShuffleP bad_proof = valid_proof;
        // Modify one ciphertext in the output deck
        bad_proof.permuted[0].U = bad_proof.permuted[0].U + Point::Generator();
        
        Hash hash;
        std::cout << "Testing Tampered Ciphertext...\n";
        REQUIRE(shuffler.VerifyShuffle(deck, bad_proof, hash) == false);
    }

    // Attack 2: Tamper with the commitment Ca (permutation commitment)
    {
        ShuffleP bad_proof = valid_proof;
        bad_proof.Ca = bad_proof.Ca + Point::Generator();
        
        Hash hash;
        std::cout << "Testing Tampered Commitment Ca...\n";
        REQUIRE(shuffler.VerifyShuffle(deck, bad_proof, hash) == false);
    }
    
    // Attack 3: Tamper with the Product Proof (C0)
    {
        ShuffleP bad_proof = valid_proof;
        bad_proof.product_proof.C0 = bad_proof.product_proof.C0 + Point::Generator();
        
        Hash hash;
        std::cout << "Testing Tampered Product Proof...\n";
        REQUIRE(shuffler.VerifyShuffle(deck, bad_proof, hash) == false);
    }

    // Attack 4: Tamper with MultiExp Proof (scalar response r)
    {
        ShuffleP bad_proof = valid_proof;
        bad_proof.multiexp_proof.r = bad_proof.multiexp_proof.r + Scalar::CreateFromInt(1);
        
        Hash hash;
        std::cout << "Testing Tampered Scalar Response...\n";
        REQUIRE(shuffler.VerifyShuffle(deck, bad_proof, hash) == false);
    }
    
    // Attack 5: Swap Input Deck (Replay Attack context)
    {
        std::vector<Ctxt> other_deck = deck;
        // Swap first two cards in input
        std::swap(other_deck[0], other_deck[1]);
        
        Hash hash;
        std::cout << "Testing Swapped Input Deck...\n";
        // The proof is valid for 'deck', but should be invalid for 'other_deck'
        REQUIRE(shuffler.VerifyShuffle(other_deck, valid_proof, hash) == false);
    }
}

TEST_CASE("Security: Consistency check", "[consistency]") {
    CurveInit();
    Prg prg = CreateTestPrg(0x01);
    size_t n = 3;
    CommitKey ck = CreateCommitKey(n);
    SecretKey sk = Scalar::CreateRandom(prg);
    PublicKey pk = CreatePublicKey(sk);
    
    std::vector<Ctxt> deck;
    for(size_t i=0; i<n; ++i) deck.push_back(Encrypt(pk, Point::Generator()));

    // Run two identical shuffles with same PRG seed
    Prg prg1 = CreateTestPrg(0x99);
    Shuffler s1(pk, ck, prg1);
    Hash h1;
    ShuffleP p1 = s1.Shuffle(deck, h1);

    Prg prg2 = CreateTestPrg(0x99);
    Shuffler s2(pk, ck, prg2);
    Hash h2;
    ShuffleP p2 = s2.Shuffle(deck, h2);

    // Outputs must be identical (Deterministic)
    REQUIRE(p1.permuted[0].U == p2.permuted[0].U);
    REQUIRE(p1.Ca == p2.Ca);
    
    // Run shuffle with DIFFERENT seed
    Prg prg3 = CreateTestPrg(0xAA);
    Shuffler s3(pk, ck, prg3);
    Hash h3;
    ShuffleP p3 = s3.Shuffle(deck, h3);

    // Outputs must differ
    REQUIRE(p1.permuted[0].U != p3.permuted[0].U);
    REQUIRE(p1.Ca != p3.Ca);
}
