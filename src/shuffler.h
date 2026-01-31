#ifndef SHF_SHUFFLER_H
#define SHF_SHUFFLER_H

#include <stdexcept>
#include <vector>

#include "cipher.h"
#include "commit.h"
#include "curve.h"
#include "prg.h"
#include "zkp.h"

namespace shf {

/**
 * @brief A permutation is represented as a vector of indices.
 * The permutation maps input position i to output position p[i].
 */
using Permutation = std::vector<std::size_t>;

/**
 * @brief Create a random permutation of a given size.
 * @param size the size of the permutation
 * @param prg the random generator to use
 * @return a random permutation.
 */
Permutation CreatePermutation(std::size_t size, shf::Prg& prg);

/**
 * @brief Permute a list of things.
 * @param things the list of things to permute
 * @param perm the permutation to use
 * @return a permutation of the input.
 * @throws std::invalid_argument if permutation size doesn't match input size
 * @throws std::out_of_range if any permutation index is out of bounds
 * @throws std::bad_alloc if memory allocation fails
 */
template <typename T>
std::vector<T> Permute(const std::vector<T>& things, const Permutation& perm) {
   const std::size_t n = things.size();
   if (n != perm.size()) throw std::invalid_argument("invalid permutation size");

   std::vector<T> permuted;
   permuted.reserve(n);
   for (std::size_t i = 0; i < perm.size(); ++i) {
       if (perm[i] >= n) {
           throw std::out_of_range("permutation index " + std::to_string(i) +
                                   " = " + std::to_string(perm[i]) +
                                   " out of bounds (size=" + std::to_string(n) + ")");
       }
       permuted.emplace_back(things[perm[i]]);
   }
   return permuted;
}

struct ShuffleP {
  std::vector<Ctxt> permuted;
  Point Ca;
  Point Cb;
  ProductP product_proof;
  MultiExpP multiexp_proof;
};

 class Shuffler {
  public:
   /**
    * @brief Construct a shuffler with given keys and PRG
    * @param pk Public key for encryption
    * @param ck Commitment key for proofs
    * @param prg Pseudo-random generator for creating permutations
    * @note The PRG should not be reused across multiple shuffle operations
    *       in the same context to prevent potential predictability
    */
   Shuffler(const PublicKey& pk, const CommitKey& ck, Prg& prg)
       : m_pk(pk), m_ck(ck), m_prg(prg) {}

   /**
    * @brief Shuffle a set of ciphertexts and return a proof of correctness.
    * @param ctxts ciphertexts to shuffle
    * @param hash a hash function object
    * @return a proof of that the shuffle was done correctly.
    * @throws std::invalid_argument if ctxts is empty or exceeds commitment key size
    * @throws std::runtime_error if cryptographic operations fail
    * @throws std::bad_alloc if memory allocation fails
    */
   ShuffleP Shuffle(const std::vector<Ctxt>& ctxts, Hash& hash);

   /**
    * @brief Verify a shuffle.
    * @param ctxts the ciphertexts that were shuffled
    * @param proof the proof to verify
    * @param hash a hash function object
    * @return true if the shuffle was correct and false otherwise.
    * @throws std::runtime_error if cryptographic operations fail
    * @throws std::bad_alloc if memory allocation fails
    */
   bool VerifyShuffle(const std::vector<Ctxt>& ctxts, const ShuffleP& proof,
                      Hash& hash) const;

 private:
  PublicKey m_pk;
  CommitKey m_ck;
  Prg m_prg;
};

}  // namespace shf

#endif  // SHF_SHUFFLER_H
