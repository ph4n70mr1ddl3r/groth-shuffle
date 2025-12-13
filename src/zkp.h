#ifndef SHF_ZKP_H
#define SHF_ZKP_H

#include "cipher.h"
#include "commit.h"
#include "hash.h"
#include "prg.h"

namespace shf {

struct DLogS {
  Point B;
  Point P;
};

struct DLogP {
  Point T;
  Scalar r;
};

DLogP CreateProof(const DLogS& statement, Hash& hash, const Scalar& w, Prg& prg);
bool VerifyProof(const DLogS& statement, Hash& hash, const DLogP& proof);

struct DLogEqS {
  Point G;
  Point A;
  Point H;
  Point B;
};

struct DLogEqP {
  Point T;
  Point K;
  Scalar r;
};

DLogEqP CreateProof(const DLogEqS& statement, Hash& hash, const Scalar& w, Prg& prg);
bool VerifyProof(const DLogEqS& statement, Hash& hash, const DLogEqP& proof);

struct ProductS {
  Point C;
  Scalar b;
};

struct ProductP {
  Point C0;
  Point C1;
  Point C2;
  std::vector<Scalar> as;
  std::vector<Scalar> bs;
  Scalar r;
  Scalar s;
};

ProductP CreateProof(const CommitKey& ck, Hash& hash, const ProductS& statement,
                     const std::vector<Scalar>& w0, const Scalar& w1, Prg& prg);

bool VerifyProof(const CommitKey& ck, Hash& hash, const ProductS& statement,
                 const ProductP& proof);

struct MultiExpS {
  Point C;
  Ctxt E;
  std::vector<Ctxt> Es;
};

struct MultiExpP {
  Point C0;
  Point C1;
  Ctxt E;
  std::vector<Scalar> a;
  Scalar r;
  Scalar b;
  Scalar s;
  Scalar t;
};

MultiExpP CreateProof(const CommitKey& ck, const PublicKey& pk, Hash& hash,
                      const MultiExpS& statement, const std::vector<Scalar>& w0,
                      const Scalar& w1, const Scalar& w2, Prg& prg);

bool VerifyProof(const CommitKey& ck, const PublicKey& pk, Hash& hash,
                 const MultiExpS& statement, const MultiExpP& proof);

}  // namespace shf

#endif  // SHF_ZKP_H
