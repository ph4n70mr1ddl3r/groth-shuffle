#ifndef SHF_CIPHER_H
#define SHF_CIPHER_H

#include <vector>

#include "curve.h"

namespace shf {

struct Ctxt {
  Point U;
  Point V;
};

using SecretKey = Scalar;
using PublicKey = Point;

[[nodiscard]] SecretKey CreateSecretKey();
[[nodiscard]] PublicKey CreatePublicKey(const SecretKey& sk);

[[nodiscard]] Ctxt Encrypt(const PublicKey& pk, const Point& m, const Scalar& r);
[[nodiscard]] Ctxt Encrypt(const PublicKey& pk, const Point& m);
[[nodiscard]] Point Decrypt(const SecretKey& sk, const Ctxt& ctxt);
[[nodiscard]] Ctxt Multiply(const Scalar& s, const Ctxt& E);
[[nodiscard]] Ctxt Add(const Ctxt& E0, const Ctxt& E1);
[[nodiscard]] Ctxt Dot(const std::vector<shf::Scalar>& as, const std::vector<Ctxt>& Es);

}  // namespace shf

#endif  // SHF_CIPHER_H
