#ifndef SHF_COMMIT_H
#define SHF_COMMIT_H

#include <vector>

#include "curve.h"

namespace shf {

struct CommitKey {
  std::vector<Point> G;
  Point H;

  std::size_t Size() const { return G.size(); }
};

[[nodiscard]] CommitKey CreateCommitKey(const std::size_t size);

struct CommitmentAndRandomness {
  Point C;
  Scalar r;
};

[[nodiscard]] CommitmentAndRandomness Commit(const CommitKey& ck,
                                const std::vector<Scalar>& m);
[[nodiscard]] Point Commit(const CommitKey& ck, const Scalar& r,
              const std::vector<Scalar>& m);
[[nodiscard]] bool CheckCommitment(const CommitKey& ck, const Point& comm, const Scalar& r,
                      const std::vector<Scalar>& m);

}  // namespace shf

#endif  // SHF_COMMIT_H
