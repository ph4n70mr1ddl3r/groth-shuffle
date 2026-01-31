#include "commit.h"

#include <stdexcept>

static constexpr std::size_t MAX_COMMIT_KEY_SIZE = 10000;

shf::CommitKey shf::CreateCommitKey(const std::size_t size) {
  if (size == 0) {
    throw std::invalid_argument("Cannot create a commitment key of size 0");
  }
  if (size > MAX_COMMIT_KEY_SIZE) {
    throw std::invalid_argument("Commitment key size too large: " +
                              std::to_string(size) +
                              " (max: " + std::to_string(MAX_COMMIT_KEY_SIZE) + ")");
  }

  CommitKey ck;
  ck.G.reserve(size);
  const Scalar h_scalar = Scalar::CreateRandom();
  ck.H = h_scalar * Point::Generator();
  for (std::size_t i = 0; i < size; ++i) {
    ck.G.emplace_back(Point::CreateRandom());
  }
  return ck;
}

shf::Point shf::Commit(const shf::CommitKey& ck, const shf::Scalar& r,
                       const std::vector<shf::Scalar>& m) {
  const std::size_t n = m.size();
  if (n != ck.G.size()) {
    throw std::invalid_argument("Message vector size (" + std::to_string(n) +
                               ") does not match commitment key size (" +
                               std::to_string(ck.G.size()) + ")");
  }
  Point C;
  for (std::size_t i = 0; i < n; ++i) {
    C += m[i] * ck.G[i];
  }
  return C + r * ck.H;
}

shf::CommitmentAndRandomness shf::Commit(const shf::CommitKey& ck,
                                       const std::vector<shf::Scalar>& m) {
  const auto r = Scalar::CreateRandom();
  const auto C = Commit(ck, r, m);
  return {C, r};
}

bool shf::CheckCommitment(const shf::CommitKey& ck, const shf::Point& comm,
                         const shf::Scalar& r,
                         const std::vector<shf::Scalar>& m) {
  const auto comm_ = Commit(ck, r, m);
  return comm_ == comm;
}
