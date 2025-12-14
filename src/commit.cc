#include "commit.h"

#include "parallel.h"
#include <thread>
#include <stdexcept>

shf::CommitKey shf::CreateCommitKey(const std::size_t size) {
  if (size == 0) throw std::invalid_argument("cannot create a key of size 0");

  CommitKey ck;
  ck.G.reserve(size);
  ck.H = Point::CreateRandom();
  for (std::size_t i = 0; i < size; ++i)
    ck.G.emplace_back(Point::CreateRandom());
  return ck;
}

shf::Point shf::Commit(const shf::CommitKey& ck, const shf::Scalar& r,
                     const std::vector<shf::Scalar>& m) {
  const std::size_t n = m.size();
  if (n > ck.G.size()) {
    throw std::invalid_argument("commitment key too small");
  }
  Point C;
  unsigned int max_threads = std::thread::hardware_concurrency();
  if (max_threads == 0) max_threads = 4;
  std::vector<Point> partial_sums(max_threads);

  shf::ParallelChunks(0, n, [&](std::size_t start, std::size_t end, std::size_t t_id) {
    if (t_id < partial_sums.size()) {
        for (std::size_t i = start; i < end; ++i) partial_sums[t_id] += m[i] * ck.G[i];
    }
  });

  for (const auto& p : partial_sums) C += p;

  return C + r * ck.H;
}

shf::CommitmentAndRandomness shf::Commit(const shf::CommitKey& ck,
                                       const std::vector<shf::Scalar>& m, shf::Prg& prg) {
  const auto r = Scalar::CreateRandom(prg);
  const auto C = Commit(ck, r, m);
  return {C, r};
}

bool shf::CheckCommitment(const shf::CommitKey& ck, const shf::Point& comm,
                         const shf::Scalar& r,
                         const std::vector<shf::Scalar>& m) {
  const auto comm_ = Commit(ck, r, m);
  return comm_ == comm;
}
