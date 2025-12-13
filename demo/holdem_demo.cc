#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "cipher.h"
#include "curve.h"
#include "hash.h"
#include "shuffler.h"

namespace {

using Clock = std::chrono::high_resolution_clock;

struct StepTimer {
  explicit StepTimer(std::string label)
      : label(std::move(label)), start(Clock::now()) {}

  long long ElapsedMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                                 start)
        .count();
  }

  std::string label;
  Clock::time_point start;
};

static inline std::string CardName(std::size_t card_index) {
  static const char* kRanks[] = {"2", "3", "4", "5", "6", "7", "8",
                                 "9", "T", "J", "Q", "K", "A"};
  static const char* kSuits[] = {"c", "d", "h", "s"};

  const std::size_t rank = card_index % 13;
  const std::size_t suit = card_index / 13;
  return std::string(kRanks[rank]) + kSuits[suit];
}

static inline shf::Scalar CardScalar(std::uint32_t card_index) {
  shf::Hash h;
  h.Update(reinterpret_cast<const std::uint8_t*>("CARD"), 4);
  h.Update(reinterpret_cast<const std::uint8_t*>(&card_index), sizeof(card_index));
  return shf::ScalarFromHash(h);
}

static inline shf::Point CardPoint(std::uint32_t card_index) {
  return shf::Point::Generator() * CardScalar(card_index);
}

static inline int DecodeCard(const shf::Point& p,
                             const std::vector<shf::Point>& deck_points) {
  for (std::size_t i = 0; i < deck_points.size(); ++i) {
    if (p == deck_points[i]) return static_cast<int>(i);
  }
  return -1;
}

static inline shf::Ctxt PartialDecrypt(const shf::SecretKey& sk,
                                       const shf::Ctxt& ctxt) {
  return {ctxt.U, ctxt.V - sk * ctxt.U};
}

static inline void PrintStep(const std::string& step, long long ms) {
  std::cout << std::left << std::setw(40) << step << " " << std::right
            << std::setw(6) << ms << " ms\n";
}

}  // namespace

int main() {
  std::cout << "2-player mental poker demo (Texas Hold'em)\n";
  std::cout << "Note: demo only; not a production-secure protocol.\n\n";

  StepTimer total("total");

  StepTimer init("init");
  shf::CurveInit();

  // Build a 52-card deck as curve points.
  std::vector<shf::Point> deck_points;
  deck_points.reserve(52);
  for (std::uint32_t i = 0; i < 52; ++i) deck_points.emplace_back(CardPoint(i));
  PrintStep("Init curve + encode deck", init.ElapsedMs());

  StepTimer keygen("keygen");
  const shf::SecretKey p1_sk = shf::CreateSecretKey();
  const shf::PublicKey p1_pk = shf::CreatePublicKey(p1_sk);

  const shf::SecretKey p2_sk = shf::CreateSecretKey();
  const shf::PublicKey p2_pk = shf::CreatePublicKey(p2_sk);

  // Joint key: pk_total = (sk1 + sk2) * G  ==  sk1*G + sk2*G
  const shf::PublicKey pk_total = p1_pk + p2_pk;
  PrintStep("Keygen (P1,P2) + joint public key", keygen.ElapsedMs());

  StepTimer setup("setup");
  const std::size_t n = 52;
  const shf::CommitKey ck = shf::CreateCommitKey(n);
  PrintStep("Setup commitment key (CRS)", setup.ElapsedMs());

  StepTimer encrypt("encrypt");
  std::vector<shf::Ctxt> deck_ctxts;
  deck_ctxts.reserve(n);
  for (std::size_t i = 0; i < n; ++i) {
    deck_ctxts.emplace_back(shf::Encrypt(pk_total, deck_points[i]));
  }
  PrintStep("Encrypt full deck under joint key", encrypt.ElapsedMs());

  // Player 1 shuffles and proves.
  shf::Prg prg1;
  shf::Shuffler shuffler1(pk_total, ck, prg1);

  StepTimer p1_prove("p1_prove");
  shf::Hash h1p;
  const shf::ShuffleP proof1 = shuffler1.Shuffle(deck_ctxts, h1p);
  PrintStep("P1 shuffle + proof generation", p1_prove.ElapsedMs());

  StepTimer p1_verify("p1_verify");
  shf::Hash h1v;
  const bool ok1 = shuffler1.VerifyShuffle(deck_ctxts, proof1, h1v);
  PrintStep(std::string("P1 shuffle proof verify (ok=") + (ok1 ? "true" : "false") +
                ")",
            p1_verify.ElapsedMs());
  if (!ok1) {
    std::cerr << "Verification failed for P1 shuffle proof.\n";
    return 1;
  }

  // Player 2 shuffles and proves.
  shf::Prg prg2;
  shf::Shuffler shuffler2(pk_total, ck, prg2);

  StepTimer p2_prove("p2_prove");
  shf::Hash h2p;
  const shf::ShuffleP proof2 = shuffler2.Shuffle(proof1.permuted, h2p);
  PrintStep("P2 shuffle + proof generation", p2_prove.ElapsedMs());

  StepTimer p2_verify("p2_verify");
  shf::Hash h2v;
  const bool ok2 = shuffler2.VerifyShuffle(proof1.permuted, proof2, h2v);
  PrintStep(std::string("P2 shuffle proof verify (ok=") + (ok2 ? "true" : "false") +
                ")",
            p2_verify.ElapsedMs());
  if (!ok2) {
    std::cerr << "Verification failed for P2 shuffle proof.\n";
    return 1;
  }

  StepTimer deal("deal");
  const auto& shuffled = proof2.permuted;
  const std::vector<shf::Ctxt> p1_hole = {shuffled[0], shuffled[1]};
  const std::vector<shf::Ctxt> p2_hole = {shuffled[2], shuffled[3]};
  const std::vector<shf::Ctxt> board = {shuffled[4], shuffled[5], shuffled[6],
                                        shuffled[7], shuffled[8]};
  PrintStep("Deal 2 hole cards each + 5 board cards", deal.ElapsedMs());

  auto reveal_card = [&](const char* who, const shf::Ctxt& ctxt) -> int {
    StepTimer t("reveal");
    const shf::Ctxt after_p1 = PartialDecrypt(p1_sk, ctxt);
    const shf::Point m = shf::Decrypt(p2_sk, after_p1);
    const int card = DecodeCard(m, deck_points);
    const auto ms = t.ElapsedMs();
    std::cout << "  " << who << " reveal: " << (card >= 0 ? CardName(card) : "<?>")
              << " (" << ms << " ms)\n";
    return card;
  };

  std::cout << "\nShow board:\n";
  StepTimer show_board("show_board");
  std::cout << "  Flop:\n";
  reveal_card("Board", board[0]);
  reveal_card("Board", board[1]);
  reveal_card("Board", board[2]);
  std::cout << "  Turn:\n";
  reveal_card("Board", board[3]);
  std::cout << "  River:\n";
  reveal_card("Board", board[4]);
  PrintStep("Reveal board cards", show_board.ElapsedMs());

  std::cout << "\nShowdown:\n";
  StepTimer showdown("showdown");
  reveal_card("P1", p1_hole[0]);
  reveal_card("P1", p1_hole[1]);
  reveal_card("P2", p2_hole[0]);
  reveal_card("P2", p2_hole[1]);
  PrintStep("Reveal hole cards (showdown)", showdown.ElapsedMs());

  PrintStep("Total", total.ElapsedMs());
  return 0;
}

