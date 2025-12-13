#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <random>

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

// Compute size of a point in bytes
static inline size_t SizeOf(const shf::Point&) {
  return shf::Point::ByteSize();
}

// Compute size of a scalar
static inline size_t SizeOf(const shf::Scalar&) {
  return shf::Scalar::ByteSize();
}

// Compute size of a ciphertext
static inline size_t SizeOf(const shf::Ctxt& ctxt) {
  return SizeOf(ctxt.U) + SizeOf(ctxt.V);
}

// Compute size of a vector of elements
template <typename T>
static inline size_t SizeOf(const std::vector<T>& vec) {
  size_t total = 0;
  for (const auto& elem : vec) {
    total += SizeOf(elem);
  }
  return total;
}

// Compute size of a commitment key
static inline size_t SizeOf(const shf::CommitKey& ck) {
  return SizeOf(ck.G) + SizeOf(ck.H);
}

// Compute size of a ProductP proof
static inline size_t SizeOf(const shf::ProductP& proof) {
  size_t total = SizeOf(proof.C0) + SizeOf(proof.C1) + SizeOf(proof.C2);
  total += SizeOf(proof.as);
  total += SizeOf(proof.bs);
  total += SizeOf(proof.r);
  total += SizeOf(proof.s);
  return total;
}

// Compute size of a MultiExpP proof
static inline size_t SizeOf(const shf::MultiExpP& proof) {
  size_t total = SizeOf(proof.C0) + SizeOf(proof.C1);
  total += SizeOf(proof.E);
  total += SizeOf(proof.a);
  total += SizeOf(proof.r);
  total += SizeOf(proof.b);
  total += SizeOf(proof.s);
  total += SizeOf(proof.t);
  return total;
}

// Compute size of a ShuffleP proof
static inline size_t SizeOf(const shf::ShuffleP& proof) {
  size_t total = SizeOf(proof.permuted);
  total += SizeOf(proof.Ca);
  total += SizeOf(proof.Cb);
  total += SizeOf(proof.product_proof);
  total += SizeOf(proof.multiexp_proof);
  return total;
}

static inline void PrintStep(const std::string& step, long long ms, size_t bytes = 0) {
  std::cout << std::left << std::setw(40) << step << " " << std::right
            << std::setw(6) << ms << " ms";
  if (bytes > 0) {
    std::cout << " (" << bytes << " bytes)";
  }
  std::cout << "\n";
}

// Simulate network message with size tracking
struct NetworkMessage {
  std::string description;
  size_t bytes;
};

class NetworkSim {
public:
  static void Send(const std::string& desc, size_t bytes) {
    messages_.emplace_back(NetworkMessage{desc, bytes});
    total_bytes_ += bytes;
  }
  
  static void PrintSummary() {
    std::cout << "\nNetwork Summary:\n";
    for (const auto& msg : messages_) {
      std::cout << "  " << std::left << std::setw(30) << msg.description 
                << " " << std::right << std::setw(6) << msg.bytes << " bytes\n";
    }
    std::cout << "  Total data transmitted: " << total_bytes_ << " bytes\n";
  }
  
  static void Reset() {
    messages_.clear();
    total_bytes_ = 0;
  }
  
private:
  static std::vector<NetworkMessage> messages_;
  static size_t total_bytes_;
};

std::vector<NetworkMessage> NetworkSim::messages_;
size_t NetworkSim::total_bytes_ = 0;

// Player class representing a poker player
class Player {
public:
  Player(int id) : id_(id), sk_(shf::CreateSecretKey()), pk_(shf::CreatePublicKey(sk_)) {}
  
  const shf::PublicKey& GetPublicKey() const { return pk_; }
  const shf::SecretKey& GetSecretKey() const { return sk_; }
  int GetId() const { return id_; }
  
  // Shuffle the deck and generate proof
  shf::ShuffleP ShuffleDeck(const shf::PublicKey& joint_pk,
                            const shf::CommitKey& ck,
                            const std::vector<shf::Ctxt>& deck,
                            size_t& proof_size) {
    shf::Prg prg;
    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash;
    StepTimer timer("Player " + std::to_string(id_) + " shuffle");
    auto proof = shuffler.Shuffle(deck, hash);
    auto elapsed = timer.ElapsedMs();
    proof_size = SizeOf(proof);
    NetworkSim::Send("Shuffle proof from P" + std::to_string(id_), proof_size);
    PrintStep("Player " + std::to_string(id_) + " shuffle + proof", elapsed, proof_size);
    return proof;
  }
  
  // Verify a shuffle proof
  bool VerifyShuffle(const shf::PublicKey& joint_pk,
                     const shf::CommitKey& ck,
                     const std::vector<shf::Ctxt>& deck,
                     const shf::ShuffleP& proof,
                     size_t& proof_size) {
    shf::Prg prg;
    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash;
    StepTimer timer("Player " + std::to_string(id_) + " verify");
    bool ok = shuffler.VerifyShuffle(deck, proof, hash);
    auto elapsed = timer.ElapsedMs();
    proof_size = SizeOf(proof);
    NetworkSim::Send("Shuffle verification from P" + std::to_string(id_), proof_size);
    PrintStep("Player " + std::to_string(id_) + " verify proof", elapsed, proof_size);
    return ok;
  }
  
  // Partial decryption of a ciphertext
  shf::Ctxt PartialDecryptCtxt(const shf::Ctxt& ctxt) const {
    return ::PartialDecrypt(sk_, ctxt);
  }
  
private:
  int id_;
  shf::SecretKey sk_;
  shf::PublicKey pk_;
};

// Server class that controls the game
class Server {
public:
  Server(int num_players) : num_players_(num_players) {}
  
  void RunGame() {
    std::cout << "Mental Poker Server Demo (Texas Hold'em)\n";
    std::cout << "Number of players: " << num_players_ << "\n\n";
    
    StepTimer total_timer("Total game");
    NetworkSim::Reset();
    
    // 1. Initialize curve and deck
    StepTimer init_timer("Initialize curve and deck");
    shf::CurveInit();
    std::vector<shf::Point> deck_points;
    deck_points.reserve(52);
    for (std::uint32_t i = 0; i < 52; ++i) deck_points.emplace_back(CardPoint(i));
    PrintStep("Init curve + encode deck", init_timer.ElapsedMs());
    
    // 2. Create players and collect public keys
    StepTimer keygen_timer("Key generation");
    std::vector<Player> players;
    players.reserve(num_players_);
    shf::PublicKey joint_pk = shf::Point(); // infinity point
    for (int i = 0; i < num_players_; ++i) {
      players.emplace_back(i);
      joint_pk = joint_pk + players[i].GetPublicKey();
      NetworkSim::Send("Public key from P" + std::to_string(i), SizeOf(players[i].GetPublicKey()));
    }
    NetworkSim::Send("Joint public key to all players", SizeOf(joint_pk));
    size_t keygen_bytes = num_players_ * SizeOf(shf::PublicKey()) + SizeOf(joint_pk);
    PrintStep("Player key generation + joint key", keygen_timer.ElapsedMs(), keygen_bytes);
    
    // 3. Setup commitment key
    StepTimer setup_timer("Setup commitment key");
    const std::size_t n = 52;
    const shf::CommitKey ck = shf::CreateCommitKey(n);
    NetworkSim::Send("Commitment key to all players", SizeOf(ck));
    size_t setup_bytes = SizeOf(ck);
    PrintStep("Setup commitment key (CRS)", setup_timer.ElapsedMs(), setup_bytes);
    
    // 4. Encrypt deck under joint key
    StepTimer encrypt_timer("Encrypt deck");
    std::vector<shf::Ctxt> deck_ctxts;
    deck_ctxts.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
      deck_ctxts.emplace_back(shf::Encrypt(joint_pk, deck_points[i]));
    }
    size_t deck_size = SizeOf(deck_ctxts);
    NetworkSim::Send("Encrypted deck", deck_size);
    PrintStep("Encrypt full deck under joint key", encrypt_timer.ElapsedMs(), deck_size);
    
    // 5. Each player shuffles the deck sequentially
    std::vector<shf::Ctxt> current_deck = deck_ctxts;
    for (int i = 0; i < num_players_; ++i) {
      size_t proof_size = 0;
      NetworkSim::Send("Deck to player " + std::to_string(i), SizeOf(current_deck));
      auto proof = players[i].ShuffleDeck(joint_pk, ck, current_deck, proof_size);
      // Verify the proof (other players would verify, but we simulate server verification)
      size_t verify_size = 0;
      bool ok = true;
      for (int j = 0; j < num_players_; ++j) {
        if (i == j) continue;
        ok &= players[j].VerifyShuffle(joint_pk, ck, current_deck, proof, verify_size);
      }
      if (!ok) {
        std::cerr << "Shuffle verification failed for player " << i << "\n";
        return;
      }
      current_deck = proof.permuted;
      NetworkSim::Send("Shuffled deck from player " + std::to_string(i), SizeOf(current_deck));
    }
    
    // 6. Deal hole cards and board cards
    StepTimer deal_timer("Deal cards");
    // For simplicity, deal first 2*num_players cards as hole cards, next 5 as board
    std::vector<std::vector<shf::Ctxt>> hole_cards(num_players_);
    for (int i = 0; i < num_players_; ++i) {
      hole_cards[i].push_back(current_deck[2*i]);
      hole_cards[i].push_back(current_deck[2*i + 1]);
      NetworkSim::Send("Hole cards to P" + std::to_string(i), SizeOf(hole_cards[i]));
    }
    std::vector<shf::Ctxt> board_cards;
    int start_board = 2 * num_players_;
    for (int i = 0; i < 5; ++i) {
      board_cards.push_back(current_deck[start_board + i]);
    }
    NetworkSim::Send("Board cards", SizeOf(board_cards));
    size_t deal_bytes = 0;
    for (const auto& hc : hole_cards) deal_bytes += SizeOf(hc);
    deal_bytes += SizeOf(board_cards);
    PrintStep("Deal hole cards and board", deal_timer.ElapsedMs(), deal_bytes);
    
    // 7. Simulate betting rounds (simplified)
    SimulateBettingRound("Pre-flop", players);
    
    // 8. Reveal flop (first 3 board cards)
    std::cout << "\nFlop:\n";
    StepTimer flop_timer("Reveal flop");
    for (int i = 0; i < 3; ++i) {
      RevealCard("Board", board_cards[i], players, deck_points);
    }
    size_t flop_bytes = 3 * num_players_ * SizeOf(board_cards[0]);
    PrintStep("Reveal flop", flop_timer.ElapsedMs(), flop_bytes);
    
    SimulateBettingRound("Post-flop", players);
    
    // 9. Reveal turn (4th board card)
    std::cout << "\nTurn:\n";
    StepTimer turn_timer("Reveal turn");
    RevealCard("Board", board_cards[3], players, deck_points);
    size_t turn_bytes = num_players_ * SizeOf(board_cards[0]);
    PrintStep("Reveal turn", turn_timer.ElapsedMs(), turn_bytes);
    
    SimulateBettingRound("Post-turn", players);
    
    // 10. Reveal river (5th board card)
    std::cout << "\nRiver:\n";
    StepTimer river_timer("Reveal river");
    RevealCard("Board", board_cards[4], players, deck_points);
    size_t river_bytes = num_players_ * SizeOf(board_cards[0]);
    PrintStep("Reveal river", river_timer.ElapsedMs(), river_bytes);
    
    SimulateBettingRound("Post-river", players);
    
    // 11. Showdown: reveal hole cards
    std::cout << "\nShowdown:\n";
    StepTimer showdown_timer("Showdown");
    for (int i = 0; i < num_players_; ++i) {
      std::cout << "Player " << i << " hole cards:\n";
      RevealCard("P" + std::to_string(i), hole_cards[i][0], players, deck_points);
      RevealCard("P" + std::to_string(i), hole_cards[i][1], players, deck_points);
    }
    size_t showdown_bytes = (2 * num_players_) * num_players_ * SizeOf(hole_cards[0][0]);
    PrintStep("Showdown", showdown_timer.ElapsedMs(), showdown_bytes);
    
    PrintStep("Total game time", total_timer.ElapsedMs());
    NetworkSim::PrintSummary();
  }
  
private:
  int num_players_;
  
  void SimulateBettingRound(const std::string& round_name,
                            const std::vector<Player>& players) {
    std::cout << "\n" << round_name << " betting round:\n";
    // Simulate random actions for demo
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> act(0, 2);
    const char* actions[] = {"checks", "bets", "folds"};
    for (const auto& player : players) {
      int a = act(rng);
      std::cout << "  Player " << player.GetId() << " " << actions[a] << "\n";
      // Simulate network message for action
      NetworkSim::Send("Betting action from P" + std::to_string(player.GetId()), 10); // arbitrary size
    }
  }
  
  void RevealCard(const std::string& owner,
                  const shf::Ctxt& ctxt,
                  const std::vector<Player>& players,
                  const std::vector<shf::Point>& deck_points) {
    StepTimer timer("Reveal " + owner);
    // Partial decryption by each player sequentially
    shf::Ctxt partially_decrypted = ctxt;
    for (const auto& player : players) {
      partially_decrypted = player.PartialDecryptCtxt(partially_decrypted);
      NetworkSim::Send("Partial decryption from " + owner, SizeOf(partially_decrypted));
    }
    // Fully decrypted point is partially_decrypted.V (since U unchanged)
    shf::Point m = partially_decrypted.V;
    const int card = DecodeCard(m, deck_points);
    auto elapsed = timer.ElapsedMs();
    std::cout << "  " << owner << " reveal: " << (card >= 0 ? CardName(card) : "<?>")
              << " (" << elapsed << " ms)\n";
  }
};

} // namespace

int main() {
  const int NUM_PLAYERS = 2;
  Server server(NUM_PLAYERS);
  server.RunGame();
  return 0;
}