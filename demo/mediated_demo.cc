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

// --- Helper Utilities (copied from server_demo.cc) ---

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

// --- Data Structures ---

struct Deck {
  std::vector<shf::Ctxt> cards;
};

struct ShuffleMessage {
  Deck shuffled_deck; // The resulting deck
  shf::ShuffleP proof; // The proof of transition from input -> output
};

// --- Actors ---

class Player {
public:
  Player(int id) : id_(id), sk_(shf::CreateSecretKey()), pk_(shf::CreatePublicKey(sk_)) {}

  const shf::PublicKey& GetPublicKey() const { return pk_; }
  int GetId() const { return id_; }

  // Shuffle logic: Takes input deck, returns (new deck, proof)
  ShuffleMessage Shuffle(const shf::PublicKey& joint_pk, 
                         const shf::CommitKey& ck, 
                         const Deck& input_deck) {
    std::cout << "[Player " << id_ << "] Shuffling deck..." << std::endl;
    shf::Prg prg;
    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash;
    
    // The library's Shuffle method returns a ShuffleP which CONTAINS the permuted ciphertexts
    shf::ShuffleP proof = shuffler.Shuffle(input_deck.cards, hash);
    
    Deck new_deck;
    new_deck.cards = proof.permuted;
    
    return {new_deck, proof};
  }

  // Verify logic: Verifies transition from prev_deck -> claimed_shuffled_deck (inside proof)
  bool Verify(const shf::PublicKey& joint_pk, 
              const shf::CommitKey& ck, 
              const Deck& prev_deck, 
              const ShuffleMessage& msg) {
    std::cout << "[Player " << id_ << "] Verifying shuffle proof..." << std::endl;
    shf::Prg prg;
    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash;

    // msg.proof contains the 'permuted' field which IS the output deck.
    // VerifyShuffle checks if prev_deck.cards -> msg.proof.permuted is valid.
    return shuffler.VerifyShuffle(prev_deck.cards, msg.proof, hash);
  }

  // Decryption Share: Returns D_i = sk * U
  shf::Point ComputeDecryptionShare(const shf::Ctxt& ctxt) {
    return ctxt.U * sk_;
  }

private:
  int id_;
  shf::SecretKey sk_;
  shf::PublicKey pk_;
};

class Server {
public:
  Server(int num_players) : num_players_(num_players) {
    shf::CurveInit();
    // Initialize plain deck points for later decoding
    deck_points_.reserve(52);
    for (std::uint32_t i = 0; i < 52; ++i) deck_points_.emplace_back(CardPoint(i));
  }

  void RegisterPlayer(Player* p) {
    players_.push_back(p);
  }

  // Initialize Game: Joint Key, Encrypt Deck
  void InitGame() {
    std::cout << "[Server] Initializing game..." << std::endl;
    joint_pk_ = shf::Point(); // Infinity
    for (auto* p : players_) {
      joint_pk_ = joint_pk_ + p->GetPublicKey();
    }
    
    // Setup Commitment Key
    ck_ = shf::CreateCommitKey(52);

    // Encrypt initial deck
    current_deck_.cards.clear();
    current_deck_.cards.reserve(52);
    for (const auto& pt : deck_points_) {
      current_deck_.cards.emplace_back(shf::Encrypt(joint_pk_, pt));
    }
    std::cout << "[Server] Deck encrypted with Joint Public Key." << std::endl;
  }

  void RunShufflePhase() {
    std::cout << "\n--- Shuffle Phase ---\n";
    
    // We keep track of the deck state before the current shuffle to allow verification
    Deck prev_deck = current_deck_;

    // 1. Pass deck to Player 1
    // Player 1 shuffles
    std::cout << "[Server] Sending deck to Player 1." << std::endl;
    ShuffleMessage msg1 = players_[0]->Shuffle(joint_pk_, ck_, prev_deck);

    // 2. Server verifies P1
    std::cout << "[Server] Verifying Player 1's proof..." << std::endl;
    if (!VerifyProof(prev_deck, msg1)) {
        std::cerr << "[Server] Player 1 CHEATED!" << std::endl;
        exit(1);
    }
    std::cout << "[Server] Player 1 proof VALID." << std::endl;

    // Update current deck
    current_deck_ = msg1.shuffled_deck;

    // 3. Server sends (Original Deck, Proof) to Player 2 to verify
    std::cout << "[Server] Sending P1's proof to Player 2 for verification." << std::endl;
    bool p2_ok = players_[1]->Verify(joint_pk_, ck_, prev_deck, msg1);
    if (!p2_ok) {
        std::cerr << "[Player 2] claims Player 1 proof INVALID!" << std::endl;
        exit(1);
    }
    std::cout << "[Player 2] Verified Player 1's shuffle." << std::endl;

    // 4. Player 2 Shuffles (using the result from P1)
    prev_deck = current_deck_; // Now the input to P2 is the output of P1
    std::cout << "[Server] Sending deck to Player 2." << std::endl;
    ShuffleMessage msg2 = players_[1]->Shuffle(joint_pk_, ck_, prev_deck);

    // 5. Server verifies P2
    std::cout << "[Server] Verifying Player 2's proof..." << std::endl;
    if (!VerifyProof(prev_deck, msg2)) {
         std::cerr << "[Server] Player 2 CHEATED!" << std::endl;
         exit(1);
    }
    std::cout << "[Server] Player 2 proof VALID." << std::endl;

    // Update current deck to final state
    current_deck_ = msg2.shuffled_deck;
    
    // (Optional) P1 could verify P2 here, but per prompt "so on and so on", we are done with 2 players.
    std::cout << "[Server] Shuffle phase complete. Deck is ready.\n";
  }

  void RunGamePhase() {
      // Index for dealing from the top of the deck
      int card_idx = 0;
      
      std::cout << "\n--- Dealing Phase ---\n";
      
      // Deal Hole Cards
      // P1 Card 1
      DealCardToPlayer(0, current_deck_.cards[card_idx++]);
      // P2 Card 1
      DealCardToPlayer(1, current_deck_.cards[card_idx++]);
      // P1 Card 2
      DealCardToPlayer(0, current_deck_.cards[card_idx++]);
      // P2 Card 2
      DealCardToPlayer(1, current_deck_.cards[card_idx++]);

      // Burn 1 (typically) - skipping for simplicity or just incrementing
      card_idx++; 

      // Flop
      std::cout << "\n--- Flop ---\n";
      RevealCard(current_deck_.cards[card_idx++], "Flop 1");
      RevealCard(current_deck_.cards[card_idx++], "Flop 2");
      RevealCard(current_deck_.cards[card_idx++], "Flop 3");

      // Turn
      card_idx++; // Burn
      std::cout << "\n--- Turn ---\n";
      RevealCard(current_deck_.cards[card_idx++], "Turn");

      // River
      card_idx++; // Burn
      std::cout << "\n--- River ---\n";
      RevealCard(current_deck_.cards[card_idx++], "River");

      // Showdown (Reveal Hole Cards)
      std::cout << "\n--- Showdown ---\n";
      // We already dealt them, but for the demo "Showdown" means revealing them to everyone.
      // In a real game, players would reveal them voluntarily.
      // Here, we just reveal the cards at indices 0, 2 (P1) and 1, 3 (P2).
      
      std::cout << "Player 1 shows:\n";
      RevealCard(current_deck_.cards[0], "P1 Hole 1");
      RevealCard(current_deck_.cards[2], "P1 Hole 2");

      std::cout << "Player 2 shows:\n";
      RevealCard(current_deck_.cards[1], "P2 Hole 1");
      RevealCard(current_deck_.cards[3], "P2 Hole 2");
  }

private:
  bool VerifyProof(const Deck& input, const ShuffleMessage& msg) {
      shf::Prg prg;
      shf::Shuffler shuffler(joint_pk_, ck_, prg);
      shf::Hash hash;
      return shuffler.VerifyShuffle(input.cards, msg.proof, hash);
  }

  // To deal a card to P_target:
  // 1. Server asks ALL OTHER players for decryption shares.
  // 2. Server sends Ctxt + Sum(Shares_Others) to P_target.
  // 3. P_target decrypts using their share.
  void DealCardToPlayer(int target_id, const shf::Ctxt& ctxt) {
      std::cout << "[Server] Dealing card to Player " << target_id << "...\n";
      
      // Collect shares from everyone EXCEPT target
      shf::Point sum_shares = shf::Point(); // Infinity
      for (auto* p : players_) {
          if (p->GetId() == target_id) continue;
          sum_shares = sum_shares + p->ComputeDecryptionShare(ctxt);
      }

      // Simulate sending to Target
      // Target computes their share and finishes decryption
      Player* target = players_[target_id];
      shf::Point target_share = target->ComputeDecryptionShare(ctxt);
      
      // Total Decrypted V = V_ctxt - (Sum_Others + Target_Share)
      // Actually: M = V - xU. xU = Sum(x_i * U).
      shf::Point total_decryption_factor = sum_shares + target_share;
      shf::Point m = ctxt.V - total_decryption_factor;
      
      int card_val = DecodeCard(m, deck_points_);
      std::cout << "   (Player " << target_id << " privately sees: " 
                << (card_val >= 0 ? CardName(card_val) : "INVALID") << ")\n";
  }

  // To reveal a card to EVERYONE:
  // 1. Server collects shares from ALL players.
  // 2. Server decrypts and broadcasts.
  void RevealCard(const shf::Ctxt& ctxt, const std::string& label) {
      shf::Point sum_shares = shf::Point();
      for (auto* p : players_) {
          sum_shares = sum_shares + p->ComputeDecryptionShare(ctxt);
      }
      
      shf::Point m = ctxt.V - sum_shares;
      int card_val = DecodeCard(m, deck_points_);
      std::cout << "   " << label << ": " 
                << (card_val >= 0 ? CardName(card_val) : "INVALID") << "\n";
  }

  int num_players_;
  std::vector<Player*> players_;
  shf::PublicKey joint_pk_;
  shf::CommitKey ck_;
  std::vector<shf::Point> deck_points_;
  Deck current_deck_;
};

} // namespace

int main() {
  std::cout << "=== Mediated Mental Poker Simulation ===\n";
  std::cout << "1 Server, 2 Players.\n\n";

  Server server(2);
  Player p1(0);
  Player p2(1);

  server.RegisterPlayer(&p1);
  server.RegisterPlayer(&p2);

  // 1. Setup
  server.InitGame();

  // 2. Shuffle
  server.RunShufflePhase();

  // 3. Play (Deal, Flop, Turn, River, Showdown)
  server.RunGamePhase();

  std::cout << "\n=== Simulation Complete ===\n";
  return 0;
}
