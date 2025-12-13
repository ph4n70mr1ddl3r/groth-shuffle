#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <random>
#include <sstream>

#include "cipher.h"
#include "curve.h"
#include "hash.h"
#include "shuffler.h"

namespace {

// --- Helper Utilities ---

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

// Convert byte vector to hex string
std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Convert hex string to byte vector
std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (std::size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// --- Key Management Helpers ---

// Save a scalar (Secret Key) to a file in hex format
void SaveKeyToFile(const std::string& filename, const shf::Scalar& key) {
  std::ofstream ofs(filename); // No binary mode for hex string
  if (!ofs) throw std::runtime_error("Cannot write to file: " + filename);
  std::vector<uint8_t> buffer(shf::Scalar::ByteSize());
  key.Write(buffer.data());
  ofs << bytesToHex(buffer);
  std::cout << "   [System] Saved new identity key to " << filename << "\n";
}

// Load a scalar from file (hex format), or generate and save if missing
shf::Scalar LoadOrGenerateKey(const std::string& filename) {
  std::ifstream ifs(filename);
  if (ifs) {
    std::string hex_key_string;
    ifs >> hex_key_string;
    if (ifs && hex_key_string.length() == shf::Scalar::ByteSize() * 2) { // Each byte is 2 hex chars
      std::cout << "   [System] Loaded existing identity key from " << filename << "\n";
      std::vector<uint8_t> buffer = hexToBytes(hex_key_string);
      return shf::Scalar::Read(buffer.data());
    }
  }
  
  // Generate new
  shf::Scalar new_key = shf::Scalar::CreateRandom();
  SaveKeyToFile(filename, new_key);
  return new_key;
}

// --- Data Structures ---

struct Deck {
  std::vector<shf::Ctxt> cards;
};

struct ShuffleMessage {
  Deck shuffled_deck;
  shf::ShuffleP proof;
};

// --- Actors ---

class Player {
public:
  Player(int id, std::string key_file) : id_(id) {
    identity_sk_ = LoadOrGenerateKey(key_file);
  }

  void InitHand(const std::string& hand_id) {
    shf::Hash h;
    h.Update(identity_sk_);
    h.Update(reinterpret_cast<const uint8_t*>(hand_id.data()), hand_id.size());
    
    hand_sk_ = shf::ScalarFromHash(h);
    hand_pk_ = shf::CreatePublicKey(hand_sk_);
  }

  const shf::PublicKey& GetHandPublicKey() const { return hand_pk_; }
  int GetId() const { return id_; }

  ShuffleMessage Shuffle(const shf::PublicKey& joint_pk, 
                         const shf::CommitKey& ck, 
                         const Deck& input_deck) {
    std::cout << "[Player " << id_ << "] Shuffling deck..." << std::endl;
    shf::Prg prg;
    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash;
    
    shf::ShuffleP proof = shuffler.Shuffle(input_deck.cards, hash);
    
    Deck new_deck;
    new_deck.cards = proof.permuted;
    
    return {new_deck, proof};
  }

  bool Verify(const shf::PublicKey& joint_pk, 
              const shf::CommitKey& ck, 
              const Deck& prev_deck, 
              const ShuffleMessage& msg) {
    std::cout << "[Player " << id_ << "] Verifying shuffle proof..." << std::endl;
    shf::Prg prg;
    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash;
    return shuffler.VerifyShuffle(prev_deck.cards, msg.proof, hash);
  }

  shf::Point ComputeDecryptionShare(const shf::Ctxt& ctxt) {
    return ctxt.U * hand_sk_;
  }

private:
  int id_;
  shf::Scalar identity_sk_;
  shf::SecretKey hand_sk_;
  shf::PublicKey hand_pk_;
};

class Server {
public:
  Server(int num_players) : num_players_(num_players) {
    shf::CurveInit();
    deck_points_.reserve(52);
    for (std::uint32_t i = 0; i < 52; ++i) deck_points_.emplace_back(CardPoint(i));
  }

  void RegisterPlayer(Player* p) {
    players_.push_back(p);
  }

  void InitGame() {
    hand_id_ = "1"; // Hardcoded for this simulation
    std::cout << "\n=== Starting New Hand ===\n";
    std::cout << "[Server] Generated Hand ID: " << hand_id_ << "\n";

    joint_pk_ = shf::Point();
    for (auto* p : players_) {
      p->InitHand(hand_id_);
      joint_pk_ = joint_pk_ + p->GetHandPublicKey();
    }
    std::cout << "[Server] Joint Public Key assembled from derived player keys.\n";
    
    ck_ = shf::CreateCommitKey(52);

    current_deck_.cards.clear();
    current_deck_.cards.reserve(52);
    for (const auto& pt : deck_points_) {
      current_deck_.cards.emplace_back(shf::Encrypt(joint_pk_, pt));
    }
    std::cout << "[Server] Deck encrypted.\n";
  }

  void RunShufflePhase() {
    std::cout << "\n--- Shuffle Phase ---\n";
    Deck prev_deck = current_deck_;

    std::cout << "[Server] Sending deck to Player 1.\n";
    ShuffleMessage msg1 = players_[0]->Shuffle(joint_pk_, ck_, prev_deck);

    if (!VerifyProof(prev_deck, msg1)) {
        std::cerr << "CHEATING DETECTED by P1\n"; exit(1);
    }
    
    if (!players_[1]->Verify(joint_pk_, ck_, prev_deck, msg1)) {
        std::cerr << "P2 rejected P1 proof\n"; exit(1);
    }

    current_deck_ = msg1.shuffled_deck;
    prev_deck = current_deck_;

    std::cout << "[Server] Sending deck to Player 2.\n";
    ShuffleMessage msg2 = players_[1]->Shuffle(joint_pk_, ck_, prev_deck);

    if (!VerifyProof(prev_deck, msg2)) {
         std::cerr << "CHEATING DETECTED by P2\n"; exit(1);
    }

    current_deck_ = msg2.shuffled_deck;
    std::cout << "[Server] Shuffle phase complete.\n";
  }

  void RunGamePhase() {
      int card_idx = 0;
      std::cout << "\n--- Dealing Phase ---\n";
      
      DealCardToPlayer(0, current_deck_.cards[card_idx++]);
      DealCardToPlayer(1, current_deck_.cards[card_idx++]);
      DealCardToPlayer(0, current_deck_.cards[card_idx++]);
      DealCardToPlayer(1, current_deck_.cards[card_idx++]);

      card_idx++; // Burn
      std::cout << "\n--- Flop ---\n";
      RevealCard(current_deck_.cards[card_idx++], "Flop 1");
      RevealCard(current_deck_.cards[card_idx++], "Flop 2");
      RevealCard(current_deck_.cards[card_idx++], "Flop 3");

      card_idx++; // Burn
      std::cout << "\n--- Turn ---\n";
      RevealCard(current_deck_.cards[card_idx++], "Turn");

      card_idx++; // Burn
      std::cout << "\n--- River ---\n";
      RevealCard(current_deck_.cards[card_idx++], "River");

      std::cout << "\n--- Showdown ---\n";
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

  void DealCardToPlayer(int target_id, const shf::Ctxt& ctxt) {
      shf::Point sum_shares = shf::Point();
      for (auto* p : players_) {
          if (p->GetId() == target_id) continue;
          sum_shares = sum_shares + p->ComputeDecryptionShare(ctxt);
      }
      Player* target = players_[target_id];
      shf::Point target_share = target->ComputeDecryptionShare(ctxt);
      shf::Point m = ctxt.V - (sum_shares + target_share);
      
      int card_val = DecodeCard(m, deck_points_);
      std::cout << "   (Player " << target_id << " privately sees: " 
                << (card_val >= 0 ? CardName(card_val) : "INVALID") << ")\n";
  }

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
  std::string hand_id_;
  shf::PublicKey joint_pk_;
  shf::CommitKey ck_;
  std::vector<shf::Point> deck_points_;
  Deck current_deck_;
};

} // namespace

int main() {
  std::cout << "=== Mediated Mental Poker (Deterministic Keys) ===\n";
  
  Player p1(0, "player0.key");
  Player p2(1, "player1.key");

  Server server(2);
  server.RegisterPlayer(&p1);
  server.RegisterPlayer(&p2);

  server.InitGame();
  server.RunShufflePhase();
  server.RunGamePhase();

  std::cout << "\n=== Hand Complete ===\n";
  return 0;
}
