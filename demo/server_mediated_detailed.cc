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
#include <array>

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

// Convert container of bytes to hex string
template <typename Container>
std::string bytesToHex(const Container& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::size_t CtxtByteSize() {
    return shf::Point::ByteSize() * 2;
}

void CtxtWrite(const shf::Ctxt& c, uint8_t* buf) {
    c.U.Write(buf);
    c.V.Write(buf + shf::Point::ByteSize());
}

// --- Key Management Helpers ---

void SaveKeyToFile(const std::string& filename, const shf::Scalar& key) {
  std::ofstream ofs(filename);
  if (!ofs) throw std::runtime_error("Cannot write to file: " + filename);
  std::vector<uint8_t> buffer(shf::Scalar::ByteSize());
  key.Write(buffer.data());
  ofs << bytesToHex(buffer);
}

shf::Scalar LoadOrGenerateKey(const std::string& filename) {
  std::ifstream ifs(filename);
  if (ifs) {
    std::string hex_key_string;
    ifs >> hex_key_string;
    if (ifs && hex_key_string.length() == shf::Scalar::ByteSize() * 2) {
      std::vector<uint8_t> bytes;
      for (std::size_t i = 0; i < hex_key_string.length(); i += 2) {
        std::string byteString = hex_key_string.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
      }
      return shf::Scalar::Read(bytes.data());
    }
  }
  shf::Scalar new_key = shf::Scalar::CreateRandom();
  SaveKeyToFile(filename, new_key);
  return new_key;
}

// --- Data Structures & Messages ---

struct Deck {
  std::vector<shf::Ctxt> cards;
  
  std::string GetHash() const {
      // Return a short hash of the deck content for logging
      shf::Hash h;
      std::vector<uint8_t> buf(CtxtByteSize());
      for (const auto& c : cards) {
           CtxtWrite(c, buf.data());
           h.Update(buf.data(), buf.size());
      }
      auto digest = h.Finalize();
      return bytesToHex(digest).substr(0, 8);
  }
};

// Simulation of Network Logging
struct SimulatedNetwork {
    static void Log(const std::string& from, const std::string& to, const std::string& type, const std::string& payload) {
        std::cout << "  [MSG] " << std::left << std::setw(10) << from 
                  << " -> " << std::setw(10) << to 
                  << " | Type: " << std::setw(20) << type << "\n";
        std::cout << "        Payload: " << payload << "\n";
    }
};

// --- Actors ---

class Player {
public:
  Player(int id, std::string key_file) : id_(id), name_("Player" + std::to_string(id + 1)) {
    identity_sk_ = LoadOrGenerateKey(key_file);
  }

  std::string GetName() const { return name_; }

  // MSG_HANDSHAKE_REQ -> MSG_HANDSHAKE_RESP
  shf::PublicKey HandleHandshakeRequest(const std::string& hand_id) {
    // Derive ephemeral key for this hand
    shf::Hash h;
    h.Update(identity_sk_);
    h.Update(reinterpret_cast<const uint8_t*>(hand_id.data()), hand_id.size());
    hand_sk_ = shf::ScalarFromHash(h);
    hand_pk_ = shf::CreatePublicKey(hand_sk_);
    
    SimulatedNetwork::Log(name_, "Server", "HANDSHAKE_RESP", "PublicKey: " + bytesToHex(GetPkBytes()).substr(0, 16) + "...");
    return hand_pk_;
  }

  // MSG_SHUFFLE_REQ -> MSG_SHUFFLE_RESP
  struct ShuffleResp {
      Deck new_deck;
      shf::ShuffleP proof;
  };

  ShuffleResp HandleShuffleRequest(const shf::PublicKey& joint_pk, const shf::CommitKey& ck, const Deck& input_deck, const std::string& hand_id) {
    // Deterministic seed for PRG
    shf::Hash h;
    h.Update(identity_sk_);
    h.Update(reinterpret_cast<const uint8_t*>(hand_id.data()), hand_id.size());
    h.Update(reinterpret_cast<const uint8_t*>("SHUFFLE"), 7);
    shf::Digest digest = h.Finalize();
    shf::Prg prg(digest.data());

    shf::Shuffler shuffler(joint_pk, ck, prg);
    shf::Hash hash; 
    
    // Simulate "Work"
    shf::ShuffleP proof = shuffler.Shuffle(input_deck.cards, hash);
    Deck new_deck;
    new_deck.cards = proof.permuted;

    SimulatedNetwork::Log(name_, "Server", "SHUFFLE_RESP", 
        "NewDeckHash: " + new_deck.GetHash() + ", Proof: [Attached]");

    return {new_deck, proof};
  }

  // MSG_VERIFY_REQ -> MSG_VERIFY_RESP
  bool HandleVerifyRequest(const shf::PublicKey& joint_pk, const shf::CommitKey& ck, const Deck& old_deck, const Deck& /*new_deck*/, const shf::ShuffleP& proof) {
      shf::Prg prg;
      shf::Shuffler shuffler(joint_pk, ck, prg);
      shf::Hash hash;
      bool ok = shuffler.VerifyShuffle(old_deck.cards, proof, hash);
      
      SimulatedNetwork::Log(name_, "Server", "VERIFY_RESP", ok ? "APPROVED" : "REJECTED");
      return ok;
  }

  // MSG_DECRYPT_SHARE_REQ -> MSG_DECRYPT_SHARE_RESP
  shf::Point HandleDecryptShareRequest(const shf::Ctxt& ctxt) {
      shf::Point share = ctxt.U * hand_sk_;
      
      std::vector<uint8_t> buf(shf::Point::ByteSize());
      share.Write(buf.data());
      SimulatedNetwork::Log(name_, "Server", "DECRYPT_SHARE_RESP", "Share: " + bytesToHex(buf).substr(0, 12) + "...");
      
      return share;
  }

  // MSG_PRIVATE_CARD_DELIVERY
  // Server sends ciphertext + others' shares so this player can fully decrypt
  int HandlePrivateCardDelivery(const shf::Ctxt& ctxt, const std::vector<shf::Point>& other_shares, const std::vector<shf::Point>& deck_points) {
      shf::Point sum_shares = shf::Point();
      for (const auto& s : other_shares) sum_shares = sum_shares + s;
      
      shf::Point my_share = ctxt.U * hand_sk_;
      shf::Point m = ctxt.V - (sum_shares + my_share);
      
      int val = DecodeCard(m, deck_points);
      SimulatedNetwork::Log(name_, "Server", "ACK_CARD_RECEIVED", val >= 0 ? "Decrypted successfully" : "Decryption Failed");
      return val;
  }

private:
  std::vector<uint8_t> GetPkBytes() {
      std::vector<uint8_t> b(shf::PublicKey::ByteSize());
      hand_pk_.Write(b.data());
      return b;
  }

  int id_;
  std::string name_;
  shf::Scalar identity_sk_;
  shf::SecretKey hand_sk_;
  shf::PublicKey hand_pk_;
};

class Server {
public:
  Server() {
    shf::CurveInit();
    deck_points_.reserve(52);
    for (std::uint32_t i = 0; i < 52; ++i) deck_points_.emplace_back(CardPoint(i));
  }

  void RegisterPlayer(Player* p) {
    players_.push_back(p);
  }

  void RunHand() {
    hand_id_ = "Hand_" + std::to_string(std::time(nullptr));
    std::cout << "\n=== [Server] Initializing " << hand_id_ << " ===\n";

    // 1. Handshake Phase
    std::cout << "\n--- Handshake Phase ---\n";
    joint_pk_ = shf::Point();
    for (auto* p : players_) {
        SimulatedNetwork::Log("Server", p->GetName(), "HANDSHAKE_REQ", "HandID: " + hand_id_);
        shf::PublicKey pk = p->HandleHandshakeRequest(hand_id_);
        joint_pk_ = joint_pk_ + pk;
    }
    ck_ = shf::CreateCommitKey(52);
    
    // Create Deck
    current_deck_.cards.clear();
    for (const auto& pt : deck_points_) {
      current_deck_.cards.emplace_back(shf::Encrypt(joint_pk_, pt));
    }
    std::cout << "Server: Deck created and encrypted. Hash: " << current_deck_.GetHash() << "\n";

    // 2. Shuffle Phase
    std::cout << "\n--- Shuffle Phase ---\n";
    
    // Iterate through players to shuffle
    for (size_t i = 0; i < players_.size(); ++i) {
        Player* shuffler = players_[i];
        Deck input_deck = current_deck_;
        
        // Request Shuffle
        SimulatedNetwork::Log("Server", shuffler->GetName(), "SHUFFLE_REQ", "DeckHash: " + input_deck.GetHash());
        auto resp = shuffler->HandleShuffleRequest(joint_pk_, ck_, input_deck, hand_id_);
        
        // Server validates proof
        shf::Hash h;
        shf::Prg prg;
        shf::Shuffler verifier(joint_pk_, ck_, prg);
        if (!verifier.VerifyShuffle(input_deck.cards, resp.proof, h)) {
            std::cerr << "SERVER ALARM: Verification failed for " << shuffler->GetName() << "\n";
            exit(1);
        }

        // Ask other players to verify
        for (size_t j = 0; j < players_.size(); ++j) {
            if (i == j) continue; // Don't verify own shuffle
            Player* verifier_p = players_[j];
            SimulatedNetwork::Log("Server", verifier_p->GetName(), "VERIFY_REQ", 
                "OldDeck: " + input_deck.GetHash() + ", NewDeck: " + resp.new_deck.GetHash());
            
            if (!verifier_p->HandleVerifyRequest(joint_pk_, ck_, input_deck, resp.new_deck, resp.proof)) {
                 std::cerr << "SERVER ALARM: " << verifier_p->GetName() << " rejected shuffle by " << shuffler->GetName() << "\n";
                 exit(1);
            }
        }
        
        current_deck_ = resp.new_deck;
    }

    // 3. Deal Phase
    std::cout << "\n--- Dealing Phase ---\n";
    int card_idx = 0;
    
    // Deal Hole Cards (Private)
    DealPrivateCard(0, current_deck_.cards[card_idx++]);
    DealPrivateCard(1, current_deck_.cards[card_idx++]);
    DealPrivateCard(0, current_deck_.cards[card_idx++]);
    DealPrivateCard(1, current_deck_.cards[card_idx++]);

    // Flop (Public)
    card_idx++; // Burn
    std::cout << "\n--- Flop (Public Reveal) ---\n";
    RevealPublicCard(current_deck_.cards[card_idx++], "Flop 1");
    RevealPublicCard(current_deck_.cards[card_idx++], "Flop 2");
    RevealPublicCard(current_deck_.cards[card_idx++], "Flop 3");

    // Turn
    card_idx++; // Burn
    std::cout << "\n--- Turn (Public Reveal) ---\n";
    RevealPublicCard(current_deck_.cards[card_idx++], "Turn");

    // River
    card_idx++; // Burn
    std::cout << "\n--- River (Public Reveal) ---\n";
    RevealPublicCard(current_deck_.cards[card_idx++], "River");

    // Showdown (Reveal hole cards)
    std::cout << "\n--- Showdown ---\n";
    std::cout << "P1 Shows:\n";
    RevealPublicCard(current_deck_.cards[0], "P1 Hole 1");
    RevealPublicCard(current_deck_.cards[2], "P1 Hole 2");
    
    std::cout << "P2 Shows:\n";
    RevealPublicCard(current_deck_.cards[1], "P2 Hole 1");
    RevealPublicCard(current_deck_.cards[3], "P2 Hole 2");
  }

  void DealPrivateCard(int target_idx, const shf::Ctxt& ctxt) {
      Player* target = players_[target_idx];
      std::vector<shf::Point> other_shares;
      
      std::cout << "Server: Facilitating private deal to " << target->GetName() << "...\n";

      // Collect shares from everyone ELSE
      for (size_t i = 0; i < players_.size(); ++i) {
          if (static_cast<int>(i) == target_idx) continue;
          
          SimulatedNetwork::Log("Server", players_[i]->GetName(), "DECRYPT_SHARE_REQ", "CiphertextID: " + GetCtxtId(ctxt));
          other_shares.push_back(players_[i]->HandleDecryptShareRequest(ctxt));
      }

      // Send shares + ciphertext to target
      std::stringstream ss;
      ss << "CiphertextID: " << GetCtxtId(ctxt) << ", OtherSharesCount: " << other_shares.size();
      SimulatedNetwork::Log("Server", target->GetName(), "PRIVATE_CARD_DELIVERY", ss.str());
      
      int val = target->HandlePrivateCardDelivery(ctxt, other_shares, deck_points_);
      std::cout << "   -> " << target->GetName() << " privately sees: " << (val >= 0 ? CardName(val) : "INVALID") << "\n";
  }

  void RevealPublicCard(const shf::Ctxt& ctxt, const std::string& label) {
      std::vector<shf::Point> all_shares;
      std::cout << "Server: Facilitating public reveal of " << label << "...\n";

      // Collect shares from EVERYONE
      for (auto* p : players_) {
          SimulatedNetwork::Log("Server", p->GetName(), "DECRYPT_SHARE_REQ", "CiphertextID: " + GetCtxtId(ctxt));
          all_shares.push_back(p->HandleDecryptShareRequest(ctxt));
      }

      // Server combines them
      shf::Point sum = shf::Point();
      for (const auto& s : all_shares) sum = sum + s;
      shf::Point m = ctxt.V - sum;
      
      int val = DecodeCard(m, deck_points_);
      std::cout << "   -> PUBLIC REVEAL " << label << ": " << (val >= 0 ? CardName(val) : "INVALID") << "\n";
  }
  
  std::string GetCtxtId(const shf::Ctxt& c) {
      std::vector<uint8_t> buf(CtxtByteSize());
      CtxtWrite(c, buf.data());
      shf::Hash h; h.Update(buf.data(), buf.size());
      auto digest = h.Finalize();
      return bytesToHex(digest).substr(0, 6);
  }

private:
  std::vector<Player*> players_;
  std::string hand_id_;
  shf::PublicKey joint_pk_;
  shf::CommitKey ck_;
  std::vector<shf::Point> deck_points_;
  Deck current_deck_;
};

} // namespace

int main() {
  std::cout << "=== Mediated Mental Poker Simulation (Detailed Protocol Log) ===\n";
  
  Player p1(0, "player0.key");
  Player p2(1, "player1.key");

  Server server;
  server.RegisterPlayer(&p1);
  server.RegisterPlayer(&p2);

  server.RunHand();

  std::cout << "\n=== Simulation Complete ===\n";
  return 0;
}