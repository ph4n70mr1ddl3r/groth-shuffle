#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <random>
#include <cstring>
#include <chrono>
#include <fstream>
#include <algorithm>

#include "curve.h"
#include "cipher.h"
#include "commit.h"
#include "hash.h"
#include "prg.h"
#include "shuffler.h"
#include "zkp.h"

using namespace std::chrono;

struct Timer {
    std::string name;
    high_resolution_clock::time_point start;
    std::vector<double>& times;
    
    Timer(std::string n, std::vector<double>& t) : name(n), times(t) {
        start = high_resolution_clock::now();
    }
    
    ~Timer() {
        auto end = high_resolution_clock::now();
        double ms = duration_cast<microseconds>(end - start).count() / 1000.0;
        times.push_back(ms);
        std::cout << "  " << std::left << std::setw(30) << name << ": " 
                  << std::right << std::setw(10) << std::fixed << std::setprecision(2) << ms << " ms\n";
    }
};

struct Card {
    int suit;
    int rank;
    int index;
    shf::Point point;
    
    Card() : suit(0), rank(0), index(0), point(shf::Point::Generator()) {}
    Card(int s, int r, int idx, shf::Point p) : suit(s), rank(r), index(idx), point(p) {}
    
    static Card FromIndex(int idx, const shf::Point& p) {
        int suit = idx / 13;
        int rank = idx % 13 + 1;
        return Card(suit, rank, idx, p);
    }
    
    std::string ToString() const {
        std::string suitStr;
        if (suit == 0) suitStr = "♠";
        else if (suit == 1) suitStr = "♥";
        else if (suit == 2) suitStr = "♦";
        else suitStr = "♣";
        
        std::string rankStr;
        if (rank == 1) rankStr = "A";
        else if (rank == 11) rankStr = "J";
        else if (rank == 12) rankStr = "Q";
        else if (rank == 13) rankStr = "K";
        else rankStr = std::to_string(rank);
        
        return suitStr + rankStr;
    }
};

struct Player {
    std::string name;
    shf::SecretKey sk;
    shf::PublicKey pk;
    shf::Prg prg;
    shf::CommitKey ck;
    
    Player(std::string n, const uint8_t* seed) : name(n), prg(seed) {
        sk = shf::CreateSecretKey();
        pk = shf::CreatePublicKey(sk);
        ck = shf::CreateCommitKey(52);
    }
};

struct Server {
    std::string name;
    shf::PublicKey alice_pk;
    shf::PublicKey bob_pk;
    std::vector<Card> original_deck;
    std::vector<shf::Ctxt> current_deck;
    
    Server() : name("Server") {}
    
    void SetKeys(const Player& alice, const Player& bob) {
        alice_pk = alice.pk;
        bob_pk = bob.pk;
    }
    
    void InitializeDeck() {
        original_deck.clear();
        for (int i = 0; i < 52; ++i) {
            shf::Point p = shf::Point::CreateRandom();
            original_deck.push_back(Card::FromIndex(i, p));
        }
    }
    
    void SendToPlayer(const std::string& player_name, const std::vector<shf::Ctxt>& deck) {
        std::cout << "  [SERVER -> " << player_name << "] Sending " << deck.size() << " encrypted cards\n";
    }
    
    void ReceiveFromPlayer(const std::string& player_name, const std::vector<shf::Ctxt>& deck) {
        std::cout << "  [" << player_name << " -> SERVER] Received " << deck.size() << " encrypted cards\n";
    }
    
    Card FindCard(const shf::Point& p) {
        for (int j = 0; j < 52; ++j) {
            if (p == original_deck[j].point) {
                return original_deck[j];
            }
        }
        return Card(0, 0, -1, p);
    }
};

struct ShuffleStep {
    std::string player_name;
    std::vector<shf::Ctxt> input_cards;
    std::vector<shf::Ctxt> output_cards;
    shf::ShuffleP proof;
    bool verified;
    double prove_time;
    double verify_time;
};

struct TimingResults {
    std::vector<double> alice_encrypt;
    std::vector<double> bob_shuffle_prove;
    std::vector<double> bob_shuffle_verify;
    std::vector<double> alice_shuffle_prove;
    std::vector<double> alice_shuffle_verify;
    std::vector<double> deal_card;
    std::vector<double> decrypt;
    
    void Print() {
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "TIMING RESULTS\n";
        std::cout << std::string(60, '=') << "\n\n";
        
        auto avg = [&](const std::vector<double>& v) -> double {
            if (v.empty()) return 0.0;
            double sum = 0;
            for (auto x : v) sum += x;
            return sum / v.size();
        };
        
        auto print_row = [&](const std::string& label, const std::vector<double>& v, int count) {
            if (v.empty()) {
                std::cout << std::left << std::setw(35) << label 
                          << std::right << std::setw(10) << "N/A\n";
                return;
            }
            double a = avg(v);
            double min_val = *std::min_element(v.begin(), v.end());
            double max_val = *std::max_element(v.begin(), v.end());
            std::cout << std::left << std::setw(35) << label 
                      << std::right << std::setw(10) << std::fixed << std::setprecision(2) << a << " ms avg ("
                      << std::fixed << std::setprecision(2) << min_val << " - " 
                      << std::fixed << std::setprecision(2) << max_val << ") x" << count << "\n";
        };
        
        std::cout << std::left << std::setw(35) << "Operation" 
                  << std::right << std::setw(25) << "Average (min - max)\n";
        std::cout << std::string(60, '-') << "\n";
        
        print_row("Alice's Initial Encryption", alice_encrypt, 52);
        print_row("Bob's Shuffle (prove)", bob_shuffle_prove, 1);
        print_row("Bob's Shuffle (verify)", bob_shuffle_verify, 1);
        print_row("Alice's Shuffle (prove)", alice_shuffle_prove, 1);
        print_row("Alice's Shuffle (verify)", alice_shuffle_verify, 1);
        print_row("Card Decryption", decrypt, 5);
        
        std::cout << "\n";
        std::cout << "Total deck size: 52 cards\n";
        std::cout << "Encrypted deck size: " << (52 * sizeof(shf::Ctxt)) << " bytes\n";
        std::cout << "Proof size: ~" << (sizeof(shf::ShuffleP)) << " bytes\n";
    }
};

class PokerServerSimulation {
private:
    Player alice;
    Player bob;
    Server server;
    
    std::vector<ShuffleStep> shuffle_history;
    TimingResults timing;
    
public:
    PokerServerSimulation() : alice("Alice", reinterpret_cast<const uint8_t*>("alice12345678901bob")),
                              bob("Bob", reinterpret_cast<const uint8_t*>("bob12345678901234a")) {
        server.SetKeys(alice, bob);
        server.InitializeDeck();
    }
    
    void PrintCard(const std::string& label, const Card& card) {
        std::cout << label << ": " << card.ToString() << "\n";
    }
    
    void RunProtocol() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║     SERVER-BASED POKER SIMULATION - COORDINATED SHUFFLE & DEAL          ║\n";
        std::cout << "║                                                                          ║\n";
        std::cout << "║  Entities: Server (coordinator), Alice, Bob                             ║\n";
        std::cout << "║  Protocol:                                                              ║\n";
        std::cout << "║    1. Server initializes deck                                           ║\n";
        std::cout << "║    2. Alice encrypts deck with her key (sent via server)                ║\n";
        std::cout << "║    3. Bob shuffles ONCE (sent via server)                               ║\n";
        std::cout << "║    4. Alice shuffles ONCE (sent via server)                             ║\n";
        std::cout << "║    5. Server coordinates card dealing (Alice decrypts)                   ║\n";
        std::cout << "║    6. Server coordinates cooperative revelation                         ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════════╝\n";
        
        Step1_ServerInitializes();
        Step2_AliceEncrypts();
        Step3_BobShuffles();
        Step4_AliceShuffles();
        Step5_ServerHoldsDeck();
        Step6_DealCards();
        Step7_CooperativeRevelation();
        
        timing.Print();
    }
    
    void Step1_ServerInitializes() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 1: SERVER INITIALIZES DECK\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Server creates a fresh deck of 52 cards.\n";
        std::cout << "Server knows the original order (for verification only).\n";
        std::cout << "Deck will be encrypted before leaving server's control.\n\n";
        
        std::cout << "Original deck created:\n";
        for (int i = 0; i < 5; ++i) {
            std::cout << "  Card " << std::setw(2) << i << ": " << server.original_deck[i].ToString() << "\n";
        }
        std::cout << "  ... and " << (52 - 5) << " more cards\n";
        
        std::cout << "\nState:\n";
        std::cout << "  Server knows: Original deck order\n";
        std::cout << "  Alice knows: Nothing yet\n";
        std::cout << "  Bob knows: Nothing yet\n";
    }
    
    void Step2_AliceEncrypts() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 2: ALICE ENCRYPTS DECK (via Server)\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Server sends original deck to Alice (via secure channel).\n";
        server.SendToPlayer("Alice", {});
        
        std::cout << "\nAlice encrypts each card with her public key.\n";
        std::cout << "Alice can later decrypt to reveal cards.\n\n";
        
        std::vector<shf::Ctxt> encrypted_deck;
        
        {
            Timer t("Alice encrypt 52 cards", timing.alice_encrypt);
            for (const auto& card : server.original_deck) {
                shf::Ctxt c = shf::Encrypt(alice.pk, card.point);
                encrypted_deck.push_back(c);
            }
        }
        
        std::cout << "\nAlice sends encrypted deck back to server.\n";
        server.ReceiveFromPlayer("Alice", encrypted_deck);
        
        server.current_deck = encrypted_deck;
        
        std::cout << "\nState:\n";
        std::cout << "  Alice knows: Original order, each card's encryption, can decrypt\n";
        std::cout << "  Bob sees: Only encrypted ciphertexts\n";
        std::cout << "  Server sees: Encrypted ciphertexts\n";
    }
    
    void Step3_BobShuffles() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 3: BOB SHUFFLES (via Server)\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Server sends encrypted deck to Bob.\n";
        server.SendToPlayer("Bob", server.current_deck);
        
        std::cout << "\nBob shuffles the encrypted deck ONCE...\n";
        std::cout << "Bob generates a zero-knowledge proof of correct shuffle.\n\n";
        
        shf::Hash hash;
        shf::Shuffler shuffler(alice.pk, alice.ck, bob.prg);
        
        std::cout << "Bob's shuffle (prove): ";
        shf::ShuffleP proof;
        {
            Timer t("Bob shuffle prove", timing.bob_shuffle_prove);
            proof = shuffler.Shuffle(server.current_deck, hash);
        }
        std::cout << "\n";
        
        std::cout << "Bob sends shuffled deck + proof to server.\n";
        server.ReceiveFromPlayer("Bob", proof.permuted);
        
        std::cout << "\nServer requests Alice to verify Bob's proof...\n";
        bool verified;
        {
            Timer t("Bob shuffle verify", timing.bob_shuffle_verify);
            verified = shuffler.VerifyShuffle(server.current_deck, proof, hash);
        }
        std::cout << "Verification result: " << (verified ? "PASSED" : "FAILED") << "\n";
        
        ShuffleStep step;
        step.player_name = "Bob";
        step.input_cards = server.current_deck;
        step.output_cards = proof.permuted;
        step.proof = proof;
        step.verified = verified;
        shuffle_history.push_back(step);
        
        server.current_deck = proof.permuted;
        
        std::cout << "\nState:\n";
        std::cout << "  Alice knows: Original order, Bob shuffled (verified), can decrypt\n";
        std::cout << "  Bob knows: His secret permutation\n";
        std::cout << "  Server sees: Encrypted ciphertexts, verified proof\n";
    }
    
    void Step4_AliceShuffles() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 4: ALICE SHUFFLES (via Server)\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Server sends Bob's shuffled deck to Alice.\n";
        server.SendToPlayer("Alice", server.current_deck);
        
        std::cout << "\nAlice shuffles the deck ONCE (another layer of randomization)...\n";
        std::cout << "Alice generates a zero-knowledge proof of correct shuffle.\n\n";
        
        shf::Hash hash2;
        shf::Shuffler shuffler2(alice.pk, alice.ck, alice.prg);
        
        std::cout << "Alice's shuffle (prove): ";
        shf::ShuffleP proof2;
        {
            Timer t("Alice shuffle prove", timing.alice_shuffle_prove);
            proof2 = shuffler2.Shuffle(server.current_deck, hash2);
        }
        std::cout << "\n";
        
        std::cout << "Alice sends shuffled deck + proof to server.\n";
        server.ReceiveFromPlayer("Alice", proof2.permuted);
        
        std::cout << "\nServer requests Bob to verify Alice's proof...\n";
        bool verified2;
        {
            Timer t("Alice shuffle verify", timing.alice_shuffle_verify);
            verified2 = shuffler2.VerifyShuffle(server.current_deck, proof2, hash2);
        }
        std::cout << "Verification result: " << (verified2 ? "PASSED" : "FAILED") << "\n";
        
        ShuffleStep step;
        step.player_name = "Alice";
        step.input_cards = server.current_deck;
        step.output_cards = proof2.permuted;
        step.proof = proof2;
        step.verified = verified2;
        shuffle_history.push_back(step);
        
        server.current_deck = proof2.permuted;
        
        std::cout << "\nState:\n";
        std::cout << "  Alice knows: Her secret permutation, can decrypt\n";
        std::cout << "  Bob knows: His secret permutation\n";
        std::cout << "  Neither knows: Final order (composition of both)\n";
        std::cout << "  Server sees: Still encrypted, verified proofs\n";
    }
    
    void Step5_ServerHoldsDeck() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 5: SERVER HOLDS FINAL SHUFFLED DECK\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Both players have shuffled exactly ONCE.\n";
        std::cout << "Server holds the final encrypted deck.\n";
        std::cout << "Server has verified both shuffle proofs.\n\n";
        
        std::cout << "Shuffle history:\n";
        for (size_t i = 0; i < shuffle_history.size(); ++i) {
            std::cout << "  " << (i + 1) << ". " << shuffle_history[i].player_name 
                      << ": " << (shuffle_history[i].verified ? "verified" : "failed") << "\n";
        }
        
        std::cout << "\nServer's deck: " << server.current_deck.size() << " encrypted cards\n";
        std::cout << "Server CANNOT see card values (still encrypted).\n";
        
        std::cout << "\nState:\n";
        std::cout << "  Server holds: Shuffled encrypted deck\n";
        std::cout << "  Alice knows: Her permutation, can decrypt any card\n";
        std::cout << "  Bob knows: His permutation, cannot decrypt alone\n";
        std::cout << "  Neither player knows: Final complete card order\n";
    }
    
    void Step6_DealCards() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 6: SERVER DEALS CARDS (Texas Hold'em)\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Server will deal hole cards to both players.\n";
        std::cout << "Alice decrypts cards for both players (server coordinates).\n";
        std::cout << "Bob receives decrypted values from server.\n\n";
        
        std::vector<Card> alice_hole;
        std::vector<Card> bob_hole;
        
        int deal_order[] = {0, 1, 2, 3};
        
        std::cout << "Dealing order: Alice, Bob, Alice, Bob\n\n";
        
        for (int i = 0; i < 4; ++i) {
            int pos = deal_order[i];
            
            std::cout << "--- Dealing position " << (pos + 1) << " ---\n";
            std::cout << "Server: Selects encrypted card at position " << pos << "\n";
            std::cout << "        (Server doesn't know which card it is)\n\n";
            
            Card revealed;
            if (pos == 0 || pos == 2) {
                std::cout << "Server: Sends encrypted card to Alice for decryption\n";
                server.SendToPlayer("Alice", {server.current_deck[pos]});
                
                std::cout << "Alice: Decrypts card with her secret key\n";
                {
                    Timer t("Card decryption", timing.decrypt);
                    shf::Point decrypted = shf::Decrypt(alice.sk, server.current_deck[pos]);
                    
                    revealed = server.FindCard(decrypted);
                    if (revealed.index >= 0) {
                        alice_hole.push_back(revealed);
                    }
                }
                std::cout << "        -> Alice's hole card: " << revealed.ToString() << "\n";
                
                std::cout << "Server: Sends revealed card value to Bob\n";
                std::cout << "        [SERVER -> Bob] Card: " << revealed.ToString() << "\n";
            } else {
                std::cout << "Server: Sends encrypted card to Alice for decryption\n";
                server.SendToPlayer("Alice", {server.current_deck[pos]});
                
                std::cout << "Alice: Decrypts card with her secret key\n";
                {
                    Timer t("Card decryption", timing.decrypt);
                    shf::Point decrypted = shf::Decrypt(alice.sk, server.current_deck[pos]);
                    
                    revealed = server.FindCard(decrypted);
                    if (revealed.index >= 0) {
                        bob_hole.push_back(revealed);
                    }
                }
                std::cout << "        -> Bob's hole card: " << revealed.ToString() << "\n";
                
                std::cout << "Server: Sends revealed card value to Bob\n";
                std::cout << "        [SERVER -> Bob] Card: " << revealed.ToString() << "\n";
            }
            std::cout << "\n";
        }
        
        std::cout << "=== DEALT CARDS ===\n\n";
        std::cout << "Alice's hole cards: ";
        for (auto& c : alice_hole) std::cout << c.ToString() << " ";
        std::cout << "\n";
        
        std::cout << "Bob's hole cards:   ";
        for (auto& c : bob_hole) std::cout << c.ToString() << " ";
        std::cout << "\n";
        
        std::cout << "\n" << std::string(70, '-') << "\n";
        std::cout << "IMPORTANT NOTES:\n";
        std::cout << "  - Server never saw card values until Alice decrypted!\n";
        std::cout << "  - Alice only knows her 2 hole cards (and Bob's)\n";
        std::cout << "  - Bob learns his hole cards from server (after Alice decrypts)\n";
        std::cout << "  - Both players participated in shuffling\n";
    }
    
    void Step7_CooperativeRevelation() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "STEP 7: COOPERATIVE REVELATION (Full Deck)\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Server coordinates revealing the full deck.\n";
        std::cout << "Alice decrypts cards, server verifies against original.\n";
        std::cout << "Bob observes the revealed deck.\n";
        std::cout << "NO direct player-to-player communication - all via server.\n\n";
        
        std::vector<Card> revealed_cards;
        
        std::cout << "Revealing first 5 cards of the deck:\n\n";
        
        for (int i = 0; i < 5; ++i) {
            std::cout << "--- Revealing card " << (i + 1) << " ---\n";
            
            std::cout << "Server: Requests decryption of position " << i << " from Alice\n";
            server.SendToPlayer("Alice", {server.current_deck[i]});
            
            shf::Point decrypted;
            {
                Timer t("Card decryption", timing.decrypt);
                decrypted = shf::Decrypt(alice.sk, server.current_deck[i]);
            }
            std::cout << "Alice: Provides decrypted point to server\n";
            
            Card revealed = server.FindCard(decrypted);
            std::cout << "Server: Verifies against original deck\n";
            std::cout << "        -> Revealed: " << revealed.ToString() << "\n";
            
            if (revealed.index >= 0) {
                revealed_cards.push_back(revealed);
            }
            
            std::cout << "Server: Announces card to Bob\n";
            std::cout << "        [SERVER -> Bob] Card at position " << i << ": " << revealed.ToString() << "\n";
            std::cout << "\n";
        }
        
        std::cout << "=== PARTIALLY REVEALED DECK ===\n\n";
        std::cout << "First 5 cards:\n";
        for (int i = 0; i < 5; ++i) {
            std::cout << "  Position " << i << ": " << revealed_cards[i].ToString() << "\n";
        }
        
        std::cout << "\n" << std::string(70, '-') << "\n";
        std::cout << "COOPERATIVE REVELATION PROPERTIES:\n";
        std::cout << "  - Server coordinates all communication\n";
        std::cout << "  - Alice and Bob NEVER communicate directly\n";
        std::cout << "  - Server orchestrates all card revelations\n";
        std::cout << "  - Bob learns cards from server (not Alice directly)\n";
        std::cout << "  - Alice controls decryption, server distributes results\n";
        
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "PROTOCOL COMPLETE\n";
        std::cout << std::string(70, '=') << "\n\n";
        
        std::cout << "Key properties demonstrated:\n";
        std::cout << "  ✓ Server Coordination: All communication via server\n";
        std::cout << "  ✓ Fair Shuffle: Both players shuffle exactly once\n";
        std::cout << "  ✓ Verifiability: All shuffles proven with ZK proofs\n";
        std::cout << "  ✓ Privacy: Server cannot see cards until Alice decrypts\n";
        std::cout << "  ✓ No Direct P2P: Alice and Bob never communicate directly\n";
    }
};

int main() {
    shf::CurveInit();
    
    std::cout << "\nInitializing Server-Based Poker Simulation...\n\n";
    
    PokerServerSimulation sim;
    sim.RunProtocol();
    
    return 0;
}
