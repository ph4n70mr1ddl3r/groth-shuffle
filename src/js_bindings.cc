#include <emscripten/bind.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <stdexcept>

#include "curve.h"
#include "cipher.h"
#include "commit.h"
#include "shuffler.h"
#include "prg.h"

using namespace emscripten;
using namespace shf;

// --- Helpers for Byte/Hex Conversion ---

std::string ToHex(const uint8_t* data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for(size_t i=0; i<len; ++i) {
        ss << std::setw(2) << (int)data[i];
    }
    return ss.str();
}

std::vector<uint8_t> FromHex(const std::string& hex) {
    if ((hex.size() % 2) != 0) {
        throw std::invalid_argument("hex string must have even length");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const std::string byteString = hex.substr(i, 2);
        std::size_t parsed = 0;
        const auto v = std::stoul(byteString, &parsed, 16);
        if (parsed != 2 || v > 0xFFu) {
            throw std::invalid_argument("invalid hex string");
        }
        bytes.push_back(static_cast<uint8_t>(v));
    }
    return bytes;
}

// --- Wrappers ---

std::string ScalarToHex(const Scalar& s) {
    std::vector<uint8_t> buf(Scalar::ByteSize());
    s.Write(buf.data());
    return ToHex(buf.data(), buf.size());
}

Scalar ScalarFromHex(const std::string& hex) {
    std::vector<uint8_t> bytes = FromHex(hex);
    if (bytes.size() != Scalar::ByteSize()) {
        throw std::invalid_argument("invalid scalar encoding length");
    }
    return Scalar::Read(bytes.data());
}

std::string PointToHex(const Point& p) {
    std::vector<uint8_t> buf(Point::ByteSize());
    p.Write(buf.data());
    return ToHex(buf.data(), buf.size());
}

Point PointFromHex(const std::string& hex) {
    std::vector<uint8_t> bytes = FromHex(hex);
    if (bytes.size() != Point::ByteSize()) {
        throw std::invalid_argument("invalid point encoding length");
    }
    return Point::Read(bytes.data());
}

// --- Benchmark Class ---

class Benchmark {
public:
    Benchmark(int num_cards) : num_cards_(num_cards) {
        // Need to default construct members that are not in initializer list
        // CommitKey has no default ctor? It's a struct with vectors, so it does.
    }

    void Setup() {
        CurveInit();
        // Generate Keys
        p1_sk_ = Scalar::CreateRandom();
        p1_pk_ = CreatePublicKey(p1_sk_);
        
        p2_sk_ = Scalar::CreateRandom();
        p2_pk_ = CreatePublicKey(p2_sk_);
        
        joint_pk_ = p1_pk_ + p2_pk_;
        ck_ = CreateCommitKey(num_cards_);
        
        // Encrypt Deck
        deck_.clear();
        Point G = Point::Generator();
        for(int i=0; i<num_cards_; ++i) {
            // Just encrypt G for simulation
             deck_.push_back(Encrypt(joint_pk_, G));
        }
    }

    double RunShuffle() {
        Prg prg;
        Shuffler s(joint_pk_, ck_, prg);
        Hash h;
        auto start = std::chrono::high_resolution_clock::now();
        proof_ = s.Shuffle(deck_, h);
        auto end = std::chrono::high_resolution_clock::now();
        
        std::chrono::duration<double, std::milli> ms = end - start;
        return ms.count();
    }
    
    double RunVerify() {
        Prg prg;
        Shuffler s(joint_pk_, ck_, prg);
        Hash h;
        auto start = std::chrono::high_resolution_clock::now();
        bool ok = s.VerifyShuffle(deck_, proof_, h);
        auto end = std::chrono::high_resolution_clock::now();
        
        if (!ok) return -1.0;
        
        std::chrono::duration<double, std::milli> ms = end - start;
        return ms.count();
    }

private:
    int num_cards_;
    Scalar p1_sk_, p2_sk_;
    Point p1_pk_, p2_pk_, joint_pk_;
    CommitKey ck_;
    std::vector<Ctxt> deck_;
    ShuffleP proof_;
};

// --- Main Bindings ---

EMSCRIPTEN_BINDINGS(groth_shuffle) {
    function("init", &CurveInit);

    class_<Scalar>("Scalar")
        .constructor<>()
        .class_function("fromHex", &ScalarFromHex)
        .function("toHex", &ScalarToHex);

    class_<Point>("Point")
        .constructor<>()
        .class_function("fromHex", &PointFromHex)
        .function("toHex", &PointToHex);

    value_object<Ctxt>("Ctxt")
        .field("U", &Ctxt::U)
        .field("V", &Ctxt::V);

    register_vector<Ctxt>("VectorCtxt");
    register_vector<Scalar>("VectorScalar");
    
    // Simple PRG wrapper that just uses system entropy
    class_<Prg>("Prg")
        .constructor<>();

    function("createSecretKey", &CreateSecretKey);
    function("createPublicKey", &CreatePublicKey);
    
    function("encrypt", select_overload<Ctxt(const PublicKey&, const Point&)>(&Encrypt));
    function("decrypt", &Decrypt);

    class_<Benchmark>("Benchmark")
        .constructor<int>()
        .function("setup", &Benchmark::Setup)
        .function("runShuffle", &Benchmark::RunShuffle)
        .function("runVerify", &Benchmark::RunVerify);
}
