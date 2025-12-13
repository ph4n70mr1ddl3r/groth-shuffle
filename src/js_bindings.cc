#include <emscripten/bind.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>

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
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
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
         // Handle error or padding? For now assume correct input.
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
    return Point::Read(bytes.data());
}

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
}
