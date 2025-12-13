#include <catch2/catch.hpp>
#include <vector>

#include "curve.h"

TEST_CASE("point") {
  shf::CurveInit();

  SECTION("add") {
    shf::Point p = shf::Point::CreateRandom();
    shf::Point q = shf::Point::CreateRandom();
    shf::Point inf;
    REQUIRE(p + q == q + p);
    REQUIRE(p + inf == p);
    REQUIRE(p + p != p);
    const auto sum = p + q;
    p += q;
    REQUIRE(p == sum);
  }

  SECTION("subtract") {
    shf::Point p = shf::Point::CreateRandom();
    shf::Point q = shf::Point::CreateRandom();
    shf::Point inf;
    REQUIRE(p - q != q - p);
    REQUIRE(p - inf == p);
    const auto diff = p - q;
    p -= q;
    REQUIRE(p == diff);
  }

  SECTION("scalar mul") {
    shf::Point p = shf::Point::CreateRandom();
    shf::Scalar x = shf::Scalar::CreateRandom();
    shf::Scalar y = shf::Scalar::CreateRandom();
    REQUIRE(p * x == x * p);
    REQUIRE((p * x) * y == (p * y) * x);
  }

  SECTION("infinity serialization is deterministic") {
    shf::Point inf;
    std::vector<uint8_t> bytes(shf::Point::ByteSize(), 0xAA);
    inf.Write(bytes.data());
    REQUIRE(bytes[0] == 1);
    for (std::size_t i = 1; i < bytes.size(); ++i) REQUIRE(bytes[i] == 0);
  }
}

TEST_CASE("scalar") {
  shf::CurveInit();

  SECTION("add") {
    shf::Scalar a = shf::Scalar::CreateRandom();
    shf::Scalar b = shf::Scalar::CreateRandom();
    shf::Scalar z;
    REQUIRE(a + b == b + a);
    REQUIRE(a + z == a);
    REQUIRE(a + a != a);
  }

  SECTION("from int") {
    shf::Scalar a = shf::Scalar::CreateRandom();
    shf::Scalar two = shf::Scalar::CreateFromInt(2);
    REQUIRE(a + a == two * a);
  }

  SECTION("negation of zero") {
    shf::Scalar z;
    REQUIRE((-z).IsZero());
  }
}
