#include "curve.h"

#include <iostream>
#include <mutex>
#include <stdexcept>

static bn_t k_curve_order;
static std::once_flag k_curve_init_once;

void shf::CurveInit() {
  std::call_once(k_curve_init_once, []() {
    core_init();
    if (err_get_code() != RLC_OK) {
      throw std::runtime_error("relic core_init() failed");
    }

    RLC_TRY { ep_param_set(NIST_P256); }
    RLC_CATCH_ANY {
      core_clean();
      throw std::runtime_error("relic ep_param_set(NIST_P256) failed");
    }

    bn_new(k_curve_order);
    ec_curve_get_ord(k_curve_order);
    if (static_cast<std::size_t>(bn_size_bin(k_curve_order)) >
        shf::Scalar::ByteSize()) {
      throw std::runtime_error("curve order exceeds Scalar::ByteSize()");
    }
  });
}

shf::Point shf::Point::Generator() {
  CurveInit();
  Point g;
  ec_curve_get_gen(g.m_internal);
  return g;
}

shf::Point shf::Point::CreateRandom() {
  CurveInit();
  Point p;
  ec_rand(p.m_internal);
  return p;
}

shf::Point shf::Point::Read(const uint8_t* bytes) {
  CurveInit();
  Point p;
  if (bytes[0] == 1) {
    ec_set_infty(p.m_internal);
    return p;
  }
  if (bytes[0] != 0) {
    throw std::runtime_error("invalid point encoding");
  }
  RLC_TRY { ec_read_bin(p.m_internal, bytes + 1, ByteSize() - 1); }
  RLC_CATCH_ANY { throw std::runtime_error("failed to parse point encoding"); }
  if (ec_on_curve(p.m_internal) != 1) {
    throw std::runtime_error("invalid curve point");
  }
  return p;
}

shf::Point::Point() {
  CurveInit();
  ec_new(m_internal);
  ec_set_infty(m_internal);
}

shf::Point::~Point() { ec_free(m_internal); }

shf::Point::Point(const shf::Point& other) {
  ec_new(m_internal);
  ec_copy(m_internal, other.m_internal);
}

shf::Point::Point(shf::Point&& other) {
  ec_new(m_internal);
  ec_copy(m_internal, other.m_internal);
}

shf::Point& shf::Point::operator=(const shf::Point& other) {
  ec_copy(m_internal, other.m_internal);
  return *this;
}

shf::Point& shf::Point::operator=(shf::Point&& other) {
  ec_copy(m_internal, other.m_internal);
  return *this;
}

bool shf::Point::IsInfinity() const { return ec_is_infty(m_internal) == 1; }

shf::Point shf::Point::operator+(const shf::Point& other) const {
  CurveInit();
  Point r;
  ec_add(r.m_internal, m_internal, other.m_internal);
  return r;
}

shf::Point shf::Point::operator-(const shf::Point& other) const {
  CurveInit();
  Point r;
  ec_sub(r.m_internal, m_internal, other.m_internal);
  return r;
}

shf::Point& shf::Point::operator+=(const shf::Point& other) {
  CurveInit();
  ec_add(m_internal, m_internal, other.m_internal);
  return *this;
}

shf::Point& shf::Point::operator-=(const shf::Point& other) {
  CurveInit();
  ec_sub(m_internal, m_internal, other.m_internal);
  return *this;
}

shf::Point shf::Point::operator*(const shf::Scalar& scalar) const {
  CurveInit();
  Point r;
  ec_mul(r.m_internal, m_internal, scalar.m_internal);
  return r;
}

bool shf::Point::operator==(const shf::Point& other) const {
  return ec_cmp(m_internal, other.m_internal) == RLC_EQ;
}

void shf::Point::Write(uint8_t* dest) const {
  if (IsInfinity()) {
    dest[0] = 1;
    for (std::size_t i = 1; i < ByteSize(); ++i) dest[i] = 0;
  } else {
    dest[0] = 0;
    ec_write_bin(dest + 1, ByteSize() - 1, m_internal, 1);
  }
}

shf::Scalar::Scalar() {
  bn_new(m_internal);
  bn_zero(m_internal);
}

shf::Scalar::~Scalar() { bn_free(m_internal); }

shf::Scalar::Scalar(const shf::Scalar& other) {
  bn_new(m_internal);
  bn_copy(m_internal, other.m_internal);
}

shf::Scalar::Scalar(shf::Scalar&& other) {
  bn_new(m_internal);
  bn_copy(m_internal, other.m_internal);
}

shf::Scalar& shf::Scalar::operator=(const shf::Scalar& other) {
  bn_copy(m_internal, other.m_internal);
  return *this;
}

shf::Scalar& shf::Scalar::operator=(shf::Scalar&& other) {
  bn_copy(m_internal, other.m_internal);
  return *this;
}

bool shf::Scalar::IsZero() const { return bn_is_zero(m_internal) == 1; }

shf::Scalar shf::Scalar::operator+(const shf::Scalar& other) const {
  CurveInit();
  Scalar r;
  bn_add(r.m_internal, m_internal, other.m_internal);
  bn_mod(r.m_internal, r.m_internal, k_curve_order);
  return r;
}

shf::Scalar shf::Scalar::operator-(const shf::Scalar& other) const {
  CurveInit();
  Scalar r;
  bn_sub(r.m_internal, m_internal, other.m_internal);
  bn_mod(r.m_internal, r.m_internal, k_curve_order);
  return r;
}

shf::Scalar shf::Scalar::operator*(const shf::Scalar& other) const {
  CurveInit();
  Scalar r;
  bn_mul(r.m_internal, m_internal, other.m_internal);
  bn_mod(r.m_internal, r.m_internal, k_curve_order);
  return r;
}

shf::Scalar shf::Scalar::operator-() const {
  CurveInit();
  Scalar r;
  bn_sub(r.m_internal, k_curve_order, m_internal);
  bn_mod(r.m_internal, r.m_internal, k_curve_order);
  return r;
}

shf::Scalar& shf::Scalar::operator+=(const shf::Scalar& other) {
  CurveInit();
  bn_add(m_internal, m_internal, other.m_internal);
  bn_mod(m_internal, m_internal, k_curve_order);
  return *this;
}

shf::Scalar& shf::Scalar::operator-=(const shf::Scalar& other) {
  CurveInit();
  bn_sub(m_internal, m_internal, other.m_internal);
  bn_mod(m_internal, m_internal, k_curve_order);
  return *this;
}

shf::Scalar& shf::Scalar::operator*=(const shf::Scalar& other) {
  CurveInit();
  bn_mul(m_internal, m_internal, other.m_internal);
  bn_mod(m_internal, m_internal, k_curve_order);
  return *this;
}

bool shf::Scalar::operator==(const shf::Scalar& other) const {
  return bn_cmp(m_internal, other.m_internal) == RLC_EQ;
}

void shf::Scalar::Write(uint8_t* dest) const {
  bn_write_bin(dest, ByteSize(), m_internal);
}

shf::Scalar shf::Scalar::CreateRandom() {
  CurveInit();
  Scalar s;
  bn_rand_mod(s.m_internal, k_curve_order);
  return s;
}

shf::Scalar shf::Scalar::CreateRandom(shf::Prg& prg) {
  CurveInit();
  Scalar s;
  std::vector<uint8_t> buffer(ByteSize());
  prg.Fill(buffer);
  
  // Create a scalar from bytes
  bn_read_bin(s.m_internal, buffer.data(), buffer.size());
  
  // Ensure strict modulo reduction (Relic's bn_read_bin doesn't reduce)
  bn_mod(s.m_internal, s.m_internal, k_curve_order);
  
  return s;
}

shf::Scalar shf::Scalar::CreateFromInt(unsigned long long v) {
  CurveInit();
  Scalar s;
  bn_set_dig(s.m_internal, (dig_t)v);
  return s;
}

shf::Scalar shf::Scalar::Read(const uint8_t* bytes) {
  CurveInit();
  Scalar s;
  bn_read_bin(s.m_internal, bytes, ByteSize());
  bn_mod(s.m_internal, s.m_internal, k_curve_order);
  return s;
}
