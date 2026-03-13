#ifndef SHF_CURVE_H
#define SHF_CURVE_H

#include <gmp.h>

#include <cstdint>

extern "C" {
#include "include/relic/relic.h"
}

namespace shf {

/**
 * @brief Initializes relic. Must be called before anything else.
 */
void CurveInit();

class Point;

class Scalar {
 public:
  friend class Point;

  [[nodiscard]] static Scalar CreateRandom();
  [[nodiscard]] static Scalar CreateFromInt(unsigned int v);
  [[nodiscard]] static Scalar Read(const uint8_t* bytes);

  [[nodiscard]] static constexpr std::size_t ByteSize() noexcept { return 32; }

  Scalar();
  ~Scalar() noexcept;

  Scalar(const Scalar& other);
  Scalar(Scalar&& other) noexcept;

  Scalar& operator=(const Scalar& other) noexcept;
  Scalar& operator=(Scalar&& other) noexcept;

  [[nodiscard]] bool IsZero() const noexcept;

  [[nodiscard]] Scalar operator+(const Scalar& other) const;
  [[nodiscard]] Scalar operator-(const Scalar& other) const;
  [[nodiscard]] Scalar operator*(const Scalar& other) const;

  [[nodiscard]] Scalar operator-() const;

  Scalar& operator+=(const Scalar& other);
  Scalar& operator-=(const Scalar& other);
  Scalar& operator*=(const Scalar& other);

  [[nodiscard]] bool operator==(const Scalar& other) const noexcept;
  [[nodiscard]] bool operator!=(const Scalar& other) const noexcept { return !(*this == other); }

  /**
   * @brief Writes the scalar to a byte buffer.
   * @param dest Destination buffer, must not be null and have at least ByteSize() bytes.
   * @throws std::invalid_argument if dest is null
   */
  void Write(uint8_t* dest) const;

#ifdef SHF_DEBUG
  void Print() const { bn_print(m_internal); }
#endif

 private:
  bn_t m_internal;
};

class Point {
 public:
  [[nodiscard]] static Point Generator();
  [[nodiscard]] static Point CreateRandom();
  [[nodiscard]] static Point Read(const uint8_t* bytes);

  [[nodiscard]] static constexpr std::size_t ByteSize() noexcept { return 2 + RLC_FP_BYTES; }

  Point() noexcept;
  ~Point() noexcept;

  Point(const Point& other);
  Point(Point&& other) noexcept;

  Point& operator=(const Point& other) noexcept;
  Point& operator=(Point&& other) noexcept;

  [[nodiscard]] bool IsInfinity() const noexcept;

  [[nodiscard]] Point operator+(const Point& other) const;
  [[nodiscard]] Point operator-(const Point& other) const;

  Point& operator+=(const Point& other);
  Point& operator-=(const Point& other);

  [[nodiscard]] Point operator*(const Scalar& scalar) const;
  [[nodiscard]] friend Point operator*(const Scalar& scalar, const Point& point) {
    return point * scalar;
  };

  [[nodiscard]] bool operator==(const Point& other) const noexcept;
  [[nodiscard]] bool operator!=(const Point& other) const noexcept { return !(*this == other); }

  /**
   * @brief Writes the point to a byte buffer.
   * @param dest Destination buffer, must not be null and have at least ByteSize() bytes.
   * @throws std::invalid_argument if dest is null
   */
  void Write(uint8_t* dest) const;

#ifdef SHF_DEBUG
  void Print() const { ec_print(m_internal); }
#endif

 private:
  ec_t m_internal;
};

}  // namespace shf
#endif  // SHF_CURVE_H
