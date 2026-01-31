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
 *
 * This function initializes the Relic cryptographic library and sets up
 * the elliptic curve parameters. It must be called once at program startup
 * before any other curve operations are performed.
 *
 * @throws std::runtime_error if Relic initialization fails
 */
void CurveInit();

/**
 * @brief Cleans up relic resources. Call when done using the library.
 *
 * This function releases all resources allocated by Relic, including
 * the curve order big number. After calling this, no curve operations
 * should be performed until CurveInit() is called again.
 */
void CurveCleanup();

/**
 * @brief Get the curve order for scalar modulo operations.
 *
 * The curve order is used to ensure scalars are in the correct range
 * [0, curve_order). This is necessary for cryptographic operations to
 * work correctly.
 *
 * @return pointer to the curve order big number
 */
const bn_t* GetCurveOrder();

class Point;

class Scalar {
 public:
  // internal access needed for scalar multiplications.
  friend class Point;

  /**
   * @brief Create a random scalar in the range [0, curve_order)
   * @return A randomly generated scalar
   * @throws std::runtime_error if random number generation fails
   */
  static Scalar CreateRandom();
  
  /**
   * @brief Create a scalar from an unsigned integer
   * @param v The integer value
   * @return A scalar with the given value
   */
  static Scalar CreateFromInt(unsigned int v);
  
  /**
   * @brief Read a scalar from a byte array
   * @param bytes Pointer to byte array of at least ByteSize() bytes
   * @return A scalar decoded from the byte array
   * @throws std::invalid_argument if bytes is null
   * @throws std::runtime_error if decoding fails
   */
  static Scalar Read(const uint8_t* bytes);

  static constexpr std::size_t ByteSize() { return 32; };

  /**
   * @brief Default constructor - creates a scalar with value 0
   * @throws std::runtime_error if memory allocation fails
   */
  Scalar();
  
  ~Scalar();

  Scalar(const Scalar& other);
  Scalar(Scalar&& other) noexcept;

  Scalar& operator=(const Scalar& other);
  Scalar& operator=(Scalar&& other) noexcept;

  /**
   * @brief Check if the scalar is zero
   * @return true if the scalar is zero, false otherwise
   */
  bool IsZero();

  /**
   * @brief Add two scalars (mod curve_order)
   * @param other The scalar to add
   * @return The sum of the two scalars
   * @throws std::runtime_error if addition or modulo operation fails
   */
  Scalar operator+(const Scalar& other) const;
  
  /**
   * @brief Subtract two scalars (mod curve_order)
   * @param other The scalar to subtract
   * @return The difference of the two scalars
   * @throws std::runtime_error if subtraction or modulo operation fails
   */
  Scalar operator-(const Scalar& other) const;
  
  /**
   * @brief Multiply two scalars (mod curve_order)
   * @param other The scalar to multiply by
   * @return The product of the two scalars
   * @throws std::runtime_error if multiplication or modulo operation fails
   */
  Scalar operator*(const Scalar& other) const;

  /**
   * @brief Negate the scalar (mod curve_order)
   * @return The negated scalar
   * @throws std::runtime_error if negation or modulo operation fails
   */
  Scalar operator-();

  Scalar& operator+=(const Scalar& other);
  Scalar& operator-=(const Scalar& other);
  Scalar& operator*=(const Scalar& other);

  bool operator==(const Scalar& other) const;
  bool operator!=(const Scalar& other) const { return !(*this == other); };

  /**
   * @brief Write the scalar to a byte array
   * @param dest Pointer to destination buffer
   * @param dest_size Size of destination buffer (must be >= ByteSize())
   * @throws std::invalid_argument if dest is null or buffer too small
   */
  void Write(uint8_t* dest, std::size_t dest_size = ByteSize()) const;

  void Print() const { bn_print(m_internal); }

 private:
  bn_t m_internal;
};

class Point {
 public:
  /**
   * @brief Get the generator point of the elliptic curve
   * @return The generator point G
   */
  static Point Generator();
  
  /**
   * @brief Create a random point on the curve
   * @return A randomly generated point
   */
  static Point CreateRandom();
  
  /**
   * @brief Read a point from a byte array
   * @param bytes Pointer to byte array of at least ByteSize() bytes
   * @return A point decoded from the byte array
   * @throws std::invalid_argument if bytes is null or encoding is invalid
   * @throws std::runtime_error if decoded point is not on the curve
   *
   * The encoding format is:
   * - bytes[0] == 1: point at infinity
   * - bytes[0] == 0: point encoded in bytes[1..ByteSize()-1]
   */
  static Point Read(const uint8_t* bytes);

  static constexpr std::size_t ByteSize() { return 2 + RLC_FP_BYTES; };

  /**
   * @brief Default constructor - creates the point at infinity
   * @throws std::runtime_error if memory allocation fails
   */
  Point();
  ~Point();

  Point(const Point& other);
  Point(Point&& other) noexcept;

  Point& operator=(const Point& other);
  Point& operator=(Point&& other) noexcept;

  /**
   * @brief Check if the point is at infinity
   * @return true if the point is at infinity, false otherwise
   */
  bool IsInfinity() const;

  Point operator+(const Point& other) const;
  Point operator-(const Point& other) const;

  Point& operator+=(const Point& other);
  Point& operator-=(const Point& other);

  /**
   * @brief Scalar multiplication: point * scalar
   * @param scalar The scalar to multiply by
   * @return The result of point * scalar
   */
  Point operator*(const Scalar& scalar) const;
  friend Point operator*(const Scalar& scalar, const Point& point) {
    return point * scalar;
  };

  bool operator==(const Point& other) const;
  bool operator!=(const Point& other) const { return !(*this == other); }

  /**
   * @brief Write the point to a byte array
   * @param dest Pointer to destination buffer
   * @param dest_size Size of destination buffer (must be >= ByteSize())
   * @throws std::invalid_argument if dest is null or buffer too small
   */
  void Write(uint8_t* dest, std::size_t dest_size = ByteSize()) const;

  void Print() const { ec_print(m_internal); }

 private:
  ec_t m_internal;
};

}  // namespace shf
#endif  // SHF_CURVE_H
