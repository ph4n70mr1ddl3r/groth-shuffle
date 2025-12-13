# Cryptographic Shuffle ala. Bayer and Groth.

This is a simple implementation of the shuffle presented by Stephanie Bayer and
Jens Groth in their paper [Efficient Zero-Knowledge Argument for Correctness of
a Shuffle](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf).

The implementation uses [Relic](https://github.com/relic-toolkit/relic/) for
elliptic curve operations.

## Quick Start

### Dependencies
- **CMake** (≥3.10)
- **GMP** (GNU Multiple Precision Arithmetic Library)
- **C++17** compiler

On Debian/Ubuntu:
```bash
sudo apt install cmake libgmp-dev g++
```

On macOS (using Homebrew):
```bash
brew install cmake gmp
```

### Build & Test
Clone the repository and run the provided script:
```bash
git clone <repository-url>
cd groth-shuffle
./run.sh
```

This will:
1. Configure the project with CMake
2. Build the library, tests, and demo
3. Run all tests

Alternatively, you can build manually:
```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Security Considerations

### Curve Selection
This library uses Relic's default elliptic curve (determined by `ec_param_set_any()`).
The pre‑built Relic library in `thirdparty/` is configured for a 256‑bit prime curve.
For production use, verify that the curve meets your security requirements (e.g.,
secp256k1, NIST P‑256, or another standard curve).  You may need to rebuild Relic
with the desired curve parameters.

### Constant‑Time Operations
Cryptographic operations should be constant‑time to prevent side‑channel attacks.
The pre‑built Relic library may not have been compiled with constant‑time guarantees
(e.g., `-DRELIC_USE_CONSTANT_TIME`).  When deploying this code in a production
environment, ensure Relic is built with appropriate flags and that the underlying
arithmetic routines are secret‑independent.

### Randomness
The implementation uses Relic's random number generator (Hash‑DRBG) for scalar
generation and AES‑CTR for pseudorandom bytes.  Ensure your system provides
adequate entropy for the random seed.

## Disclaimer

This code was taken from a previous project of mine, and it's free to use
(without warranty and all that jazz).

The hash used is Keccak and its implementation is based the available reference
implementation.

The PRG is simply AES in counter mode.
