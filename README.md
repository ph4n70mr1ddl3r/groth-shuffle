# Cryptographic Shuffle Implementation

This is a C++ implementation of the cryptographic shuffle protocol presented by Stephanie Bayer and Jens Groth in their paper ["Efficient Zero-Knowledge Argument for Correctness of a Shuffle"](http://www0.cs.ucl.ac.uk/staff/J.Groth/MinimalShuffle.pdf).

## Overview

The implementation provides:
- **Zero-knowledge shuffle proofs**: Prove that a permutation of ciphertexts was performed correctly without revealing the permutation
- **Cryptographic commitments**: Hide values while allowing later verification
- **Elliptic curve cryptography**: Using the Relic toolkit for efficient operations
- **Poker simulation**: A complete example showing server-coordinated card shuffling and dealing

## Features

- **Secure shuffling**: Cryptographically secure permutation with zero-knowledge proofs
- **Verifiable correctness**: Anyone can verify that shuffling was done correctly
- **Privacy preservation**: Server cannot see card values during shuffling
- **Multi-party coordination**: Support for multiple players shuffling in sequence

## Dependencies

- [Relic Toolkit](https://github.com/relic-toolkit/relic/) - Elliptic curve cryptography library
- C++17 compiler
- CMake 3.10+
- GMP library

## Building

```bash
# Configure the build
cmake . -B build

# Build the main executable
cd build && make

# Build with tests enabled
cmake . -B build -DBUILD_TESTS=ON
cd build && make
```

## Usage

The main executable demonstrates a server-based poker protocol:

```bash
./bg12_poker_server
```

This runs a complete simulation where:
1. Server initializes a deck of 52 cards
2. Alice encrypts the entire deck
3. Bob shuffles the encrypted deck with a zero-knowledge proof
4. Alice shuffles again with another proof
5. Server coordinates dealing hole cards for Texas Hold'em
6. Cards are revealed cooperatively

## Architecture

### Core Components

- **`Shuffler`**: Main class handling shuffle operations and proof generation/verification
- **`Cipher`**: ElGamal encryption/decryption operations
- **`Commit`**: Pedersen commitment scheme for hiding values
- **`ZKP`**: Zero-knowledge proof implementations (DLog, DLog equality, product proofs)
- **`Curve`**: Elliptic curve operations wrapper around Relic
- **`PRG`**: Pseudorandom generator using AES in counter mode
- **`Hash`**: Keccak hash function for Fiat-Shamir transforms

### Security Properties

- **Correctness**: Shuffle proofs guarantee the permutation was performed correctly
- **Privacy**: Ciphertexts hide card values from unauthorized parties
- **Soundness**: Invalid shuffles will fail verification with high probability
- **Zero-knowledge**: Proofs reveal nothing about the secret permutation

## Testing

Run the test suite:

```bash
cd build && ./tests
```

Tests cover:
- Shuffle correctness and verification
- Zero-knowledge proof soundness
- Curve operations
- Hash functions

## Disclaimer

This code is provided as-is for educational and research purposes. It has not been audited for production use.

## References

- Bayer, S., & Groth, J. (2012). Efficient zero-knowledge argument for correctness of a shuffle. In Advances in Cryptology–EUROCRYPT 2012 (pp. 263-280). Springer Berlin Heidelberg.
- The hash implementation is based on the Keccak reference implementation
- PRG uses AES in counter mode with AES-NI acceleration
