# MMR Accumulator

C implementation of a Merkle Mountain Range (MMR) accumulator with efficient element addition, removal, and membership verification.

## Overview

This library provides a cryptographic accumulator based on Merkle Mountain Ranges:
- Add elements and maintain a compact representation of the set
- Generate inclusion proofs (witnesses) for elements (planned feature)
- Verify membership of elements using witnesses
- Remove elements with appropriate witnesses (planned feature)

## Features
- Efficient Storage: Uses a forest of perfect binary trees to minimize storage overhead
- Fast Operations: Logarithmic time complexity for most operations
- Cryptographically Secure: Built on SHA-256 hash functions
