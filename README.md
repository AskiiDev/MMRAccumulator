# MMR Accumulator (In Progress)

A C implementation of a Merkle Mountain Range (MMR) accumulator for cryptographic set operations.

## What it does

This library maintains a compact cryptographic representation of a set where you can:
- Add elements and maintain a logarithmic size representation of the set
- Verify element membership using inclusion proofs (witnesses)
- Generate witnesses for any accumulated element
- Remove elements with deletion proofs  _(planned)_

I built this primarily as an educational tool - both for myself and others wanting to understand how cryptographic accumulators work. It's like a stepping stone toward more complex systems like [UTreeXO](https://github.com/utreexo/utreexo).

## How does an MMR work?

Merkle Mountain Range is essentially a forest of perfect binary trees. When you add elements:

1. Each element becomes a leaf node (tree of size 1)
2. Adjacent trees of the same size merge into a larger tree
3. The accumulator maintains the list of tree roots

The beauty is that the accumulator size grows logarithmically while supporting efficient proofs. This can effectively reduce gigabytes of data down to mere kilobytes, in the case of the Bitcoin UTXO set.

## Core components

**MMRAcccumulator:** The main structure containing:
- `head`: Linked list of tree roots
- `tracker`: Hash table tracking all nodes for memory management

**MMRNode:** Represents nodes in the forest:
- `hash`: SHA-256 hash of the node
- `n_leaves` Number of leaf elements under this node
- `parent/left/right`: Tree structure pointers
- `next`: Links root nodes together

**MMRTracker**: Hash table using FNV-1a hashing:
- Provides O(1) node lookup by hash
- Handles all node pointers and memory cleanup on `mmr_destroy`
- Resizes dynamically to maintain performance

**MMRWitness:** A compact proof showing that an element is part of the accumulator:
- `hash`: The hash of the element
- `siblings`: Array of sibling hashes needed to reconstruct the path
- `n_siblings`: Number of siblings in the path (proof depth)
- `path`: Bitfield encoding left/right order at each level

## API Overview

### Initialisation and destruction:

```c
void mmr_init(MMRAccumulator *acc)
void mmr_destroy(MMRAccumulator *acc)
```

---

### Adding and removing elements:

```c
bool mmr_add(MMRAccumulator *acc, const uint8_t *e, size_t n)
bool mmr_remove(MMRAccumulator *acc, const MMRWitness *proof)
```

---

### Proving membership

```c
bool mmr_verify(const MMRAccumulator *acc, const MMRWitness *w)
bool mmr_witness(const MMRAccumulator *acc, MMRWitness *w, const uint8_t *e, size_t n)
```

## Planned features

### Witness caching

The current implementation regenerates witnesses from scratch each time `mmr_witness()` is called. A planned optimisation will cache computed witnesses within the tracker, allowing:

- Instant witness retrieval for previously computed proofs
- Incremental witness updates when the accumulator structure changes

The foundation for this feature exists in the  `MMRItem`  structure, which already stores witness data alongside each node.

---

### Element removal

Support for deletion proofs to prune old elements from the accumulator while maintaining cryptographic integrity.

---

### Persistence

Serialise/deserialise accumulators for disk or network usage.

---

### Performance and scalability

Memory-efficient node storage and configurable hash functions.

---

_This is experimental code. Don't use it in production without further review and testing._
