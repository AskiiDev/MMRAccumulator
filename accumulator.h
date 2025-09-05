#ifndef MERKLE_ACCUMULATOR_H
#define MERKLE_ACCUMULATOR_H

#include <openssl/sha.h>
#include <stdbool.h>
#include <string.h>

// ---------------------------- HASHING -------------------------------------

typedef uint8_t bytes32[SHA256_DIGEST_LENGTH];
typedef uint8_t merkle64[SHA256_DIGEST_LENGTH * 2];

// --------------------------- MMR FOREST -----------------------------------

/**
 * Represents a single node in the Merkle Mountain Range forest
 * Forms a binary tree structure with parent-child relationships
 * Root nodes are linked together via the next pointer
 */
typedef struct MMRNode
{
    bytes32 hash;
    size_t n_leaves;

    struct MMRNode *parent;
    struct MMRNode *left;
    struct MMRNode *right;

    // Only relevant for root nodes
    struct MMRNode *next;
} MMRNode;

/**
 * Merkle inclusion proof for demonstrating element membership in the MMR
 * Contains the element hash and sibling hashes needed to reconstruct a root hash
 * The path encodes which side each sibling is on during hash reconstruction
 */
typedef struct
{
    bytes32 hash;

    bytes32 *siblings;
    size_t n_siblings;
    size_t path;
} MMRWitness;

// -------------------------- MMR TRACKER -----------------------------------

/**
 * Hash table entry linking MMR nodes with their cached witnesses
 * Forms linked lists for collision resolution in the hash table
 */
typedef struct MMRItem
{
    MMRNode *node;
    MMRWitness witness;

    struct MMRItem *next;
} MMRItem;

/**
 * Hash table for tracking all MMR nodes with O(1) lookup by hash
 * Provides memory management and fast node retrieval for the MMR accumulator
 * MEMORY OWNERSHIP: Owns ALL dynamically allocated memory including:
 *  - All MMRNode instances and their data
 *  - All MMRItem instances
 *  - All witness siblings arrays
 *  - The hash table array itself
 * Callers must NEVER free any pointers returned by tracker functions
 * All cleanup is handled automatically by the destroy function
 */
typedef struct
{
    MMRItem **items;

    size_t capacity;
    size_t count;
} MMRTracker;

// ------------------------ MMR ACCUMULATOR ---------------------------------

/**
 * Merkle Mountain Range accumulator for incremental set membership proofs
 * Maintains a forest of perfect binary trees in decreasing size order
 * Supports efficient addition of elements and generation of inclusion proofs
 * 
 * MEMORY MODEL:
 *  - The tracker owns all dynamically allocated memory
 *  - Callers receive pointers for convenience but must not free them
 *  - All cleanup is handled by mmr_destroy()
 */
typedef struct
{
    MMRNode *head;
    MMRTracker tracker;
} MMRAccumulator;

/**
 * Initialize an empty MMR accumulator
 * Sets up the internal data structures for storing MMR nodes and witnesses
 * Must be called before using any other MMR functions
 * @param acc Pointer to accumulator structure to initialize
 */
void mmr_init(MMRAccumulator *acc);

/**
 * Destroy MMR accumulator and free all associated memory
 * Cleans up all nodes, witnesses, hash table, and internal data structures
 * MEMORY SAFETY: Frees ALL memory owned by the accumulator including nodes,
 * witnesses, siblings arrays, and tracker data - no manual cleanup required
 * After calling this function, the accumulator is invalid and must not be used
 * @param acc Pointer to accumulator to destroy and clean up
 */
void mmr_destroy(MMRAccumulator *acc);

/**
 * Add element to MMR accumulator
 * Creates a leaf node for the element and merges it with existing roots
 * Uses a binary addition algorithm to efficiently merge trees of equal size
 * @param acc Pointer to accumulator to add element to
 * @param e Element data to add to the accumulator
 * @param n Size of element data in bytes (must be > 0)
 * @return true on successful addition, false on failure or invalid parameters
 */
bool mmr_add(MMRAccumulator *acc, const uint8_t *e, size_t n);

/**
 * Remove element from MMR accumulator using witness
 * TODO: This function is currently unimplemented
 * @param acc Pointer to accumulator to remove element from
 * @param w Witness proving the element's membership for safe removal
 * @return true on successful removal, false on failure
 *       */
bool mmr_remove(MMRAccumulator *acc, const MMRWitness *w);

/**
 * Verify witness against MMR accumulator
 * Reconstructs the root hash by following the witness path and sibling hashes
 * Checks if the computed root matches any current root in the accumulator
 * Validates witness structure and parameters before verification
 * @param acc Pointer to accumulator to verify witness against
 * @param w Witness to verify for element membership
 * @return true if witness is valid and element is in the accumulator, false otherwise
 */
bool mmr_verify(const MMRAccumulator *acc, const MMRWitness *w);

/**
 * Create witness for element in MMR accumulator  
 * Generates a Merkle inclusion proof by collecting sibling hashes along
 * the path from the element's leaf node to a root node
 * MEMORY OWNERSHIP: The generated witness contains a siblings array that is
 * owned by the tracker - caller must NOT free w->siblings manually
 * The siblings array remains valid until mmr_destroy() is called
 * @param acc Pointer to accumulator containing the element
 * @param w Witness structure to populate with proof data
 * @param e Element data to create witness for
 * @param n Size of element data in bytes (must be > 0)
 * @return true on successful witness generation, false if element not found or failure
 */
bool mmr_witness(const MMRAccumulator *acc, MMRWitness *w, const uint8_t *e, size_t n);

#endif
