#ifndef MERKLE_ACCUMULATOR_H
#define MERKLE_ACCUMULATOR_H

#include <openssl/sha.h>
#include <stdbool.h>
#include <string.h>

// ---------------------------- HASHING -------------------------------------

typedef uint8_t bytes32[SHA256_DIGEST_LENGTH];
typedef uint8_t merkle64[SHA256_DIGEST_LENGTH * 2];

// --------------------------- MMR FOREST -----------------------------------

typedef enum
{
    MMR_SIBLING_LEFT,
    MMR_SIBLING_RIGHT
} MerkleSiblingOrder;

typedef struct MMRNode
{
    bytes32 hash;
    size_t n_leaves;

    struct MMRNode *next;
} MMRNode;

typedef struct
{
    bytes32 *siblings;
    size_t n_siblings;
    size_t leaf_index;
} MMRWitness;

// -------------------------- MMR TRACKER -----------------------------------

typedef enum
{
    MMR_LEAF,
    MMR_ROOT
} MMRTrackerType;

typedef struct MMRItem
{
    MMRNode node;
    struct MMRItem *next;
} MMRItem;

typedef struct
{
    MMRItem **items;

    size_t capacity;
    size_t count;
} MMRSet;

typedef struct
{
    MMRSet roots;
    MMRSet leaves;
} MMRTracker;

// ------------------------ MMR ACCUMULATOR ---------------------------------

typedef struct
{
    MMRNode *head;
    MMRTracker tracker;
} MMRAccumulator;

void mmr_init(MMRAccumulator *acc);
void mmr_destroy(MMRAccumulator *acc);

bool mmr_add(MMRAccumulator *acc, const uint8_t *e, size_t n);
bool mmr_remove(MMRAccumulator *acc, const MMRWitness *proof);

bool mmr_verify(const MMRAccumulator *acc, const MMRWitness *w, const uint8_t *e, size_t n);
bool mmr_witness(const MMRAccumulator *acc, MMRWitness *w, const uint8_t *e, size_t n);

#endif
