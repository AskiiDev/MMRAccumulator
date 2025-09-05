#include "accumulator.h"
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * MMR sibling position constants for witness path encoding
 * Used to determine which side of the parent node a sibling is on
 */
#define MMR_SIBLING_LEFT 0
#define MMR_SIBLING_RIGHT 1

#define WITNESS_MAX_SIBLINGS 63
#define TRACKER_LOAD_THRESH 0.75
#define TRACKER_MIN_CAPACITY 16

// ---------------------------- HASHING -------------------------------------

/**
 * Compute SHA-256 hash of a message
 * @param msg Input message data to hash
 * @param n Length of the message in bytes
 * @param hash Output buffer to store the computed hash
 * @return true on success, false if any parameter is NULL
 */
static inline bool sha256(const uint8_t *msg, size_t n, bytes32 *hash)
{
    if (!msg || !hash) return false;

    SHA256(msg, n, (unsigned char *) hash);
    return true;
}

/**
 * Compute Merkle hash by concatenating and hashing two child hashes
 * @param left Hash of the left child node
 * @param right Hash of the right child node
 * @param hash Output buffer to store the computed parent hash
 * @return true on success, false if any parameter is NULL or hashing fails
 */
static inline bool merkle_hash(const bytes32 *left, const bytes32 *right, bytes32 *hash)
{
    if (!left || !right || !hash) return false;

    merkle64 buff;
    memcpy(buff, *left, SHA256_DIGEST_LENGTH);
    memcpy(buff + SHA256_DIGEST_LENGTH, *right, SHA256_DIGEST_LENGTH);

    if (!sha256(buff, SHA256_DIGEST_LENGTH * 2, hash)) return false;

    return true;
}

/**
 * Compare two hash values for equality
 * @param a First hash to compare
 * @param b Second hash to compare
 * @return true if hashes are equal, false otherwise or if either is NULL
 */
static inline bool hashes_equal(const bytes32 *a, const bytes32 *b)
{
    if (!a || !b) return false;
    return memcmp(*a, *b, SHA256_DIGEST_LENGTH) == 0;
}

// -------------------------- MMR TRACKER -----------------------------------

/**
 * Initialize an empty MMR tracker with default capacity
 * Sets up the hash table for tracking MMR nodes and their witnesses
 * @param tracker Pointer to tracker structure to initialize
 */
static inline void mmr_tr_init(MMRTracker *tracker)
{
    if (!tracker) return;

    memset(tracker, 0, sizeof(MMRTracker));
    tracker->capacity = TRACKER_MIN_CAPACITY;
    tracker->items = calloc(tracker->capacity, sizeof(MMRItem *));
}

/**
 * Destroy MMR tracker and free all associated memory
 * Walks through all hash table buckets and cleans up nodes, witnesses, and items
 * MEMORY OWNERSHIP: The tracker owns and frees ALL dynamically allocated memory
 * including MMRNodes, MMRItems, witness siblings arrays, and the hash table itself
 * @param tracker Pointer to tracker structure to destroy
 */
static inline void mmr_tr_destroy(MMRTracker *tracker)
{
    if (!tracker) return;

    if (tracker->items)
    {
        for (size_t i = 0; i < tracker->capacity; ++i)
        {
            // Clean up the linked list in this bucket
            MMRItem *item = tracker->items[i];
            while (item)
            {
                MMRItem *next = item->next;

                if (item->node)
                {
                    free(item->node);
                    item->node = NULL;
                }

                if (item->witness.siblings)
                {
                    free(item->witness.siblings);
                    item->witness.siblings = NULL;
                }

                // Clear stale witness data
                memset(item->witness.hash, 0, sizeof(bytes32));
                item->witness.n_siblings = 0;
                item->witness.path = 0;

                free(item);
                item = next;
            }
        }

        free(tracker->items);
        tracker->items = NULL;
    }

    tracker->capacity = 0;
    tracker->count = 0;
}

/**
 * Compute hash table index for a given hash using FNV-1a algorithm
 * Uses FNV-1a for good distribution properties and collision resistance
 * @param hash The hash value to compute table index for
 * @param capacity Size of the hash table (must be > 0)
 * @return Hash table index in range [0, capacity)
 */
static inline size_t mmr_tr_hash(const bytes32 *hash, size_t capacity)
{
    if (!hash || capacity < 1) return 0;

    size_t h = 14695981039346656037ULL; // FNV-1a 64-bit offset basis

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        h ^= (*hash)[i];
        h *= 1099511628211ULL; // FNV-1a prime
    }

    return h % capacity;
}

/**
 * Resize the MMR tracker hash table when load factor exceeds threshold
 * Doubles the capacity and rehashes all existing items to new positions
 * @param tracker Pointer to tracker to resize
 * @return true on success, false on memory allocation failure
 */
static bool mmr_tr_resize(MMRTracker *tracker)
{
    if (!tracker || !tracker->items) return false;

    // Check if resizing is actually needed
    if (tracker->count <= tracker->capacity * TRACKER_LOAD_THRESH)
    {
        return true;
    }

    size_t new_capacity = tracker->capacity * 2;
    MMRItem **temp = calloc(new_capacity, sizeof(MMRItem *));
    if (!temp) return false;

    // Rehash all existing items into the new table
    for (size_t i = 0; i < tracker->capacity; ++i)
    {
        MMRItem *item = tracker->items[i];
        while (item)
        {
            MMRItem *next = item->next;

            size_t key = mmr_tr_hash(&item->node->hash, new_capacity);

            item->next = temp[key];
            temp[key] = item;

            item = next;
        }
    }

    free(tracker->items);

    tracker->items = temp;
    tracker->capacity = new_capacity;

    return true;
}

/**
 * Look up an MMR item by its hash value in the tracker
 * Searches the appropriate hash table bucket for a matching node
 * MEMORY OWNERSHIP: Returned item pointer is owned by tracker - caller must NOT free
 * The returned item and its contents remain valid until mmr_tr_destroy() is called
 * @param tracker Pointer to tracker to search in
 * @param hash Hash value to search for
 * @param item Output pointer to store found item (tracker retains ownership)
 * @return true if item was found, false otherwise
 */
static bool mmr_tr_get(const MMRTracker *tracker, const bytes32 *hash, MMRItem **item)
{
    if (!item) return false;
    *item = NULL;
    
    if (!tracker || !tracker->items) return false;

    MMRItem *cur = tracker->items[mmr_tr_hash(hash, tracker->capacity)];
    while (cur)
    {
        if (hashes_equal(hash, &cur->node->hash))
        {
            *item = cur;
            return true;
        }

        cur = cur->next;
    }

    return false;
}

/**
 * Check if the accumulator has a root node with the given hash
 * A root node is one that has no parent (is at the top of a tree)
 * @param acc Pointer to accumulator to check
 * @param hash Hash value to search for among root nodes
 * @return true if a root with this hash exists, false otherwise
 */
static bool mmr_tr_has_root(const MMRAccumulator *acc, const bytes32 *hash)
{
    if (!acc) return false;

    MMRItem *cur = acc->tracker.items[mmr_tr_hash(hash, acc->tracker.capacity)];
    while (cur)
    {
        // A node is a root if it has no parent
        if (cur->node->parent == NULL && hashes_equal(hash, &cur->node->hash))
        {
            return true;
        }

        cur = cur->next;
    }

    return false;
}

/**
 * Check if the tracker contains a specific MMR node pointer
 * Searches for the exact pointer value, not just hash equality
 * @param tracker Pointer to tracker to search in
 * @param node Pointer to the node to search for
 * @return true if the exact node pointer is found, false otherwise
 */
static bool mmr_tr_has_ptr(const MMRTracker *tracker, const MMRNode *node)
{

    if (!tracker || !tracker->items) return false;

    MMRItem *cur = tracker->items[mmr_tr_hash(&node->hash, tracker->capacity)];
    while (cur)
    {
        if (node == cur->node)
        {
            return true;
        }

        cur = cur->next;
    }

    return false;
}

/**
 * Insert a new MMR node into the tracker hash table
 * Automatically handles table resizing and prevents duplicate insertions
 * MEMORY OWNERSHIP: The tracker takes ownership of the node pointer and will
 * free it during mmr_tr_destroy() - callers must NOT free the node manually
 * @param tracker Pointer to tracker to insert into
 * @param node Pointer to node to insert (ownership transferred to tracker)
 * @return true on success, false on failure or if node already exists
 */
static bool mmr_tr_insert(MMRTracker *tracker, MMRNode *node)
{
    if (!tracker || !tracker->items || !node) return false;
    if (!mmr_tr_resize(tracker)) return false;

    // Tracker already has the node
    if (mmr_tr_has_ptr(tracker, node)) return true;

    MMRItem *item = malloc(sizeof(MMRItem));
    if (!item) return false;

    item->node = node;
    item->next = NULL;
    memset(&item->witness, 0, sizeof(MMRWitness));
    item->witness.siblings = NULL;

    size_t key = mmr_tr_hash(&node->hash, tracker->capacity);
    if (!tracker->items[key])
    {
        tracker->items[key] = item;
    }
    else
    {
        item->next = tracker->items[key];
        tracker->items[key] = item;
    }

    ++tracker->count;

    return true;
}

// --------------------------- MMR FOREST -----------------------------------

/**
 * Create leaf node from element data
 * Computes the hash of the element and creates a new leaf node in the MMR
 * MEMORY OWNERSHIP: The created node is owned by the tracker after successful insertion
 * Caller receives a pointer for convenience but must NOT free the node
 * @param tracker Pointer to tracker to register the new node with (takes ownership)
 * @param e Element data to create leaf for
 * @param n Size of element data in bytes
 * @param leaf Output pointer to store the created leaf node (tracker owns the memory)
 * @return true on success, false on failure
 */
static bool create_leaf(MMRTracker *tracker, const uint8_t *e, size_t n, MMRNode **leaf)
{
    if (!tracker || !leaf || !e || n < 1) return false;

    MMRNode *node = malloc(sizeof(MMRNode));
    if (!node) return false;

    if (!sha256(e, n, &node->hash))
    {
        free(node);
        return false;
    }

    if (!mmr_tr_insert(tracker, node))
    {
        free(node);
        return false;
    }

    node->n_leaves = 1;
    node->next = NULL;
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;

    *leaf = node;

    return true;
}

/**
 * Merge two nodes of equal size into a parent node
 * Creates a new internal node by hashing the two child nodes together
 * MEMORY OWNERSHIP: The created parent node is owned by the tracker after successful insertion
 * Child nodes remain owned by tracker, caller receives parent pointer but must NOT free it
 * @param tracker Pointer to tracker to register the new parent node with (takes ownership)
 * @param left Left child node to merge (must be tracker-owned)
 * @param right Right child node to merge (must be tracker-owned)
 * @param parent Output pointer to store the created parent node (tracker owns the memory)
 * @return true on success, false on failure
 */
static bool merge_nodes(MMRTracker *tracker, MMRNode *left, MMRNode *right, MMRNode **parent)
{
    if (!tracker || !parent || !left || !right) return false;
    if (left->n_leaves != right->n_leaves) return false;

    MMRNode *result = malloc(sizeof(MMRNode));
    if (!result) return false;

    if (!merkle_hash(&left->hash, &right->hash, &result->hash))
    {
        free(result);
        return false;
    }

    if (!mmr_tr_insert(tracker, result))
    {
        free(result);
        return false;
    }

    result->n_leaves = left->n_leaves * 2;

    // Establish relationships
    left->parent = result;
    right->parent = result;

    result->left = left;
    result->right = right;

    // Clear next pointers since children are no longer roots
    left->next = NULL;
    right->next = NULL;
    result->next = NULL;

    result->parent = NULL;

    *parent = result;

    return true;
}

// ------------------------ MMR ACCUMULATOR ---------------------------------

/**
 * Initialize an empty MMR accumulator
 * Sets up the root list and internal node tracker
 * @param acc Pointer to accumulator to initialize
 */
void mmr_init(MMRAccumulator *acc)
{
    if (!acc) return;

    acc->head = NULL;
    mmr_tr_init(&acc->tracker);
}

/**
 * Destroy MMR accumulator and free all memory
 * Cleans up all nodes, witnesses, and internal data structures
 * MEMORY OWNERSHIP: This function frees ALL memory associated with the accumulator
 * including all MMR nodes, witnesses, and tracker data - no manual cleanup required
 * @param acc Pointer to accumulator to destroy
 */
void mmr_destroy(MMRAccumulator *acc)
{
    if (!acc) return;

    acc->head = NULL;
    mmr_tr_destroy(&acc->tracker);
}

/**
 * Add element to MMR accumulator
 * Creates a leaf node and merges it with existing roots of the same size
 * @param acc Pointer to accumulator
 * @param e Element data to add
 * @param n Size of element data in bytes
 * @return true on success, false on failure
 */
bool mmr_add(MMRAccumulator *acc, const uint8_t *e, size_t n)
{
    if (!acc || !e || n < 1) return false;

    MMRNode *node;
    if (!create_leaf(&acc->tracker, e, n, &node))
    {
        return false;
    }

    MMRNode **cur = &acc->head;

    // Merge with existing roots of same size
    while (*cur && (*cur)->n_leaves == node->n_leaves)
    {
        MMRNode *next = (*cur)->next;
        MMRNode *parent;
        if (!merge_nodes(&acc->tracker, *cur, node, &parent))
        {
            return false;
        }

        node = parent;
        *cur = next;
    }

    node->next = *cur;
    *cur = node;

    return true;
}

/**
 * TODO Remove element from MMR accumulator using witness
 * @param acc Pointer to accumulator
 * @param w Witness for element removal
 * @return true on success, false on failure
 */
// bool mmr_remove(MMRAccumulator *acc, const MMRWitness *w)
// {
//     if (!acc || !w) return false;
//
//     return false;
// }

/**
 * Verify witness against MMR accumulator
 * Reconstructs the root hash from the witness path and checks if it matches
 * any root in the accumulator's current state
 * @param acc Pointer to accumulator
 * @param w Witness to verify
 * @return true if proof is valid, false otherwise
 */
bool mmr_verify(const MMRAccumulator *acc, const MMRWitness *w)
{
    if (!acc || !w) return false;
    if (w->n_siblings > 0 && !w->siblings) return false;
    if (w->n_siblings > WITNESS_MAX_SIBLINGS) return false;
    if (w->path >= (1ULL << w->n_siblings)) return false;

    bytes32 hash;
    memcpy(hash, w->hash, SHA256_DIGEST_LENGTH);

    // Reconstruct the root hash by following the witness path
    for (size_t i = 0; i < w->n_siblings; ++i)
    {
        // Extract the bit at position i to determine sibling order
        int sibling_order = (w->path >> i) & 1;
        if (sibling_order == MMR_SIBLING_RIGHT)
        {
            if (!merkle_hash(&hash, &w->siblings[i], &hash))
            {
                return false;
            }
        }
        else
        {
            if (!merkle_hash(&w->siblings[i], &hash, &hash))
            {
                return false;
            }
        }

        if (mmr_tr_has_root(acc, &hash))
        {
            return true;
        }
    }

    return mmr_tr_has_root(acc, &hash);
}

/**
 * Create witness for element in MMR accumulator
 * Generates a Merkle proof that demonstrates the element is included
 * in the accumulator by collecting sibling hashes along the path to root
 * MEMORY OWNERSHIP: The witness siblings array is owned by the tracker after creation
 * Caller receives populated witness struct but must NOT free w->siblings manually
 * The siblings array will be freed automatically during mmr_destroy()
 * @param acc Pointer to accumulator
 * @param w Witness structure to populate with proof data (siblings owned by tracker)
 * @param e Element to create witness for
 * @param n Size of element in bytes
 * @return true on success, false on failure
 */
bool mmr_witness(const MMRAccumulator *acc, MMRWitness *w, const uint8_t *e, size_t n)
{
    if (!acc || !w || !e || n < 1) return false;

    bytes32 hash;
    if (!sha256(e, n, &hash)) return false;

    MMRItem *item;
    if (!mmr_tr_get(&acc->tracker, &hash, &item))
    {
        return false;
    }

    // TODO Cache and re-use unchanged witnesses
    // if (item->witness.siblings)
    // {
    // }

    MMRNode *node = item->node;

    memset(w, 0, sizeof(MMRWitness));

    size_t path = 0;
    size_t level = 0;

    // Allocate maximum possible space for sibling hashes
    bytes32 *siblings = calloc(WITNESS_MAX_SIBLINGS, sizeof(bytes32));

    while (node->parent)
    {
        if (level >= WITNESS_MAX_SIBLINGS)
        {
            free(siblings);
            return false;
        }

        MMRNode *parent = node->parent;
        MMRNode *sibling;

        // Determine which child we are and find our sibling
        if (parent->left == node)
        {
            // We are the left child, sibling is on the right
            sibling = parent->right;

            // Set bit to indicate right sibling
            path |= (1ULL << level);
        }
        else if (parent->right == node)
        {
            // We are the right child, sibling is on the left
            sibling = parent->left;
            // Path bit remains 0 for left sibling
        }
        else
        {
            // Invalid tree structure
            free(siblings);
            return false;
        }

        memcpy(siblings[level], sibling->hash, sizeof(bytes32));

        node = parent;
        ++level;
    }

    memcpy(w->hash, hash, sizeof(bytes32));
    w->n_siblings = level;
    w->path = path;

    // Check if this is a leaf level proof
    if (level == 0)
    {
        free(siblings);
        siblings = NULL;
    }
    else
    {
        // Shrink the array down if possible to save some memory
        bytes32 *shrink = realloc(siblings, level * sizeof(bytes32));
        if (shrink)
        {
            siblings = shrink;
        }
    }

    w->siblings = siblings;

    // If we've previously calculated a witness
    // for this node, we need to manually free it,
    // otherwise it'll be overwritten and go untracked
    if (item->witness.siblings)
    {
        free(item->witness.siblings);
        item->witness.siblings = NULL;
    }

    item->witness = *w;

    return true;
}
