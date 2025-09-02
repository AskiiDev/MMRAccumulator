#include "accumulator.h"
#include <assert.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRACKER_LOAD_THRESH 0.75
#define TRACKER_MIN_CAPACITY 16

// ---------------------------- HASHING -------------------------------------

static inline bool sha256(const uint8_t *msg, size_t n, bytes32 *hash)
{
    if (!msg || n < 1 || !hash) return false;

    SHA256(msg, n, (unsigned char *) hash);
    return true;
}

static inline bool merkle_hash(const bytes32 *left, const bytes32 *right, bytes32 *hash)
{
    if (!left || !right || !hash) return false; 

    merkle64 buff;
    memcpy(buff, *left, SHA256_DIGEST_LENGTH);
    memcpy(buff + SHA256_DIGEST_LENGTH, *right, SHA256_DIGEST_LENGTH);

    if (!sha256(buff, SHA256_DIGEST_LENGTH * 2, hash)) return false;

    return true;
}

static inline bool hashes_equal(const bytes32 *a, const bytes32 *b)
{
    if (!a || !b) return false;
    return memcmp(*a, *b, SHA256_DIGEST_LENGTH) == 0;
}

// -------------------------- MMR TRACKER -----------------------------------

static inline void mmr_tr_init(MMRTracker *tracker)
{
    if (!tracker) return;

    tracker->leaves.count = 0;
    tracker->leaves.capacity = TRACKER_MIN_CAPACITY;

    if (tracker->leaves.items) free(tracker->leaves.items);
    tracker->leaves.items = calloc(tracker->leaves.capacity, sizeof(MMRItem *));

    tracker->roots.count = 0;
    tracker->roots.capacity = TRACKER_MIN_CAPACITY;

    if (tracker->roots.items) free(tracker->roots.items);
    tracker->roots.items = calloc(tracker->roots.capacity, sizeof(MMRItem *));
}

static inline void mmr_tr_set_destroy(MMRSet *set)
{
    if (!set) return;

    if (set->items) {
        for (size_t i = 0; i < set->capacity; ++i)
        {
            MMRItem *item = set->items[i];
            while (item)
            {
                MMRItem *next = item->next;
                
                free(item);
                item = next;
            }
        }

        free(set->items);
        set->items = NULL;
    }

    set->capacity = 0;
    set->count = 0;

}

static inline void mmr_tr_destroy(MMRTracker *tracker)
{
    if (!tracker) return;

    mmr_tr_set_destroy(&tracker->leaves);
    mmr_tr_set_destroy(&tracker->roots);
}

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

static bool mmr_tr_set_resize(MMRSet *set)
{
    if (!set) return false;
    if (set->count <= set->capacity * TRACKER_LOAD_THRESH)
    {
        return true;
    }

    size_t new_capacity = set->capacity * 2;
    MMRItem **temp = calloc(new_capacity, sizeof(MMRItem *));
    if (!temp) return false;

    for (size_t i = 0; i < set->capacity; ++i)
    {
        MMRItem *item = set->items[i];
        while (item) {
            MMRItem *next = item->next;

            size_t key = mmr_tr_hash(&item->node.hash, new_capacity);

            item->next = temp[key];
            temp[key] = item;

            item = next;
        }
    }

    free(set->items);

    set->items = temp;
    set->capacity = new_capacity;

    return true;
}

static bool mmr_tr_set_insert(MMRSet *set, const MMRNode *node)
{
    if (!set || !node) return false;
    if (!mmr_tr_set_resize(set)) return false;

    MMRItem *item = malloc(sizeof(MMRItem));
    item->node = *node;
    item->next = NULL;

    size_t key = mmr_tr_hash(&node->hash, set->capacity);
    if (!set->items[key])
    {
        set->items[key] = item;
    }
    else 
    {
        item->next = set->items[key];
        set->items[key] = item;
    }

    set->count++;

    return true;
}


static bool mmr_tr_insert(MMRTracker *tracker, const MMRNode *node, MMRTrackerType type)
{
    if (type == MMR_LEAF)
    {
        return mmr_tr_set_insert(&tracker->leaves, node);
    }

    if (type == MMR_ROOT)
    {
        return mmr_tr_set_insert(&tracker->roots, node);
    }

    return false;
}

static bool mmr_tr_get(const MMRTracker *tr, MMRNode *node, const uint8_t *e, size_t n)
{
    MMRNode *temp;
    if (!sha256(e, n, &temp->hash)) return false;

    // TODO I NEED TO DO THIS!!!!

    return true;
}

// --------------------------- MMR FOREST -----------------------------------

/**
 * Create leaf node from element data
 * @param e Element data
 * @param n Size of element data
 * @param leaf Pointer to leaf node
 * @return true on success, false on failure
 */
static bool create_leaf(MMRTracker *tracker, const uint8_t *e, size_t n, MMRNode **leaf)
{
    if (!e || n < 1) return false;

    MMRNode *root = malloc(sizeof(MMRNode));
    if (!root) return false;

    root->n_leaves = 1;
    root->next = NULL;

    sha256(e, n, &root->hash);

    if (!mmr_tr_insert(tracker, root, MMR_LEAF))
    {
        free(root);
        return false;
    }

    *leaf = root;
    return true;
}

/**
 * Merge two nodes of equal size into dest node
 * @param dest Destination node (will be modified)
 * @param src Source node (will be freed)
 * @return true on success, false on failure
 */
static bool merge_nodes(MMRNode *dest, MMRNode *src)
{
    if (!dest || !src) return false;
    if (dest->n_leaves != src->n_leaves) return false;

    dest->n_leaves *= 2;
    dest->next = NULL;

    if (!merkle_hash(&dest->hash, &src->hash, &dest->hash)) return false;
    
    free(src);
    return true;
}

// ------------------------ MMR ACCUMULATOR ---------------------------------

/**
 * Initialize an empty MMR accumulator
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
 * @param acc Pointer to accumulator to destroy
 */
void mmr_destroy(MMRAccumulator *acc)
{
    if (!acc) return;

    MMRNode *cur = acc->head;
    while (cur)
    {
        MMRNode *next = cur->next;

        free(cur);
        cur = next;
    }

    acc->head = NULL;

    mmr_tr_destroy(&acc->tracker);
}

/**
 * Add element to MMR accumulator
 * @param acc Pointer to accumulator
 * @param e Element data to add
 * @param n Size of element data
 * @return true on success, false on failure
 */
bool mmr_add(MMRAccumulator *acc, const uint8_t *e, size_t n)
{
    if (!acc || !e || n < 1) return false;

    MMRNode *node;
    if (!create_leaf(&acc->tracker, e, n, &node)) return false;

    MMRNode **cur = &acc->head;

    // Merge with existing roots of same size
    while (*cur && (*cur)->n_leaves == node->n_leaves)
    {
        MMRNode *next = (*cur)->next;
        if (!merge_nodes(node, *cur))
        {
            free(node);
            return false;
        }

        *cur = next;
    }

    // Insert the merged node in sorted order (largest first)
    node->next = *cur;
    *cur = node;

    return true;
}

/**
 * Remove element from MMR accumulator using witness
 * @param acc Pointer to accumulator
 * @param w Witness for element removal
 * @return true on success, false on failure
 */
bool mmr_remove(MMRAccumulator *acc, const MMRWitness *w)
{
    if (!acc || !w) return false;

    return false;
}

/**
 * Verify witness against MMR accumulator
 * @param acc Pointer to accumulator
 * @param w Witness to verify
 * @param e Element to check
 * @param n Size of element
 * @return true if proof is valid, false otherwise
 */
bool mmr_verify(const MMRAccumulator *acc, const MMRWitness *w, const uint8_t *e, size_t n)
{
    // Tree sizes should always be powers of two
    if (!acc || !w || !e || n < 1) return false;
    if (w->leaf_index >= (1ULL << w->n_siblings)) return false;

    bytes32 hash;
    sha256(e, n, &hash);

    for (size_t i = 0; i < w->n_siblings; ++i)
    {
        // Extract the order at the current level
        int sibling_order = (w->leaf_index >> i) & 1;
        if (sibling_order == MMR_SIBLING_RIGHT)
        {
            if (!merkle_hash(&hash, &w->siblings[i], &hash)) return false; 
        }
        else
        {
            if (!merkle_hash(&w->siblings[i], &hash, &hash)) return false;
        }
    }

    MMRNode *cur = acc->head;
    while (cur)
    {
        if (hashes_equal(&cur->hash, &hash))
        {
            return true;
        }

        cur = cur->next;
    }

    return false;
}

/**
 * Create witness for element in MMR accumulator
 * @param acc Pointer to accumulator
 * @param w Witness to write to
 * @param e Element to witness
 * @param n Size of element
 * @return true on success, false on failure
 */
bool mmr_witness(const MMRAccumulator *acc, MMRWitness *w, const uint8_t *e, size_t n)
{
    if (!acc || !e || n < 1) return false;

    // TODO MMR Tracker

    return false;
}
