#include "accumulator.h"
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MMR_SIBLING_LEFT 0
#define MMR_SIBLING_RIGHT 1

#define WITNESS_MAX_SIBLINGS 63
#define TRACKER_LOAD_THRESH 0.75
#define TRACKER_MIN_CAPACITY 16

// ---------------------------- HASHING -------------------------------------

static inline bool sha256(const uint8_t *msg, size_t n, bytes32 *hash)
{
    if (!msg || !hash) return false;

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

    memset(tracker, 0, sizeof(MMRTracker));
    tracker->capacity = TRACKER_MIN_CAPACITY;
    tracker->items = calloc(tracker->capacity, sizeof(MMRItem *));
}

static inline void mmr_tr_destroy(MMRTracker *tracker)
{
    if (!tracker) return;

    if (tracker->items)
    {
        for (size_t i = 0; i < tracker->capacity; ++i)
        {
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

static bool mmr_tr_resize(MMRTracker *tracker)
{
    if (!tracker || !tracker->items) return false;
    if (tracker->count <= tracker->capacity * TRACKER_LOAD_THRESH)
    {
        return true;
    }

    size_t new_capacity = tracker->capacity * 2;
    MMRItem **temp = calloc(new_capacity, sizeof(MMRItem *));
    if (!temp) return false;

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

static bool mmr_tr_get(const MMRTracker *tracker, const bytes32 *hash, MMRItem **item)
{
    if (item) *item = NULL;
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
 * @param e Element data
 * @param n Size of element data
 * @param leaf Pointer to leaf node
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
 * @param left
 * @param right
 * @param parent
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

    left->parent = result;
    right->parent = result;

    result->left = left;
    result->right = right;

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
        if (!merge_nodes(&acc->tracker, node, *cur, &parent))
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
 * Remove element from MMR accumulator using witness
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
 * @param acc Pointer to accumulator
 * @param w Witness to verify
 * @return true if proof is valid, false otherwise
 */
bool mmr_verify(const MMRAccumulator *acc, const MMRWitness *w)
{
    // Tree sizes should always be powers of two
    if (!acc || !w) return false;
    if (w->n_siblings > 0 && !w->siblings) return false;
    if (w->n_siblings > WITNESS_MAX_SIBLINGS) return false;
    if (w->path >= (1ULL << w->n_siblings)) return false;

    bytes32 hash;
    memcpy(hash, w->hash, SHA256_DIGEST_LENGTH);

    for (size_t i = 0; i < w->n_siblings; ++i)
    {
        // Extract the order at the current level
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
 * @param acc Pointer to accumulator
 * @param w Witness to write to
 * @param e Element to witness
 * @param n Size of element
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

        if (parent->left == node)
        {
            sibling = parent->right;
            path |= (1ULL << level);
        }
        else if (parent->right == node)
        {
            sibling = parent->left;
        }
        else
        {
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

    if (level == 0)
    {
        free(siblings);
        siblings = NULL;
    }
    else
    {
        bytes32 *shrink = realloc(siblings, level * sizeof(bytes32));
        if (shrink)
        {
            siblings = shrink;
        }
    }

    w->siblings = siblings;

    if (item->witness.siblings)
    {
        free(item->witness.siblings);
        item->witness.siblings = NULL;
    }

    item->witness = *w;

    return true;
}
