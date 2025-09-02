#include "accumulator.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline void log_hash256(const bytes32 hash)
{
    for (int i = 0; i < 4; ++i) printf("%02x", hash[i]);
    printf("...");
}

void print_structure(MMRAccumulator *bc)
{
    MMRNode *cur = bc->head;
    printf("\nStructure: ");

    while (cur)
    {
        log_hash256(cur->hash);
        printf(": [size %zu] -> ", cur->n_leaves);

        cur = cur->next;
    }

    printf("NULL\n");

    if (0)
    {
        for (size_t i = 0; i < bc->tracker.leaves.count; ++i)
        {
            // log_hash256(bc->tracker.leaves.items[i]);
            printf("\n");
        }
    }

    printf("\n");
}

int main()
{
    MMRAccumulator acc;

    mmr_init(&acc);

    char buff[256] = "";
    const char *input = "1";

    for (int i = 0; i < 10; ++i)
    {
        strcat(buff, input);
        mmr_add(&acc, (uint8_t *) buff, strlen(buff));
        print_structure(&acc);
    }

    mmr_destroy(&acc);

    return 0;
}
