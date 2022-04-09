#include <hash.h>
#include <string.h>
#include <mm/slab.h>

static uint64_t fnv_hash(char *data, size_t byte_cnt) {
    uint64_t hash = 0xcbf29ce484222325;

    for(size_t i = 0; i < byte_cnt; i++) {
        hash ^= *(data + i);
        hash *= 0x100000001b3;
    }

    return hash;
}

void *hash_table_search(struct hash_table *table, void *key, size_t key_size) {
    if(table->capacity == 0) {
        return NULL;
    }

    uint64_t hash = fnv_hash(key, key_size);

    size_t index = hash & (table->capacity - 1);

    for(; index < table->capacity; index++) {
        if(table->keys[index] != NULL && memcmp(table->keys[index], key, key_size) == 0) {
            return table->data[index];
        }
    }

    return NULL;
}

void hash_table_push(struct hash_table *table, void *key, void *data, size_t key_size) {
    if(table->capacity == 0) {
        table->capacity = 16;

        table->data = alloc(table->capacity * sizeof(void*));
        table->keys = alloc(table->capacity * sizeof(void*));
    }

    uint64_t hash = fnv_hash(key, key_size);

    size_t index = hash & (table->capacity - 1);

    for(; index < table->capacity; index++) {
        if(table->keys[index] == NULL) {
            table->keys[index] = key;
            table->data[index] = data;
            return;
        }
    }

    struct hash_table expanded_table = {
        .capacity = table->capacity * 2,
        .keys = alloc(table->capacity * sizeof(void*)),
        .data = alloc(table->capacity * sizeof(void*))
    };

    for(size_t i = 0; i < table->capacity; i++) {
        if(table->keys[i] != NULL) {
            hash_table_push(&expanded_table, table->keys[i], table->data[i], key_size);
        }
    }

    hash_table_push(&expanded_table, key, data, key_size);

    *table = expanded_table;
}

void hash_table_delete(struct hash_table *table, void *key, size_t key_size) {
    if(table->capacity == 0) {
        return;
    }

    uint64_t hash = fnv_hash(key, key_size);

    size_t index = hash & (table->capacity - 1);

    for(; index < table->capacity; index++) {
        if(table->keys[index] != NULL && memcmp(table->keys[index], key, key_size) == 0) {
            table->keys[index] = NULL;
            table->data[index] = NULL;
            return;
        }
    }
}
