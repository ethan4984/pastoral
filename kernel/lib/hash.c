#include <hash.h>
#include <string.h>

uint64_t fnv_hash(char *data, size_t byte_cnt) {
    uint64_t hash = 0xcbf29ce484222325;

    for(size_t i = 0; i < byte_cnt; i++) {
        hash ^= *(data + i);
        hash *= 0x100000001b3;
    }

    return hash;
}

void *hash_table_search(struct hash_table *table, void *key, size_t key_size) {
    uint64_t hash = fnv_hash(key, key_size);

    size_t index = hash & table->capacity;

    if(memcmp(table->keys.elements[index], key, key_size) == 0) {
        return table->data.elements[index];
    }

    for(; table->keys.elements[index] != NULL && index < table->capacity; index++) {
        if(memcmp(table->keys.elements[index], key, key_size) == 0) {
            return table->data.elements[index];
        }
    }

    return NULL;
}

void hash_table_push(struct hash_table *table, void *key, void *data, size_t key_size) {
    uint64_t hash = fnv_hash(key, key_size);

    size_t index = hash & table->capacity;

    if(table->keys.elements[index] == NULL) {
        table->data.elements[index] = data;
        return;
    }

    for(; index < table->capacity; index++) {
        if(table->keys.elements[index] == NULL) {
            table->data.elements[index] = data;
            return;
        }
    }

    table->capacity *= 2;

    VECTOR_INIT(table->data, table->capacity);
    VECTOR_INIT(table->keys, table->capacity);

    hash_table_push(table, key, data, key_size);
}
