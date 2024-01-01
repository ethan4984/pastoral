#pragma once

#include <stddef.h>
#include <stdint.h>

struct hash_table {
    void **keys;
    void **data;

    int capacity;
	int element_cnt;
};

uint64_t fnv_hash(char *data, size_t size);

void *hash_table_search(struct hash_table *table, void *key, size_t key_size);
void hash_table_push(struct hash_table *table, void *key, void *data, size_t key_size);
void hash_table_delete(struct hash_table *table, void *key, size_t key_size);
