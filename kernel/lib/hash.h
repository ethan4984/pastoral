#pragma once

#include <vector.h>

struct hash_table {
    VECTOR(void*) keys;
    VECTOR(void*) data;

    int hash_modulo;
    int capacity;
};
