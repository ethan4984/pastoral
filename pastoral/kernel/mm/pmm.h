#pragma once

#include <stdint.h>

void pmm_init();
uint64_t pmm_alloc(uint64_t cnt, uint64_t align);
void pmm_free(uint64_t base, uint64_t cnt);
