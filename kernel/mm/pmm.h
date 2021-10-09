#pragma once

#include <stivale.h>

void pmm_init(struct stivale_struct *stivale_struct);
uint64_t pmm_alloc(uint64_t cnt, uint64_t align);
void pmm_free(uint64_t base, uint64_t cnt);
