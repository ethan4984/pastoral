#pragma once

#include <types.h>

ssize_t ramfs_read(struct asset *asset, void*, off_t offset, off_t cnt, void *buf);
ssize_t ramfs_write(struct asset *asset, void*, off_t offset, off_t cnt, void *buf);
int ramfs_resize(struct asset *asset, void*, off_t cnt);
