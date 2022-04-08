#pragma once

#include <fs/vfs.h>

struct vfs_node *ramfs_create(struct vfs_node *parent, const char *name, int mode);
ssize_t ramfs_read(struct asset *asset, void*, off_t offset, off_t cnt, void *buf);
ssize_t ramfs_write(struct asset *asset, void*, off_t offset, off_t cnt, const void *buf);
int ramfs_resize(struct asset *asset, void*, off_t cnt);
