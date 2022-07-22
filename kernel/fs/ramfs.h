#pragma once

#include <fs/fd.h>
#include <fs/vfs.h>
#include <hash.h>

struct ramfs_handle {
	size_t inode;
	void *buffer;
};

extern size_t ramfs_inode_cnt;
extern char ramfs_lock;

extern struct hash_table ramfs_node_list;
extern struct filesystem ramfs_filesystem;
extern struct file_ops ramfs_fops;

