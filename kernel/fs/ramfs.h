#pragma once

#include <fs/fd.h>
#include <fs/vfs.h>
#include <hash.h>
#include <lock.h>

struct ramfs_handle {
	size_t inode;
	void *buffer;
};

extern size_t ramfs_inode_cnt;
extern struct spinlock ramfs_lock;

extern struct hash_table ramfs_node_list;
extern struct filesystem ramfs_filesystem;
extern struct file_ops ramfs_fops;
