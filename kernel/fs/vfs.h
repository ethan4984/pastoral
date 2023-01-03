#pragma once

#include <lib/cpu.h>
#include <types.h>
#include <vector.h>
#include <hash.h>
#include <lock.h>

#define MAX_PATH_LENGTH 4096
#define MAX_FILENAME 256

struct vfs_cluster;
struct vfs_node;
struct file_ops;

struct vfs_node {
	struct spinlock lock;
	const char *name;

	struct file_ops *fops;
	struct filesystem *filesystem;

	struct vfs_node *parent;
	struct vfs_node *mountpoint;

	VECTOR(struct vfs_node*) children;
	int refresh;

	struct hash_table shared_pages;

	const char *symlink;
	struct stat *stat;
};

struct filesystem {
	struct vfs_node *(*create)(struct vfs_node *parent, const char *name, struct stat *stat);
	int (*truncate)(struct vfs_node *node, off_t count);
	int (*refresh)(struct vfs_node *dir);

	void *private_data;
};

struct vfs_node *vfs_create(struct vfs_node *parent, const char *name, struct stat *stat);
int vfs_truncate(struct vfs_node *node, off_t count);
int vfs_refresh(struct vfs_node *dir);

extern struct vfs_node *vfs_root;

struct vfs_node *vfs_create_node_deep(struct vfs_node *parent, struct file_ops *fops, struct filesystem *filesystem, struct stat *stat, const char *str);
struct vfs_node *vfs_create_node(struct vfs_node *parent, struct file_ops *fops, struct filesystem *filesystem, struct stat *stat, const char *name, int dangle);
struct vfs_node *vfs_search_absolute(struct vfs_node *parent, const char *path, bool symfollow);
struct vfs_node *vfs_search_relative(struct vfs_node *parent, const char *name, bool symfollow);
struct vfs_node *vfs_parent_dir(struct vfs_node *parent, const char *path);
struct vfs_node *vfs_get_node(struct vfs_node *parent, int index);
const char *vfs_absolute_path(struct vfs_node *node);
int vfs_mount(struct vfs_node *target, struct stat *stat, struct filesystem *filesystem, struct file_ops *fops);
void vfs_init();

static inline void node_lock(struct vfs_node *node) {
	if(node) {
		spinlock_irqsave(&node->lock);
	}
}

static inline void node_unlock(struct vfs_node *node) {
	if(node) {
		spinrelease_irqsave(&node->lock);
	}
}
