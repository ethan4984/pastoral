#pragma once

#include <types.h>
#include <vector.h>

#define MAX_PATH_LENGTH 4096
#define MAX_FILENAME 256

struct vfs_cluster;
struct vfs_node;

struct vfs_node {
	const char *name;

	struct asset *asset;
	struct filesystem *filesystem;

	struct vfs_node *parent;
	struct vfs_node *mountpoint;

	VECTOR(struct vfs_node*) children;

	const char *symlink;
};

struct filesystem {
	struct vfs_node *(*create)(struct vfs_node *parent, const char *name, int mode);
};

struct vfs_node *vfs_create_node_deep(struct vfs_node *parent, struct asset *asset, struct filesystem *filesystem, const char *str);
struct vfs_node *vfs_create_node(struct vfs_node *parent, struct asset *asset, struct filesystem *filesystem, const char *name, int dangle);
struct vfs_node *vfs_search_absolute(struct vfs_node *parent, const char *path);
const char *vfs_absolute_path(struct vfs_node *node);
struct asset *vfs_default_asset(mode_t mode);
int vfs_mount(struct vfs_node *vfs_node, const char *source, const char *target, struct filesystem *filesystem);
void vfs_init();
