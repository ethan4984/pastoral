#pragma once

#include <types.h>

#define MAX_PATH_LENGTH 4096
#define MAX_FILENAME 256

struct vfs_cluster;
struct vfs_node;

struct filesystem {

};

struct vfs_node {
	const char *name;

	struct asset *asset;
	struct filesystem *filesystem;

	struct vfs_node *next;

	struct vfs_node *parent;
	struct vfs_node *child;

	struct cluster *parent_cluster;
	struct cluster *child_cluster; 
};

struct vfs_cluster {
	struct vfs_node *root_node;
	struct filesystem *filesystem;
};

struct vfs_node *vfs_create_node(struct vfs_node *parent, struct asset *asset, const char *name);
struct vfs_node *vfs_search_absolute(const char *src, struct vfs_node *node);
const char *vfs_absolute_path(struct vfs_node *node);
