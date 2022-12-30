#include <fs/vfs.h>
#include <vector.h>
#include <debug.h>
#include <string.h>
#include <time.h>
#include <fs/ramfs.h>
#include <sched/sched.h>

struct vfs_node *vfs_root;

struct vfs_node *vfs_create_node(struct vfs_node *parent, struct file_ops *fops, struct filesystem *filesystem, struct stat *stat, const char *name, int dangle) {
	if(parent == NULL) {
		parent = vfs_root;
	}

	struct vfs_node *node = alloc(sizeof(struct vfs_node));

	node->name = name;
	node->fops = fops;
	node->stat = stat;
	node->filesystem = filesystem;
	node->parent = parent;

	if(!dangle) {
		VECTOR_PUSH(parent->children, node);
	}

	if(S_ISDIR(stat->st_mode)) {
		struct vfs_node *current_directory = alloc(sizeof(struct vfs_node));
		struct vfs_node *last_directory = alloc(sizeof(struct vfs_node));

		current_directory->name = ".";
		current_directory->stat = stat;
		current_directory->filesystem = filesystem;
		current_directory->parent = node;

		last_directory->name = "..";
		last_directory->stat = parent->stat;
		last_directory->filesystem = filesystem;
		last_directory->parent = node;

		VECTOR_PUSH(node->children, current_directory);
		VECTOR_PUSH(node->children, last_directory);
	}

	return node;
}

void vfs_init() {
	struct stat *root_stat = alloc(sizeof(struct stat));
	stat_init(root_stat);
	root_stat->st_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	root_stat->st_uid = 0;
	root_stat->st_gid = 0;

	vfs_root = alloc(sizeof(struct vfs_node));
	vfs_root->name = "/";
	vfs_root->stat = root_stat;
	vfs_root->filesystem = &ramfs_filesystem;
	vfs_root->parent = NULL;
	vfs_root->fops = &ramfs_fops;

	struct vfs_node *current_directory = alloc(sizeof(struct vfs_node));
	struct vfs_node *last_directory = alloc(sizeof(struct vfs_node));

	current_directory->name = ".";
	current_directory->stat = root_stat;
	current_directory->filesystem = &ramfs_filesystem;
	current_directory->parent = vfs_root;
	current_directory->fops = &ramfs_fops;

	last_directory->name = "..";
	last_directory->stat = root_stat;
	last_directory->filesystem = &ramfs_filesystem;
	last_directory->parent = vfs_root;
	last_directory->fops = &ramfs_fops;

	VECTOR_PUSH(vfs_root->children, current_directory);
	VECTOR_PUSH(vfs_root->children, last_directory);
}

struct vfs_node *vfs_search_relative(struct vfs_node *parent, const char *name, bool symlink) {
	if(strcmp(name, ".") == 0) {
		return parent;
	} else if(strcmp(name, "..") == 0) {
		return parent->parent;
	}

	for(size_t i = 0; i < parent->children.length; i++) {
		if(parent->refresh) {
			parent->filesystem->refresh(parent);
			parent->refresh = 0;
		}

		struct vfs_node *node = parent->children.data[i];

		if(strcmp(node->name, name) == 0) {
			if(symlink && S_ISLNK(node->stat->st_mode)) {
				const char *sympath = node->symlink;

				int relative = *sympath == '/' ? 0 : 1;
				if(relative) {
					node = vfs_search_absolute(parent, sympath, true);
				} else {
					node = vfs_search_absolute(NULL, sympath, true);
				}
			}

			return node;
		}
	}

	return NULL;
}

struct vfs_node *vfs_create_node_deep(struct vfs_node *parent, struct file_ops *fops, struct filesystem *filesystem, struct stat *stat, const char *path) {
	if(parent == NULL) {
		parent = vfs_root;
	}

	VECTOR(const char*) subpath_list = { 0 };

	char *str = alloc(strlen(path));
	strcpy(str, path);

	while(*str == '/') *str++ = 0;

	while(*str) {
		const char *subpath = str;

		while(*str && *str != '/') str++;
		while(*str == '/') *str++ = 0;

		VECTOR_PUSH(subpath_list, subpath);
	}

	size_t i = 0;
	for(; i < subpath_list.length; i++) {
		struct vfs_node *node = vfs_search_relative(parent, subpath_list.data[i], true);
		if(node == NULL) {
			break;
		}

		if(node->mountpoint) {
			parent = node->mountpoint;
		} else {
			parent = node;
		}
	}

	if(i >= subpath_list.length) {
		return parent;
	}

	for(; i < (subpath_list.length - 1); i++) {
		struct stat *stat = alloc(sizeof(struct stat));
		stat_init(stat);
		stat->st_mode = parent->stat->st_mode;
		parent = vfs_create_node(parent, parent->fops, parent->filesystem, stat, subpath_list.data[i], 0);
		if(parent->mountpoint) {
			parent = parent->mountpoint;
		}
	}

	return vfs_create_node(parent, fops, filesystem, stat, subpath_list.data[i], 0);
}

struct vfs_node *vfs_search_absolute(struct vfs_node *parent, const char *path, bool symfollow) {
	if(parent == NULL) {
		parent = vfs_root;
	}

	VECTOR(const char*) subpath_list = { 0 };

	char *str = alloc(strlen(path));
	strcpy(str, path);

	while(*str == '/') *str++ = 0;

	while(*str) {
		const char *subpath = str;

		while(*str && *str != '/') str++;
		while(*str == '/') *str++ = 0;

		VECTOR_PUSH(subpath_list, subpath);
	}

	if(subpath_list.length == 0) {
		return vfs_root;
	}

	size_t i;
	for(i = 0; i < (subpath_list.length - 1); i++) {
		parent = vfs_search_relative(parent, subpath_list.data[i], true);
		if(parent == NULL) {
			return NULL;
		}

		if(parent->mountpoint) {
			parent = parent->mountpoint;
		}

		if(!S_ISDIR(parent->stat->st_mode)) {
			return NULL;
		}
	}

	return vfs_search_relative(parent, subpath_list.data[i], symfollow);
}

const char *vfs_absolute_path(struct vfs_node *node) {
	if(node == NULL) {
		return vfs_root->name;
	}

	VECTOR(struct vfs_node*) node_list = { 0 };

	while(node) {
		VECTOR_PUSH(node_list, node);
		node = node->parent;
	}

	char *ret = alloc(MAX_PATH_LENGTH);

	for(size_t i = node_list.length; i-- > 0;) {
		if(S_ISDIR(node_list.data[i]->stat->st_mode)) {
			sprint(ret + strlen(ret), "%s/", node_list.data[i]->name);
		} else {
			sprint(ret + strlen(ret), "%s", node_list.data[i]->name);
		}
	}

	VECTOR_CLEAR(node_list);

	return ++ret;
}

struct vfs_node *vfs_parent_dir(struct vfs_node *parent, const char *path) {
	if(parent == NULL) {
		parent = vfs_root;
	}

	VECTOR(const char*) subpath_list = { 0 };

	char *str = alloc(strlen(path));
	strcpy(str, path);

	while(*str == '/') *str++ = 0;

	while(*str) {
		const char *subpath = str;

		while(*str && *str != '/') str++;
		while(*str == '/') *str++ = 0;

		VECTOR_PUSH(subpath_list, subpath);
	}

	subpath_list.length--;

	if(subpath_list.length == 0) {
		return vfs_root;
	}

	size_t i;
	for(i = 0; i < (subpath_list.length - 1); i++) {
		parent = vfs_search_relative(parent, subpath_list.data[i], true);
		if(parent == NULL) {
			return NULL;
		}

		if(parent->mountpoint) {
			parent = parent->mountpoint;
		}

		if(!S_ISDIR(parent->stat->st_mode)) {
			return NULL;
		}
	}

	return vfs_search_relative(parent, subpath_list.data[i], true);
}

int vfs_mount(struct vfs_node *parent, const char *source, const char *target, struct filesystem *filesystem, struct file_ops *fops) {
	struct vfs_node *source_node = vfs_search_absolute(parent, source, true);
	struct vfs_node *target_node = vfs_search_absolute(parent, target, true);

	if(source_node == NULL || target_node == NULL) {
		return -1;
	}

	if(!S_ISDIR(target_node->stat->st_mode)) {
		return -1;
	}

	struct stat *stat = alloc(sizeof(struct stat));
	stat_init(stat);
	stat->st_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
	target_node->mountpoint = vfs_create_node(target_node->parent, fops, filesystem, stat, target_node->name, 1);

	return 0;
}
