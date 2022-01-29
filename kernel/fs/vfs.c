#include <fs/vfs.h>
#include <vector.h>
#include <debug.h>
#include <string.h>
#include <time.h>
#include <fs/ramfs.h>

struct vfs_node *vfs_root;

struct asset *vfs_default_asset(mode_t mode) {
	struct asset *asset = alloc(sizeof(struct asset));
	asset->stat = alloc(sizeof(struct stat));
	asset->stat->st_mode = mode;
	asset->stat->st_atim = clock_realtime;
	asset->stat->st_mtim = clock_realtime;
	asset->stat->st_ctim = clock_realtime;
	return asset;
}

struct vfs_node *vfs_create_node(struct vfs_node *parent, struct asset *asset, struct filesystem *filesystem, const char *name, int dangle) {
	if(parent == NULL) {
		parent = vfs_root;
	}

	struct vfs_node *node = alloc(sizeof(struct vfs_node));

	node->name = name;
	node->asset = asset;
	node->filesystem = filesystem;
	node->parent = parent;

	if(!dangle) {
		VECTOR_PUSH(parent->children, node);
	}

	if(S_ISDIR(asset->stat->st_mode)) {
		struct vfs_node *current_directory = alloc(sizeof(struct vfs_node));
		struct vfs_node *last_directory = alloc(sizeof(struct vfs_node));

		current_directory->name = ".";
		current_directory->asset = vfs_default_asset(S_IFDIR);
		current_directory->filesystem = filesystem;
		current_directory->parent = node;

		last_directory->name = "..";
		last_directory->asset = vfs_default_asset(S_IFDIR);
		last_directory->filesystem = filesystem;
		last_directory->parent = node;

		VECTOR_PUSH(node->children, current_directory);
		VECTOR_PUSH(node->children, last_directory);
	}

	return node;
}

void vfs_init() {
	vfs_root = alloc(sizeof(struct asset));

	vfs_root->name = "/";
	vfs_root->asset = vfs_default_asset(S_IFDIR);
	vfs_root->filesystem = NULL;
	vfs_root->parent = NULL;

	vfs_root->asset->write = ramfs_write;
	vfs_root->asset->read = ramfs_read;
	vfs_root->asset->ioctl = 0;
	vfs_root->asset->resize = ramfs_resize;

	struct vfs_node *current_directory = alloc(sizeof(struct vfs_node));
	struct vfs_node *last_directory = alloc(sizeof(struct vfs_node));

	current_directory->name = ".";
	current_directory->asset = vfs_default_asset(S_IFDIR);
	current_directory->filesystem = NULL;
	current_directory->parent = vfs_root;

	current_directory->asset->write = ramfs_write;
	current_directory->asset->read = ramfs_read;
	current_directory->asset->ioctl = 0;
	current_directory->asset->resize = ramfs_resize;

	last_directory->name = "..";
	last_directory->asset = vfs_default_asset(S_IFDIR);
	last_directory->filesystem = NULL;
	last_directory->parent = vfs_root;

	last_directory->asset->write = ramfs_write;
	last_directory->asset->read = ramfs_read;
	last_directory->asset->ioctl = 0;
	last_directory->asset->resize = ramfs_resize;

	VECTOR_PUSH(vfs_root->children, current_directory);
	VECTOR_PUSH(vfs_root->children, last_directory);
}

struct vfs_node *vfs_search_relative(struct vfs_node *parent, const char *name) {
	for(size_t i = 0; i < parent->children.element_cnt; i++) {
		struct vfs_node *node = parent->children.elements[i]; 

		if(strcmp(node->name, name) == 0) {
			return node;
		}
	}

	return NULL;
}

struct vfs_node *vfs_create_node_deep(struct vfs_node *parent, struct asset *asset, struct filesystem *filesystem, const char *path) {
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
	for(; i < subpath_list.element_cnt; i++) {
		struct vfs_node *node = vfs_search_relative(parent, subpath_list.elements[i]);
		if(node == NULL) {
			break;
		}

		if(node->mountpoint) {
			parent = node->mountpoint;
		} else {
			parent = node;
		}
	}

	if(i >= subpath_list.element_cnt) {
		return parent;
	}
	
	for(; i < (subpath_list.element_cnt - 1); i++) {
		parent = vfs_create_node(parent, vfs_default_asset(S_IFDIR), parent->filesystem, subpath_list.elements[i], 0);
		if(parent->mountpoint) {
			parent = parent->mountpoint;
		} 
	}

	return vfs_create_node(parent, asset, filesystem, subpath_list.elements[i], 0);
}

struct vfs_node *vfs_search_absolute(struct vfs_node *parent, const char *path) {
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

	size_t i;
	for(i = 0; i < (subpath_list.element_cnt - 1); i++) {
		parent = vfs_search_relative(parent, subpath_list.elements[i]);
		if(parent == NULL) {
			return NULL;
		}

		if(parent->mountpoint) {
			parent = parent->mountpoint;
		} 

		if(!S_ISDIR(parent->asset->stat->st_mode)) {
			return NULL;	
		}
	}

	return vfs_search_relative(parent, subpath_list.elements[i]);
}

const char *vfs_absolute_path(struct vfs_node *node) {
	if(node == NULL) {
		return NULL;
	}

	VECTOR(struct vfs_node*) node_list = { 0 };

	while(node) {
		VECTOR_PUSH(node_list, node);
		node = node->parent;
	}

	char *ret = alloc(MAX_PATH_LENGTH);

	for(size_t i = node_list.element_cnt; i-- > 0;) {
		if(S_ISDIR(node_list.elements[i]->asset->stat->st_mode)) {
			sprint(ret + strlen(ret), "%s/", node_list.elements[i]->name);
		} else {
			sprint(ret + strlen(ret), "%s", node_list.elements[i]->name);
		}
	}

	VECTOR_DELETE(node_list);

	return ++ret;
}

int vfs_mount(struct vfs_node *parent, const char *source, const char *target, struct filesystem *filesystem) {
	struct vfs_node *source_node = vfs_search_absolute(parent, source);
	struct vfs_node *target_node = vfs_search_absolute(parent, target);

	if(source_node == NULL || target_node == NULL) {
		return -1;
	}

	if(!S_ISDIR(target_node->asset->stat->st_mode)) {
		return -1;
	}

	target_node->mountpoint = vfs_create_node(target_node->parent, vfs_default_asset(0644 | S_IFDIR), filesystem, target_node->name, 1);

	return 0;
}
