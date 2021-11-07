#include <fs/vfs.h>
#include <vector.h>
#include <debug.h>
#include <string.h>

static struct vfs_node vfs_root_node = {
	.name = "/"
};

struct vfs_node *vfs_create_node(struct vfs_node *parent, struct asset *asset, const char *name) {
	struct vfs_node *new_node = alloc(sizeof(struct vfs_node));

	if(parent == NULL) {
		parent = &vfs_root_node;
	}

	if(asset == NULL) {
		asset = parent->asset;
	}

	*new_node = (struct vfs_node) {
		.name = name,
		.asset = asset
	};

	parent->next = new_node;

	return new_node;
}

struct vfs_node *vfs_search_absolute(const char *src, struct vfs_node *node) {
	if(node == NULL) {
		node = &vfs_root_node;
	}

	char *str = alloc(strlen(src));
	strcpy(str, src);

	while(*str == '/') *str++ = 0;

	while(*str) {
		const char *subpath = str;

		while(*str && *str != '/') str++;
		while(*str == '/') *str++ = 0;

		while(node) { 
			if(node->name == subpath && node->asset->stat->st_mode & S_IFDIR) {
				node = node->child;
				break;
			}
			node = node->next;
		}
		
		return NULL;
	}

	return node; 
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
	char *str = ret;

	for(size_t i = node_list.element_cnt; i-- > 0;) {
		if(node_list.elements[i]->asset->stat->st_mode & S_IFDIR) {
			str += sprint(str, "%s/", node_list.elements[i]->name);
		} else {
			str += sprint(str, "%s", node_list.elements[i]->name);
		}
	}

	VECTOR_DELETE(node_list);

	return ret;
}
