#include <fs/initramfs.h>
#include <fs/ramfs.h>
#include <mm/slab.h>
#include <tar.h>
#include <stivale.h>
#include <types.h>
#include <string.h>
#include <debug.h>
#include <time.h>

int initramfs() {
	struct stivale_module *module = (void*)stivale_struct->modules;

	for(size_t i = 0; i < stivale_struct->module_count; i++) {
		if(module && strcmp(module->string, "initramfs") == 0) {
			break;
		}
		module = (void*)module->next;
	}

	if(module == NULL) { /* may not be guaranteed to be null */
		return -1;
	}

	struct ustar_header *ustar_header = (void*)module->begin;

	for(;;) {
		if(strncmp(ustar_header->magic, "ustar", 5) != 0) {
			break;
		}

		struct ramfs_handle *ramfs_handle = alloc(sizeof(struct ramfs_handle));

		*ramfs_handle = (struct ramfs_handle) {
			.inode = ramfs_inode_cnt++,
			.buffer = (void*)((uintptr_t)ustar_header + 512)
		};

		hash_table_push(&ramfs_node_list, &ramfs_handle->inode, ramfs_handle, sizeof(ramfs_handle->inode));

		struct asset *asset = alloc(sizeof(struct asset));
		struct stat *stat = alloc(sizeof(struct stat));

		stat->st_uid = octal_to_decimal(ustar_header->uid);
		stat->st_gid = octal_to_decimal(ustar_header->gid);
		stat->st_size = octal_to_decimal(ustar_header->size);
		stat->st_mode = octal_to_decimal(ustar_header->mode);
		stat->st_blksize = 512;
		stat->st_blocks = DIV_ROUNDUP(stat->st_size, stat->st_blksize);
		stat->st_ino = ramfs_handle->inode;
		stat->st_nlink = 1;

		stat->st_atim = clock_realtime;
		stat->st_ctim = clock_realtime;
		stat->st_mtim = clock_realtime;

		asset->stat = stat;
		asset->read = ramfs_read;
		asset->write = ramfs_write;
		asset->resize = ramfs_resize;

		switch(ustar_header->typeflag) {
			case USTAR_REGTYPE:
				stat->st_mode |= S_IFREG;
				break;
			case USTAR_DIRTYPE:
				stat->st_mode |= S_IFDIR;
				break;
			case USTAR_SYMTYPE:
				stat->st_mode |= S_IFLNK;
				break;
		}

		struct vfs_node *node = vfs_create_node_deep(NULL, asset, &ramfs_filesystem, ustar_header->name);

		if(S_ISLNK(node->asset->stat->st_mode)) {
			node->symlink = ustar_header->linkname;
		}

		ustar_header = (void*)ustar_header + 512 + ALIGN_UP(stat->st_size, 512);

		if((uintptr_t)ustar_header >= (module->begin + (module->end - module->begin))) {
			break;
		}
	}

	return 0;
}
