#include <fs/initramfs.h>
#include <fs/ramfs.h>
#include <mm/slab.h>
#include <tar.h>
#include <types.h>
#include <string.h>
#include <debug.h>
#include <time.h>
#include <limine.h>
#include <sched/sched.h>

static volatile struct limine_module_request limine_module_request = {
	.id = LIMINE_MODULE_REQUEST,
	.revision = 0
};

int initramfs() {
	if(limine_module_request.response == NULL) {
		return -1;
	}

	struct limine_file **modules = limine_module_request.response->modules;
	uint64_t module_count = limine_module_request.response->module_count;

	struct limine_file *module = NULL;

	for(uint64_t i = 0; i < module_count; i++) {
		if(strcmp(modules[i]->cmdline, "initramfs") == 0) {
			module = modules[i];
			break;
		}
	}

	if(module == NULL) {
		return -1;
	}

	print("initramfs: unpacking\n");

	struct ustar_header *ustar_header = module->address;

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

		struct stat *stat = alloc(sizeof(struct stat));

		// Initramfs files are root's property.
		stat_init(stat);
		stat->st_uid = 0;
		stat->st_gid = 0;
		stat->st_size = octal_to_decimal(ustar_header->size);
		stat->st_mode = octal_to_decimal(ustar_header->mode);
		stat->st_blksize = 512;
		stat->st_blocks = DIV_ROUNDUP(stat->st_size, stat->st_blksize);
		stat->st_ino = ramfs_handle->inode;
		stat->st_nlink = 1;

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

		//print("%s\n", ustar_header->name);

		if(strcmp(ustar_header->name, "./usr/sbin/init") == 0) {
			print("found\n");
		}

		struct vfs_node *node = vfs_create_node_deep(NULL, &ramfs_fops, &ramfs_filesystem, stat, ustar_header->name);

		if(S_ISLNK(node->stat->st_mode)) {
			node->symlink = ustar_header->linkname;
		}

		ustar_header = (void*)ustar_header + 512 + ALIGN_UP(stat->st_size, 512);

		if((uintptr_t)ustar_header >= ((uintptr_t)module->address + module->size)) {
			break;
		}
	}

	print("initramfs: unpacked\n");

	return 0;
}
