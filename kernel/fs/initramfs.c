#include <fs/initramfs.h>
#include <fs/ramfs.h>
#include <mm/slab.h>
#include <tar.h>
#include <stivale.h>
#include <types.h>
#include <string.h>
#include <debug.h>

void initramfs() {
    struct stivale_module *module = (void*)stivale_struct->modules;

    for(size_t i = 0; i < stivale_struct->module_count; i++) {
        if(module && strcmp(module->string, "initramfs") == 0) {
            break;
        }
        module = (void*)module->next;
    }

    if(module == NULL) { /* may not be guaranteed to be null */
        return;
    }

    struct ustar_header *ustar_header = (void*)module->begin;

    if(strncmp(ustar_header->magic, USTAR_MAGIC, 5) != 0) {
        return;
    }

    for(;;) {
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
        stat->st_ino = ramfs_handle->inode;

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
        }

        vfs_create_node_deep(NULL, asset, &ramfs_filesystem, ustar_header->name);

        if(ustar_next_header(&ustar_header) == -1) {
            break;
        }
    }
}
