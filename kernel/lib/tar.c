#include <tar.h>
#include <string.h>

int ustar_next_header(struct ustar_header **header) {
    size_t size = octal_to_decimal((const char*)(&(*header)->size));

    *header = (struct ustar_header*)((uintptr_t)(*header) + 512 + ALIGN_UP(size, 512));
    
    if(strncmp((*header)->magic, USTAR_MAGIC, 5) != 0) {
        return -1;
    }

    return 0;
}
