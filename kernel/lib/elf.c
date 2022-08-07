#include <elf.h>
#include <fs/fd.h>
#include <cpu.h>
#include <string.h>
#include <mm/mmap.h>
#include <limine.h>
#include <debug.h>

static volatile struct limine_kernel_file_request limine_kernel_file_request = {
	.id = LIMINE_KERNEL_FILE_REQUEST,
	.revision = 0
};

int elf_validate(struct elf_hdr *hdr) {
	uint32_t signature = *(uint32_t*)hdr;
	if(signature != ELF_SIGNATURE) {
		return -1;
	}

	if(hdr->ident[ELF_EI_OSABI] != ELF_EI_SYSTEM_V && hdr->ident[ELF_EI_OSABI] != ELF_EI_LINUX) return -1;
	if(hdr->ident[ELF_EI_DATA] != ELF_LITTLE_ENDIAN) return -1;
	if(hdr->ident[ELF_EI_CLASS] != ELF_ELF64) return -1;
	if(hdr->machine != ELF_MACH_X86_64 && hdr->machine != 0) return -1;

	return 0;
}

static const char *elf64_strtab_extract(struct elf_hdr *hdr, struct elf64_shdr *shdr, uint32_t index) {
	uintptr_t offset = shdr->sh_offset;
	const char *str = (const char*)((void*)hdr + offset + index);
	return str;
}

static struct elf64_shdr *elf64_find_section(struct elf_hdr *hdr, struct elf64_shdr *shstrtab, uint32_t type, const char *name) {
	struct elf64_shdr *shdr = ((void*)hdr + hdr->shoff);

	for(size_t i = 0; i < hdr->sh_num; i++) {
		if(shdr[i].sh_type != type) {
			continue;
		}

		const char *section_name = elf64_strtab_extract(hdr, shstrtab, shdr[i].sh_name);

		if(strcmp(section_name, name) == 0) {
			return &shdr[i];
		}
	}

	return NULL;
}

int kernel_symtable_init() {
	if(limine_kernel_file_request.response == NULL || limine_kernel_file_request.response->kernel_file == NULL) {
		return -1;
	}

	struct limine_file *file = limine_kernel_file_request.response->kernel_file;
	struct elf_hdr *hdr = file->address;

	if(elf_validate(hdr) == -1) {
		return -1;
	}

	struct elf64_shdr *shdr = ((void*)hdr + hdr->shoff);
	struct elf64_shdr *shstrtab = shdr + hdr->shstrndx;

	struct elf64_shdr *strtab = elf64_find_section(hdr, shstrtab, SHT_STRTAB, ".strtab");
	if(strtab == NULL) { 
		return -1;
	}

	struct elf64_shdr *symtable = elf64_find_section(hdr, shstrtab, SHT_SYMTAB, ".symtab");
	if(symtable == NULL) {
		return -1;
	}

	if(symtable->sh_entsize != sizeof(struct elf64_symtab)) {
		return -1;
	}

	uint64_t entcnt = symtable->sh_size / symtable->sh_entsize;
	struct elf64_symtab *symtab = (void*)((uintptr_t)hdr + symtable->sh_offset);

	kernel_symbol_list.data = alloc(sizeof(struct symbol) * entcnt);
	kernel_symbol_list.cnt = 0;

	for(size_t i = 0; i < entcnt; i++) {
		if((symtab[i].st_info & STT_FUNC) != STT_FUNC) {
			continue;
		}

		struct symbol symbol = {
			.name = elf64_strtab_extract(hdr, strtab, symtab[i].st_name),
			.address = symtab[i].st_value,
			.size = symtab[i].st_size
		};

		kernel_symbol_list.data[kernel_symbol_list.cnt++] = symbol;
	}
	
	return 0;
}

int elf_load(struct page_table *page_table, struct aux *aux, int fd, uint64_t base, char **ld) {
	struct elf_hdr hdr;
	fd_read(fd, &hdr, sizeof(hdr));

	if(elf_validate(&hdr) == -1) {
		return -1;
	}

	struct elf64_phdr *phdr = alloc(sizeof(struct elf64_phdr) * hdr.ph_num);

	fd_seek(fd, hdr.phoff, SEEK_SET);
	fd_read(fd, phdr, sizeof(struct elf64_phdr) * hdr.ph_num);

	aux->at_phdr = 0;
	aux->at_phent = sizeof(struct elf64_phdr);
	aux->at_phnum = hdr.ph_num;

	for(size_t i = 0; i < hdr.ph_num; i++) {
		if(phdr[i].p_type == ELF_PT_INTERP) {
			if(ld == NULL) {
				continue;
			}

			*ld = alloc(phdr[i].p_filesz + 1);

			fd_seek(fd, phdr[i].p_offset, SEEK_SET);
			fd_read(fd, *ld, phdr[i].p_filesz);

			continue;
		} else if(phdr[i].p_type == ELF_PT_PHDR) {
			aux->at_phdr = base + phdr[i].p_vaddr;
			continue;
		} else if(phdr[i].p_type != ELF_PT_LOAD) {
			continue;
		}

		size_t misalignment = phdr[i].p_vaddr & (PAGE_SIZE - 1);
		size_t page_cnt = DIV_ROUNDUP(misalignment + phdr[i].p_memsz, PAGE_SIZE);

		if((misalignment + phdr[i].p_memsz) > PAGE_SIZE) {
			page_cnt++;
		}

		mmap(	page_table,
				(void*)(phdr[i].p_vaddr + base - misalignment),
				page_cnt * PAGE_SIZE,
				MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC | MMAP_PROT_USER,
				MMAP_MAP_FIXED | MMAP_MAP_ANONYMOUS,
				-1,
				-1
			);

		fd_seek(fd, phdr[i].p_offset, SEEK_SET);
		fd_read(fd, (void*)(phdr[i].p_vaddr + base), phdr[i].p_filesz);
	}

	aux->at_entry = base + hdr.entry;

	return 0;
}
