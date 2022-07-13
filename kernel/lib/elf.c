#include <elf.h>
#include <fs/fd.h>
#include <cpu.h>
#include <string.h>
#include <mm/mmap.h>

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
