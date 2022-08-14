#include <elf.h>
#include <fs/fd.h>
#include <cpu.h>
#include <string.h>
#include <mm/mmap.h>
#include <limine.h>
#include <debug.h>
#include <mm/pmm.h>

static int elf64_validate(struct elf64_hdr *hdr) {
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

static const char *elf64_extract_string(void *data, uint32_t index) {
	return (const char*)(data + index);
}

static struct elf64_shdr *elf64_find_section(struct elf_file *file, uint32_t type, const char *name) {
	struct elf64_shdr *shdr = file->shdr;

	for(size_t i = 0; i < file->header.sh_num; i++) {
		if(shdr[i].sh_type != type) {
			continue;
		}

		const char *section_name = elf64_extract_string(file->shstrtab, shdr[i].sh_name);

		if(strcmp(section_name, name) == 0) {
			return &shdr[i];
		}
	}

	return NULL;
}

static int elf64_symtab_init(struct elf_file *file) {
	if(file->symtab_hdr->sh_entsize != sizeof(struct elf64_symtab)) {
		return -1;
	}

	uint64_t entcnt = file->symtab_hdr->sh_size / file->symtab_hdr->sh_entsize;
	struct elf64_symtab *symtab = file->symtab;

	file->symbol_list.data = (void*)(pmm_alloc(DIV_ROUNDUP(sizeof(struct symbol) * entcnt, PAGE_SIZE), 1) + HIGH_VMA);
	file->symbol_list.cnt = 0;

	for(size_t i = 0; i < entcnt; i++) {
		if((symtab[i].st_info & STT_FUNC) != STT_FUNC) {
			continue;
		}

		struct symbol symbol = {
			.name = elf64_extract_string(file->strtab, symtab[i].st_name),
			.address = symtab[i].st_value,
			.size = symtab[i].st_size
		};

		file->symbol_list.data[file->symbol_list.cnt++] = symbol;
	}

	return 0;
}

int elf64_file_init(struct elf_file *file) {
	ssize_t ret = file->read(file, &file->header, 0, sizeof(struct elf64_hdr));
	if(ret != sizeof(struct elf64_hdr)) {
		return -1;
	}

	file->phdr = alloc(sizeof(struct elf64_phdr) * file->header.ph_num);
	file->shdr = alloc(sizeof(struct elf64_shdr) * file->header.sh_num);

	ret = file->read(file, file->shdr, file->header.shoff, sizeof(struct elf64_shdr) * file->header.sh_num);
	if(ret == -1) {
		return -1;
	}

	ret = elf64_validate(&file->header);
	if(ret == -1) {
		return -1;
	}

	ret = file->read(file, file->phdr, file->header.phoff, sizeof(struct elf64_phdr) * file->header.ph_num);
	if(ret == -1) {
		return -1;
	}

	file->shstrtab_hdr = file->shdr + file->header.shstrndx;
	file->shstrtab = (void*)(pmm_alloc(DIV_ROUNDUP(file->shstrtab_hdr->sh_size, PAGE_SIZE), 1) + HIGH_VMA);
	ret = file->read(file, file->shstrtab, file->shstrtab_hdr->sh_offset, file->shstrtab_hdr->sh_size);
	if(ret != file->shstrtab_hdr->sh_size) {
		return -1;
	}

	file->strtab_hdr = elf64_find_section(file, SHT_STRTAB, ".strtab");
	if(file->strtab_hdr == NULL) {
		return 0;	
	}

	file->strtab = (void*)(pmm_alloc(DIV_ROUNDUP(file->strtab_hdr->sh_size, PAGE_SIZE), 1) + HIGH_VMA);
	ret = file->read(file, file->strtab, file->strtab_hdr->sh_offset, file->strtab_hdr->sh_size);
	if(ret != file->strtab_hdr->sh_size) {
		return -1;
	}

	file->symtab_hdr = elf64_find_section(file, SHT_SYMTAB, ".symtab");
	if(file->symtab_hdr == NULL) {
		return 0;
	}

	file->symtab = (void*)(pmm_alloc(DIV_ROUNDUP(file->symtab_hdr->sh_size, PAGE_SIZE), 1) + HIGH_VMA);
	ret = file->read(file, file->symtab, file->symtab_hdr->sh_offset, file->symtab_hdr->sh_size);
	if(ret != file->symtab_hdr->sh_size) {
		return -1;
	}

	ret = elf64_symtab_init(file);
	if(ret == -1) {
		return -1;
	}

	return 0;
}

int elf64_file_load(struct elf_file *file) {
	for(size_t i = 0; i < file->header.ph_num; i++) {
		if(file->phdr[i].p_type != ELF_PT_LOAD) {
			continue;
		}

		struct elf64_phdr *phdr = &file->phdr[i];

		size_t misalignment = phdr->p_vaddr & (PAGE_SIZE - 1);
		size_t page_cnt = DIV_ROUNDUP(misalignment + phdr->p_memsz, PAGE_SIZE);

		if((misalignment + phdr->p_memsz) > PAGE_SIZE) {
			page_cnt++;
		}

		mmap(
			file->page_table,
			(void*)(phdr->p_vaddr + file->load_offset - misalignment),
			page_cnt * PAGE_SIZE,
			MMAP_PROT_READ | MMAP_PROT_WRITE | MMAP_PROT_EXEC | MMAP_PROT_USER,
			MMAP_MAP_FIXED | MMAP_MAP_ANONYMOUS,
			-1,
			-1
		);

		file->read(file, (void*)(phdr->p_vaddr + file->load_offset), phdr->p_offset, phdr->p_filesz);
	}

	return 0;
}

int elf64_file_runtime(struct elf_file *file, char **runtime_path) {
	struct elf64_phdr *phdr = NULL;

	for(size_t i = 0; i < file->header.ph_num; i++) {
		if(file->phdr[i].p_type == ELF_PT_INTERP) {
			phdr = &file->phdr[i];
			break;		
		}
	}

	if(phdr == NULL) {
		return -1;
	}

	*runtime_path = alloc(phdr->p_filesz + 1);
	file->read(file, *runtime_path, phdr->p_offset, phdr->p_filesz);

	return 0;	
}

int elf64_file_aux(struct elf_file *file, struct aux *aux) {
	aux->at_phdr = 0;
	aux->at_phent = sizeof(struct elf64_phdr);
	aux->at_phnum = file->header.ph_num;
	aux->at_entry = file->load_offset + file->header.entry;

	for(size_t i = 0; i < file->header.ph_num; i++) {
		if(file->phdr[i].p_type == ELF_PT_PHDR) {
			aux->at_phdr = file->load_offset + file->phdr[i].p_vaddr;
		}
	}

	return 0;
}

struct symbol *elf64_search_symtable(struct elf_file *file, uintptr_t addr) {
	for(size_t i = 0; i < file->symbol_list.cnt; i++) {
		struct symbol *symbol = &file->symbol_list.data[i];

		if(symbol->address <= addr && (symbol->address + symbol->size) >= addr) {
			return symbol;
		}
	}

	return NULL;
}

ssize_t elf_read_fd(struct elf_file *file, void *buffer, off_t offset, size_t cnt) {
	ssize_t ret = fd_seek(file->fd, offset, SEEK_SET);
	if(ret == -1) {
		return -1;
	}

	ret = fd_read(file->fd, buffer, cnt);
	return ret;
} 
