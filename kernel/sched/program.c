#include <sched/program.h>
#include <sched/sched.h>
#include <fs/fd.h>
#include <string.h>
#include <debug.h>

static int program_load_parameters(struct program *program, char **argv, char **envp) {
	for(;;program->parameters.envp_cnt++) {
		if(envp[program->parameters.envp_cnt] == NULL) break;
	}

	for(;;program->parameters.argv_cnt++) {
		if(argv[program->parameters.argv_cnt] == NULL) break;
	}

	program->parameters.argv = alloc(sizeof(char*) * program->parameters.argv_cnt);
	program->parameters.envp = alloc(sizeof(char*) * program->parameters.envp_cnt);

	for(int i = 0; i < program->parameters.argv_cnt; i++) {
		program->parameters.argv[i] = alloc(strlen(argv[i]) + 1);		
		strcpy(program->parameters.argv[i], argv[i]);
	}

	for(int i = 0; i < program->parameters.envp_cnt; i++) {
		program->parameters.envp[i] = alloc(strlen(envp[i]) + 1);		
		strcpy(program->parameters.envp[i], envp[i]);
	}

	return 0;
}

static uint64_t *program_place_args(struct program *program, uint64_t *location) {
	for(int i = 0; i < program->parameters.envp_cnt; i++) {
		location = (uint64_t*)((void*)location - (strlen(program->parameters.envp[i]) + 1)); strcpy((void*)location, program->parameters.envp[i]);
	}

	for(int i = 0; i < program->parameters.argv_cnt; i++) {
		location = (uint64_t*)((void*)location - (strlen(program->parameters.argv[i]) + 1)); strcpy((void*)location, program->parameters.argv[i]);
	}

	location = (void*)((uint64_t)location & -16ll);

	if((program->parameters.argv_cnt + program->parameters.envp_cnt + 1) & 1) {
		location--;
	}

	return location;
}

static uint64_t *program_place_aux(struct program *program, uint64_t *location) {
	location -= 10;

	location[0] = ELF_AT_PHNUM; location[1] = program->file.aux.at_phnum;
	location[2] = ELF_AT_PHENT; location[3] = program->file.aux.at_phent;
	location[4] = ELF_AT_PHDR;  location[5] = program->file.aux.at_phdr;
	location[6] = ELF_AT_ENTRY; location[7] = program->file.aux.at_entry;
	location[8] = 0; location[9] = 0;

	return location;
}

int program_place_parameters(struct program *program, char **envp, char **argv) {
	int ret = program_load_parameters(program, argv, envp);
	if(ret == -1) return -1;

	struct sched_thread *thread = program->thread;
	if(thread == NULL) {
		panic("");
	}

	uint64_t *location = (void*)thread->user_stack.sp;
	uint64_t argument_location = (uint64_t)location;

	location = program_place_args(program, location);
	location = program_place_aux(program, location);

	*(--location) = 0;
	location -= program->parameters.envp_cnt;

	for(size_t i = 0; i < program->parameters.envp_cnt; i++) {
		argument_location -= strlen(program->parameters.envp[i]) + 1;
		location[i] = argument_location;
	}

	*(--location) = 0;
	location -= program->parameters.argv_cnt;

	for(size_t i = 0; i < program->parameters.argv_cnt; i++) {
		argument_location -= strlen(program->parameters.argv[i]) + 1;
		location[i] = argument_location;
	}

	*(--location) = program->parameters.argv_cnt;

	thread->regs.rsp = (uint64_t)location;

	return 0;
}

int program_load(struct program *program, const char *path) {
	int fd = fd_openat(AT_FDCWD, path, O_RDONLY, 0);
	if(fd == -1) {
		return -1;
	}

	program->file.page_table = CURRENT_TASK->page_table;
	program->file.fd = fd;
	program->file.read = elf_read_fd;

	int ret = elf64_file_init(&program->file);
	if(ret == -1) return -1;

	ret = elf64_file_aux(&program->file, &program->file.aux);
	if(ret == -1) return -1;

	ret = elf64_file_load(&program->file);
	if(ret == -1) return -1;

	program->entry = program->file.aux.at_entry;
	program->interp_present = elf64_file_runtime(&program->file, &program->interp_path) == -1 ? false : true;

	fd_close(fd);

	if(program->interp_present) {
		fd = fd_openat(AT_FDCWD, program->interp_path, O_RDONLY, 0);
		if(fd == -1) {
			return -1;
		}

		program->interp.page_table = CURRENT_TASK->page_table;
		program->interp.load_offset = 0x40000000;
		program->interp.fd = fd;
		program->interp.read = elf_read_fd;

		int ret = elf64_file_init(&program->interp);
		if(ret == -1) return -1;

		ret = elf64_file_aux(&program->interp, &program->interp.aux);
		if(ret == -1) return -1;

		ret = elf64_file_load(&program->interp);
		if(ret == -1) return -1;

		program->entry = program->interp.aux.at_entry;

		fd_close(fd);
	}

	program->file_path = alloc(strlen(path) + 1);
	strcpy(program->file_path, path);

	program->loaded = true;

	return 0;
}
