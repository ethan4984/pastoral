#pragma once

#include <elf.h>

struct sched_thread;

struct program {
	struct elf_file file;
	struct elf_file interp;

	char *file_path;
	char *interp_path;
	bool interp_present;

	struct sched_thread *thread;

	struct {
		int envp_cnt;
		int argv_cnt;

		char **argv;
		char **envp;
	} parameters;

	uint64_t entry;
	bool loaded;
};

int program_load(struct program *program, const char *path);
int program_place_parameters(struct program *program, char **envp, char **argv);
