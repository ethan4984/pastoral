#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>

#define serrno strerror(errno)


static void su_usage() {
	printf("Usage: su [OPTION] ... [FILE] [ARGS]\n"
		   "Executes a program as another user. If FILE is not provided, the shell will be ran.\n\n"
		   "Valid options:\n"
		   "%-10s Runs as user <user>. <user> can be a name or a uid. Default is 0\n"
		   "%-10s Runs as group <group>. <group> can be a name or a gid. Default is 0.\n"
		   "%-10s Shows this text.\n\n"
		   "Notes:\n"
		   "/etc/passwd and /etc/group must be available for this command to function properly.\n",

		   "-u <user>", "-g <group>", "-h");
}



static struct passwd *get_passwd(const char *arg) {
	uid_t uid;
	char *end;
	struct passwd *ret;
	uid = strtol(arg, &end, 10);
	if(end == arg)
		ret = getpwnam(arg);
	else
		ret = getpwuid(uid);

	return ret;
}

static struct group *get_group(const char *arg) {
	gid_t gid;
	char *end;
	struct group *ret;
	gid = strtol(arg, &end, 10);
	if(end == arg)
		ret = getgrnam(arg);
	else
		ret = getgrgid(gid);

	return ret;
}

#define PW_BUFSIZE 32

int main(int argc, char **argv) {
	int c, status;
	const char *uid_arg = NULL, *gid_arg = NULL;
	char *file;
	struct passwd *pw_ent;
	struct group *gr_ent;
	char pwbuf1[PW_BUFSIZE], pwbuf2[PW_BUFSIZE];
	pid_t pid;
	char **argv_alt;

	opterr = 1;

	while((c = getopt(argc, argv, "hg:u:")) != -1) {
		switch(c) {
			case 'h':
				su_usage();
				return 0;
			case 'u':
				uid_arg = optarg;
				break;
			case 'g':
				gid_arg = optarg;
				break;
			case '?':
				fprintf(stderr, "su: invalid option: %c\n", optopt);
				return 1;
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "su: not running as euid 0\n");
		abort();
	}

	if(!uid_arg)
		uid_arg = "0";
	if(!gid_arg)
		gid_arg = "0";

	pw_ent = get_passwd(uid_arg);
	if(!pw_ent) {
		fprintf(stderr, "su: could not fetch /etc/passwd entry for %s\n", uid_arg);
		return 1;
	}

	gr_ent = get_group(gid_arg);
	if(!gr_ent) {
		fprintf(stderr, "su: could not fetch /etc/group entry for %s\n", gid_arg);
		return 1;
	}


	file = argv[optind];
	if (!file) {
		file = pw_ent->pw_shell;
		if (!file) {
			fprintf(stderr, "su: warning: no default shell, assuming /usr/bin/bash\n");
			file = "/usr/bin/bash";
		}
	}

	if(pw_ent->pw_passwd) {
		if(strlen(pw_ent->pw_passwd) > 31) {
			fprintf(stderr, "su: passwd password too long\n");
			abort();
		}

		printf("user password: ");
		fflush(stdout);
		scanf("%31s", pwbuf1);
	}

	if(gr_ent->gr_passwd) {
		if(strlen(gr_ent->gr_passwd) > 31) {
			fprintf(stderr, "su: group password too long\n");
			abort();
		}

		printf("group password: ");
		fflush(stdout);
		scanf("%31s", pwbuf2);
	}

	if(pw_ent->pw_passwd) {
		if(strncmp(pw_ent->pw_passwd, pwbuf1, 31)) {
			fprintf(stderr, "password mismatch\n");
			return 1;
		}
	}

	if(gr_ent->gr_passwd) {
		if(strncmp(gr_ent->gr_passwd, pwbuf2, 31)) {
			fprintf(stderr, "password mismatch\n");
			return 1;
		}
	}

	if(setuid(pw_ent->pw_uid) < 0) {
		fprintf(stderr, "setuid failure: %s\n", serrno);
		return 1;
	}

	if(setgid(gr_ent->gr_gid) < 0) {
		fprintf(stderr, "setgid failure: %s\n", serrno);
		return 1;
	}

	pid = fork();
	if(pid < 0) {
		fprintf(stderr, "fork failure: %s\n", serrno);
		return 1;
	} else if(pid == 0) {
		if(argv[optind] == NULL) {
			argv[optind - 1] = file;
			argv_alt = &argv[optind - 1];
		} else {
			argv_alt = &argv[optind];
		}
		if(execvp(file, argv_alt) < 0) {
			fprintf(stderr, "execl failure: %s\n", serrno);
			return 1;
		}
	}

	wait(&status);
	return status;
}
