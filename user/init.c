#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

// TODO: Runlevels


// Utility macros
enum LogLevel;
static void init_exit(int status);
static void print(enum LogLevel level, const char *fmt, ...);

#define EXIT_IF_FAIL(func) 		\
	if((func) < 0) { 			\
		init_exit(1);			\
		__builtin_unreachable();\
	}


#define BUG(msg, ...) 		   								\
	print(LOG_FAILURE, "init internal error on %s:%d: %s", 	\
			__FILE__, __LINE__, msg, ##__VA_ARGS__); 	\
	init_exit(-1);											\
	__builtin_unreachable();


#define BUG_ON_FAILURE(func, msg, ...)	\
	if((func) < 0) {					\
		BUG(msg, ##__VA_ARGS__);		\
	}

// Logging facilities

enum LogLevel {
	LOG_NONE,
	LOG_INFO,
	LOG_SUCCESS,
	LOG_FAILURE,
	LOG_WARNING,
	LOG_LAUNCH
};

FILE *logfile, *logtty;

static void print_init() {
	logfile = fopen("/run/init.log", "w");

	int stdin = open("/dev/tty0", O_RDONLY | O_NOCTTY);
	int stdout = open("/dev/tty0", O_WRONLY | O_NOCTTY);
	int stderr = open("/dev/tty0", O_WRONLY | O_NOCTTY);

	if(stdout >= 0) {
		logtty = fdopen(stdout, "w");
	}
}

static void print(enum LogLevel level, const char *fmt, ...) {
	va_list argp;
	va_start(argp, fmt);

	char *aux_tty, *aux_log;
	switch(level) {
		case LOG_INFO:
			aux_tty = "[ INFO ] ";
			aux_log = "[ INFO ] ";
			break;
		case LOG_SUCCESS:
			aux_tty = "[ \033[32;m OK\033[39;m  ] ";
			aux_log = "[  OK  ] ";
			break;
		case LOG_FAILURE:
			aux_tty = "[\033[31;m FAIL\033[39;m ] ";
			aux_log = "[ FAIL ] ";
			break;
		case LOG_WARNING:
			aux_tty = "[\033[33;m WARN\033[39;m ] ";
			aux_log = "[ WARN ] ";
			break;
		case LOG_LAUNCH:
			aux_tty = "[\033[36;mLAUNCH\033[39;m] ";
			aux_log = "[LAUNCH] ";
			break;
		case LOG_NONE:
		default:
			aux_tty = "";
			aux_log = "";
	}

	if(logfile) {
		fprintf(logfile, "\n%s", aux_log);
		vfprintf(logfile, fmt, argp);
		fflush(logfile);
	}

	if(logtty) {
		fprintf(logtty, "\n%s", aux_tty);
		vfprintf(logtty, fmt, argp);
		fflush(logtty);
	}

	va_end(argp);
}

// Service launching facility

FILE *inittab;

static int inittab_init() {
	print(LOG_LAUNCH, "Parsing /etc/inittab ...");

	inittab = fopen("/etc/inittab", "r");
	if(!inittab) {
		print(LOG_FAILURE, "/etc/inittab not found");
		return -1;
	}

	fclose(inittab);
	print(LOG_WARNING, "TODO /etc/inittab ...");
	return 0;
}

// Child handling

static void reap_zombies() {
	while(wait(NULL) != -1);
}

static void sigchld_handle(int sig) {
	(void) sig;
	reap_zombies();
}

// Miscelaneous

static void signals_init() {
	struct sigaction act;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = SIG_IGN;

	BUG_ON_FAILURE(sigaction(SIGCHLD, &act, NULL), "sigaction(SIGCHLD) failure");

	act.sa_handler = SIG_IGN;
	BUG_ON_FAILURE(sigaction(SIGINT, &act, NULL), "sigaction(SIGINT) failure");
	BUG_ON_FAILURE(sigaction(SIGTERM, &act, NULL), "sigaction(SIGTERM) failure");
	BUG_ON_FAILURE(sigaction(SIGQUIT, &act, NULL), "sigaction(SIGQUIT) failure");
}

static void init_exit(int status) {
	print(LOG_NONE, "init returning with status %d", status);
	exit(status);
}

static void launch_shell() {
	print(LOG_LAUNCH, "Running shell ...\n\n");
	pid_t pid;
	BUG_ON_FAILURE((pid = fork()), "fork() failure");

	if(pid == 0) {
		int openmax = sysconf(_SC_OPEN_MAX);
		for(int i = 0; i < openmax; i++) {
			close(i);
		}

		setsid();
		int stdin = open("/dev/tty0", O_RDONLY);
		int stdout = open("/dev/tty0", O_WRONLY);
		int stderr = open("/dev/tty0", O_WRONLY);

		if(stdin != 0 || stdout != 1 || stderr != 2) {
			_exit(-1);
		}

		execl("/usr/bin/bash", "bash", NULL);
		_exit(-1);
	}
}

int main() {
	print_init();
	print(LOG_NONE,
		"Welcome to \033[34;mPastoral x86_64!\033[39;m\n");

	signals_init();
	EXIT_IF_FAIL(inittab_init());
	launch_shell();

	for(;;){}
}
