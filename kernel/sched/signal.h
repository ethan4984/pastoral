#pragma once

#include <types.h>
#include <vector.h>

#define SIGHUP 1
#define SIGINT 2
#define SIGQUIT 3
#define SIGILL 4
#define SIGTRAP 5
#define SIGABRT 6
#define SIGBUS 7
#define SIGFPE 8
#define SIGKILL 9
#define SIGUSR1 10
#define SIGSEGV 11
#define SIGUSR2 12
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM 15
#define SIGSTKFLT 16
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGURG 23
#define SIGXCPU 24
#define SIGXFSZ 25
#define SIGVTALRM 26
#define SIGPROF 27
#define SIGWINCH 28
#define SIGIO 29
#define SIGPOLL SIGIO
#define SIGPWR 30
#define SIGSYS 31
#define SIGRTMIN 32
#define SIGRTMAX 33
#define SIGCANCEL 34

#define SIGMASK(SIG) (1ull << ((SIG) - 1))

union sigval {
	int sival_int;
	void *sival_ptr;
};

struct siginfo {
	int si_signo;
	int si_code;
	int si_errno;
	pid_t si_pid;
	uid_t si_uid;
	void *si_addr;
	int si_status;
	union sigval si_value;
};

struct sigaction {
	union {
		void (*sa_handler)(int signum);
		void (*sa_sigaction)(int signum, struct siginfo *siginfo, void *context);
	} handler;
	sigset_t sa_mask;
	int sa_flags;
	void (*sa_restorer);
};

struct signal_queue;

struct signal {
	int refcnt;

	struct siginfo *siginfo;
	struct sigaction *sigaction;

	struct signal_queue *queue;
};

struct sched_thread;

struct signal_queue {
	VECTOR(struct signal*) pending;
	sigset_t sigpending;

	struct sched_thread *thread;	
};

int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
