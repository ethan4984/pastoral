#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>


int main(void) {

	int ret = setsid();
	assert(ret > 0);
	int stdin = open("/dev/tty0", O_RDONLY);
	int stdout = open("/dev/tty0", O_WRONLY);
	int stderr = open("/dev/tty0", O_WRONLY);

	assert(stdin == 0 && stdout == 1 && stderr == 2);

	int pid = fork();

	if(pid == 0) {
		char *argv[] = { "/usr/bin/bash", NULL };
		char *envp[] = {
			"HOME=/",
			"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
			"TERM=linux",
			NULL
		};

		execve("/usr/bin/bash", argv, envp);
	}

	for(;;) {
		asm ("pause");
	}
}
