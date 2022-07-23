#include <stdio.h>
#include <unistd.h>

int main(void) {
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
