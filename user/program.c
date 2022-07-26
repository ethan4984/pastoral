#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <termios.h>

static void sighand(int sig) {
	printf("sigint %d\n", sig);
	exit(EXIT_SUCCESS);
}

int main() {
	printf("Hello\n");
	int ptm = posix_openpt(O_RDWR | O_NOCTTY);
	assert(ptm >= 0);

	printf("pts name is %s\n", ptsname(ptm));
	int pts = open(ptsname(ptm), O_RDWR | O_NOCTTY);
	assert(pts >= 0);

	printf("disabling echo on master and slave\n");
	struct termios attr;
	tcgetattr(ptm, &attr);
	attr.c_lflag &= ~(ECHO | ECHOCTL | ECHOE);
	tcsetattr(ptm, TCSAFLUSH, &attr);
	tcgetattr(pts, &attr);
	attr.c_lflag &= ~(ECHO | ECHOCTL | ECHOE);
	tcsetattr(ptm, TCSAFLUSH, &attr);

	printf("writing hello to master\n");
	char buf[1000];
	memset(buf, 0, sizeof(buf));
	char *str = "hello\n";
	write(ptm, str, strlen(str));
	printf("reading from slave\n");
	read(pts, buf, 1000);
	printf("slave data: %.1000s\n", buf);

	printf("writing bye to slave\n");
	char *str2 = "bye\n";
	write(pts, str2, strlen(str2));
	printf("reading from master\n");
	memset(buf, 0, sizeof(buf));
	read(ptm, buf, 1000);
	printf("master data: %.1000s\n", buf);

	close(pts);
	close(ptm);
	return 0;
}
