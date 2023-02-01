#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <sys/types.h>

int main(void) {
	if (setuid(0) || setgid(0))
		err(1, "setuid/setgid");
	fputs("we have root privs now...\n", stderr);
	execl("/bin/bash", "bash", NULL);
	err(1, "execl");
}
