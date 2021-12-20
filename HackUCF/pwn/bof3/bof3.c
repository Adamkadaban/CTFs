#include <stdio.h>
#include <stdlib.h>

void win(void) {
	char flag[64];
	
	FILE* fp = fopen("flag.txt", "r");
	if(!fp) {
		puts("error, contact admin");
		exit(0);
	}
	
	fgets(flag, sizeof(flag), fp);
	fclose(fp);
	puts(flag);
}

void lose(void) {
	puts("you suck!\n");
	fflush(stdout);
	exit(0);
}

int main(void) {
	void (*fp)(); 
	char bof[64];
	
	fp = &lose;
	
	scanf("%s", bof);
	fp();
	return 0;
}
