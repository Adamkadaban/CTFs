#include <stdio.h>
#include <stdlib.h>

#define FLAGBUF 40
#define INPUTBUF 32

void winner_winner_chicken_dinner() {
	char buf[FLAGBUF];
	FILE *f = fopen("flag.txt","r");
	if (f == NULL) {
		puts("If you receive this output, then there's no flag.txt on the server -- message an admin on Discord.");
		puts("Alternatively, you may be testing your code locally, in which case you need a fake flag.txt file in your directory.");
		exit(0);
	}

	fgets(buf,FLAGBUF,f);
	printf("%s",buf);
	exit(0);
}

void vuln(){
	char buf[INPUTBUF];
	gets(buf); //ruh-roh
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);
	puts("Welcome to the feast! \nThere's a delicious dinner waiting for you, if you can get to it!");
	printf("> ");
	vuln();
	printf("Oh, not hungry? Maybe next time.");
	return 0;
}