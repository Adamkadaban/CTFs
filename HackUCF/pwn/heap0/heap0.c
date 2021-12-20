#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(void) {
	char* username = malloc(50);
	char* shell = malloc(50);
	
	printf("username at %p\n", username);
	printf("shell at %p\n", shell);
	
	strcpy(shell, "/bin/ls");
	
	printf("Enter username: ");
	scanf("%s", username);
	
	printf("Hello, %s. Your shell is %s.\n", username, shell);
	system(shell);
	
	return 0;
}
