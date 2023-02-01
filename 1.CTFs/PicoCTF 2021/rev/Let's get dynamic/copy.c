#include <stdlib.h>
#include <stdio.h>

int main(){
	char user_input [64];
	char changeString [64];

	fgets(user_input, 0x31, stdin);
	int i = 0;

	int local_98 = 0x396c109a7067b614;
	int local_58 = 0x563f52ce0f15cd77;

	while (1==1){
		int eight = strlen((char *)&local_98);
		if (eight <= i) break;
		changeString[i] = i ^ ((long)&local_98 + (long)i) ^ ((long)&local_58 + (long)i) ^ 0x13 ;
		i = i + 1;

	}

	int c = memcmp(user_input, changeString, 0x31);
	puts(user_input);
	puts(changeString);
	if (c != 0){
		puts ("no");
	}
	else{
		puts ("yes");
	}
}
