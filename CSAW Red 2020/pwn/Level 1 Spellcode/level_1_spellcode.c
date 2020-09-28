#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFSIZE 60
#define MAXINPUTSIZE 2

// This binary was compiled with an executable stack
// To compile locally, use: 
// gcc -m32 -fno-stack-protector -z execstack -fno-pie -no-pie level_1_spellcode.c -o level_1_spellcode
// or work with the binary provided

void getInput(int length, char * buffer){
    memset(buffer, 0, length);
    int count = 0;
    char c;
    while((c = getchar()) != '\n' && !feof(stdin)){
        if(count < (length-1)){
            buffer[count] = c;
            count++;
        }
    }
    buffer[count] = '\x00'; 
}

int getIntClean(){
    char input[MAXINPUTSIZE]; 
    getInput(MAXINPUTSIZE, input);
    return atoi(input);
}

void runGame(){
    char shellcode[BUFSIZE];

    puts("*** Welcome to the Spellcode challenges! ***\n");
    puts("   You walk into 150 Jay Street and stop at the turnstiles.");
    puts("Your destination is the OSIRIS Lab. Ty, the watchman, is");
    puts("listening to his usual audiobook. He looks at you expectantly,");
    puts("as if you were about to cast something.");
    puts("   Time to cast a level 1 spell! Choose wisely.");
    puts("");
    printf("Choose a spell to cast:\n");
    printf("   1)   Alarm\n");
    printf("   2)   Jump\n");
    printf("   3)   Sleep\n");
    printf("   4)   Grease\n");
    printf("   5)   Expeditious Retreat\n");
    printf("   6)   Custom\n");
    printf(">");
    fflush(stdout);
    int selection = getIntClean();
    if (selection == 1){
        puts("You set off the alarm!!\n");
        // This actually causes the program running on the docker container to exit, so we're not going to actually call it.
        // Too bad, I liked the pun...
        //alarm(1); 
        //sleep(1);
        exit(0);
    }
    else if(selection == 2){
        runGame();
    }
    else if (selection == 3){
        puts("You fall asleep...\n");
        sleep(2);
        exit(0);
    }
    else if (selection == 4){
        puts("   You eat the slice of pizza on the paper plate in your hand. That hit the spot!");
        puts("And only $1. You head back outside for another.");
        exit(0);
    }
    else if (selection == 5){
        puts("   You exit(0)!!!");
        exit(0);
    }
    else if (selection == 6){
        printf("Enter your spell code (up to %d bytes): > ", BUFSIZE);
        fflush(stdout);
        // Make sure there is something to run
        int code_length = read(0, shellcode, BUFSIZE);
        if(code_length > 0){
            void (*runthis)() = (void (*)()) shellcode;
            runthis();
        }
    }
    else
    {
        puts("Error: invalid selection.");
        exit(0);
    }
}

int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    runGame();
    printf("\n");
    return 0;
}


