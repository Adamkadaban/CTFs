#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#define PHRASELENGTH 20
#define FLAGBUF 40

int roll_value;

void win() {
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

void roll20(){
    // Random number generator
    time_t t;
    srand((unsigned) time(&t));
    roll_value = rand() % 19 + 1;
}

void runChallenge(){
    char phrase[PHRASELENGTH];

    puts("*** Prison Break ***\n");
    puts("   You find yourself a prisoner in the wizard Profion's");
    puts("dungeon! The door to your cell has heavy iron bars, they");
    puts("require a natural 20 to bend. But Profion's magic affects");
    puts("even the laws of probability...you wonder if anyone can");
    puts("roll a 20 on a twenty-sided die in here.");

    roll20();

    puts("   Profion's familiar, a parrot, flies up and perches on a ");
    puts("stone just outside the cell. \"AWK! Say the right thing ");
    puts("and escape!\" it cries.");
    puts("");
    //fflush(stdout);
    printf("   What do you say? >");
    fflush(stdout);

    getInput(PHRASELENGTH, phrase);
    puts("");
    printf("   \"AWK! ");
    printf(phrase);
    printf(",\" says the parrot.\n");
    puts("   You strain at the bars...\n");

    if(roll_value == 20){
        puts("   \"AWK! Natural 20. Natural 20.\"");
        puts("   You pry the bars apart with your bare hands and escape!");
        puts("");
        fflush(stdout);
        win();
    }else{
        printf("   You rolled a %d...\n",roll_value);
        printf("   \"AWK! Try again! AWK!\"\n");
        fflush(stdout);
    }
}

int main(int argc, char**argv){
    runChallenge();
    return 0;
}