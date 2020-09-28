#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define NAMELENGTH 16
#define PARTYSIZE 6
#define MAXINTLENGTH 10
#define TRUE 1
#define FALSE 0

typedef struct _character{
    char name[NAMELENGTH];
    char strength;
    char dexterity;
    char constitution;
    char intelligence;
    char wisdom;
    char charisma;
    short hitpoints;
} character;

character party[PARTYSIZE];

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
    char input[MAXINTLENGTH]; 
    getInput(MAXINTLENGTH, input);
    return atoi(input);
}

int rolld6(){
    return rand() % 6 + 1;
}

int max(int a, int b) {
    return a>b ? a: b;
}

// Roll 4d6 and take the top three rolls, following D&D character creation rules.
int rollstat(){
    int roll1 = rolld6();
    int roll2 = rolld6();
    int roll3 = rolld6();
    int roll4 = rolld6();
    int min=roll1;
    if(roll2 < min){
        min=roll2;
    }
    if(roll3 < min){
        min = roll3;
    }
    if(roll4 < min){
        min = roll4;
    }
    return roll1 + roll2 + roll3 + roll4 - min;
}

void createCharacter(){
    int index = 0;
    while(index < 6 && strlen(party[index].name) > 0){
        index++;
    }
    if (index == 6){
        printf("Your party is full!");
    }
    else{
        printf("Enter your character's name:\n>");
        fflush(stdout);
        getInput(NAMELENGTH, party[index].name);
        party[index].strength = rollstat();
        party[index].dexterity = rollstat();
        party[index].constitution = rollstat();
        party[index].intelligence = rollstat();
        party[index].wisdom = rollstat();
        party[index].charisma = rollstat();
        party[index].hitpoints = max((rolld6()+((party[index].constitution-10)/2)),1);
        printf("%s has joined your party!\n", party[index].name);
    }
    fflush(stdout);
    return;
}

void init(){
    // Initialize random number generator
    time_t t;
    srand((unsigned) time(&t));
    int index = 0;
    while (index < 6){
        strcpy(party[index].name, "");
        party[index].strength = 0;
        party[index].dexterity = 0;
        party[index].constitution = 0;
        party[index].intelligence = 0;
        party[index].wisdom = 0;
        party[index].charisma = 0;
        party[index].hitpoints = 0;
        index++;
    }
    return;
}

void viewCharacter(){
    printf("Which character do you wish to view (0-5)? \n>");
    fflush(stdout);
    int index = getIntClean();

    // Make sure we don't view past the end of the array of party members
    if (index < 6){
        printf("-----------------------------\n");
        printf("Party member  %d\n", index);
        printf("-----------------------------\n");
        printf("Name:         %s\n", party[index].name);
        printf("Strength:     %d\n", party[index].strength);
        printf("Dexterity:    %d\n", party[index].dexterity);
        printf("Constitution: %d\n", party[index].constitution);
        printf("Intelligence: %d\n", party[index].intelligence);
        printf("Wisdom:       %d\n", party[index].wisdom);
        printf("Charisma:     %d\n", party[index].charisma);
        printf("Hit points:   %d\n", party[index].hitpoints);
        printf("-----------------------------\n");
    }
    else{
        printf("Illegal party member index.\n");
        exit(0);
    }
    fflush(stdout);
    return;
}

void renameCharacter(){
    printf("Which character do you wish to rename (0-5)? \n>");
    fflush(stdout);
    int index = getIntClean();
    // Make sure we don't write past the end of the array of party members
    if (index < 6){
        puts("");
        printf("Enter your character's name:\n>");
        fflush(stdout);
        getInput(NAMELENGTH, party[index].name);
        puts("");
        printf("Rename complete.\n");
    }
    else{
        printf("Illegal party member index.\n");
        exit(0);
    }
    fflush(stdout);
}

void runMenu(){
    puts("   What do you want to do?");
    puts("");
    puts("Options:");
    puts("(1) Create New Character");
    puts("(2) View a Character");
    puts("(3) Rename a Character");
    puts("(4) Begin Hacking");
    printf("> ");
    fflush(stdout);
    int selection = getIntClean();

    if(selection == 1){
        createCharacter();
    }
    else if(selection ==2){
        viewCharacter();
    }
    else if(selection == 3){
        renameCharacter();
    }
    else if(selection == 4){
        puts("");
        printf("   Your newly assembled party registers for CSAW RED!\n");
        printf("Don't forget that even your characters with high\n");
        printf("constitution still need to sleep.\n");
        puts("");
        fflush(stdout);
        exit(0);
    }
    else{
        printf("Illegal selection.");
        fflush(stdout);
        exit(0);
    }
    return;
}


void runChallenge(){
    puts("*** Party Creation ***\n");
    puts("   Welcome to the official CSAW RED party creation program!");
    puts("Here you can create a party of up to six characters to venture");
    puts("forth into servers unknown. You can even view and rename your");
    puts("characters. There is nothing this program cannot do! The only");
    puts("limit is your imagination (and the size of your party).");
    puts("");
    fflush(stdout);
    while(TRUE){
        runMenu();
    }
}

int main(int argc, char**argv){
    init();
    runChallenge();
    return 0;
}