#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define IDCARDBUFSIZE 400
#define LABELBUFSIZE 64
#define IDCARDSIZE 256

char * id_prefix = "Hi, my name is Jangui. My card is my passport. Please verify me.";
char id1[IDCARDBUFSIZE];
char id2[IDCARDBUFSIZE];

int validHashes(const char* buf1, const char* buf2, int bufLength){
    char md5hash1[MD5_DIGEST_LENGTH];
    MD5(buf1, bufLength, md5hash1);
    char md5hash2[MD5_DIGEST_LENGTH];
    MD5(buf2, bufLength, md5hash2);
    if (strncmp(md5hash1, md5hash2, MD5_DIGEST_LENGTH)){
        puts("MD5 hashes are not the same and should be!");
        return 0;
    }
    char sha256hash1[SHA256_DIGEST_LENGTH];
    SHA256(buf1, bufLength, sha256hash1);
    char sha256hash2[SHA256_DIGEST_LENGTH];
    SHA256(buf2, bufLength, sha256hash2);
    if (!strncmp(sha256hash1, sha256hash2,SHA256_DIGEST_LENGTH)){
        puts("SHA256 hashes are the same and should not be!");
        return 0;
    }
    return 1;
}


void runGame(){
    char idCard[IDCARDSIZE];
    puts("---- ID Verification program ----\n");
    puts("   Please enter two Jangui ID cards ");
    puts("with the same MD5 sums and different");
    puts("SHA-256 hashes.\n");
    puts("   Expected ID card prefix:\n");
    printf("%s\n",id_prefix);
    puts("");
    printf("   Input ID card 1: >");
    fflush(stdout);

    int card_1_length = read(0, id1, IDCARDBUFSIZE);
    printf("   Input ID card 2: >");
    fflush(stdout);

    int card_2_length = read(0, id2, IDCARDBUFSIZE);
    puts("Scanning...");
    if (strncmp(id1, id2, 0x40)!=0 || strncmp(id1, id_prefix,0x40)!=0){
        puts("Error: ID prefix mismatch.");
        exit(0);
    }else{
        if(!(validHashes(id1, id2, IDCARDBUFSIZE))){
            puts("Hashes do not check out!");
            exit(0);
        }
    }
    puts("Thank you for logging in, Jangui. You have been validated. Have a nice day.");
    memcpy(idCard, id1, IDCARDBUFSIZE);
    return;
}

int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("*** Fabricator ***\n");
    puts("   In the dark of night (if you have been playing the");
    puts("spellcoding challenges), you have broken into the");
    puts("OSIRIS Lab, faced off against an admin in an");
    puts("impressive display of mental and actual gymnastics,");
    puts("and countered their own shellcode. Reacting to the");
    puts("admin's attack, you cast a confusion spell, and every");
    puts("admin in the room starts deleting random Discord posts.");
    puts("You have a minute to pwn the challenge server, before");
    puts("they get their wits back.\n");
    puts("   Now it is said that Jangui only ever needs");
    puts("physical access to the server when he is beside");
    puts("himself -- and true to the legend, you can see two");
    puts("identical slots in the side of the challenge server.");
    puts("You swipe a template access card off a table...to pwn");
    puts("the server, you will need to first create two unique");
    puts("access cards with the same MD5 sum. A tense few");
    puts("seconds pass as you cast Fabricate...\n");
    puts("");
    fflush(stdout);
    runGame();
    printf("\n");
    return 0;
}


