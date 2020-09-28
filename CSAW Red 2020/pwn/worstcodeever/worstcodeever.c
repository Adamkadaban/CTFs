#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NAME_LENGTH 64
#define MAX_FRIENDS 10

union identifier
{
    char *name;
    int64_t id;
};

typedef struct Friend
{
    union identifier identity;
    int age;
} Friend;

Friend *friend_list[MAX_FRIENDS] = {};
int friend_type[MAX_FRIENDS] = {};
int f_index = 0;

void add_friend()
{
    int human_name;
    if (f_index >= MAX_FRIENDS)
    {
        puts("You have too many friends, save some for the rest of us.");
        return;
    }

    Friend *f = malloc(sizeof(Friend));
    char *name = malloc(sizeof(char) * NAME_LENGTH);

    puts("Is your friend organic and of flesh?");
    scanf("%d", &human_name);

    if (human_name != 0)
    {
        puts("What is your friends name?");

        fgets(name, NAME_LENGTH, stdin);
        name[NAME_LENGTH] = 0;
        name[strcspn(name, "\n")] = 0;

        f->identity.name = name;
    } else
    {
        puts("What is your friends barcode tag?");
        scanf("%ld", &f->identity.id);
    }

    puts("What is their age?");

    scanf("%d", &f->age);

    friend_type[f_index] = human_name;
    friend_list[f_index++] = f;

    puts("Your friend was added");
}

void remove_friend()
{
    if (f_index <= 1)
    {
        puts("You have too few friends. It is good to have some friends.");
        return;
    }

    int index = 0;

    puts("Which friend would you like to remove?");
    scanf("%d", &index);

    if (index < 0 || index >= MAX_FRIENDS || friend_list[index] == 0)
    {
        puts("That is not your friend.");
        return;
    }

    if (friend_type[index] != 0)
        free(friend_list[index]->identity.name);
    free(friend_list[index]);

    puts("Your friend was removed");
}

void edit_friend()
{
    int index = 0;

    puts("Which friend do you want to edit?");
    scanf("%d", &index);

    while ((getchar()) != '\n');

    if (index < 0 || index >= MAX_FRIENDS || friend_list[index] == 0)
    {
        puts("That is not your friend.");
        return;
    }

    if (friend_type[index] != 0)
    {
        puts("What is their new name?");
        fgets(friend_list[index]->identity.name, NAME_LENGTH, stdin);
    } else
    {
        puts("What is their new barcode?");
        scanf("%ld", &friend_list[index]->identity.id);
    }

    puts("What is their new age?");
    scanf("%d", &friend_list[index]->age);

    puts("Done. Happy birthday to your friend.");
}

void display()
{
    int index = 0;

    puts("Which friend would you like to look at?");
    scanf("%d", &index);

    if (index < 0 || index >= MAX_FRIENDS || friend_list[index] == 0)
    {
        puts("That is not your friend.");
    }

    if (friend_type[index] != 0)
    {
        printf("Your friend's name: %s\n", friend_list[index]->identity.name);
        printf("Your friend's age: %d\n", friend_list[index]->age);
    } else
    {
        printf("Your friend's barcode tag: %ld\n", friend_list[index]->identity.id);
        printf("Your friend's age: %d\n", friend_list[index]->age);
    }
}

void play()
{
    for (int i = 0; i < 50; ++i)
    {
        printf("What would you like to do?\n");
        printf("\t1. Add a friend\n");
        printf("\t2. Remove a friend\n");
        printf("\t3. Display a friend\n");
        printf("\t4. Edit a friend\n");
        printf("> ");

        int option;
        scanf("%d", &option);

        if (option == 1)
        {
            add_friend();
        } else if (option == 2)
        {
            remove_friend();
        } else if (option == 3)
        {
            display();
        } else if (option == 4)
        {
            edit_friend();
        }
    }
}

void init()
{
    setvbuf(stdout, NULL, _IONBF, 0);
}

int main()
{
    init();
    play();

    return 0;
}
