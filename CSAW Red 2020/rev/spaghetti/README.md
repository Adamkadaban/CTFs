# spaghetti (200pt)

> Due to technical difficulties, we can only give you the source our intern wrote. We told them to ensure they were using secure coding standards, but they ended up with this... nc [rev.red.csaw.io](http://rev.red.csaw.io/) 5001

1. The code is put together in a mess of definitions. Write a python script to make it readable

    ```bash
    stuff = {}
    lines=[]
    with open('inp') as fin:
      for i in fin:
        lines.append(i.rstrip())

    for i in lines:
      things = i.split()
      stuff[things[1]]=things[2]

    print(stuff)

    with open('code') as fin:
      code = fin.readline().rstrip().split()

    with open('outCode', 'w') as fout:
      for i in code:
        fout.write(stuff[i] + " ")

    # put the output of outCode into an ide to format it nicely
    ```

    - Use this website to format it nicely: [https://codebeautify.org/c-formatter-beautifier](https://codebeautify.org/c-formatter-beautifier)
    - We get the code to be:

    ```c
    #include <stdio.h> 
    #include <stdlib.h> 
    #include <stdint.h> 
    #include <string.h> 
    #include <unistd.h> 
    #define BUF_SIZE 2048
    static inline void wrapper(uint32_t * eax, uint32_t * ebx, uint32_t * ecx, uint32_t * edx) {
      asm volatile("cpuid": "=a"( * eax), "=b"( * ebx), "=c"( * ecx), "=d"( * edx): "0"( * eax), "2"( * ecx));
    }
    void win(void) {
      FILE * file;
      char buf[255];
      file = fopen("flag.txt", "r");
      if (!file) return;
      fscanf(file, "%s", buf);
      printf("%s\n", buf);
      fclose(file);
    }
    int main(int argc, char * argv[]) {
      setvbuf(stdout, NULL, _IONBF, 0);
      uint32_t eax;
      eax = 0;
      char input[17];
      fgets(input, sizeof(input), stdin);
      char * buf = malloc(sizeof(char) * 17);
      buf[0] = 'C';
      buf[1] = 'P';
      buf[2] = 'U';
      buf[3] = ':';
      wrapper(&eax, (uint32_t* )&buf[4], (uint32_t*)&buf[12], (uint32_t*)&buf[8]);
      buf[16] = '\0';
      if (strncmp(buf, input, 17) == 0) win();
      free(buf);
      return 0;
    }
    ```

2. The if-statement in the end is checking the **buf** variable with our input to see if they match. What we can do is print out the value of **buf** before the if-statement, and we will know what we need to type:

    ![spaghetti%20(200pt)%2054e0b7c71f3245ee800053955ae3b2d0/Untitled_3.png](spaghetti%20(200pt)%2054e0b7c71f3245ee800053955ae3b2d0/Untitled_3.png)

3. We now learn that in this case, buf is equal to **CPU:GenuineIntel** :

    ![spaghetti%20(200pt)%2054e0b7c71f3245ee800053955ae3b2d0/Untitled_4.png](spaghetti%20(200pt)%2054e0b7c71f3245ee800053955ae3b2d0/Untitled_4.png)

4. Let’s connect to the server and get our flag:

    ![spaghetti%20(200pt)%2054e0b7c71f3245ee800053955ae3b2d0/Untitled_5.png](spaghetti%20(200pt)%2054e0b7c71f3245ee800053955ae3b2d0/Untitled_5.png)

5. The flag is flag{s0m3b0dy_t0ucha_my_spagh3tt}