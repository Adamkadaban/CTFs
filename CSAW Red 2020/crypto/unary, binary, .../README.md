> Sean Sears, the international Rock, Paper, Scissors champion, gives his adoring fans a thumbs-up after every bout. His grueling daily training routine starts with unary exercises, then progresses to binary, and then...

1. Given the problem statement, we can guess that the next word in the sequence is tertiary
    - This makes sense given that rock, paper, scissors is essentially base 3 and that the problem says it is used to communicate
2. First, turn each of the pictures into a series of numbers. It doesn't matter what they are as long as you keep track
    - I wrote it down based on the number of fingers up

    ```bash
    5025015500
    0150525150
    2551555201
    5500215255
    1502001522
    0150552150
    0051222215
    0002150552
    1550251502
    2215255155
    0001550001
    5555215552
    21
    ```

3. Given that the game is generally rock, paper, scissors, we can assign those to 0,1,2 respectively. We also need to split the inputs based on the thumbs up.
4. Once that is done, we can convert from base 3 to decimal, and from decimal to ascii
5. The code below does displays the process:

    ```bash
    def val(c): 
        if c >= '0' and c <= '9': 
            return ord(c) - ord('0') 
        else: 
            return ord(c) - ord('A') + 10; 
    def toDeci(str,base): 
        llen = len(str) 
        power = 1 #Initialize power of base 
        num = 0     #Initialize result 
      
        # Decimal equivalent is str[len-1]*1 +  
        # str[len-2]*base + str[len-3]*(base^2) + ...  
        for i in range(llen - 1, -1, -1): 
              
            # A digit in input number must  
            # be less than number's base  
            if val(str[i]) >= base: 
                print('Invalid Number') 
                return -1
            num += val(str[i]) * power 
            power = power * base 
        return num 
    x=[]
    with open('inp') as fin:
      for i in fin:
        temp = i.rstrip()
        temp2 = list(map(int, list(temp)))
        # print(temp2)
        x += temp2
    # print(x)

    new = "".join([str(i) for i in x])
    newSep = new.split('1')
    # print(newSep)

    def edit(n):
      r = ""
      n = str(n)
      for i in n:
        if i=="0":
          r+="0"
        if i=="5":
          r+="1"
        if i=="2":
          r+="2"
      return r

    newEdit = [edit(i) for i in newSep]

    # for i in range(len(newEdit)):
    #   print(newSep[i], newEdit[i])

    with open('outp', 'w') as fout:
      for i in newEdit:
        t = toDeci(i, 3)
        t = chr(t)
        fout.write(str(t))
    ```

6. The flag is flag{n1c3_RPS_sk1llz}
