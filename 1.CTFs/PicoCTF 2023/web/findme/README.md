Putting the website through the burp proxy lets us intercept all request / redirections

The two first redirections have an `id` with a base64 string. Decoding and concatinating them provides the flag
