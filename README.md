This is a tweaked version of the public SHA1 implementation from https://github.com/clibs/sha1

The state has been changed to the value of a message authentication code (MAC) supposedly intercepted. (Note: the context -> count[0] variable was also changed to 1024 to make it appear that the algorithm had already created 2 512-bit blocks of data and is continuing with a new fake block of message). 

By spoofing the padding that would have existed with a secret key and original message, we can send the message + padding + my own addition. When the receiver prepends the secret key and sends it through the real SHA1 algorithm, the MAC output will be the same as when I put my addition to the message through the altered SHA1 algorithm. (Note: the length when sent through the SHA1() function should always the be byte amount of the buffer going through it.) 

To compile: gcc -o main main.c

To run: ./main

This code already has the values plugged in for this particular problem, so no input is required. It simply calculates and prints the MAC I needed for this project.
