#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

int i;
int check();

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("Enter the password:");
        if(!check()) {
            puts("Welcome user.");
        } else {
            puts("Bad password !");
        }
}

int check() {
    char buf[21];
    read(STDIN_FILENO, buf, 1024);
    buf[20] = '\00';
    return strcmp(buf, "SuperSecretPassword!");
}
