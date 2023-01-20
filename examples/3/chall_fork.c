#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "serve.h"

int authentification(int fd) {
    char buf[20];
    write(fd, "Password :\n",11);
    read(fd, buf, 1024);
    if (!strcmp(buf, "SuperPassword!")) {
        return 1;
    } else {
        return 0;
    }
}

void serve(int fd) {
    int auth;

    write(fd, "Welcome, please login in order to use the app.\n",47);
    auth = authentification(fd);

    if (auth) {
        write(fd, "Welcome User\n",13);
    } else {
        write(fd, "Bad password\n",13);
    }
    return;
}


int main() {
    Serve socket = Serve_Create();

    if(socket.Bind(&socket, "0.0.0.0", 1337) < 0){
        perror("Binding socket error :");
        exit(1);
    } else if (socket.Listen(&socket, serve, 5) < 0){
        perror("Listen error :");
        exit(1);
    }
    return 0;
}
