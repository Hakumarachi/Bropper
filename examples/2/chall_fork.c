#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "serve.h"

int authentification(int fd) {
    char buf[20];
    dprintf(fd, "Password :\n");
    read(fd, buf, 1024);
    if (!strcmp(buf, "SuperPassword!")) {
        return 1;
    } else {
        return 0;
    }
}

void serve(int fd) {
    int auth;

    dprintf(fd, "Welcome, please login in order to use the app.\n");
    auth = authentification(fd);

    if (auth) {
        dprintf(fd, "Welcome User\n");
    } else {
        dprintf(fd, "Bad password\n");
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
