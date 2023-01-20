//
// Created by aku on 1/11/23.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include "serve.h"

static void Serve_Init(Serve *This){
    // Initialize the Bind and Listen function pointers
    // that are specific to the Serve struct
    This->Bind = Serve_Bind;
    This->Listen = Serve_Listen;
    // set the addr_size variable
    This->addr_size = sizeof(This->server_addr);
}


int childpid;
pid_t pid;
pid_t parent;
int fd;

void Serve_SigHandler(int signum){
    // check if the process is a child process
    if (childpid == 0) {
        //printf("signal %d for %d\n", signum, pid);
        // close the file descriptor
        //printf("Closing fd : %d\n", fd);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        // exit the child process
        exit(0);
    }
}

void Serve_ChildHandler(int signum){
    //printf("signal %d for %d\n", signum, pid);
    int p;
    int status;
    // wait for any child process that terminates
    // and handle them with kill -12
    while ((p = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        //printf("\n\npid : %d, status : %d\n", p, status);
        kill(p, 12);
    }
}

Serve Serve_Create(void){
    // Create an instance of the Serve struct
    Serve This;
    // Initialize the struct's function pointers and addr_size
    Serve_Init(&This);
    return This;
}

int Serve_Bind(Serve *This, const char *addr, int port){
    // Register signal handlers for various signals
    signal(SIGALRM, Serve_SigHandler);
    signal(SIGSEGV, Serve_SigHandler);
    signal(12, Serve_SigHandler);
    signal(SIGCHLD, Serve_ChildHandler);

    pid = getpid();
    parent = getpid();

    int ret;
    int optval = 1;

    // Clear the server_addr struct and set its values
    memset(&This->server_addr, '\0', This->addr_size);
    This->server_addr.sin_family = AF_INET;
    This->server_addr.sin_port = htons(port);
    This->server_addr.sin_addr.s_addr = inet_addr(addr);

    // Create a socket
    This->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (This->socket_fd < 0) {
        return This->socket_fd;
    }

    // Allow reuse of the address and port
    ret = setsockopt(This->socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if(ret < 0){
        return ret;
    }

    // Bind the socket to the server_addr
    ret = bind(This->socket_fd, (struct sockaddr *) &This->server_addr, This->addr_size);
    if (ret < 0) {
        return ret;
    }

    // Listen for incoming connections, with a backlog of 10
    if (listen(This->socket_fd, 10) == 0) {
        return 0;
    }
    return -1;
}

int Serve_Listen(Serve *This, void (*callback)(int), int timeout){
    // Infinite loop to wait for new connections
    while(1){
        // Wait for an incoming connection
        // If successful, fd will be the file descriptor for the accepted connection
        fd = accept(This->socket_fd, (struct sockaddr *) &This->new_addr, &This->addr_size);
        // check accept return value
        if (fd < 0) {
            return fd;
        }
        printf("Connection accepted from %s:%d\n", inet_ntoa(This->new_addr.sin_addr), ntohs(This->new_addr.sin_port));

        // fork a child process to handle the connection
        if ((childpid = fork()) == 0) {
            pid = getpid();
            printf("fork pid = %d\n", pid);

            // set alarm
            alarm(timeout);

            // Close the original socket descriptor
            // It's not needed in the child process
            close(This->socket_fd);

            // Call the provided callback function and pass the file descriptor
            (*callback)(fd);

            printf("Closing connection from %s:%d\n", inet_ntoa(This->new_addr.sin_addr), ntohs(This->new_addr.sin_port));

            // Close the file descriptor for the connection
            // and shutdown the connection
            shutdown(fd, SHUT_RDWR);
            close(fd);
            break;
        }
        if(parent != getpid()){
            shutdown(fd, SHUT_RDWR);
            close(fd);
            exit(0);
        }
        close(fd);
    }
    return 0;
}
