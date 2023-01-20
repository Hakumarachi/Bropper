//
// Created by aku on 1/11/23.
//
#ifndef SERVE_H
#define SERVE_H

#include <sys/socket.h> // For socket-related functions and data structures
#include <netinet/in.h> // For internet-related functions and data structures
#include <sys/types.h>  // For miscellaneous types used in socket programming

// Serve struct contains information about a socket and function pointers for the
// Bind and Listen functions
typedef struct Serve {
    int socket_fd; // Socket descriptor

    // Information about the server address
    struct sockaddr_in server_addr;

    // Information about the client address for new connections
    struct sockaddr_in new_addr;

    // Size of a socket address
    socklen_t addr_size;

    // Pointers to functions
    int (*Bind)(struct Serve*,const char*, int);
    int (*Listen)(struct Serve*, void (*callback)(int), int);
} Serve;

// Signal handler for the server
void Serve_SigHandler(int);

// Signal handler for child processes
void Serve_ChildHandler(int);

// Creates an instance of the Serve struct
Serve Serve_Create(void);

// Binds the socket to a specific address and port
int Serve_Bind(Serve*, const char*, int);

// Starts listening for incoming connections on the socket and handle with
// the callback function on accepted connection
int Serve_Listen(Serve*, void (*callback)(int), int);

#endif /* SERVE_H */