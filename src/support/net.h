#ifndef DOMINT_NET_H
#define DOMINT_NET_H

#include <stddef.h>
#include <sys/socket.h>

/* Applies SO_RCVTIMEO and SO_SNDTIMEO so reads and writes cannot block forever. */
void set_socket_timeout(int sockfd);

int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

/* Returns a connected TCP socket to host:port, or -1. */
int connect_to_host(const char *host, const char *port);

/* Reads exactly `length` bytes. Returns 0, or -1 on error or early close. */
int recv_exact(int sockfd, unsigned char *buffer, size_t length);

#endif
