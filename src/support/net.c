#include "support/net.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define SOCKET_TIMEOUT_SECONDS 5

void set_socket_timeout(int sockfd)
{
    struct timeval timeout = {.tv_sec = SOCKET_TIMEOUT_SECONDS, .tv_usec = 0};

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

/* A plain connect() to a host that silently drops packets blocks for over a
 * minute, so connect in non-blocking mode and wait with poll() instead. */
int connect_with_timeout(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int flags = fcntl(sockfd, F_GETFL, 0);

    if (flags == -1 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        return -1;
    }

    int result = connect(sockfd, addr, addrlen);

    if (result == -1 && errno == EINPROGRESS)
    {
        struct pollfd pfd = {.fd = sockfd, .events = POLLOUT};
        int error = 0;
        socklen_t error_len = sizeof(error);

        if (poll(&pfd, 1, SOCKET_TIMEOUT_SECONDS * 1000) == 1 &&
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &error_len) == 0 &&
            error == 0)
        {
            result = 0;
        }
    }

    if (fcntl(sockfd, F_SETFL, flags) == -1)
    {
        return -1;
    }

    return result;
}

int connect_to_host(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &results) != 0)
    {
        return -1;
    }

    int sockfd = -1;

    for (struct addrinfo *p = results; p != NULL; p = p->ai_next)
    {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (sockfd == -1)
        {
            continue;
        }

        set_socket_timeout(sockfd);

        if (connect_with_timeout(sockfd, p->ai_addr, p->ai_addrlen) == 0)
        {
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(results);

    return sockfd;
}

int recv_exact(int sockfd, unsigned char *buffer, size_t length)
{
    size_t total = 0;

    while (total < length)
    {
        ssize_t bytes_received = recv(sockfd, buffer + total, length - total, 0);

        if (bytes_received <= 0)
        {
            return -1;
        }

        total += (size_t)bytes_received;
    }

    return 0;
}
