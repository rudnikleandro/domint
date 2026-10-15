#include "http.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "memory.h"
#include "net.h"
#include "text.h"

#define HTTP_PORT "80"

/* Looks `name` up among the response headers. Header names are
 * case-insensitive and the space after the colon is optional. */
static int extract_http_header(const char *response, const char *name, char *out, size_t out_size)
{
    size_t name_len = strlen(name);
    const char *line = strstr(response, "\r\n");

    while (line != NULL)
    {
        line += 2;

        if (*line == '\0' || strncmp(line, "\r\n", 2) == 0)
        {
            break;
        }

        if (strncasecmp(line, name, name_len) == 0 && line[name_len] == ':')
        {
            const char *value = line + name_len + 1;

            while (*value == ' ' || *value == '\t')
            {
                value++;
            }

            size_t len = strcspn(value, "\r\n");

            if (len >= out_size)
            {
                len = out_size - 1;
            }

            memcpy(out, value, len);
            out[len] = '\0';
            return 1;
        }

        line = strstr(line, "\r\n");
    }

    return 0;
}

/* TCP is a stream, so the headers can arrive split across several reads:
 * keep reading until the blank line that ends them, the buffer fills up or
 * the server closes. Returns the number of bytes read or -1. */
static ssize_t recv_http_headers(int sockfd, char *buffer, size_t size)
{
    size_t total = 0;

    buffer[0] = '\0';

    while (total < size - 1)
    {
        ssize_t bytes_received = recv(sockfd, buffer + total, size - 1 - total, 0);

        if (bytes_received == -1 && total == 0)
        {
            return -1;
        }

        if (bytes_received <= 0)
        {
            break;
        }

        total += (size_t)bytes_received;
        buffer[total] = '\0';

        if (strstr(buffer, "\r\n\r\n") != NULL)
        {
            break;
        }
    }

    return (ssize_t)total;
}

/* Returns 1 when the address answered the request. */
static int probe_address(const struct addrinfo *address, const char *host, http_info *http)
{
    int sockfd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);

    if (sockfd == -1)
    {
        return 0;
    }

    set_socket_timeout(sockfd);

    char request[512];

    snprintf(
        request,
        sizeof(request),
        "HEAD / HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: " HTTP_USER_AGENT "\r\n"
        "Connection: close\r\n"
        "\r\n",
        host);

    char response[16384];
    ssize_t received = -1;

    if (connect_with_timeout(sockfd, address->ai_addr, address->ai_addrlen) == 0 &&
        send(sockfd, request, strlen(request), 0) != -1)
    {
        received = recv_http_headers(sockfd, response, sizeof(response));
    }

    close(sockfd);

    if (received <= 0)
    {
        return 0;
    }

    sanitize_text(response, (size_t)received, 1);

    size_t status_len = strcspn(response, "\r\n");

    if (status_len >= sizeof(http->status_line))
    {
        status_len = sizeof(http->status_line) - 1;
    }

    memcpy(http->status_line, response, status_len);
    http->status_line[status_len] = '\0';

    extract_http_header(response, "Location", http->location, sizeof(http->location));
    extract_http_header(response, "Server", http->server, sizeof(http->server));

    http->raw = xstrdup(response);

    return 1;
}

void http_probe(domain_report *report)
{
    http_info *http = &report->http;
    http->status = LOOKUP_FAILED;

    for (size_t i = 0; i < report->address_count; i++)
    {
        const char *ip = report->addresses[i].ip;
        struct addrinfo hints;
        struct addrinfo *address = NULL;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST;

        if (getaddrinfo(ip, HTTP_PORT, &hints, &address) != 0)
        {
            continue;
        }

        http->attempts++;

        int answered = probe_address(address, report->name, http);

        freeaddrinfo(address);

        if (answered)
        {
            snprintf(http->endpoint, sizeof(http->endpoint), strchr(ip, ':') != NULL ? "[%s]:%s" : "%s:%s", ip, HTTP_PORT);
            http->status = LOOKUP_OK;
            return;
        }
    }
}
