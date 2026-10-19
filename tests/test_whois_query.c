#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test.h"
#include "whois.h"

/* Starts a one-shot server on 127.0.0.1 that reads the query, answers with
 * `size` bytes and closes. Writes the chosen port and returns the child pid. */
static pid_t serve_once(size_t size, char *port, size_t port_size)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (listener == -1 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0)
    {
        return -1;
    }

    snprintf(port, port_size, "%u", (unsigned)ntohs(addr.sin_port));
    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();

    if (pid == 0)
    {
        /* The client hangs up early when the answer is too large. */
        signal(SIGPIPE, SIG_IGN);

        int client = accept(listener, NULL, NULL);
        char query[256];
        char chunk[4096];
        size_t sent = 0;

        recv(client, query, sizeof(query), 0);
        memset(chunk, 'A', sizeof(chunk));

        while (sent < size)
        {
            size_t remaining = size - sent;
            ssize_t written = send(client, chunk, remaining < sizeof(chunk) ? remaining : sizeof(chunk), 0);

            if (written <= 0)
            {
                break;
            }

            sent += (size_t)written;
        }

        close(client);
        close(listener);
        _exit(0);
    }

    close(listener);
    return pid;
}

static whois_response query_local(size_t size)
{
    char port[16];
    pid_t pid = serve_once(size, port, sizeof(port));
    whois_response failed = {OBS_ERROR, "server not started", NULL, 0};

    CHECK(pid > 0);

    if (pid <= 0)
    {
        return failed;
    }

    whois_response response = whois_query_port("127.0.0.1", port, "example.com");

    waitpid(pid, NULL, 0);
    return response;
}

void test_whois_query(void)
{
    whois_response response = query_local(100);

    CHECK_INT(response.status, OBS_OK);
    CHECK(response.data != NULL);
    CHECK_INT(response.length, 100);
    CHECK(response.error == NULL);
    free(response.data);

    response = query_local(0);
    CHECK_INT(response.status, OBS_EMPTY);
    CHECK(response.data == NULL);
    CHECK_STR(response.error, "empty response");

    response = query_local(300 * 1024);
    CHECK_INT(response.status, OBS_LIMITED);
    CHECK(response.data == NULL);
    CHECK(response.error != NULL && strstr(response.error, "larger than") != NULL);

    /* A port nobody listens on: bind to get a free one, then release it. */
    char port[16];
    int probe = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(probe, (struct sockaddr *)&addr, sizeof(addr));
    getsockname(probe, (struct sockaddr *)&addr, &addr_len);
    snprintf(port, sizeof(port), "%u", (unsigned)ntohs(addr.sin_port));
    close(probe);

    response = whois_query_port("127.0.0.1", port, "example.com");
    CHECK_INT(response.status, OBS_NO_RESPONSE);
    CHECK_STR(response.error, "connection failed");
}
