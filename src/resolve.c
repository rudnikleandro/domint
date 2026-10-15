#include "resolve.h"

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "text.h"

static int already_listed(const domain_report *report, const char *ip)
{
    for (size_t i = 0; i < report->address_count; i++)
    {
        if (strcmp(report->addresses[i].ip, ip) == 0)
        {
            return 1;
        }
    }

    return 0;
}

void resolve_addresses(domain_report *report)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(report->name, NULL, &hints, &results);

    if (status != 0)
    {
        report->resolve_status = LOOKUP_FAILED;
        snprintf(report->resolve_error, sizeof(report->resolve_error), "%s",
                 status == EAI_NONAME ? "no A/AAAA records (or the name does not exist)" : gai_strerror(status));
        return;
    }

    report->resolve_status = LOOKUP_OK;

    for (struct addrinfo *p = results; p != NULL && report->address_count < MAX_ADDRESSES; p = p->ai_next)
    {
        char ip[IP_SIZE];

        if (getnameinfo(p->ai_addr, p->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) != 0 ||
            already_listed(report, ip))
        {
            continue;
        }

        address_info *address = &report->addresses[report->address_count];
        report->address_count++;

        snprintf(address->ip, sizeof(address->ip), "%s", ip);

        if (getnameinfo(p->ai_addr, p->ai_addrlen, address->ptr, sizeof(address->ptr), NULL, 0, NI_NAMEREQD) == 0)
        {
            sanitize_text(address->ptr, strlen(address->ptr), 0);
        }
        else
        {
            address->ptr[0] = '\0';
        }
    }

    freeaddrinfo(results);
}
