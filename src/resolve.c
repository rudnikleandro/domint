#include "resolve.h"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "model.h"
#include "util.h"

#define RESOLVE_COLLECTOR "resolve"
#define RESOLVE_SOURCE "system resolver (getaddrinfo)"
#define RESOLVE_LIMITATION "addresses and PTR names as returned by getaddrinfo/getnameinfo; " \
                           "the raw DNS answers are not available through this interface"

/* The evidence is one line per address: "<ip>\t<ptr>\n", ptr empty when
 * there is none. */
void resolve_collect(const char *name, observation_list *observations)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(name, NULL, &hints, &results);

    if (status == EAI_NONAME)
    {
        record_observation(observations, RESOLVE_COLLECTOR, RESOLVE_SOURCE, name, OBS_EMPTY,
                           "no A/AAAA records (or the name does not exist)", NULL, 0);
        return;
    }

    if (status != 0)
    {
        record_observation(observations, RESOLVE_COLLECTOR, RESOLVE_SOURCE, name,
                           status == EAI_AGAIN ? OBS_NO_RESPONSE : OBS_ERROR, gai_strerror(status), NULL, 0);
        return;
    }

    size_t capacity = 256;
    size_t length = 0;
    char *lines = xcalloc(capacity, 1);
    char seen[MAX_ADDRESSES][IP_SIZE];
    size_t listed = 0;

    for (struct addrinfo *p = results; p != NULL && listed < MAX_ADDRESSES; p = p->ai_next)
    {
        char ip[IP_SIZE];
        char ptr[FIELD_SIZE] = "";
        char line[IP_SIZE + FIELD_SIZE + 4];
        int duplicate = 0;

        if (getnameinfo(p->ai_addr, p->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) != 0)
        {
            continue;
        }

        /* getaddrinfo can list an address more than once. */
        for (size_t i = 0; i < listed; i++)
        {
            duplicate |= strcmp(seen[i], ip) == 0;
        }

        if (duplicate)
        {
            continue;
        }

        snprintf(seen[listed], sizeof(seen[listed]), "%s", ip);

        if (getnameinfo(p->ai_addr, p->ai_addrlen, ptr, sizeof(ptr), NULL, 0, NI_NAMEREQD) != 0)
        {
            ptr[0] = '\0';
        }

        int written = snprintf(line, sizeof(line), "%s\t%s\n", ip, ptr);

        while (length + (size_t)written + 1 > capacity)
        {
            capacity *= 2;
            lines = xrealloc(lines, capacity);
        }

        memcpy(lines + length, line, (size_t)written + 1);
        length += (size_t)written;
        listed++;
    }

    freeaddrinfo(results);

    record_observation(observations, RESOLVE_COLLECTOR, RESOLVE_SOURCE, name, OBS_OK, RESOLVE_LIMITATION, lines, length);
    free(lines);
}

void resolve_interpret(const observation_list *observations, domain_report *report)
{
    const observation *item = find_observation(observations, RESOLVE_COLLECTOR, report->name);

    report->address_count = 0;

    if (item == NULL)
    {
        report->resolve_status = LOOKUP_SKIPPED;
        return;
    }

    if (item->status != OBS_OK)
    {
        report->resolve_status = LOOKUP_FAILED;
        snprintf(report->resolve_error, sizeof(report->resolve_error), "%s", item->detail);
        return;
    }

    report->resolve_status = LOOKUP_OK;

    char *text = observation_text(item);
    char *saveptr;

    for (char *line = strtok_r(text, "\n", &saveptr); line != NULL && report->address_count < MAX_ADDRESSES;
         line = strtok_r(NULL, "\n", &saveptr))
    {
        address_info *address = &report->addresses[report->address_count];
        size_t ip_length = strcspn(line, "\t");

        memset(address, 0, sizeof(*address));
        snprintf(address->ip, sizeof(address->ip), "%.*s", (int)ip_length, line);

        if (line[ip_length] == '\t')
        {
            snprintf(address->ptr, sizeof(address->ptr), "%s", line + ip_length + 1);
        }

        report->address_count++;
    }

    free(text);
}
