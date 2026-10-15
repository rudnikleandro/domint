#include "whois.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net.h"
#include "text.h"

#define WHOIS_PORT "43"
#define IANA_WHOIS_SERVER "whois.iana.org"
#define TLD_CACHE_SIZE 64

typedef struct
{
    char tld[64];
    char server[FIELD_SIZE];
} tld_entry;

/* IANA's answer for a TLD does not change during a run, so ask once per TLD. */
static tld_entry tld_cache[TLD_CACHE_SIZE];
static size_t tld_cache_count;

/* Registries format their records differently; these are the field names
 * seen across the common gTLD and ccTLD servers, in order of preference. */
static const char *const registrar_fields[] = {"Registrar:", "Sponsoring Registrar:", "registrar-name:", NULL};
static const char *const created_fields[] = {"Creation Date:", "Created On:", "Created:", "Registered on:",
                                             "Registration Time:", "Registration Date:", "Domain Registration Date:",
                                             "registered:", NULL};
static const char *const expires_fields[] = {"Registry Expiry Date:", "Registrar Registration Expiration Date:",
                                             "Expiry Date:", "Expiration Date:", "Expiration Time:", "Expires On:",
                                             "Expires:", "paid-till:", NULL};
static const char *const updated_fields[] = {"Updated Date:", "Last Updated On:", "Last updated:", "Last Modified:",
                                             "Changed:", "last-update:", NULL};
static const char *const registrant_fields[] = {"Registrant Organization:", "Registrant Organisation:",
                                                "Registrant Name:", "Registrant:", "owner:", "org-name:", NULL};
static const char *const country_fields[] = {"Registrant Country:", NULL};

static const char *const not_found_markers[] = {"No match for", "NOT FOUND", "No Data Found", "No entries found",
                                                "Domain not found", "No Object Found", "no matching objects",
                                                "is available for registration", "Status: free", "Status: AVAILABLE",
                                                NULL};
static const char *const privacy_markers[] = {"privacy", "redacted", "withheld", "proxy", "protected",
                                              "not disclosed", "gdpr", NULL};

/* Sends `query` to `server` on the WHOIS port and returns the full,
 * null-terminated response. WHOIS has no length header, so the response
 * is read in a loop until the server closes the connection. */
char *whois_query(const char *server, const char *query)
{
    int sockfd = connect_to_host(server, WHOIS_PORT);

    if (sockfd == -1)
    {
        return NULL;
    }

    char request[256];
    snprintf(request, sizeof(request), "%s\r\n", query);

    if (send(sockfd, request, strlen(request), 0) == -1)
    {
        close(sockfd);
        return NULL;
    }

    size_t capacity = 8192;
    size_t total = 0;
    char *buffer = malloc(capacity);

    if (buffer == NULL)
    {
        close(sockfd);
        return NULL;
    }

    ssize_t bytes_received;

    while ((bytes_received = recv(sockfd, buffer + total, capacity - total - 1, 0)) > 0)
    {
        total += (size_t)bytes_received;

        if (total >= capacity - 1)
        {
            capacity *= 2;
            char *new_buffer = realloc(buffer, capacity);

            if (new_buffer == NULL)
            {
                free(buffer);
                close(sockfd);
                return NULL;
            }

            buffer = new_buffer;
        }
    }

    close(sockfd);

    if (bytes_received == -1 && total == 0)
    {
        free(buffer);
        return NULL;
    }

    sanitize_text(buffer, total, 1);
    buffer[total] = '\0';

    return buffer;
}

static size_t indentation(const char *line)
{
    return strspn(line, " \t");
}

static int copy_value(const char *value, char *out, size_t out_size)
{
    value += strspn(value, " \t");

    size_t len = strcspn(value, "\r\n");

    if (len == 0)
    {
        return 0;
    }

    if (len >= out_size)
    {
        len = out_size - 1;
    }

    memcpy(out, value, len);
    out[len] = '\0';
    return 1;
}

/* Copies the value of the first line that starts with `field` (ignoring
 * case and leading whitespace). Some registries (.uk) put the value on the
 * next, more indented line instead. Returns 1 when a value was found. */
static int extract_field(const char *response, const char *field, char *out, size_t out_size)
{
    size_t field_len = strlen(field);
    const char *line = response;

    while (line != NULL && *line != '\0')
    {
        const char *next_line = strchr(line, '\n');
        const char *text = line + indentation(line);

        if (strncasecmp(text, field, field_len) == 0)
        {
            if (copy_value(text + field_len, out, out_size))
            {
                return 1;
            }

            if (next_line != NULL && indentation(next_line + 1) > indentation(line) &&
                copy_value(next_line + 1, out, out_size))
            {
                return 1;
            }
        }

        line = next_line != NULL ? next_line + 1 : NULL;
    }

    return 0;
}

static void extract_first(const char *response, const char *const *fields, char *out, size_t out_size)
{
    out[0] = '\0';

    for (; *fields != NULL; fields++)
    {
        if (extract_field(response, *fields, out, out_size))
        {
            return;
        }
    }
}

static int contains_any(const char *text, const char *const *markers)
{
    for (; *markers != NULL; markers++)
    {
        if (contains_ci(text, *markers))
        {
            return 1;
        }
    }

    return 0;
}

/* Finds the WHOIS server of a TLD through IANA. Returns 1 when found, 0 when
 * IANA lists none and -1 when IANA could not be reached. */
static int whois_server_for(const char *tld, char *server, size_t size, int *queried_iana)
{
    *queried_iana = 0;

    for (size_t i = 0; i < tld_cache_count; i++)
    {
        if (strcmp(tld_cache[i].tld, tld) == 0)
        {
            snprintf(server, size, "%s", tld_cache[i].server);
            return server[0] != '\0';
        }
    }

    *queried_iana = 1;

    char *response = whois_query(IANA_WHOIS_SERVER, tld);

    if (response == NULL)
    {
        return -1;
    }

    /* gTLDs use "whois:"; some ccTLDs use "refer:" instead. */
    static const char *const fields[] = {"whois:", "refer:", NULL};
    extract_first(response, fields, server, size);
    free(response);

    if (tld_cache_count < TLD_CACHE_SIZE)
    {
        snprintf(tld_cache[tld_cache_count].tld, sizeof(tld_cache[tld_cache_count].tld), "%s", tld);
        snprintf(tld_cache[tld_cache_count].server, sizeof(tld_cache[tld_cache_count].server), "%s", server);
        tld_cache_count++;
    }

    return server[0] != '\0';
}

void whois_collect(const char *domain, whois_info *info)
{
    snprintf(info->queried, sizeof(info->queried), "%s", domain);
    info->status = LOOKUP_FAILED;

    const char *dot = strrchr(domain, '.');
    const char *tld = dot != NULL ? dot + 1 : domain;

    int found = whois_server_for(tld, info->server, sizeof(info->server), &info->iana_queried);

    if (found < 0)
    {
        snprintf(info->note, sizeof(info->note), "could not reach %s", IANA_WHOIS_SERVER);
        return;
    }

    /* IANA no longer lists a server for some TLDs whose registry still runs
     * one under the whois.nic.<tld> convention (.uk, for example). */
    if (found == 0)
    {
        snprintf(info->server, sizeof(info->server), "whois.nic.%s", tld);
    }

    char *response = whois_query(info->server, domain);

    if (response == NULL)
    {
        if (found == 0)
        {
            snprintf(info->note, sizeof(info->note),
                     "no WHOIS server published for .%s, and %s did not answer (the registry may offer RDAP only)",
                     tld, info->server);
        }
        else
        {
            snprintf(info->note, sizeof(info->note), "no answer from %s", info->server);
        }

        return;
    }

    info->status = LOOKUP_OK;
    info->raw = response;
    info->registered = !contains_any(response, not_found_markers);

    if (!info->registered)
    {
        return;
    }

    extract_first(response, registrar_fields, info->registrar, sizeof(info->registrar));
    extract_first(response, created_fields, info->created, sizeof(info->created));
    extract_first(response, updated_fields, info->updated, sizeof(info->updated));
    extract_first(response, expires_fields, info->expires, sizeof(info->expires));
    extract_first(response, registrant_fields, info->registrant, sizeof(info->registrant));
    extract_first(response, country_fields, info->registrant_country, sizeof(info->registrant_country));

    info->privacy = info->registrant[0] != '\0' && contains_any(info->registrant, privacy_markers);
}
