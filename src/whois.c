#include "whois.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include "model.h"
#include "util.h"
#include "net.h"

#define WHOIS_PORT "43"
#define IANA_WHOIS_SERVER "whois.iana.org"
#define TLD_CACHE_SIZE 64

/* Real WHOIS answers are a few kilobytes. */
#define WHOIS_MAX_RESPONSE (256 * 1024)
#define WHOIS_MAX_RESPONSE_TEXT "256 KiB"

#define WHOIS_COLLECTOR "whois"
#define WHOIS_IANA_COLLECTOR "whois-iana"
#define WHOIS_CACHED_DETAIL "answer reused from an earlier query in this run"

typedef struct
{
    char tld[64];
    observation original;
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

static whois_response failure(observation_status status, const char *error)
{
    whois_response response = {status, error, NULL, 0};
    return response;
}

whois_response whois_query(const char *server, const char *query)
{
    return whois_query_port(server, WHOIS_PORT, query);
}

/* WHOIS has no length header, so the response is read until the server
 * closes the connection; the size limit keeps a hostile server from
 * exhausting memory. The bytes are returned untouched, as evidence. */
whois_response whois_query_port(const char *server, const char *port, const char *query)
{
    int sockfd = connect_to_host(server, port);

    if (sockfd == -1)
    {
        return failure(OBS_NO_RESPONSE, "connection failed");
    }

    char request[256];
    snprintf(request, sizeof(request), "%s\r\n", query);

    if (send(sockfd, request, strlen(request), 0) == -1)
    {
        close(sockfd);
        return failure(OBS_NO_RESPONSE, "could not send the query");
    }

    size_t capacity = 8192;
    size_t total = 0;
    char *buffer = malloc(capacity);

    if (buffer == NULL)
    {
        close(sockfd);
        return failure(OBS_ERROR, "out of memory");
    }

    ssize_t bytes_received;

    while ((bytes_received = recv(sockfd, buffer + total, capacity - total - 1, 0)) > 0)
    {
        total += (size_t)bytes_received;

        if (total > WHOIS_MAX_RESPONSE)
        {
            free(buffer);
            close(sockfd);
            return failure(OBS_LIMITED, "response larger than " WHOIS_MAX_RESPONSE_TEXT);
        }

        if (total >= capacity - 1)
        {
            capacity *= 2;
            char *new_buffer = realloc(buffer, capacity);

            if (new_buffer == NULL)
            {
                free(buffer);
                close(sockfd);
                return failure(OBS_ERROR, "out of memory");
            }

            buffer = new_buffer;
        }
    }

    close(sockfd);

    /* An empty answer is not a record: without this it would parse as a
     * registered domain with no fields. */
    if (total == 0)
    {
        free(buffer);
        return bytes_received == -1 ? failure(OBS_NO_RESPONSE, "no response before the timeout")
                                    : failure(OBS_EMPTY, "empty response");
    }

    buffer[total] = '\0';

    whois_response response = {OBS_OK, NULL, buffer, total};
    return response;
}

/* Records the exchange, then makes the text safe to parse and print. */
static char *record_and_sanitize(observation_list *observations, const char *collector, const char *server,
                                 const char *query, whois_response *response)
{
    char source[FIELD_SIZE];
    snprintf(source, sizeof(source), "%s:%s", server, WHOIS_PORT);

    record_observation(observations, collector, source, query, response->status, response->error, response->data,
                       response->length);

    if (response->data != NULL)
    {
        sanitize_text(response->data, response->length, 1);
    }

    return response->data;
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
 * IANA lists none and -1 when IANA could not be reached (`*error` says why). */
/* The WHOIS server IANA lists for a TLD, from its (sanitized) answer. */
static void iana_server(const char *iana_answer, char *server, size_t size)
{
    /* gTLDs use "whois:"; some ccTLDs use "refer:" instead. */
    static const char *const fields[] = {"whois:", "refer:", NULL};
    extract_first(iana_answer, fields, server, size);
}

static const char *tld_of(const char *domain)
{
    const char *dot = strrchr(domain, '.');
    return dot != NULL ? dot + 1 : domain;
}

/* Asks IANA which server handles the TLD, reusing an earlier answer from
 * this run when there is one. Either way the answer is recorded for this
 * domain, so its evidence is complete on its own. Returns 1 when a server
 * is listed, 0 when none is and -1 when IANA could not be asked. */
static int find_whois_server(const char *tld, char *server, size_t size, observation_list *observations)
{
    for (size_t i = 0; i < tld_cache_count; i++)
    {
        if (strcmp(tld_cache[i].tld, tld) == 0)
        {
            const observation *original = &tld_cache[i].original;
            observation *cached = record_observation(observations, WHOIS_IANA_COLLECTOR, original->source, tld, OBS_OK,
                                                     WHOIS_CACHED_DETAIL, original->content, original->content_length);
            char *answer = observation_text(cached);

            /* The answer keeps the time it was actually received. */
            snprintf(cached->collected_at, sizeof(cached->collected_at), "%s", original->collected_at);
            iana_server(answer, server, size);
            free(answer);
            return server[0] != '\0';
        }
    }

    whois_response response = whois_query(IANA_WHOIS_SERVER, tld);
    char *answer = record_and_sanitize(observations, WHOIS_IANA_COLLECTOR, IANA_WHOIS_SERVER, tld, &response);

    if (answer == NULL)
    {
        return -1;
    }

    iana_server(answer, server, size);
    free(answer);

    if (tld_cache_count < TLD_CACHE_SIZE)
    {
        /* Keep the raw bytes, not the sanitized text, so the reused
         * observation shows exactly what IANA sent. */
        const observation *recorded = &observations->items[observations->count - 1];
        tld_entry *entry = &tld_cache[tld_cache_count];
        tld_cache_count++;

        snprintf(entry->tld, sizeof(entry->tld), "%s", tld);
        entry->original = *recorded;
        entry->original.content = xcalloc(recorded->content_length + 1, 1);
        memcpy(entry->original.content, recorded->content, recorded->content_length);
    }

    return server[0] != '\0';
}

void whois_collect(const char *domain, observation_list *observations)
{
    const char *tld = tld_of(domain);
    char server[FIELD_SIZE] = "";
    int found = find_whois_server(tld, server, sizeof(server), observations);

    if (found < 0)
    {
        record_observation(observations, WHOIS_COLLECTOR, "", domain, OBS_NOT_QUERIED,
                           "the registry's server is unknown because " IANA_WHOIS_SERVER " gave no usable answer", NULL, 0);
        return;
    }

    /* IANA no longer lists a server for some TLDs whose registry still runs
     * one under the whois.nic.<tld> convention (.uk, for example). */
    if (found == 0)
    {
        snprintf(server, sizeof(server), "whois.nic.%s", tld);
    }

    whois_response response = whois_query(server, domain);
    free(record_and_sanitize(observations, WHOIS_COLLECTOR, server, domain, &response));
}

void whois_interpret(const char *domain, const observation_list *observations, whois_info *info)
{
    const char *tld = tld_of(domain);
    const observation *iana = find_observation(observations, WHOIS_IANA_COLLECTOR, tld);
    const observation *registry = find_observation(observations, WHOIS_COLLECTOR, domain);

    snprintf(info->queried, sizeof(info->queried), "%s", domain);
    info->status = LOOKUP_FAILED;
    info->iana_queried = iana != NULL && strcmp(iana->detail, WHOIS_CACHED_DETAIL) != 0;

    if (registry == NULL)
    {
        snprintf(info->note, sizeof(info->note), "not collected");
        return;
    }

    if (registry->status == OBS_NOT_QUERIED)
    {
        snprintf(info->note, sizeof(info->note), "%s", registry->detail);
        return;
    }

    /* The source is "server:43"; the report shows just the server. */
    snprintf(info->server, sizeof(info->server), "%.*s", (int)strcspn(registry->source, ":"), registry->source);

    if (registry->status != OBS_OK)
    {
        char listed[FIELD_SIZE] = "";

        if (iana != NULL && iana->status == OBS_OK)
        {
            char *answer = observation_text(iana);
            iana_server(answer, listed, sizeof(listed));
            free(answer);
        }

        if (iana != NULL && listed[0] == '\0')
        {
            snprintf(info->note, sizeof(info->note),
                     "IANA lists no WHOIS server for .%s, and %s gave no usable answer (%s); the registry may offer RDAP only",
                     tld, info->server, registry->detail);
        }
        else
        {
            snprintf(info->note, sizeof(info->note), "no usable answer from %s: %s", info->server, registry->detail);
        }

        return;
    }

    info->status = LOOKUP_OK;
    info->raw = observation_text(registry);
    whois_parse(info->raw, info);
}

void whois_parse(const char *response, whois_info *info)
{
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
