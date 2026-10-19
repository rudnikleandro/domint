#ifndef EXPOSUREPROOF_WHOIS_H
#define EXPOSUREPROOF_WHOIS_H

#include <stddef.h>

#include "model.h"

typedef struct
{
    observation_status status;
    const char *error;
    char *data;
    size_t length;
} whois_response;

/* Sends one WHOIS query. On OBS_OK, `data` holds the raw bytes plus a
 * terminating NUL and must be freed; otherwise `error` says why. */
whois_response whois_query(const char *server, const char *query);

/* whois_query() on a port other than 43; used by the tests. */
whois_response whois_query_port(const char *server, const char *port, const char *query);

/* Asks IANA for the TLD's server and that server for the registration of
 * `domain` (a registrable domain such as example.com), recording both. */
void whois_collect(const char *domain, observation_list *observations);

/* Builds `info` from the observations recorded by whois_collect(). */
void whois_interpret(const char *domain, const observation_list *observations, whois_info *info);

/* Fills the registration fields of `info` from a registry's response text.
 * Network-free, so it can be tested against saved responses. */
void whois_parse(const char *response, whois_info *info);

#endif
