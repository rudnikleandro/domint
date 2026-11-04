#ifndef DOMINT_SUBDOMAIN_H
#define DOMINT_SUBDOMAIN_H

#include <stddef.h>

#include "core/model.h"

#define SUBDOMAIN_COLLECTOR "subdomain"
#define SUBDOMAIN_PROBE_COLLECTOR "subdomain-probe"

/* Queries passive OSINT sources (Certificate Transparency logs on crt.sh,
 * AlienVault OTX passive DNS, and HackerTarget host search) for subdomains
 * without sending traffic to the target domain or its authoritative servers.
 * The names found are added to `found` (sorted, no repeats) for probing. */
void subdomain_collect(const char *domain, observation_list *observations, subdomain_list *found);

/* Rebuilds `subdomains` from the observations alone: the valid subdomains
 * of `domain`, sorted and deduplicated, with the recorded probe results. */
void subdomain_interpret(const char *domain, const observation_list *observations,
                         subdomain_list *subdomains, lookup_status *status);

/* The date (YYYY-MM-DD) of the earliest certificate crt.sh lists for
 * `domain`, or "" when crt.sh did not answer. */
void subdomain_ct_first_seen(const observation_list *observations, const char *domain, char *out, size_t size);


/* Parsing helpers exposed for testing */
int subdomain_parse_crtsh(const char *json_text, size_t length, const char *target_domain, subdomain_list *subdomains);
int subdomain_parse_otx(const char *json_text, size_t length, const char *target_domain, subdomain_list *subdomains);
int subdomain_parse_hackertarget(const char *text, const char *target_domain, subdomain_list *subdomains);

#endif
