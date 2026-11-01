#ifndef DOMINT_SUBDOMAIN_H
#define DOMINT_SUBDOMAIN_H

#include <stddef.h>

#include "model.h"

#define SUBDOMAIN_COLLECTOR "subdomain"
#define SUBDOMAIN_PROBE_COLLECTOR "subdomain-probe"

/* Queries passive OSINT sources (Certificate Transparency logs on crt.sh,
 * AlienVault OTX passive DNS, and HackerTarget host search) for subdomains
 * without sending traffic to the target domain or its authoritative servers. */
void subdomain_collect(const char *domain, observation_list *observations);

/* Extracts, deduplicates, and sorts valid subdomains of `domain` from observations. */
void subdomain_interpret(const char *domain, const observation_list *observations,
                         subdomain_list *subdomains, lookup_status *status);

/* Probes discovered subdomains over HTTPS/HTTP to determine liveness, status codes
 * (200 OK, 403 Forbidden, 301/302 Redirect, etc.), IP address, and server banner.
 * Skips probing if passive mode or no_probe is set. */
void subdomain_probe(subdomain_list *subdomains, int passive, int no_probe,
                     observation_list *observations, const char *domain);

/* Parsing helpers exposed for testing */
int subdomain_parse_crtsh(const char *json_text, size_t length, const char *target_domain, subdomain_list *subdomains);
int subdomain_parse_otx(const char *json_text, size_t length, const char *target_domain, subdomain_list *subdomains);
int subdomain_parse_hackertarget(const char *text, const char *target_domain, subdomain_list *subdomains);

#endif
