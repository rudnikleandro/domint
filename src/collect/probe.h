#ifndef DOMINT_PROBE_H
#define DOMINT_PROBE_H

#include "core/model.h"

/* Probes up to 100 subdomains, the likeliest to matter first (www, mail,
 * remote access, admin and test names), over HTTPS, then HTTP for those
 * that did not answer, several at a time. Each attempt is recorded as an
 * observation and its result (status code, IP address, Server, Location,
 * title) filled into `subdomains`. Skips probing if passive mode or
 * no_probe is set. */
void subdomain_probe(subdomain_list *subdomains, int passive, int no_probe,
                     observation_list *observations, const char *domain);

/* Fills the probe results of `subdomains` (sorted by name) from the
 * recorded attempts: the first answer wins, HTTPS being recorded before
 * HTTP; otherwise the last failure is kept. */
void subdomain_apply_probes(const observation_list *observations, subdomain_list *subdomains);

#endif
