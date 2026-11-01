#ifndef EXPOSUREPROOF_RDAP_H
#define EXPOSUREPROOF_RDAP_H

#include <stddef.h>

#include "model.h"

#define RDAP_COLLECTOR "rdap"

/* Looks up `domain` (a registrable domain) over RDAP, directly at the
 * registry that IANA's bootstrap file lists for its TLD. Returns 1 when the
 * registry gave a usable answer (a record, or "no such domain"), 0 when the
 * caller should fall back to WHOIS. */
int rdap_collect(const char *domain, observation_list *observations);

/* Fills `info` from the recorded RDAP answer. Returns 0, or -1 when there
 * is no usable RDAP observation for `domain`. */
int rdap_interpret(const char *domain, const observation_list *observations, whois_info *info);

/* Reads a domain object (RFC 9083) into `info`. Returns 0, or -1 when the
 * text is not a JSON object. Network-free, for tests. */
int rdap_parse(const char *text, size_t length, whois_info *info);

/* The RDAP base URL IANA's bootstrap document lists for `tld` (an https://
 * URL), written into `out`. Returns 1 when found, 0 when none, -1 when the
 * document is invalid. Network-free, for tests. */
int rdap_find_service(const char *bootstrap, size_t length, const char *tld, char *out, size_t size);

#endif
