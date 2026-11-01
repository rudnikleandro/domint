#ifndef DOMINT_TLS_H
#define DOMINT_TLS_H

#include <stddef.h>
#include <time.h>

#include "model.h"

#define TLS_COLLECTOR "tls"

/* Opens a TLS connection to port 443 of the first address that answers and
 * records the server certificate as libcurl describes it. Like the HTTP
 * request, this contacts the target. */
void tls_collect(const char *host, const address_info *addresses, size_t count, observation_list *observations);

/* Fills `tls` from the recorded certificate. */
void tls_interpret(const observation_list *observations, tls_info *tls);

/* Reads libcurl's "Field:value" certificate lines. Network-free, for tests. */
void tls_parse(const char *certificate, tls_info *tls);

/* Parses a certificate date such as "Jan 12 03:54:30 2027 GMT". */
int tls_parse_time(const char *text, time_t *out);

#endif
