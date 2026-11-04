#ifndef DOMINT_PROVIDERS_H
#define DOMINT_PROVIDERS_H

#include <stddef.h>

/* Provider names for well-known hosts, or NULL. */
const char *dns_provider_name(const char *nameserver);
const char *mail_provider_name(const char *mail_host);

/* CDN/proxy and cloud provider names for an AS name, or NULL. */
const char *proxy_provider_name(const char *as_name);
const char *cloud_provider_name(const char *as_name);

/* True for TXT records that prove control of the domain to a third-party
 * service (google-site-verification=..., MS=..., and so on). */
int is_verification_token(const char *txt);

/* The service a verification token belongs to ("google", "microsoft"),
 * written to `out`. Returns 1 when the token names one. */
int service_from_token(const char *txt, char *out, size_t size);

#endif
