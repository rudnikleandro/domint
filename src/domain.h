#ifndef EXPOSUREPROOF_DOMAIN_H
#define EXPOSUREPROOF_DOMAIN_H

#include <stddef.h>

#define DOMAIN_INVALID (-1)
#define DOMAIN_IS_IP (-2)

/* Turns user input (URL, defanged IOC, mixed case) into a bare lowercase
 * domain name. Returns 0, DOMAIN_INVALID or DOMAIN_IS_IP. */
int normalize_domain(const char *input, char *out, size_t out_size);

/* The registrable part of a name: www.example.co.uk -> example.co.uk. */
void organizational_domain(const char *domain, char *out, size_t out_size);

#endif
