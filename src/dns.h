#ifndef EXPOSUREPROOF_DNS_H
#define EXPOSUREPROOF_DNS_H

#include <netinet/in.h>

#include "model.h"

/* Collects NS, MX, TXT, SOA, CAA and DMARC records. `custom_resolver` is
 * NULL to use the system nameservers. */
void dns_collect(const char *domain, const char *org_domain, const struct in_addr *custom_resolver, dns_info *info);

/* MX entries are stored as "<priority> <host>"; these split them. */
unsigned mx_priority(const char *entry);
const char *mx_host(const char *entry);

/* A "null MX" (host ".") declares that the domain accepts no mail. */
int mx_is_null(const char *entry);

#endif
