#ifndef EXPOSUREPROOF_DNS_H
#define EXPOSUREPROOF_DNS_H

#include <netinet/in.h>
#include <stddef.h>

#include "model.h"

#define DNS_COLLECTOR "dns"
#define DNS_CONFIG_COLLECTOR "dns-config"

/* Queries NS, MX, TXT, SOA, CAA and DMARC records, recording each raw
 * answer. `custom_resolver` is NULL to use the system nameservers. */
void dns_collect(const char *domain, const char *org_domain, const struct in_addr *custom_resolver,
                 observation_list *observations);

/* Builds `info` from the recorded answers. */
void dns_interpret(const char *domain, const char *org_domain, const observation_list *observations, dns_info *info);

/* Reads the answer records of `type` from a raw DNS response into `values`
 * (SOA fields go into `info`). Returns how many matched, or -1 when the
 * packet is malformed. */
int dns_parse_answer(const unsigned char *packet, size_t length, int type, string_list *values, dns_info *info);

/* MX entries are stored as "<priority> <host>"; these split them. */
unsigned mx_priority(const char *entry);
const char *mx_host(const char *entry);

/* A "null MX" (host ".") declares that the domain accepts no mail. */
int mx_is_null(const char *entry);

#define EDNS0_OPT_SIZE 11

/* Appends an EDNS0 OPT record to a DNS query and bumps its additional-record
 * count. Returns the new length, or -1 when it does not fit. */
int dns_append_edns0(unsigned char *query, int query_len, int capacity);

#endif
