#ifndef EXPOSUREPROOF_ANALYSIS_H
#define EXPOSUREPROOF_ANALYSIS_H

#include <stddef.h>
#include <time.h>

#include "model.h"

/* Derives the summary (hosting, providers, services) and the risk signals
 * of a report whose lookups have already run. */
void analyze_domain(domain_report *report);

/* Parses the date formats registries use (2001-10-02T..., 02-Oct-2001,
 * 20011002, ...). Returns 0 on success. */
int parse_whois_date(const char *text, time_t *out);

/* Writes a WHOIS date as YYYY-MM-DD, or the original text when unparseable. */
void whois_date(const char *text, char *out, size_t size);

/* "12 days", "5 months", "25 years". */
void describe_age(long days, char *out, size_t size);

/* Provider names for well-known hosts, or NULL. */
const char *dns_provider_name(const char *nameserver);
const char *mail_provider_name(const char *mail_host);

/* CDN/proxy and cloud provider names for an AS name, or NULL. */
const char *proxy_provider_name(const char *as_name);
const char *cloud_provider_name(const char *as_name);

/* True for TXT records that prove control of the domain to a third-party
 * service (google-site-verification=..., MS=..., and so on). */
int is_verification_token(const char *txt);

#endif
