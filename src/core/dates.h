#ifndef DOMINT_DATES_H
#define DOMINT_DATES_H

#include <stddef.h>
#include <time.h>

/* Parses the date formats registries use (2001-10-02T..., 02-Oct-2001,
 * 20011002, ...). Returns 0 on success. */
int parse_whois_date(const char *text, time_t *out);

/* Writes a WHOIS date as YYYY-MM-DD, or the original text when unparseable. */
void whois_date(const char *text, char *out, size_t size);

/* "12 days", "5 months", "25 years". */
void describe_age(long days, char *out, size_t size);

#endif
