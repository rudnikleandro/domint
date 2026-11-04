#ifndef DOMINT_ANALYSIS_INTERNAL_H
#define DOMINT_ANALYSIS_INTERNAL_H

/* Shared by the analysis_*.c files; not part of the public API, which is
 * core/analysis.h. */

#include <time.h>

#include "core/model.h"

#define SECONDS_PER_DAY 86400
#define NEW_DOMAIN_DAYS 30
#define YOUNG_DOMAIN_DAYS 180
#define EXPIRY_WARNING_DAYS 30
#define EXPIRY_IMMINENT_DAYS 7
#define CERTIFICATE_WARNING_DAYS 14
#define TXT_COPY_SIZE 2048

/* Appends a signal to the report, or drops the least severe one to make
 * room for it when the list is full. */
void add_finding(domain_report *report, severity level, const char *format, ...) __attribute__((format(printf, 3, 4)));

/* One per area; each adds its signals to the report. */
void analyze_registration(domain_report *report, time_t now);
void analyze_addresses(domain_report *report);
void analyze_dns(domain_report *report);
void analyze_email(domain_report *report);
void analyze_web(domain_report *report);
void analyze_tls(domain_report *report, time_t now);
void analyze_certificate_names(domain_report *report);
void analyze_subdomains(domain_report *report);
void analyze_ct(domain_report *report, time_t now);
void analyze_reputation(domain_report *report);
void analyze_lookalikes(domain_report *report);

#endif
