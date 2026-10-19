#ifndef EXPOSUREPROOF_PIPELINE_H
#define EXPOSUREPROOF_PIPELINE_H

#include <netinet/in.h>

#include "model.h"

/* Runs every lookup for `report->name`, appending each exchange to
 * `report->observations`. In passive mode the target is never contacted. */
void collect_domain(domain_report *report, int passive, const struct in_addr *custom_resolver);

/* Builds the report (addresses, DNS, WHOIS, HTTP, signals) from
 * `report->observations` alone, so everything shown can be traced back to a
 * recorded answer. Call once per report, after collect_domain(). */
void interpret_domain(domain_report *report);

#endif
