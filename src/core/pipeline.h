#ifndef DOMINT_PIPELINE_H
#define DOMINT_PIPELINE_H

#include <netinet/in.h>

#include "core/model.h"

/* Runs the lookups of the modules in `report->modules` for `report->name`,
 * appending each exchange to `report->observations`. Only what `options`
 * allows reaches the target or its subdomains. */
typedef struct
{
    int contact_target;   /* HTTP and TLS requests to the domain itself (--active, -t, -H) */
    int probe_subdomains; /* HTTP/HTTPS requests to each subdomain (--active) */
    int no_probe;         /* --no-probe was given, to say so in the report */
    const struct in_addr *resolver; /* --resolver, or NULL for the system ones */
} collect_options;

void collect_domain(domain_report *report, const collect_options *options);

/* How many progress steps collect_domain() announces for `report->modules`. */
size_t collect_steps(const domain_report *report);

/* Builds the report (addresses, DNS, WHOIS, HTTP, signals) from
 * `report->observations` alone, so everything shown can be traced back to a
 * recorded answer. Call once per report, after collect_domain(). */
void interpret_domain(domain_report *report);

#endif
