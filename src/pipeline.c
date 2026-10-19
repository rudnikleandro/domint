#include "pipeline.h"

#include "analysis.h"
#include "asn.h"
#include "dns.h"
#include "domain.h"
#include "model.h"
#include "http.h"
#include "resolve.h"
#include "whois.h"

void collect_domain(domain_report *report, int passive, const struct in_addr *custom_resolver)
{
    observation_list *observations = &report->observations;

    organizational_domain(report->name, report->org_domain, sizeof(report->org_domain));

    /* The addresses decide which ASN and HTTP lookups follow. */
    resolve_collect(report->name, observations);
    resolve_interpret(observations, report);

    for (size_t i = 0; i < report->address_count; i++)
    {
        asn_collect(report->addresses[i].ip, observations);
    }

    if (passive)
    {
        record_observation(observations, HTTP_COLLECTOR, "target", report->name, OBS_NOT_QUERIED,
                           "--passive: the target is not contacted", NULL, 0);
    }
    else
    {
        http_collect(report->name, report->addresses, report->address_count, observations);
    }

    dns_collect(report->name, report->org_domain, custom_resolver, observations);
    whois_collect(report->org_domain, observations);
}

void interpret_domain(domain_report *report)
{
    const observation_list *observations = &report->observations;

    organizational_domain(report->name, report->org_domain, sizeof(report->org_domain));

    resolve_interpret(observations, report);

    for (size_t i = 0; i < report->address_count; i++)
    {
        asn_interpret(observations, &report->addresses[i]);
    }

    http_interpret(observations, &report->http);
    dns_interpret(report->name, report->org_domain, observations, &report->dns);
    whois_interpret(report->org_domain, observations, &report->whois);
    analyze_domain(report);
}
