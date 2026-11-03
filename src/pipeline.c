#include "pipeline.h"

#include "analysis.h"
#include "asn.h"
#include "dns.h"
#include "domain.h"
#include "model.h"
#include "http.h"
#include "progress.h"
#include "rdap.h"
#include "resolve.h"
#include "subdomain.h"
#include "tls.h"
#include "whois.h"

void collect_domain(domain_report *report, int passive, int no_subdomains, int no_probe, const struct in_addr *custom_resolver)
{
    observation_list *observations = &report->observations;

    organizational_domain(report->name, report->org_domain, sizeof(report->org_domain));

    /* The addresses decide which ASN and HTTP lookups follow. */
    progress_step("resolving addresses");
    resolve_collect(report->name, observations);
    resolve_interpret(observations, report);

    progress_step("network lookup (ASN)");

    for (size_t i = 0; i < report->address_count; i++)
    {
        asn_collect(report->addresses[i].ip, observations);
    }

    progress_step(passive ? "HTTP and TLS skipped (--passive)" : "HTTP and TLS");

    if (passive)
    {
        record_observation(observations, HTTP_COLLECTOR, "target", report->name, OBS_NOT_QUERIED,
                           "--passive: the target is not contacted", NULL, 0);
        record_observation(observations, TLS_COLLECTOR, "target", report->name, OBS_NOT_QUERIED,
                           "--passive: the target is not contacted", NULL, 0);
    }
    else
    {
        http_collect(report->name, report->addresses, report->address_count, observations);
        tls_collect(report->name, report->addresses, report->address_count, observations);
    }

    progress_step("DNS records");
    dns_collect(report->name, report->org_domain, custom_resolver, observations);

    /* RDAP gives structured data; WHOIS covers registries without it. */
    progress_step("registration (RDAP/WHOIS)");

    if (!rdap_collect(report->org_domain, observations))
    {
        whois_collect(report->org_domain, observations);
    }

    if (no_subdomains)
    {
        record_observation(observations, SUBDOMAIN_COLLECTOR, "osint", report->name, OBS_NOT_QUERIED,
                           "--no-subdomains: passive subdomain scan skipped", NULL, 0);
    }
    else
    {
        /* A working list for the probes and ASN lookups; the report's own
         * list is rebuilt from the observations in interpret_domain(). */
        subdomain_list found = {0};

        subdomain_collect(report->name, observations, &found);
        progress_step("probing subdomains");
        subdomain_probe(&found, passive, no_probe, observations, report->name);
        progress_step("subdomain networks (ASN)");
        asn_collect_subdomains(&found, observations);
        subdomain_list_free(&found);
    }
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
    tls_interpret(observations, &report->tls);
    dns_interpret(report->name, report->org_domain, observations, &report->dns);

    if (rdap_interpret(report->org_domain, observations, &report->whois) != 0)
    {
        whois_interpret(report->org_domain, observations, &report->whois);
    }

    subdomain_interpret(report->name, observations, &report->subdomains, &report->subdomain_status);
    asn_interpret_subdomains(observations, &report->subdomains);

    analyze_domain(report);
}
