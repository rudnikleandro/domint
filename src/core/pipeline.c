#include "core/pipeline.h"

#include "core/analysis.h"
#include "collect/asn.h"
#include "collect/dns.h"
#include "support/domain.h"
#include "core/model.h"
#include "collect/http.h"
#include "collect/lookalike.h"
#include "support/status.h"
#include "collect/rdap.h"
#include "collect/reputation.h"
#include "collect/resolve.h"
#include "collect/subdomain.h"
#include "collect/tls.h"
#include "collect/whois.h"

/* TLS and HTTP connect to the addresses, so they need them resolved too. */
static int needs_addresses(const domain_report *report)
{
    return report_has(report, MODULE_ADDRESSES | MODULE_TLS | MODULE_HTTP);
}

size_t collect_steps(const domain_report *report)
{
    return (size_t)needs_addresses(report) + (size_t)report_has(report, MODULE_ADDRESSES) +
           (size_t)report_has(report, MODULE_TLS | MODULE_HTTP) + (size_t)report_has(report, MODULE_DNS) +
           (size_t)report_has(report, MODULE_WHOIS) + (size_t)report_has(report, MODULE_REPUTATION) +
           (size_t)report_has(report, MODULE_LOOKALIKES) +
           (report_has(report, MODULE_SUBDOMAINS) ? 6 : 0);
}

void collect_domain(domain_report *report, const collect_options *options)
{
    int passive = !options->contact_target;
    observation_list *observations = &report->observations;
    int tls = report_has(report, MODULE_TLS);
    int http = report_has(report, MODULE_HTTP);

    organizational_domain(report->name, report->org_domain, sizeof(report->org_domain));

    /* The addresses decide which ASN, HTTP and TLS lookups follow. */
    if (needs_addresses(report))
    {
        status_step("resolving addresses");
        resolve_collect(report->name, observations);
        resolve_interpret(observations, report);
    }

    if (report_has(report, MODULE_ADDRESSES))
    {
        status_step("network lookup (ASN)");

        for (size_t i = 0; i < report->address_count; i++)
        {
            asn_collect(report->addresses[i].ip, observations);
        }
    }

    if (tls || http)
    {
        status_step(passive ? "HTTP and TLS skipped (passive)" : tls && http ? "HTTP and TLS" : tls ? "TLS" : "HTTP");

        if (passive)
        {
            if (http)
            {
                record_observation(observations, HTTP_COLLECTOR, "target", report->name, OBS_NOT_QUERIED,
                                   "passive mode: the target is not contacted (--active to reach it)", NULL, 0);
            }

            if (tls)
            {
                record_observation(observations, TLS_COLLECTOR, "target", report->name, OBS_NOT_QUERIED,
                                   "passive mode: the target is not contacted (--active to reach it)", NULL, 0);
            }
        }
        else
        {
            if (http)
            {
                http_collect(report->name, report->addresses, report->address_count, observations);
            }

            if (tls)
            {
                tls_collect(report->name, report->addresses, report->address_count, observations);
            }
        }
    }

    if (report_has(report, MODULE_DNS))
    {
        status_step("DNS records");
        dns_collect(report->name, report->org_domain, options->resolver, observations);
    }

    /* RDAP gives structured data; WHOIS covers registries without it. */
    if (report_has(report, MODULE_WHOIS))
    {
        status_step("registration (RDAP/WHOIS)");

        if (!rdap_collect(report->org_domain, observations))
        {
            whois_collect(report->org_domain, observations);
        }
    }

    if (report_has(report, MODULE_REPUTATION))
    {
        status_step("reputation (OTX, abuse.ch)");
        reputation_collect(report->name, observations);
    }

    if (report_has(report, MODULE_LOOKALIKES))
    {
        status_step("lookalike domains");
        lookalike_collect(report->name, options->resolver, observations);
    }

    if (report_has(report, MODULE_SUBDOMAINS))
    {
        /* A working list for the probes and ASN lookups; the report's own
         * list is rebuilt from the observations in interpret_domain(). */
        subdomain_list found = {0};

        subdomain_collect(report->name, observations, &found);
        status_step("subdomain aliases (CNAME)");
        dns_collect_cnames(&found, options->resolver, observations);
        status_step("probing subdomains");
        subdomain_probe(&found, !options->probe_subdomains, options->no_probe, observations, report->name);
        status_step("subdomain networks (ASN)");
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
    dns_interpret_cnames(observations, &report->subdomains);
    asn_interpret_subdomains(observations, &report->subdomains);
    subdomain_ct_first_seen(observations, report->name, report->ct_first_seen, sizeof(report->ct_first_seen));
    reputation_interpret(observations, report->name, &report->reputation);
    lookalike_interpret(report->name, observations, &report->lookalikes);

    analyze_domain(report);
}
