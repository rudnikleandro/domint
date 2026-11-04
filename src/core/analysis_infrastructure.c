/* Signals about registration, addresses and DNS hygiene. */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/analysis_internal.h"
#include "core/dates.h"
#include "core/providers.h"
#include "support/util.h"

/* Different CDNs seen among one domain's addresses, at most. */
#define MAX_PROXIES 8

void analyze_registration(domain_report *report, time_t now)
{
    const whois_info *whois = &report->whois;

    if (whois->status != LOOKUP_OK)
    {
        add_finding(report, SEVERITY_INFO, "Registration data unavailable: %s.", whois->note);
        return;
    }

    if (!whois->registered)
    {
        if (report->resolve_status == LOOKUP_OK)
        {
            add_finding(report, SEVERITY_MEDIUM, "The registry has no record of %s, yet the name resolves.", whois->queried);
        }
        else
        {
            add_finding(report, SEVERITY_INFO, "Not registered: the registry has no record of %s.", whois->queried);
        }

        return;
    }

    time_t created;
    char date[16];

    if (parse_whois_date(whois->created, &created) == 0)
    {
        report->age_days = (long)((now - created) / SECONDS_PER_DAY);
        whois_date(whois->created, date, sizeof(date));

        if (report->age_days < NEW_DOMAIN_DAYS)
        {
            add_finding(report, SEVERITY_HIGH,
                        "Registered %ld days ago (%s). Newly registered domains are a common phishing and malware indicator.",
                        report->age_days, date);
        }
        else if (report->age_days < YOUNG_DOMAIN_DAYS)
        {
            add_finding(report, SEVERITY_MEDIUM, "Registered %ld days ago (%s): a young domain.", report->age_days, date);
        }
    }

    time_t expires;

    if (parse_whois_date(whois->expires, &expires) == 0)
    {
        long days_left = (long)((expires - now) / SECONDS_PER_DAY);
        whois_date(whois->expires, date, sizeof(date));

        /* Renewing in the last weeks is routine, and registries hold an
         * expired name for a grace period before releasing it, so only an
         * imminent or past expiry is more than something to watch. */
        if (expires < now)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "The registration expired on %s. Once the registry's grace period ends, the name can be registered by anyone.",
                        date);
        }
        else if (days_left <= EXPIRY_IMMINENT_DAYS)
        {
            add_finding(report, SEVERITY_LOW,
                        "The registration expires in %ld day%s (%s) and has not been renewed yet.", days_left,
                        days_left == 1 ? "" : "s", date);
        }
        else if (days_left <= EXPIRY_WARNING_DAYS)
        {
            add_finding(report, SEVERITY_INFO,
                        "The registration expires in %ld days (%s). Renewal often happens close to the date; worth checking again later.",
                        days_left, date);
        }
    }

    /* Status codes are written "clientHold" in EPP/WHOIS and "client hold"
     * in RDAP; compare them without spaces or case. */
    for (size_t i = 0; i < whois->statuses.count; i++)
    {
        const char *status = whois->statuses.items[i];
        char compact[FIELD_SIZE];
        size_t length = 0;

        for (const char *c = status; *c != '\0' && length < sizeof(compact) - 1; c++)
        {
            if (*c != ' ')
            {
                compact[length++] = *c;
            }
        }

        compact[length] = '\0';

        if (strcasecmp(compact, "clientHold") == 0 || strcasecmp(compact, "serverHold") == 0)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "The registry lists the domain as \"%s\": it is withdrawn from DNS, which usually follows a "
                        "takedown, a dispute or unpaid fees.",
                        status);
        }
        else if (strcasecmp(compact, "pendingDelete") == 0 || strcasecmp(compact, "redemptionPeriod") == 0)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "The domain is being deleted (\"%s\"); it will soon be open for anyone to register.", status);
        }
    }

    if (whois->privacy)
    {
        add_finding(report, SEVERITY_INFO, "The registrant's identity is hidden behind a privacy service.");
    }
}

void analyze_addresses(domain_report *report)
{
    const char *proxies_seen[MAX_PROXIES];
    size_t proxy_count = 0;

    for (size_t i = 0; i < report->address_count; i++)
    {
        const address_info *address = &report->addresses[i];

        if (address->asn_status != LOOKUP_OK)
        {
            continue;
        }

        if (!address->announced)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "Resolves to %s, a private or unannounced address: the domain may be sinkholed, parked or exposing an internal host.",
                        address->ip);
            continue;
        }

        const char *proxy = proxy_provider_name(address->as_name);
        int seen = 0;

        for (size_t j = 0; j < proxy_count; j++)
        {
            seen |= proxies_seen[j] == proxy;
        }

        if (proxy != NULL && !seen && proxy_count < MAX_PROXIES)
        {
            proxies_seen[proxy_count] = proxy;
            proxy_count++;
            add_finding(report, SEVERITY_INFO, "Served through %s, which hides the origin server's real address.", proxy);
        }
    }

    if (report->resolve_status == LOOKUP_FAILED && report->whois.status == LOOKUP_OK && report->whois.registered)
    {
        add_finding(report, SEVERITY_INFO, "No A/AAAA records: nothing is hosted on this name (mail-only, parked or unused).");
    }
}

/* Whether the name is registered, as far as this report knows: without the
 * WHOIS module the registry was not asked, so it is taken as registered. */
static int is_registered(const domain_report *report)
{
    return !report_has(report, MODULE_WHOIS) || report->whois.registered;
}

void analyze_dns(domain_report *report)
{
    const dns_info *dns = &report->dns;

    /* CAA is inherited from parent names, so only judge it at the registrable domain. */
    if (dns->caa.status == LOOKUP_OK && dns->caa.values.count == 0 && strcmp(report->name, report->org_domain) == 0 &&
        is_registered(report))
    {
        add_finding(report, SEVERITY_INFO, "No CAA record: any certificate authority may issue certificates for this domain.");
    }

    char failed[64] = "";
    const struct
    {
        const char *name;
        lookup_status status;
    } lookups[] = {{"NS", dns->ns.status}, {"MX", dns->mx.status}, {"SOA", dns->soa_status}, {"CAA", dns->caa.status}};

    for (size_t i = 0; i < ARRAY_COUNT(lookups); i++)
    {
        if (lookups[i].status == LOOKUP_FAILED)
        {
            size_t len = strlen(failed);
            snprintf(failed + len, sizeof(failed) - len, "%s%s", len > 0 ? ", " : "", lookups[i].name);
        }
    }

    if (failed[0] != '\0')
    {
        add_finding(report, SEVERITY_INFO, "DNS lookups failed for %s; those records are missing from this report.", failed);
    }

    /* DNSSEC: DS at the parent with no DNSKEY in the zone breaks resolution
     * for validating resolvers; no DS at all just means unsigned. */
    if (dns->ds.status == LOOKUP_OK && dns->dnskey.status == LOOKUP_OK && is_registered(report))
    {
        if (dns->ds.values.count > 0 && dns->dnskey.values.count == 0)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "DNSSEC is broken: the registry publishes DS records but the zone has no DNSKEY, so validating "
                        "resolvers will refuse to resolve %s.",
                        report->org_domain);
        }
        else if (dns->ds.values.count == 0)
        {
            add_finding(report, SEVERITY_INFO,
                        "Not signed with DNSSEC: anyone able to tamper with DNS traffic can forge answers for this domain.");
        }
    }
}
