/* Risk analysis: the summary of a report and the order of its signals.
 * Each area of analysis lives in its own analysis_*.c file. */

#include "core/analysis.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "collect/dns.h"
#include "core/analysis_internal.h"
#include "core/providers.h"
#include "support/domain.h"
#include "support/util.h"

void add_finding(domain_report *report, severity level, const char *format, ...)
{
    if (report->finding_count == MAX_FINDINGS)
    {
        /* Full: drop the latest of the least severe findings to make room,
         * so a late HIGH signal is not lost to earlier INFO entries. */
        size_t weakest = 0;

        for (size_t i = 1; i < report->finding_count; i++)
        {
            if (report->findings[i].level <= report->findings[weakest].level)
            {
                weakest = i;
            }
        }

        if (report->findings[weakest].level >= level)
        {
            return;
        }

        memmove(&report->findings[weakest], &report->findings[weakest + 1],
                (report->finding_count - weakest - 1) * sizeof(report->findings[0]));
        report->finding_count--;
    }

    finding *item = &report->findings[report->finding_count];
    report->finding_count++;
    item->level = level;

    va_list args;
    va_start(args, format);
    vsnprintf(item->text, sizeof(item->text), format, args);
    va_end(args);
}

static void summarize(domain_report *report)
{
    string_list networks = {0};

    for (size_t i = 0; i < report->address_count; i++)
    {
        const address_info *address = &report->addresses[i];

        if (address->asn_status == LOOKUP_OK && address->announced)
        {
            char label[FIELD_SIZE * 2];
            snprintf(label, sizeof(label), "AS%s %s", address->asn, address->as_name);
            string_list_add_unique(&networks, label);
        }
    }

    if (networks.count == 1)
    {
        snprintf(report->hosting, sizeof(report->hosting), "%s", networks.items[0]);
    }
    else if (networks.count > 1)
    {
        snprintf(report->hosting, sizeof(report->hosting), "%s (+%zu more)", networks.items[0], networks.count - 1);
    }

    string_list_free(&networks);

    if (report->dns.ns.values.count > 0)
    {
        const char *nameserver = report->dns.ns.values.items[0];
        const char *name = dns_provider_name(nameserver);

        if (name != NULL)
        {
            snprintf(report->dns_provider, sizeof(report->dns_provider), "%s", name);
        }
        else
        {
            organizational_domain(nameserver, report->dns_provider, sizeof(report->dns_provider));
            to_lower(report->dns_provider);
        }
    }

    /* MX entries are sorted by priority, so the first is the preferred server. */
    if (report->dns.mx.values.count > 0)
    {
        const char *entry = report->dns.mx.values.items[0];
        const char *name = mail_provider_name(mx_host(entry));

        if (mx_is_null(entry))
        {
            snprintf(report->mail_provider, sizeof(report->mail_provider), "accepts no mail (null MX)");
        }
        else if (name != NULL)
        {
            snprintf(report->mail_provider, sizeof(report->mail_provider), "%s", name);
        }
        else
        {
            organizational_domain(mx_host(entry), report->mail_provider, sizeof(report->mail_provider));
            to_lower(report->mail_provider);
        }
    }

    for (size_t i = 0; i < report->dns.txt.values.count; i++)
    {
        char service[64];

        if (service_from_token(report->dns.txt.values.items[i], service, sizeof(service)))
        {
            string_list_add_unique(&report->services, service);
        }
    }

    string_list_sort(&report->services);
}

/* Most severe first. Insertion sort because it is stable: signals of equal
 * severity keep the order they were found in, so reports are reproducible. */
static void sort_findings(domain_report *report)
{
    for (size_t i = 1; i < report->finding_count; i++)
    {
        finding current = report->findings[i];
        size_t j = i;

        while (j > 0 && report->findings[j - 1].level < current.level)
        {
            report->findings[j] = report->findings[j - 1];
            j--;
        }

        report->findings[j] = current;
    }
}

void analyze_domain(domain_report *report)
{
    time_t now = time(NULL);

    report->age_days = -1;
    summarize(report);

    /* Only the modules that ran: a lookup that was not made must not read
     * as "no records". */
    if (report_has(report, MODULE_WHOIS))
    {
        analyze_registration(report, now);
    }

    if (report_has(report, MODULE_ADDRESSES))
    {
        analyze_addresses(report);
    }

    if (report_has(report, MODULE_DNS))
    {
        analyze_email(report);
    }

    if (report_has(report, MODULE_HTTP))
    {
        analyze_web(report);
    }

    if (report_has(report, MODULE_TLS))
    {
        analyze_tls(report, now);
        analyze_certificate_names(report);
    }

    if (report_has(report, MODULE_REPUTATION))
    {
        analyze_reputation(report);
    }

    if (report_has(report, MODULE_DNS))
    {
        analyze_dns(report);
    }

    if (report_has(report, MODULE_SUBDOMAINS))
    {
        analyze_subdomains(report);
        analyze_ct(report, now);
    }

    if (report_has(report, MODULE_LOOKALIKES))
    {
        analyze_lookalikes(report);
    }

    sort_findings(report);
}
