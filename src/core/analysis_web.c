/* Signals about the web server and its TLS certificate. */

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "collect/tls.h"
#include "core/analysis_internal.h"
#include "support/domain.h"

void analyze_web(domain_report *report)
{
    const http_info *http = &report->http;

    if (http->status != LOOKUP_OK)
    {
        return;
    }

    const char *slash = strchr(http->server, '/');

    if (slash != NULL && isdigit((unsigned char)slash[1]))
    {
        add_finding(
            report, SEVERITY_LOW,
            "The web server announces its version (%s), which makes it easy to match against known vulnerabilities.",
            http->server);
    }

    char host[DOMAIN_SIZE];
    char host_org[DOMAIN_SIZE];

    if (http->location[0] != '\0' && normalize_domain(http->location, host, sizeof(host)) == 0)
    {
        organizational_domain(host, host_org, sizeof(host_org));

        if (strcmp(host_org, report->org_domain) != 0)
        {
            add_finding(report, SEVERITY_INFO, "Redirects to another domain: %s.", host);
        }
    }
}

void analyze_tls(domain_report *report, time_t now)
{
    const tls_info *tls = &report->tls;
    time_t until;

    if (tls->status != LOOKUP_OK)
    {
        return;
    }

    int dated = tls_parse_time(tls->valid_until, &until) == 0;
    long days_left = dated ? (long)((until - now) / SECONDS_PER_DAY) : 0;

    if (dated && until < now)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "The TLS certificate expired %ld day%s ago (%s); visitors get a warning, which often means the "
                    "site is no longer maintained.",
                    -days_left, days_left == -1 ? "" : "s", tls->valid_until);
    }
    else if (!tls->trusted)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "The TLS certificate is not trusted (%s): self-signed, wrong name or incomplete chain.",
                    tls->trust_error);
    }
    else if (dated && days_left <= CERTIFICATE_WARNING_DAYS)
    {
        add_finding(report, SEVERITY_LOW, "The TLS certificate expires in %ld day%s (%s).", days_left,
                    days_left == 1 ? "" : "s", tls->valid_until);
    }
}

/* Other registrable domains on the certificate share an owner or a
 * hosting account with this one: a pivot to related infrastructure. */
void analyze_certificate_names(domain_report *report)
{
    string_list others = {0};

    for (size_t i = 0; i < report->tls.names.count; i++)
    {
        const char *name = report->tls.names.items[i];
        char org[DOMAIN_SIZE];

        organizational_domain(name[0] == '*' && name[1] == '.' ? name + 2 : name, org, sizeof(org));

        if (strcasecmp(org, report->org_domain) != 0)
        {
            string_list_add_unique(&others, org);
        }
    }

    if (others.count > 0)
    {
        char list[400] = "";

        for (size_t i = 0; i < others.count; i++)
        {
            if (strlen(list) + strlen(others.items[i]) + 6 >= sizeof(list))
            {
                strncat(list, ", ...", sizeof(list) - strlen(list) - 1);
                break;
            }

            if (i > 0)
            {
                strncat(list, ", ", sizeof(list) - strlen(list) - 1);
            }

            strncat(list, others.items[i], sizeof(list) - strlen(list) - 1);
        }

        add_finding(report, SEVERITY_INFO,
                    "The TLS certificate also covers %zu other domain%s, a lead to related "
                    "infrastructure: %s.",
                    others.count, others.count == 1 ? "" : "s", list);
    }

    string_list_free(&others);
}
