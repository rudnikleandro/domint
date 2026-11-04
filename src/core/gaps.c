#include "core/gaps.h"

#include <stdio.h>
#include <string.h>

#include "collect/asn.h"
#include "collect/dns.h"
#include "collect/lookalike.h"
#include "collect/reputation.h"
#include "collect/subdomain.h"
#include "core/model.h"

static const char *const labels[GAP_COUNT] = {
    "addresses", "network (ASN)", "DNS", "registration", "reputation", "subdomains", "aliases (CNAME)", "lookalikes"};
static const char *const impacts[GAP_COUNT] = {NULL,
                                               "hosting unknown",
                                               "those records are missing",
                                               NULL,
                                               "a listing may be missed",
                                               "the list may be incomplete",
                                               "takeover checks are incomplete",
                                               "some variants went unchecked"};

const char *gap_label(gap_area area)
{
    return labels[area];
}

const char *gap_impact(gap_area area)
{
    return impacts[area];
}

static int is_failure(observation_status status)
{
    return status == OBS_NO_RESPONSE || status == OBS_LIMITED || status == OBS_ERROR;
}

int is_target_address(const domain_report *report, const char *ip)
{
    for (size_t i = 0; i < report->address_count; i++)
    {
        if (strcmp(report->addresses[i].ip, ip) == 0)
        {
            return 1;
        }
    }

    return 0;
}

int gap_area_of(const domain_report *report, const observation *item)
{
    if (!is_failure(item->status))
    {
        return -1;
    }

    if (strcmp(item->collector, "resolve") == 0)
    {
        return GAP_ADDRESSES;
    }

    if (strcmp(item->collector, ASN_COLLECTOR) == 0)
    {
        return is_target_address(report, item->query) ? GAP_NETWORK : -1;
    }

    if (strcmp(item->collector, DNS_COLLECTOR) == 0 && strncmp(item->query, "A ", 2) == 0)
    {
        return GAP_ALIASES;
    }

    if (strcmp(item->collector, DNS_COLLECTOR) == 0 || strcmp(item->collector, DNS_CONFIG_COLLECTOR) == 0)
    {
        return GAP_DNS;
    }

    if (strncmp(item->collector, "rdap", 4) == 0 || strncmp(item->collector, "whois", 5) == 0)
    {
        return report->whois.status == LOOKUP_OK ? -1 : GAP_REGISTRATION;
    }

    if (strcmp(item->collector, REPUTATION_COLLECTOR) == 0)
    {
        return GAP_REPUTATION;
    }

    if (strcmp(item->collector, SUBDOMAIN_COLLECTOR) == 0)
    {
        return GAP_SUBDOMAINS;
    }

    /* Only the summary: one unanswered variant among a thousand is noise. */
    if (strcmp(item->collector, LOOKALIKE_COLLECTOR) == 0 && strchr(item->query, ' ') == NULL)
    {
        return GAP_LOOKALIKES;
    }

    return -1;
}

void gap_describe(const observation *item, gap_area area, char *what, size_t what_size, char *why, size_t why_size)
{
    const char *asked = item->source;

    if (area == GAP_DNS || area == GAP_NETWORK)
    {
        asked = item->query;
    }
    else if (area == GAP_ALIASES)
    {
        asked = item->query + strlen("A ");
    }
    else if (area == GAP_ADDRESSES)
    {
        asked = "system resolver";
    }

    if (area == GAP_LOOKALIKES)
    {
        asked = item->detail;
    }

    snprintf(what, what_size, "%s", asked);
    snprintf(why, why_size, "%s",
             strncmp(item->detail, "HTTP ", 5) == 0 ? item->detail
             : item->status == OBS_NO_RESPONSE      ? "no response"
             : item->status == OBS_LIMITED          ? "response too large"
                                                    : "error");
}
