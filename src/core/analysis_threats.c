/* Signals from threat intelligence: reputation feeds and lookalike domains. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "core/analysis_internal.h"
#include "support/util.h"

static void join_list(const string_list *list, char *out, size_t size)
{
    out[0] = '\0';

    for (size_t i = 0; i < list->count; i++)
    {
        if (i > 0)
        {
            strncat(out, ", ", size - strlen(out) - 1);
        }

        strncat(out, list->items[i], size - strlen(out) - 1);
    }
}

/* Pulse titles quoted one by one: "a", "b". */
static void join_pulses(const string_list *list, char *out, size_t size)
{
    out[0] = '\0';

    for (size_t i = 0; i < list->count; i++)
    {
        if (i > 0)
        {
            strncat(out, "\", \"", size - strlen(out) - 1);
        }

        strncat(out, list->items[i], size - strlen(out) - 1);
    }
}

static int is_listed(const char *verdict)
{
    return verdict[0] != '\0' && strcasecmp(verdict, "not listed") != 0;
}

void analyze_reputation(domain_report *report)
{
    const reputation_info *rep = &report->reputation;
    char names[256];

    if (rep->threatfox_status == LOOKUP_OK && rep->threatfox_iocs > 0)
    {
        join_list(&rep->threatfox_malware, names, sizeof(names));
        add_finding(report, SEVERITY_HIGH,
                    "ThreatFox lists this domain as an indicator of compromise (%ld entr%s%s%s).", rep->threatfox_iocs,
                    rep->threatfox_iocs == 1 ? "y" : "ies", names[0] != '\0' ? ": " : "", names);
    }

    if (rep->urlhaus_status == LOOKUP_OK && rep->urlhaus_urls > 0)
    {
        join_list(&rep->urlhaus_threats, names, sizeof(names));
        add_finding(report, rep->urlhaus_online > 0 ? SEVERITY_HIGH : SEVERITY_MEDIUM,
                    "URLhaus has %ld malware URL%s on this host, %ld still online%s%s.", rep->urlhaus_urls,
                    rep->urlhaus_urls == 1 ? "" : "s", rep->urlhaus_online, names[0] != '\0' ? "; threat: " : "",
                    names);
    }

    if (rep->urlhaus_status == LOOKUP_OK && is_listed(rep->spamhaus_dbl))
    {
        add_finding(report, SEVERITY_HIGH, "Listed on the Spamhaus DBL (%s).", rep->spamhaus_dbl);
    }

    if (rep->urlhaus_status == LOOKUP_OK && is_listed(rep->surbl))
    {
        add_finding(report, SEVERITY_MEDIUM, "Listed on SURBL (%s).", rep->surbl);
    }

    /* Pulses also collect benign infrastructure that malware talks to, so
     * they are a lead to read, not a verdict; for a domain OTX itself marks
     * as known-good they are noise. */
    if (rep->otx_status == LOOKUP_OK && rep->otx_pulses > 0 && !rep->otx_allowlisted)
    {
        join_pulses(&rep->otx_pulse_names, names, sizeof(names));
        add_finding(report, SEVERITY_LOW, "Referenced in %ld AlienVault OTX pulse%s%s%s%s.", rep->otx_pulses,
                    rep->otx_pulses == 1 ? "" : "s", names[0] != '\0' ? " (e.g. \"" : "", names,
                    names[0] != '\0' ? "\")" : "");
    }
}

/* A lookalike on the domain's own nameservers or addresses was most
 * likely registered by its owner to keep it from others. */
static int shares_infrastructure(const domain_report *report, const lookalike_info *item)
{
    for (size_t i = 0; i < item->nameservers.count; i++)
    {
        if (string_list_contains(&report->dns.ns.values, item->nameservers.items[i]))
        {
            return 1;
        }
    }

    for (size_t i = 0; i < item->addresses.count; i++)
    {
        for (size_t j = 0; j < report->address_count; j++)
        {
            if (strcmp(item->addresses.items[i], report->addresses[j].ip) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}

/* Nameservers of parking and domain-sale services: a lookalike there is
 * held for resale, not set up for a campaign. */
static int is_parking(const lookalike_info *item)
{
    static const char *const markers[] = {"afternic",     "namefind",    "parklogic",   "abovedomains",  "above.com",
                                          "sedoparking",  "bodis",       "dyna-ns",     "namebrightdns", "parkingcrew",
                                          "hugedomains",  "dan.com",     "uniregistry", "fabulous.com",  "parking",
                                          "domainmarket", "undeveloped", "cashparking", "voodoo.com",    "smartname"};

    for (size_t i = 0; i < item->nameservers.count; i++)
    {
        for (size_t m = 0; m < ARRAY_COUNT(markers); m++)
        {
            if (strstr(item->nameservers.items[i], markers[m]) != NULL)
            {
                return 1;
            }
        }
    }

    return 0;
}

/* The group a registered lookalike falls in, most worrying first. */
static int lookalike_kind(const lookalike_info *item)
{
    if (item->likely_defensive)
    {
        return 4;
    }

    if (item->parked)
    {
        return 3;
    }

    return item->has_mail ? 0 : item->addresses.count > 0 ? 1 : 2;
}

#define LISTED_LOOKALIKES 6

/* "examp1e.com (homoglyph), example-login.com (phishing-word) and 4 more"
 * for the lookalikes of kind `wanted`. Returns how many there are. */
static size_t join_lookalikes(const domain_report *report, int wanted, char *out, size_t size)
{
    size_t count = 0;

    out[0] = '\0';

    for (size_t i = 0; i < report->lookalikes.count; i++)
    {
        const lookalike_info *item = &report->lookalikes.items[i];
        char entry[DOMAIN_SIZE + 40];

        if (lookalike_kind(item) != wanted)
        {
            continue;
        }

        if (count < LISTED_LOOKALIKES)
        {
            snprintf(entry, sizeof(entry), "%s%s (%s)", count > 0 ? ", " : "", item->name, item->technique);
            strncat(out, entry, size - strlen(out) - 1);
        }

        count++;
    }

    if (count > LISTED_LOOKALIKES)
    {
        char more[32];
        snprintf(more, sizeof(more), " and %zu more", count - LISTED_LOOKALIKES);
        strncat(out, more, size - strlen(out) - 1);
    }

    return count;
}

static int compare_lookalikes(const void *a, const void *b)
{
    const lookalike_info *x = a;
    const lookalike_info *y = b;
    int kind = lookalike_kind(x) - lookalike_kind(y);

    return kind != 0 ? kind : strcmp(x->name, y->name);
}

void analyze_lookalikes(domain_report *report)
{
    char names[400];
    size_t count;

    for (size_t i = 0; i < report->lookalikes.count; i++)
    {
        lookalike_info *item = &report->lookalikes.items[i];

        item->likely_defensive = shares_infrastructure(report, item);
        item->parked = is_parking(item);
    }

    /* qsort() with a NULL array is undefined even for zero items. */
    if (report->lookalikes.count > 1)
    {
        qsort(report->lookalikes.items, report->lookalikes.count, sizeof(*report->lookalikes.items),
              compare_lookalikes);
    }

    if ((count = join_lookalikes(report, 0, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "%zu lookalike domain%s can receive mail (MX), the setup used for phishing and invoice fraud: %s.",
                    count, count == 1 ? "" : "s", names);
    }

    if ((count = join_lookalikes(report, 1, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_LOW, "%zu lookalike domain%s registered and pointing to a server: %s.", count,
                    count == 1 ? " is" : "s are", names);
    }

    if ((count = join_lookalikes(report, 2, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_INFO, "%zu lookalike domain%s registered with no server or mail: %s.", count,
                    count == 1 ? " is" : "s are", names);
    }

    if ((count = join_lookalikes(report, 3, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_INFO, "%zu lookalike domain%s parked or for sale at a domain marketplace: %s.",
                    count, count == 1 ? " is" : "s are", names);
    }

    if ((count = join_lookalikes(report, 4, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_INFO,
                    "%zu lookalike domain%s the same nameservers or addresses as this one, likely registered by its "
                    "owner: %s.",
                    count, count == 1 ? " shares" : "s share", names);
    }
}
