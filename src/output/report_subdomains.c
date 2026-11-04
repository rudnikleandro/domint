/* The SUBDOMAINS section of the text report and the cross-domain list. */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "output/report_internal.h"
#include "support/domain.h"
#include "support/util.h"

/* Addresses shared by two or more online subdomains: the same server or
 * the same front end, worth knowing when mapping the infrastructure. A CDN
 * edge answering for names it has no site for says nothing, so those are
 * left out. */
static void print_shared_addresses(FILE *out, const domain_report *report)
{
    const subdomain_list *subs = &report->subdomains;
    int header = 0;

    for (size_t i = 0; i < subs->count; i++)
    {
        const subdomain_info *first = &subs->items[i];
        size_t users = 0;
        int seen = 0;

        if (subdomain_state_of(first) != SUBDOMAIN_ONLINE || first->ip[0] == '\0')
        {
            continue;
        }

        for (size_t j = 0; j < subs->count; j++)
        {
            if (subdomain_state_of(&subs->items[j]) == SUBDOMAIN_ONLINE && strcmp(subs->items[j].ip, first->ip) == 0)
            {
                seen |= j < i;
                users++;
            }
        }

        if (users < 2 || seen)
        {
            continue;
        }

        if (!header)
        {
            fprintf(out, "\n  Shared addresses:\n\n");
            header = 1;
        }

        int column;

        if (first->asn[0] != '\0')
        {
            char network[FIELD_SIZE];
            network_label(first, network, sizeof(network));
            column = fprintf(out, "    %s (%s), %zu subdomains: ", first->ip, network, users);
        }
        else
        {
            column = fprintf(out, "    %s, %zu subdomains: ", first->ip, users);
        }

        int listed = 0;

        for (size_t j = i; j < subs->count; j++)
        {
            const subdomain_info *sub = &subs->items[j];

            if (subdomain_state_of(sub) != SUBDOMAIN_ONLINE || strcmp(sub->ip, first->ip) != 0)
            {
                continue;
            }

            int length = report_short_name(sub->name, report->name);

            if (listed > 0 && column + 2 + length + 1 > REPORT_WIDTH)
            {
                column = fprintf(out, ",\n      ") - 2;
            }
            else if (listed > 0)
            {
                column += fprintf(out, ", ");
            }

            column += fprintf(out, "%.*s", length, sub->name);
            listed++;
        }

        fprintf(out, "\n");
    }
}

/* Why probing got no answer, in the order the groups are printed; any
 * other reason is listed last as "other errors". */
static const char *const probe_reasons[] = {
    "not in DNS", "timed out", "connection refused", "connection reset", "TLS handshake failed", "empty reply"};

/* The probe records "<reason>: <libcurl message>". */
static size_t reason_index(const subdomain_info *sub)
{
    size_t length = strcspn(sub->error, ":");

    for (size_t i = 0; i < ARRAY_COUNT(probe_reasons); i++)
    {
        if (strlen(probe_reasons[i]) == length && strncmp(sub->error, probe_reasons[i], length) == 0)
        {
            return i;
        }
    }

    return ARRAY_COUNT(probe_reasons);
}

/* Subdomains that were never probed (probed = 0), or probed without an
 * answer for `reason` (probed = 1). */
/* `state` picks the group; for SUBDOMAIN_NO_ANSWER `reason` narrows it to
 * one entry of probe_reasons (ARRAY_COUNT(probe_reasons) for the rest). */
static int in_group(const subdomain_info *sub, subdomain_state state, size_t reason)
{
    if (subdomain_state_of(sub) != state)
    {
        return 0;
    }

    return state != SUBDOMAIN_NO_ANSWER || reason_index(sub) == reason;
}

/* "    label (n)               www, api, mail, ..." with short names,
 * wrapped at the report width under the first name. At most `limit`
 * names are listed (0: all). */
static void print_name_group(FILE *out, const domain_report *report, const char *label, subdomain_state state,
                             size_t reason, size_t limit)
{
    size_t count = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        count += in_group(&report->subdomains.items[i], state, reason);
    }

    if (count == 0)
    {
        return;
    }

    char heading[64] = "";
    int start = 4;

    if (label != NULL)
    {
        snprintf(heading, sizeof(heading), "%s (%zu)", label, count);
        start += REASON_WIDTH;
    }

    int column = fprintf(out, "    %-*s", label != NULL ? REASON_WIDTH : 0, heading);
    size_t shown = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (!in_group(sub, state, reason))
        {
            continue;
        }

        if (limit > 0 && shown == limit)
        {
            fprintf(out, ",\n%*s... and %zu more (--full lists them all)", start, "", count - shown);
            break;
        }

        int length = report_short_name(sub->name, report->name);
        int separator = shown > 0 ? 2 : 0;

        if (shown > 0 && column + separator + length + 1 > REPORT_WIDTH)
        {
            column = fprintf(out, ",\n%*s", start, "") - 2;
        }
        else if (shown > 0)
        {
            column += fprintf(out, ", ");
        }

        column += fprintf(out, "%.*s", length, sub->name);
        shown++;
    }

    fprintf(out, "\n");
}

static void print_subdomain_table(FILE *out, const domain_report *report)
{
    /* Columns sized to the longest short name and address, so the table
     * reads down; a name past the cap just pushes its own line wider. */
    int name_width = 0;
    int ip_width = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];
        int length = report_short_name(sub->name, report->name);

        if (subdomain_state_of(sub) == SUBDOMAIN_ONLINE)
        {
            name_width = length > name_width ? length : name_width;
            ip_width = (int)strlen(sub->ip) > ip_width ? (int)strlen(sub->ip) : ip_width;
        }
    }

    name_width = name_width > MAX_NAME_WIDTH ? MAX_NAME_WIDTH : name_width;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (subdomain_state_of(sub) != SUBDOMAIN_ONLINE)
        {
            continue;
        }

        char code_str[32];
        char network[FIELD_SIZE] = "";

        snprintf(code_str, sizeof(code_str), "[%ld]", sub->http_code);

        if (sub->ip[0] != '\0' && sub->asn[0] != '\0')
        {
            network_label(sub, network, sizeof(network));
        }

        char line[DOMAIN_SIZE + FIELD_SIZE * 2];
        size_t length = (size_t)snprintf(line, sizeof(line), "    %-5s  %-5s  %-*.*s  %-*s  %s", code_str,
                                         sub->protocol, name_width, report_short_name(sub->name, report->name),
                                         sub->name, ip_width, sub->ip, network);

        length = length < sizeof(line) ? length : sizeof(line) - 1;

        while (length > 0 && line[length - 1] == ' ')
        {
            length--;
        }

        fprintf(out, "%.*s\n", (int)length, line);
    }
}

/* Aliases that leave the domain, where a third party serves the name, and
 * every alias whose target is gone. */
static int is_notable_alias(const domain_report *report, const subdomain_info *sub)
{
    char org[DOMAIN_SIZE];

    if (sub->cname[0] == '\0')
    {
        return 0;
    }

    organizational_domain(sub->cname, org, sizeof(org));
    return sub->cname_dangling || strcasecmp(org, report->org_domain) != 0;
}

static void print_aliases(FILE *out, const domain_report *report, size_t limit)
{
    size_t count = 0;
    int width = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (is_notable_alias(report, sub))
        {
            int length = report_short_name(sub->name, report->name);
            width = length > width ? length : width;
            count++;
        }
    }

    if (count == 0)
    {
        return;
    }

    width = width > MAX_NAME_WIDTH ? MAX_NAME_WIDTH : width;
    fprintf(out, "\n  Aliases to other domains (CNAME, %zu):\n\n", count);

    size_t shown = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (!is_notable_alias(report, sub))
        {
            continue;
        }

        if (limit > 0 && shown == limit)
        {
            fprintf(out, "    ... and %zu more (--full lists them all)\n", count - shown);
            break;
        }

        fprintf(out, "    %-*.*s  -> %s%s\n", width, report_short_name(sub->name, report->name), sub->name, sub->cname,
                sub->cname_dangling ? "  (target does not exist)" : "");
        shown++;
    }
}

void print_subdomains(FILE *out, const domain_report *report, int full)
{
    size_t limit = full ? 0 : CONCISE_SUBDOMAINS;
    size_t counts[SUBDOMAIN_ONLINE + 1] = {0};

    print_section(out, "SUBDOMAINS");

    if (report->subdomain_status == LOOKUP_SKIPPED)
    {
        fprintf(out, "  Skipped (--no-subdomains).\n");
        return;
    }

    if (report->subdomain_status == LOOKUP_FAILED)
    {
        fprintf(out, "  Lookup failed: no passive OSINT source answered.\n");
        return;
    }

    if (report->subdomains.count == 0)
    {
        fprintf(out, "  None found in passive OSINT sources.\n");
        return;
    }

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        counts[subdomain_state_of(&report->subdomains.items[i])]++;
    }

    if (counts[SUBDOMAIN_NOT_PROBED] == report->subdomains.count)
    {
        fprintf(out, "  %zu discovered in passive sources, not probed (--active checks which answer):\n\n",
                report->subdomains.count);
        print_name_group(out, report, NULL, SUBDOMAIN_NOT_PROBED, 0, limit);
        print_aliases(out, report, limit);
        return;
    }

    if (counts[SUBDOMAIN_ONLINE] == 0)
    {
        fprintf(out, "  None of the %zu discovered subdomains serves a site over HTTP/HTTPS.\n",
                report->subdomains.count);
    }
    else
    {
        fprintf(out, "  %zu online, answering over HTTP/HTTPS (%zu discovered):\n\n", counts[SUBDOMAIN_ONLINE],
                report->subdomains.count);
        print_subdomain_table(out, report);
    }

    print_shared_addresses(out, report);
    print_aliases(out, report, limit);

    if (counts[SUBDOMAIN_EDGE_ONLY] > 0)
    {
        fprintf(out, "\n  Only a CDN answers, no site configured (%zu):\n\n", counts[SUBDOMAIN_EDGE_ONLY]);
        print_name_group(out, report, NULL, SUBDOMAIN_EDGE_ONLY, 0, limit);
    }

    if (counts[SUBDOMAIN_NO_ANSWER] > 0)
    {
        fprintf(out, "\n  No HTTP/HTTPS response (%zu):\n\n", counts[SUBDOMAIN_NO_ANSWER]);

        for (size_t reason = 0; reason <= ARRAY_COUNT(probe_reasons); reason++)
        {
            print_name_group(out, report, reason < ARRAY_COUNT(probe_reasons) ? probe_reasons[reason] : "other errors",
                             SUBDOMAIN_NO_ANSWER, reason, limit);
        }
    }

    if (counts[SUBDOMAIN_NOT_PROBED] > 0)
    {
        fprintf(out, "\n  Not probed, over the probe limit (%zu):\n\n", counts[SUBDOMAIN_NOT_PROBED]);
        print_name_group(out, report, NULL, SUBDOMAIN_NOT_PROBED, 0, limit);
    }
}

/* Without --full only the totals per target; each domain's section
 * already lists its subdomains. */
void print_all_subdomains(FILE *out, const domain_report *reports, size_t count, int full)
{
    size_t total = 0;

    for (size_t i = 0; i < count; i++)
    {
        total += reports[i].subdomains.count;
    }

    if (total == 0)
    {
        return;
    }

    print_section(out, "SUBDOMAIN INVESTIGATION SUMMARY");
    fprintf(out, "  Total subdomains discovered across %zu targets: %zu\n\n", count, total);

    if (!full)
    {
        for (size_t i = 0; i < count; i++)
        {
            size_t live = 0;

            for (size_t j = 0; j < reports[i].subdomains.count; j++)
            {
                live += subdomain_state_of(&reports[i].subdomains.items[j]) == SUBDOMAIN_ONLINE;
            }

            fprintf(out, "  %-40s %zu discovered, %zu online\n", reports[i].name, reports[i].subdomains.count, live);
        }

        return;
    }

    for (size_t i = 0; i < count; i++)
    {
        if (reports[i].subdomains.count > 0)
        {
            fprintf(out, "  %s (%zu subdomain%s):\n", reports[i].name, reports[i].subdomains.count,
                    reports[i].subdomains.count == 1 ? "" : "s");

            for (size_t j = 0; j < reports[i].subdomains.count; j++)
            {
                const subdomain_info *sub = &reports[i].subdomains.items[j];

                if (subdomain_state_of(sub) == SUBDOMAIN_ONLINE)
                {
                    char code_str[24];

                    snprintf(code_str, sizeof(code_str), "[%ld]", sub->http_code);

                    fprintf(out, "    - %-6s %s://%s\n", code_str, sub->protocol, sub->name);
                }
                else if (!sub->probed)
                {
                    fprintf(out, "    - %s\n", sub->name);
                }
            }

            fprintf(out, "\n");
        }
    }
}
