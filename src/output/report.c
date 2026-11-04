/* The plain-text report: header, overview, summary, signals and
 * correlation. The detail sections live in report_sections.c and
 * report_subdomains.c, the formatting primitives in report_format.c. */

#include "output/report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/dates.h"
#include "core/gaps.h"
#include "output/report_internal.h"
#include "support/util.h"

static void count_findings(const domain_report *report, size_t counts[4])
{
    memset(counts, 0, 4 * sizeof(counts[0]));

    for (size_t i = 0; i < report->finding_count; i++)
    {
        counts[report->findings[i].level]++;
    }
}

static void describe_signals(const domain_report *report, char *out, size_t size)
{
    static const char *const names[] = {"info", "low", "medium", "high"};
    size_t counts[4];
    size_t len = 0;

    count_findings(report, counts);
    out[0] = '\0';

    for (int level = SEVERITY_HIGH; level >= SEVERITY_INFO && len < size; level--)
    {
        if (counts[level] > 0)
        {
            len += (size_t)snprintf(out + len, size - len, "%s%zu %s", len > 0 ? ", " : "", counts[level], names[level]);
        }
    }

    if (len == 0)
    {
        snprintf(out, size, "none");
    }
}

static void describe_created(const domain_report *report, char *out, size_t size)
{
    const whois_info *whois = &report->whois;

    if (!report_has(report, MODULE_WHOIS))
    {
        snprintf(out, size, "-");
    }
    else if (whois->status != LOOKUP_OK)
    {
        snprintf(out, size, "unknown");
    }
    else if (!whois->registered)
    {
        snprintf(out, size, "unregistered");
    }
    else
    {
        whois_date(whois->created, out, size);
    }
}

static void print_header(FILE *out, size_t count, const report_options *options)
{
    char generated[64];
    char domains[32];
    time_t now = time(NULL);
    struct tm local;

    localtime_r(&now, &local);
    strftime(generated, sizeof(generated), "%Y-%m-%d %H:%M %z", &local);
    snprintf(domains, sizeof(domains), "%zu", count);

    fprintf(out, "DOMINT REPORT\n\n");
    print_field(out, "Generated", generated);
    print_field(out, "Domains", domains);

    unsigned modules = options->modules != 0 ? options->modules : MODULE_DEFAULT;
    int contacts = !options->passive && (modules & (MODULE_HTTP | MODULE_TLS | MODULE_SUBDOMAINS)) != 0;

    print_field(out, "Mode", contacts ? "active (the targets were contacted from your IP)"
                                      : "passive (the targets were not contacted)");

    if (modules != MODULE_DEFAULT)
    {
        static const struct
        {
            unsigned bit;
            const char *name;
        } names[] = {{MODULE_ADDRESSES, "addresses"}, {MODULE_DNS, "dns"},   {MODULE_WHOIS, "whois"},
                     {MODULE_TLS, "tls"},             {MODULE_HTTP, "http"}, {MODULE_SUBDOMAINS, "subdomains"},
                     {MODULE_REPUTATION, "reputation"}, {MODULE_LOOKALIKES, "lookalikes"}};
        char list[128] = "";

        for (size_t i = 0; i < ARRAY_COUNT(names); i++)
        {
            if (modules & names[i].bit)
            {
                size_t len = strlen(list);
                snprintf(list + len, sizeof(list) - len, "%s%s", len > 0 ? ", " : "", names[i].name);
            }
        }

        print_field(out, "Modules", list);
    }
}

static void print_overview(FILE *out, const domain_report *reports, size_t count)
{
    int width = 8;
    int created_width = 9;

    for (size_t i = 0; i < count; i++)
    {
        char created[32];
        int len = (int)strlen(reports[i].name) + 2;

        if (len > width)
        {
            width = len;
        }

        describe_created(&reports[i], created, sizeof(created));
        len = (int)strlen(created) + 2;

        if (len > created_width)
        {
            created_width = len;
        }
    }

    print_section(out, "OVERVIEW");
    fprintf(out, "\n  %-*s%5s%5s%5s  %-*s%s\n", width, "Domain", "High", "Med", "Low", created_width, "Created", "Hosting");

    for (size_t i = 0; i < count; i++)
    {
        const domain_report *report = &reports[i];
        size_t counts[4];
        char cells[3][24];
        char created[32];

        count_findings(report, counts);

        for (int level = SEVERITY_HIGH; level >= SEVERITY_LOW; level--)
        {
            char *cell = cells[SEVERITY_HIGH - level];

            if (counts[level] == 0)
            {
                snprintf(cell, sizeof(cells[0]), "-");
            }
            else
            {
                snprintf(cell, sizeof(cells[0]), "%zu", counts[level]);
            }
        }

        describe_created(report, created, sizeof(created));

        fprintf(out, "  %-*s%5s%5s%5s  %-*s%s\n", width, report->name, cells[0], cells[1], cells[2], created_width,
                created, report->hosting[0] != '\0' ? report->hosting : "-");
    }
}

#define MAX_GAP_ITEMS 5

/* One line per area with a failed source, in the SUMMARY of every mode:
 * a missing value then reads as "unknown", not as "none". */
static void print_gaps(FILE *out, const domain_report *report)
{
    const char *label = "Gaps";

    for (int area = 0; area < GAP_COUNT; area++)
    {
        char text[1024];
        size_t len = (size_t)snprintf(text, sizeof(text), "%s: ", gap_label((gap_area)area));
        size_t found = 0;

        for (size_t i = 0; i < report->observations.count; i++)
        {
            const observation *item = &report->observations.items[i];
            char what[DOMAIN_SIZE + 16];
            char why[FIELD_SIZE];

            if (gap_area_of(report, item) != area)
            {
                continue;
            }

            if (found < MAX_GAP_ITEMS && len < sizeof(text))
            {
                gap_describe(item, (gap_area)area, what, sizeof(what), why, sizeof(why));
                len += (size_t)snprintf(text + len, sizeof(text) - len, "%s%s (%s)", found > 0 ? ", " : "", what, why);
            }

            found++;
        }

        if (found == 0)
        {
            continue;
        }

        if (found > MAX_GAP_ITEMS && len < sizeof(text))
        {
            len += (size_t)snprintf(text + len, sizeof(text) - len, " and %zu more", found - MAX_GAP_ITEMS);
        }

        if (gap_impact((gap_area)area) != NULL && len < sizeof(text))
        {
            snprintf(text + len, sizeof(text) - len, "; %s", gap_impact((gap_area)area));
        }

        print_paragraph(out, 2 + LABEL_WIDTH, label, text);
        label = "";
    }
}

static void print_registered(FILE *out, const domain_report *report)
{
    const whois_info *whois = &report->whois;
    char text[FIELD_SIZE * 2];

    if (whois->status != LOOKUP_OK)
    {
        print_field(out, "Registered", "unknown (no WHOIS data)");
    }
    else if (!whois->registered)
    {
        print_field(out, "Registered", "no");
    }
    else
    {
        char date[32];
        char age[32] = "";

        whois_date(whois->created, date, sizeof(date));

        if (report->age_days >= 0)
        {
            describe_age(report->age_days, age, sizeof(age));
        }

        snprintf(text, sizeof(text), "%s%s%s%s%s", date, age[0] != '\0' ? " (" : "", age,
                 age[0] != '\0' ? " ago)" : "", whois->registrar[0] != '\0' ? ", " : "");
        strncat(text, whois->registrar, sizeof(text) - strlen(text) - 1);
        print_field(out, "Registered", text);
    }
}

static void print_subdomain_summary(FILE *out, const domain_report *report)
{
    char text[FIELD_SIZE * 2];

    if (report->subdomain_status == LOOKUP_SKIPPED)
    {
        print_field(out, "Subdomains", "skipped (--no-subdomains)");
    }
    else if (report->subdomain_status == LOOKUP_FAILED)
    {
        print_field(out, "Subdomains", "lookup failed (no passive OSINT source answered)");
    }
    else if (report->subdomains.count == 0)
    {
        print_field(out, "Subdomains", "none found (passive OSINT)");
    }
    else
    {
        size_t counts[SUBDOMAIN_ONLINE + 1] = {0};

        for (size_t i = 0; i < report->subdomains.count; i++)
        {
            counts[subdomain_state_of(&report->subdomains.items[i])]++;
        }

        if (counts[SUBDOMAIN_NOT_PROBED] == report->subdomains.count)
        {
            snprintf(text, sizeof(text), "%zu discovered (not probed; --active checks which answer)",
                     report->subdomains.count);
        }
        else if (counts[SUBDOMAIN_EDGE_ONLY] > 0)
        {
            snprintf(text, sizeof(text), "%zu online, %zu only reach a CDN (%zu discovered)", counts[SUBDOMAIN_ONLINE],
                     counts[SUBDOMAIN_EDGE_ONLY], report->subdomains.count);
        }
        else
        {
            snprintf(text, sizeof(text), "%zu online (%zu discovered)", counts[SUBDOMAIN_ONLINE],
                     report->subdomains.count);
        }

        print_field(out, "Subdomains", text);
    }

    if (report->ct_first_seen[0] != '\0')
    {
        snprintf(text, sizeof(text), "%s (Certificate Transparency, crt.sh)", report->ct_first_seen);
        print_field(out, "First cert", text);
    }
}

static void print_summary(FILE *out, const domain_report *report)
{
    char text[FIELD_SIZE * 2];

    print_section(out, "SUMMARY");

    describe_signals(report, text, sizeof(text));
    print_field(out, "Signals", text);

    if (report->observations.count > 0)
    {
        print_field(out, "Collected", report->observations.items[0].collected_at);
    }

    if (report_has(report, MODULE_WHOIS))
    {
        print_registered(out, report);
    }

    if (report_has(report, MODULE_ADDRESSES))
    {
        print_field(out, "Hosting", report->hosting[0] != '\0' ? report->hosting
                                    : report->address_count > 0 ? "unknown"
                                                                : "no addresses");
    }

    if (report_has(report, MODULE_DNS))
    {
        print_field(out, "DNS provider", report->dns_provider[0] != '\0' ? report->dns_provider : "unknown");
        print_field(out, "Mail", report->mail_provider[0] != '\0' ? report->mail_provider : "no MX records");
    }

    if (report_has(report, MODULE_TLS) && report->tls.status == LOOKUP_OK)
    {
        char certificate[FIELD_SIZE * 2];
        describe_certificate(&report->tls, certificate, sizeof(certificate));
        print_field(out, "Certificate", certificate);
    }

    if (report_has(report, MODULE_DNS) && report->services.count > 0)
    {
        print_wrapped(out, 2, LABEL_WIDTH, "Services", (const char *const *)report->services.items, report->services.count);
    }

    if (report_has(report, MODULE_REPUTATION))
    {
        describe_reputation(&report->reputation, text, sizeof(text));
        print_field(out, "Reputation", text);
    }

    if (report_has(report, MODULE_SUBDOMAINS))
    {
        print_subdomain_summary(out, report);
    }

    if (report_has(report, MODULE_LOOKALIKES))
    {
        describe_lookalikes(&report->lookalikes, text, sizeof(text));
        print_field(out, "Lookalikes", text);
    }

    print_gaps(out, report);
}

static void print_signals(FILE *out, const domain_report *report)
{
    print_section(out, "SIGNALS");

    if (report->finding_count == 0)
    {
        fprintf(out, "  No signals.\n");
        return;
    }

    for (size_t i = 0; i < report->finding_count; i++)
    {
        print_paragraph(out, 2 + TAG_WIDTH, severity_tag(report->findings[i].level), report->findings[i].text);
    }
}

static void print_domain(FILE *out, const domain_report *report, const report_options *options)
{
    fprintf(out, "\n\n%s\n%s\n%s\n", RULE, report->name, RULE);

    /* A module picked on the command line is what the user asked to see. */
    int details = options->full || options->selected;

    print_summary(out, report);
    print_signals(out, report);

    if (details && report_has(report, MODULE_ADDRESSES))
    {
        print_addresses(out, report);
    }

    if (details && report_has(report, MODULE_HTTP))
    {
        print_http(out, report);
    }

    if (details && report_has(report, MODULE_TLS))
    {
        print_tls(out, report);
    }

    if (details && report_has(report, MODULE_DNS))
    {
        print_dns(out, report);
    }

    if (details && report_has(report, MODULE_WHOIS))
    {
        print_whois(out, report);
    }

    if (details && report_has(report, MODULE_REPUTATION))
    {
        print_reputation(out, report);
    }

    if (details && report_has(report, MODULE_LOOKALIKES))
    {
        print_lookalikes(out, report);
    }

    if (options->raw)
    {
        print_sources(out, report);
        print_raw(out, report);
    }

    if (report_has(report, MODULE_SUBDOMAINS))
    {
        print_subdomains(out, report, details);
    }
}

static const char *strength_title(link_strength strength)
{
    switch (strength)
    {
    case LINK_STRONG:
        return "HIGH SPECIFICITY (rarely shared by chance)";
    case LINK_MEDIUM:
        return "MEDIUM SPECIFICITY";
    default:
        return "LOW SPECIFICITY (shared provider infrastructure)";
    }
}

static void print_correlation(FILE *out, const domain_report *reports, size_t count, const correlation *links)
{
    const char **names = xcalloc(count, sizeof(*names));

    fprintf(out, "\n\n%s\nCORRELATION\n%s\n\n", RULE, RULE);
    fprintf(out, "Indicators found on two or more of the %zu domains, grouped by how specific\n", count);
    fprintf(out, "they are. They are leads for review, not proof of common ownership: even a\n");
    fprintf(out, "shared IP can be a hosting provider serving unrelated customers.\n");

    if (links->indicator_count == 0)
    {
        fprintf(out, "\n  No shared indicators.\n");
    }

    for (int strength = LINK_STRONG; strength >= LINK_WEAK; strength--)
    {
        int printed_title = 0;

        for (size_t i = 0; i < links->indicator_count; i++)
        {
            const shared_indicator *indicator = &links->indicators[i];

            if ((int)indicator->strength != strength)
            {
                continue;
            }

            if (!printed_title)
            {
                print_section(out, strength_title(indicator->strength));
                printed_title = 1;
            }

            for (size_t j = 0; j < indicator->domain_count; j++)
            {
                names[j] = reports[indicator->domains[j]].name;
            }

            fprintf(out, "  %-*s%s\n", KIND_WIDTH, indicator->kind, indicator->value);
            print_wrapped(out, 2, KIND_WIDTH, "", names, indicator->domain_count);
        }
    }

    print_section(out, "CANDIDATE GROUPS (joined by high-specificity indicators; review before concluding)");

    if (links->cluster_count == 0)
    {
        fprintf(out, "  None.\n");
    }

    for (size_t cluster = 0; cluster < links->cluster_count; cluster++)
    {
        char label[24];
        size_t member_count = 0;

        for (size_t i = 0; i < count; i++)
        {
            if (links->cluster_of[i] == cluster)
            {
                names[member_count++] = reports[i].name;
            }
        }

        snprintf(label, sizeof(label), "%zu.", cluster + 1);
        print_wrapped(out, 2, 4, label, names, member_count);
    }

    free(names);
}

void print_report(FILE *out, const domain_report *reports, size_t count, const correlation *links,
                  const report_options *options)
{
    print_header(out, count, options);

    if (count > 1)
    {
        print_overview(out, reports, count);
    }

    for (size_t i = 0; i < count; i++)
    {
        print_domain(out, &reports[i], options);
    }

    if (count > 1)
    {
        if (links != NULL)
        {
            print_correlation(out, reports, count, links);
        }

        if (options->modules == 0 || (options->modules & MODULE_SUBDOMAINS))
        {
            print_all_subdomains(out, reports, count, options->full);
        }
    }
}
