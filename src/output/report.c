#include "output/report.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/analysis.h"
#include "collect/asn.h"
#include "collect/dns.h"
#include "support/domain.h"
#include "core/gaps.h"
#include "core/model.h"
#include "collect/http.h"
#include "collect/subdomain.h"
#include "collect/tls.h"
#include "support/util.h"

#define RULE "================================================================================"
#define LABEL_WIDTH 14
#define SUB_LABEL_WIDTH 12
#define KIND_WIDTH 22
#define WRAP_WIDTH 64
#define REPORT_WIDTH 80
#define TAG_WIDTH 9
#define SOURCE_INDENT 15
/* Names listed per group of unanswered subdomains without --full. */
#define CONCISE_SUBDOMAINS 20
#define REASON_WIDTH 24
#define MAX_NAME_WIDTH 28

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

static void describe_certificate(const tls_info *tls, char *out, size_t size);

static const char *severity_tag(severity level)
{
    switch (level)
    {
    case SEVERITY_HIGH:
        return "[HIGH]";
    case SEVERITY_MEDIUM:
        return "[MEDIUM]";
    case SEVERITY_LOW:
        return "[LOW]";
    default:
        return "[INFO]";
    }
}

static void print_paragraph(FILE *out, int indent, const char *tag, const char *text);

/* A long value with spaces (a DMARC record, a SOA line) wraps under itself. */
static void print_field(FILE *out, const char *label, const char *value)
{
    if (2 + LABEL_WIDTH + strlen(value) > REPORT_WIDTH && strchr(value, ' ') != NULL)
    {
        print_paragraph(out, 2 + LABEL_WIDTH, label, value);
        return;
    }

    fprintf(out, "  %-*s%s\n", LABEL_WIDTH, label, value);
}

static void print_sub_field(FILE *out, const char *label, const char *value)
{
    fprintf(out, "    %-*s%s\n", SUB_LABEL_WIDTH, label, value);
}

static void print_section(FILE *out, const char *title)
{
    fprintf(out, "\n%s\n", title);
}

/* Prints a comma-separated list, wrapping onto lines aligned under the first. */
static void print_wrapped(FILE *out, int indent, int label_width, const char *label, const char *const *items, size_t count)
{
    char line[1024];
    size_t len = 0;

    for (size_t i = 0; i < count; i++)
    {
        int last = i + 1 == count;
        size_t needed = strlen(items[i]) + (last ? 0 : 1);

        if (len > 0 && len + 1 + needed > WRAP_WIDTH)
        {
            fprintf(out, "%*s%-*s%s\n", indent, "", label_width, label, line);
            label = "";
            len = 0;
        }

        int written = snprintf(line + len, sizeof(line) - len, "%s%s%s", len > 0 ? " " : "", items[i], last ? "" : ",");

        len += written > 0 ? (size_t)written : 0;

        if (len >= sizeof(line))
        {
            len = sizeof(line) - 1;
        }
    }

    if (len > 0)
    {
        fprintf(out, "%*s%-*s%s\n", indent, "", label_width, label, line);
    }
}

/* Word-wraps `text` to the report width, starting at column `indent` after
 * `tag` and indenting continuation lines the same way: "  [MEDIUM] text ...". */
static void print_paragraph(FILE *out, int indent, const char *tag, const char *text)
{
    int column = fprintf(out, "  %-*s", indent - 2, tag);

    while (*text != '\0')
    {
        size_t word_len = strcspn(text, " ");

        if (column > indent && column + 1 + (int)word_len > REPORT_WIDTH)
        {
            column = fprintf(out, "\n%*s", indent, "") - 1;
        }
        else if (column > indent)
        {
            column += fprintf(out, " ");
        }

        column += fprintf(out, "%.*s", (int)word_len, text);
        text += word_len;

        while (*text == ' ')
        {
            text++;
        }
    }

    fprintf(out, "\n");
}

static void print_list(FILE *out, const char *label, const char *const *items, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        print_field(out, i == 0 ? label : "", items[i]);
    }
}

static void print_record_set(FILE *out, const char *label, const record_set *set)
{
    if (set->status == LOOKUP_FAILED)
    {
        print_field(out, label, "lookup failed");
    }
    else if (set->values.count == 0)
    {
        print_field(out, label, "none");
    }
    else
    {
        print_list(out, label, (const char *const *)set->values.items, set->values.count);
    }
}

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

        for (size_t i = 0; i < COUNT(names); i++)
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

static void append(char *out, size_t size, const char *separator, const char *text)
{
    if (out[0] != '\0')
    {
        strncat(out, separator, size - strlen(out) - 1);
    }

    strncat(out, text, size - strlen(out) - 1);
}

static int is_listed(const char *verdict)
{
    return verdict[0] != '\0' && strcasecmp(verdict, "not listed") != 0;
}

/* "listed: ThreatFox (2 IOCs); URLhaus (3 URLs, 1 online)" or "no listings
 * in OTX, URLhaus, ThreatFox". */
static void describe_reputation(const reputation_info *rep, char *out, size_t size)
{
    char listed[FIELD_SIZE * 2] = "";
    char asked[FIELD_SIZE] = "";
    char part[FIELD_SIZE];

    if (rep->threatfox_status == LOOKUP_OK)
    {
        append(asked, sizeof(asked), ", ", "ThreatFox");

        if (rep->threatfox_iocs > 0)
        {
            snprintf(part, sizeof(part), "ThreatFox (%ld IOC%s)", rep->threatfox_iocs, rep->threatfox_iocs == 1 ? "" : "s");
            append(listed, sizeof(listed), "; ", part);
        }
    }

    if (rep->urlhaus_status == LOOKUP_OK)
    {
        append(asked, sizeof(asked), ", ", "URLhaus");

        if (rep->urlhaus_urls > 0)
        {
            snprintf(part, sizeof(part), "URLhaus (%ld URL%s, %ld online)", rep->urlhaus_urls,
                     rep->urlhaus_urls == 1 ? "" : "s", rep->urlhaus_online);
            append(listed, sizeof(listed), "; ", part);
        }

        if (is_listed(rep->spamhaus_dbl))
        {
            append(listed, sizeof(listed), "; ", "Spamhaus DBL");
        }

        if (is_listed(rep->surbl))
        {
            append(listed, sizeof(listed), "; ", "SURBL");
        }
    }

    if (rep->otx_status == LOOKUP_OK)
    {
        append(asked, sizeof(asked), ", ", "OTX");

        if (rep->otx_pulses > 0 && !rep->otx_allowlisted)
        {
            snprintf(part, sizeof(part), "OTX (%ld pulse%s)", rep->otx_pulses, rep->otx_pulses == 1 ? "" : "s");
            append(listed, sizeof(listed), "; ", part);
        }
    }

    if (listed[0] != '\0')
    {
        snprintf(out, size, "listed: %.*s", (int)(size > 9 ? size - 9 : 0), listed);
    }
    else if (asked[0] != '\0')
    {
        snprintf(out, size, "no listings in %s", asked);
    }
    else
    {
        snprintf(out, size, "unknown (no source answered)");
    }

    if (rep->otx_status == LOOKUP_OK && rep->otx_allowlisted)
    {
        strncat(out, "; OTX marks it known-good", size - strlen(out) - 1);
    }

    if (rep->urlhaus_not_queried)
    {
        strncat(out, "; URLhaus and ThreatFox need ABUSECH_AUTH_KEY", size - strlen(out) - 1);
    }
}

static void print_reputation_source(FILE *out, const char *label, lookup_status status, int not_queried,
                                    const char *text)
{
    if (not_queried)
    {
        print_field(out, label, "not queried: set ABUSECH_AUTH_KEY (free key at https://auth.abuse.ch)");
    }
    else if (status == LOOKUP_FAILED)
    {
        print_field(out, label, "lookup failed");
    }
    else if (status == LOOKUP_OK)
    {
        print_field(out, label, text);
    }
}

static void print_reputation(FILE *out, const domain_report *report)
{
    const reputation_info *rep = &report->reputation;
    char text[FIELD_SIZE * 3];
    char names[FIELD_SIZE * 2] = "";

    print_section(out, "REPUTATION");

    for (size_t i = 0; i < rep->threatfox_malware.count; i++)
    {
        append(names, sizeof(names), ", ", rep->threatfox_malware.items[i]);
    }

    if (rep->threatfox_not_queried && rep->urlhaus_not_queried)
    {
        print_field(out, "abuse.ch", "URLhaus and ThreatFox not queried: set ABUSECH_AUTH_KEY (free key at "
                                     "https://auth.abuse.ch)");
    }
    else
    {
        snprintf(text, sizeof(text), rep->threatfox_iocs > 0 ? "%ld IOC entr%s%s%s" : "no IOC entries",
                 rep->threatfox_iocs, rep->threatfox_iocs == 1 ? "y" : "ies", names[0] != '\0' ? ": " : "", names);
        print_reputation_source(out, "ThreatFox", rep->threatfox_status, rep->threatfox_not_queried, text);

        snprintf(text, sizeof(text), "%ld malware URL%s (%ld online); Spamhaus DBL: %s; SURBL: %s", rep->urlhaus_urls,
                 rep->urlhaus_urls == 1 ? "" : "s", rep->urlhaus_online,
                 rep->spamhaus_dbl[0] != '\0' ? rep->spamhaus_dbl : "not listed",
                 rep->surbl[0] != '\0' ? rep->surbl : "not listed");
        print_reputation_source(out, "URLhaus", rep->urlhaus_status, rep->urlhaus_not_queried, text);
    }

    names[0] = '\0';

    for (size_t i = 0; i < rep->otx_pulse_names.count && !rep->otx_allowlisted; i++)
    {
        append(names, sizeof(names), "; ", rep->otx_pulse_names.items[i]);
    }

    snprintf(text, sizeof(text), "%ld pulse%s%s%s%s", rep->otx_pulses, rep->otx_pulses == 1 ? "" : "s",
             names[0] != '\0' ? ": " : "", names, rep->otx_allowlisted ? " (marked known-good)" : "");
    print_reputation_source(out, "OTX", rep->otx_status, 0, text);
}

static void describe_lookalikes(const lookalike_list *list, char *out, size_t size)
{
    size_t mail = 0;
    size_t parked = 0;

    for (size_t i = 0; i < list->count; i++)
    {
        const lookalike_info *item = &list->items[i];

        mail += item->has_mail && !item->likely_defensive && !item->parked;
        parked += (size_t)(item->parked && !item->likely_defensive);
    }

    if (list->status == LOOKUP_FAILED)
    {
        snprintf(out, size, "unknown (the resolver did not answer)");
    }
    else if (list->count == 0)
    {
        snprintf(out, size, "none registered (%zu variants checked)", list->checked);
    }
    else
    {
        snprintf(out, size, "%zu registered of %zu variants (%zu can receive mail, %zu parked or for sale)",
                 list->count, list->checked, mail, parked);
    }
}

/* One line per registered variant: name, how it was made, whether it takes
 * mail, where it points and who serves its DNS. */
static void print_lookalikes(FILE *out, const domain_report *report)
{
    const lookalike_list *list = &report->lookalikes;
    int name_width = 0;

    print_section(out, "LOOKALIKES");

    if (list->status == LOOKUP_FAILED)
    {
        fprintf(out, "  Not checked: the resolver did not answer.\n");
        return;
    }

    fprintf(out, "  %zu variants checked; %zu registered%s\n", list->checked, list->count, list->count > 0 ? ":\n" : ".");

    for (size_t i = 0; i < list->count; i++)
    {
        int length = (int)strlen(list->items[i].name);
        name_width = length > name_width ? length : name_width;
    }

    name_width = name_width > MAX_NAME_WIDTH + 8 ? MAX_NAME_WIDTH + 8 : name_width;

    for (size_t i = 0; i < list->count; i++)
    {
        const lookalike_info *item = &list->items[i];
        const char *nameserver = item->dns_fails             ? "(its DNS does not answer)"
                                 : item->nameservers.count > 0 ? item->nameservers.items[0]
                                                               : "-";
        char line[DOMAIN_SIZE * 3];
        size_t length = (size_t)snprintf(line, sizeof(line), "    %-*s  %-13s  %-4s  %-15s  %s%s", name_width,
                                         item->name, item->technique, item->has_mail ? "mail" : "-",
                                         item->addresses.count > 0 ? item->addresses.items[0] : "-", nameserver,
                                         item->likely_defensive ? "  (likely the owner's)"
                                         : item->parked         ? "  (parked/for sale)"
                                                                : "");

        length = length < sizeof(line) ? length : sizeof(line) - 1;
        fprintf(out, "%.*s\n", (int)length, line);
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

static void print_addresses(FILE *out, const domain_report *report)
{
    print_section(out, "ADDRESSES");

    if (report->resolve_status == LOOKUP_FAILED)
    {
        fprintf(out, "  None: %s.\n", report->resolve_error);
        return;
    }

    for (size_t i = 0; i < report->address_count; i++)
    {
        const address_info *address = &report->addresses[i];
        char text[FIELD_SIZE * 2];

        fprintf(out, "  %s\n", address->ip);
        print_sub_field(out, "PTR", address->ptr[0] != '\0' ? address->ptr : "none");

        if (address->asn_status != LOOKUP_OK)
        {
            print_sub_field(out, "ASN", "lookup failed");
        }
        else if (!address->announced)
        {
            print_sub_field(out, "ASN", "none (private or unannounced address)");
        }
        else
        {
            snprintf(text, sizeof(text), "AS%s %s", address->asn, address->as_name);
            print_sub_field(out, "ASN", text);
            snprintf(text, sizeof(text), "%s (%s, %s, allocated %s)", address->prefix, address->country,
                     address->registry, address->allocated);
            print_sub_field(out, "Prefix", text);
        }
    }
}

/* "O=Let's Encrypt, CN=YR1" -> "Let's Encrypt"; the whole issuer otherwise. */
static void issuer_name(const char *issuer, char *out, size_t size)
{
    const char *organization = strstr(issuer, "O = ");
    size_t skip = 4;

    if (organization == NULL)
    {
        organization = strstr(issuer, "O=");
        skip = 2;
    }

    if (organization != NULL && (organization == issuer || organization[-1] == ' ' || organization[-1] == ','))
    {
        snprintf(out, size, "%.*s", (int)strcspn(organization + skip, ",/"), organization + skip);
        return;
    }

    snprintf(out, size, "%s", issuer);
}

static void describe_certificate(const tls_info *tls, char *out, size_t size)
{
    char issuer[FIELD_SIZE * 2];
    time_t until;

    issuer_name(tls->issuer, issuer, sizeof(issuer));

    if (tls_parse_time(tls->valid_until, &until) == 0)
    {
        char date[16];
        long days = (long)((until - time(NULL)) / 86400);
        struct tm parts;

        gmtime_r(&until, &parts);
        strftime(date, sizeof(date), "%Y-%m-%d", &parts);
        snprintf(out, size, "%.200s, %s %s (%ld day%s)%s", issuer, days < 0 ? "expired" : "expires", date, days < 0 ? -days : days,
                 (days == 1 || days == -1) ? "" : "s", tls->trusted ? "" : ", not trusted");
    }
    else
    {
        snprintf(out, size, "%.200s%s", issuer, tls->trusted ? "" : ", not trusted");
    }
}

/* "Aug 21 19:50:02 2026 GMT" -> "2026-08-21 19:50 UTC", like the rest of
 * the report; the original text when it does not parse. */
static void certificate_date(const char *text, char *out, size_t size)
{
    time_t when;
    struct tm parts;

    if (text[0] == '\0')
    {
        snprintf(out, size, "?");
        return;
    }

    if (tls_parse_time(text, &when) != 0)
    {
        snprintf(out, size, "%s", text);
        return;
    }

    gmtime_r(&when, &parts);
    strftime(out, size, "%Y-%m-%d %H:%M UTC", &parts);
}

static void print_tls(FILE *out, const domain_report *report)
{
    const tls_info *tls = &report->tls;

    print_section(out, "TLS CERTIFICATE");

    if (tls->not_queried)
    {
        fprintf(out, "  Not contacted (passive mode; --active reaches the target).\n");
        return;
    }

    if (tls->status == LOOKUP_SKIPPED)
    {
        fprintf(out, "  Skipped: no address to connect to.\n");
        return;
    }

    if (tls->status != LOOKUP_OK)
    {
        fprintf(out, "  No certificate from %s: %s.\n", tls->endpoint, tls->trust_error);
        return;
    }

    char text[FIELD_SIZE * 2];
    char from[32];
    char until[32];

    certificate_date(tls->valid_from, from, sizeof(from));
    certificate_date(tls->valid_until, until, sizeof(until));

    print_field(out, "Endpoint", tls->endpoint);
    print_field(out, "Subject", tls->subject[0] != '\0' ? tls->subject : "unknown");
    print_field(out, "Issuer", tls->issuer[0] != '\0' ? tls->issuer : "unknown");
    snprintf(text, sizeof(text), "%s -> %s", from, until);
    print_field(out, "Valid", text);

    if (tls->names.count > 0)
    {
        print_wrapped(out, 2, LABEL_WIDTH, "Names", (const char *const *)tls->names.items, tls->names.count);
    }

    snprintf(text, sizeof(text), "%s%.400s", tls->trusted ? "yes" : "no: ", tls->trusted ? "" : tls->trust_error);
    print_field(out, "Trusted", text);

    if (tls->signature[0] != '\0')
    {
        print_field(out, "Signature", tls->signature);
    }

    if (tls->serial[0] != '\0')
    {
        print_field(out, "Serial", tls->serial);
    }
}

static void print_http(FILE *out, const domain_report *report)
{
    const http_info *http = &report->http;

    print_section(out, "HTTP");

    if (http->not_queried)
    {
        fprintf(out, "  Not contacted (passive mode; --active reaches the target).\n");
    }
    else if (http->attempts == 0)
    {
        fprintf(out, "  Skipped: no address to connect to.\n");
    }
    else if (http->status != LOOKUP_OK)
    {
        fprintf(out, "  No answer on port 80 from %zu address%s.\n", http->attempts, http->attempts == 1 ? "" : "es");
    }
    else
    {
        print_field(out, "Endpoint", http->endpoint);
        print_field(out, "Status", http->status_line[0] != '\0' ? http->status_line : "unavailable");
        print_field(out, "Location", http->location[0] != '\0' ? http->location : "none");
        print_field(out, "Server", http->server[0] != '\0' ? http->server : "not disclosed");
    }
}

static void print_dnssec(FILE *out, const dns_info *dns)
{
    char text[FIELD_SIZE * 2];

    if (dns->ds.status == LOOKUP_SKIPPED)
    {
        return;
    }

    if (dns->ds.status != LOOKUP_OK || dns->dnskey.status != LOOKUP_OK)
    {
        print_field(out, "DNSSEC", "lookup failed");
    }
    else if (dns->ds.values.count == 0)
    {
        print_field(out, "DNSSEC", dns->dnskey.values.count > 0 ? "not signed at the parent (DNSKEY present, no DS)"
                                                                 : "not signed");
    }
    else if (dns->dnskey.values.count == 0)
    {
        print_field(out, "DNSSEC", "broken: DS at the parent, but no DNSKEY in the zone");
    }
    else
    {
        snprintf(text, sizeof(text), "signed (%zu DS, %zu DNSKEY)", dns->ds.values.count, dns->dnskey.values.count);
        print_field(out, "DNSSEC", text);
    }
}

static void print_dns(FILE *out, const domain_report *report)
{
    const dns_info *dns = &report->dns;
    char text[FIELD_SIZE * 3];

    print_section(out, "DNS");
    print_field(out, "Resolver", dns->resolver);
    print_record_set(out, "NS", &dns->ns);

    if (dns->mx.status == LOOKUP_FAILED || dns->mx.values.count == 0)
    {
        print_record_set(out, "MX", &dns->mx);
    }
    else
    {
        for (size_t i = 0; i < dns->mx.values.count; i++)
        {
            const char *entry = dns->mx.values.items[i];

            snprintf(text, sizeof(text), "%-4u%s", mx_priority(entry), mx_is_null(entry) ? ". (null MX: accepts no mail)" : mx_host(entry));
            print_field(out, i == 0 ? "MX" : "", text);
        }
    }

    /* SPF and DMARC are TXT records, shown on their own lines because they
     * are what the mail signals are based on. */
    const char **spf = xcalloc(dns->txt.values.count + 1, sizeof(*spf));
    const char **other = xcalloc(dns->txt.values.count + 1, sizeof(*other));
    size_t spf_count = 0;
    size_t other_count = 0;

    for (size_t i = 0; i < dns->txt.values.count; i++)
    {
        const char *value = dns->txt.values.items[i];

        if (strncasecmp(value, "v=spf1", 6) == 0)
        {
            spf[spf_count++] = value;
        }
        else
        {
            other[other_count++] = value;
        }
    }

    if (dns->txt.status == LOOKUP_FAILED)
    {
        print_field(out, "SPF", "unknown (TXT lookup failed)");
    }
    else if (spf_count == 0)
    {
        print_field(out, "SPF", "none");
    }
    else
    {
        print_list(out, "SPF", spf, spf_count);
    }

    print_record_set(out, "DMARC", &dns->dmarc);

    if (dns->dmarc.values.count > 0 && strcmp(dns->dmarc_name + strlen("_dmarc."), report->name) != 0)
    {
        snprintf(text, sizeof(text), "(inherited from %s)", dns->dmarc_name);
        print_field(out, "", text);
    }

    print_record_set(out, "CAA", &dns->caa);
    print_dnssec(out, dns);

    if (dns->soa_status == LOOKUP_FAILED)
    {
        print_field(out, "SOA", "lookup failed");
    }
    else if (!dns->has_soa)
    {
        print_field(out, "SOA", "none");
    }
    else
    {
        snprintf(text, sizeof(text), "%s, admin %s, serial %lu", dns->soa_primary, dns->soa_admin, dns->soa_serial);
        print_field(out, "SOA", text);
    }

    if (dns->txt.status == LOOKUP_FAILED)
    {
        print_field(out, "TXT", "lookup failed");
    }
    else if (other_count == 0)
    {
        print_field(out, "TXT", "none");
    }
    else
    {
        print_list(out, "TXT", other, other_count);
    }

    free(spf);
    free(other);
}

/* Registries write dates in many formats (2001-10-02T18:10:32Z, 20231116,
 * 15-Dec-1996); show them all as YYYY-MM-DD, or as-is when unparseable. */
static void print_whois_date(FILE *out, const char *label, const char *value)
{
    char date[64];

    if (value[0] == '\0')
    {
        print_field(out, label, "not listed");
        return;
    }

    whois_date(value, date, sizeof(date));
    print_field(out, label, date);
}

static void print_whois(FILE *out, const domain_report *report)
{
    const whois_info *whois = &report->whois;

    char title[32];

    snprintf(title, sizeof(title), "REGISTRATION (%s)", whois->protocol[0] != '\0' ? whois->protocol : "WHOIS");
    print_section(out, title);

    if (strcmp(whois->queried, report->name) != 0)
    {
        print_field(out, "Queried", whois->queried);
    }

    if (whois->status != LOOKUP_OK)
    {
        print_field(out, "Status", whois->note);
        return;
    }

    print_field(out, "Server", whois->server);

    if (!whois->registered)
    {
        print_field(out, "Status", "not registered (the registry has no record)");
        return;
    }

    print_field(out, "Registrar", whois->registrar[0] != '\0' ? whois->registrar : "not listed");
    print_whois_date(out, "Created", whois->created);
    print_whois_date(out, "Updated", whois->updated);
    print_whois_date(out, "Expires", whois->expires);
    print_field(out, "Registrant", whois->registrant[0] != '\0' ? whois->registrant : "not in the registry record");

    if (whois->abuse_email[0] != '\0')
    {
        print_field(out, "Abuse", whois->abuse_email);
    }

    if (whois->statuses.count > 0)
    {
        print_wrapped(out, 2, LABEL_WIDTH, "Status", (const char *const *)whois->statuses.items, whois->statuses.count);
    }

    if (whois->registrant_country[0] != '\0')
    {
        print_field(out, "Country", whois->registrant_country);
    }
}

/* Every query made, in order: its outcome, what was asked and of whom. The
 * HTTP request is the only one that reached the target itself. */
static void print_source(FILE *out, const observation *item)
{
    char asked[FIELD_SIZE * 2];
    char source[FIELD_SIZE + 32];
    int probe = strcmp(item->collector, SUBDOMAIN_PROBE_COLLECTOR) == 0;
    int reached_target = (strcmp(item->collector, HTTP_COLLECTOR) == 0 || strcmp(item->collector, TLS_COLLECTOR) == 0 ||
                          probe) &&
                         item->status != OBS_NOT_QUERIED;

    snprintf(asked, sizeof(asked), "%s %s", item->collector, item->query);
    snprintf(source, sizeof(source), "%s%s", item->source, reached_target ? " (target, from your IP)" : "");
    fprintf(out, "  %-12s %-34s %s\n", observation_status_name(item->status), asked, source);

    if (item->detail[0] != '\0')
    {
        print_paragraph(out, SOURCE_INDENT, "", item->detail);
    }
}

/* Every question asked, in order, with where it went and what came back:
 * the audit trail behind the report, shown with --raw. */
static void print_sources(FILE *out, const domain_report *report)
{
    print_section(out, "SOURCES");

    for (size_t i = 0; i < report->observations.count; i++)
    {
        print_source(out, &report->observations.items[i]);
    }
}

static void print_raw(FILE *out, const domain_report *report)
{
    if (report->whois.raw != NULL)
    {
        fprintf(out, "\nRAW %s RESPONSE (%s)\n\n%s\n", report->whois.protocol, report->whois.server, report->whois.raw);
    }

    if (report->http.raw != NULL)
    {
        fprintf(out, "\nRAW HTTP RESPONSE (%s)\n\n%s", report->http.endpoint, report->http.raw);
    }
}

/* "AS8075 Microsoft Azure"; for unknown networks the organization part of
 * the AS name ("NAME - Org, CC" -> "Org"). */
static void network_label(const subdomain_info *sub, char *out, size_t size)
{
    const char *provider = proxy_provider_name(sub->as_name);

    if (provider == NULL)
    {
        provider = cloud_provider_name(sub->as_name);
    }

    if (provider != NULL)
    {
        snprintf(out, size, "AS%s %s", sub->asn, provider);
        return;
    }

    const char *name = strstr(sub->as_name, " - ");
    name = name != NULL ? name + 3 : sub->as_name;

    size_t length = strlen(name);
    const char *comma = strrchr(name, ',');

    if (comma != NULL && strlen(comma) <= 4)
    {
        length = (size_t)(comma - name);
    }

    snprintf(out, size, "AS%s %.*s", sub->asn, (int)(length > 80 ? 80 : length), name);
}

/* "www" for "www.example.com" when the report is for example.com. */
static int short_name(const char *name, const char *domain)
{
    size_t name_length = strlen(name);
    size_t domain_length = strlen(domain);

    if (name_length > domain_length + 1 && strcmp(name + name_length - domain_length, domain) == 0 &&
        name[name_length - domain_length - 1] == '.')
    {
        return (int)(name_length - domain_length - 1);
    }

    return (int)name_length;
}

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

            int length = short_name(sub->name, report->name);

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
static const char *const probe_reasons[] = {"not in DNS", "timed out", "connection refused", "connection reset",
                                            "TLS handshake failed", "empty reply"};

/* The probe records "<reason>: <libcurl message>". */
static size_t reason_index(const subdomain_info *sub)
{
    size_t length = strcspn(sub->error, ":");

    for (size_t i = 0; i < COUNT(probe_reasons); i++)
    {
        if (strlen(probe_reasons[i]) == length && strncmp(sub->error, probe_reasons[i], length) == 0)
        {
            return i;
        }
    }

    return COUNT(probe_reasons);
}

/* Subdomains that were never probed (probed = 0), or probed without an
 * answer for `reason` (probed = 1). */
/* `state` picks the group; for SUBDOMAIN_NO_ANSWER `reason` narrows it to
 * one entry of probe_reasons (COUNT(probe_reasons) for the rest). */
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

        int length = short_name(sub->name, report->name);
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
        int length = short_name(sub->name, report->name);

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
                                         sub->protocol, name_width, short_name(sub->name, report->name), sub->name,
                                         ip_width, sub->ip, network);

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
            int length = short_name(sub->name, report->name);
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

        fprintf(out, "    %-*.*s  -> %s%s\n", width, short_name(sub->name, report->name), sub->name, sub->cname,
                sub->cname_dangling ? "  (target does not exist)" : "");
        shown++;
    }
}

static void print_subdomains(FILE *out, const domain_report *report, int full)
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

        for (size_t reason = 0; reason <= COUNT(probe_reasons); reason++)
        {
            print_name_group(out, report, reason < COUNT(probe_reasons) ? probe_reasons[reason] : "other errors",
                             SUBDOMAIN_NO_ANSWER, reason, limit);
        }
    }

    if (counts[SUBDOMAIN_NOT_PROBED] > 0)
    {
        fprintf(out, "\n  Not probed, over the probe limit (%zu):\n\n", counts[SUBDOMAIN_NOT_PROBED]);
        print_name_group(out, report, NULL, SUBDOMAIN_NOT_PROBED, 0, limit);
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

/* Without --full only the totals per target; each domain's section
 * already lists its subdomains. */
static void print_all_subdomains(FILE *out, const domain_report *reports, size_t count, int full)
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
            fprintf(out, "  %s (%zu subdomain%s):\n",
                    reports[i].name, reports[i].subdomains.count,
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
