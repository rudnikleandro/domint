#include "report.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "analysis.h"
#include "dns.h"
#include "http.h"
#include "memory.h"

#define RULE "================================================================================"
#define LABEL_WIDTH 14
#define SUB_LABEL_WIDTH 12
#define PARTY_WIDTH 30
#define KIND_WIDTH 22
#define WRAP_WIDTH 64
#define REPORT_WIDTH 80
#define TAG_WIDTH 9

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

static void print_field(FILE *out, const char *label, const char *value)
{
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

/* Word-wraps `text` to the report width, with continuation lines indented
 * under the first word: "  [MEDIUM] text ...". */
static void print_paragraph(FILE *out, const char *tag, const char *text)
{
    const int indent = 2 + TAG_WIDTH;
    int column = fprintf(out, "  %-*s", TAG_WIDTH, tag);

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

    if (whois->status != LOOKUP_OK)
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

    fprintf(out, "EXPOSUREPROOF REPORT\n\n");
    print_field(out, "Generated", generated);
    print_field(out, "Domains", domains);

    if (options->passive)
    {
        print_field(out, "Mode", "passive: no connection was made to the targets");
    }
    else
    {
        print_field(out, "Mode", "active: one HTTP request per domain went to the target");
        print_field(out, "", "from your IP (User-Agent " HTTP_USER_AGENT ")");
    }

    print_field(out, "Note", "DNS queries reach the targets' nameservers through the");
    print_field(out, "", "resolver, not from your IP; WHOIS and ASN lookups only");
    print_field(out, "", "reach registries.");
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

static void print_summary(FILE *out, const domain_report *report)
{
    char text[FIELD_SIZE * 2];

    print_section(out, "SUMMARY");

    describe_signals(report, text, sizeof(text));
    print_field(out, "Signals", text);

    const whois_info *whois = &report->whois;

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

    print_field(out, "Hosting", report->hosting[0] != '\0' ? report->hosting
                                : report->address_count > 0 ? "unknown"
                                                            : "no addresses");
    print_field(out, "DNS provider", report->dns_provider[0] != '\0' ? report->dns_provider : "unknown");
    print_field(out, "Mail", report->mail_provider[0] != '\0' ? report->mail_provider : "no MX records");

    if (report->services.count > 0)
    {
        print_wrapped(out, 2, LABEL_WIDTH, "Services", (const char *const *)report->services.items, report->services.count);
    }
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
        print_paragraph(out, severity_tag(report->findings[i].level), report->findings[i].text);
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

static void print_http(FILE *out, const domain_report *report, const report_options *options)
{
    const http_info *http = &report->http;

    print_section(out, "HTTP");

    if (options->passive)
    {
        fprintf(out, "  Not contacted (--passive).\n");
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

    print_section(out, "WHOIS");

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

    if (whois->registrant_country[0] != '\0')
    {
        print_field(out, "Country", whois->registrant_country);
    }
}

static void print_contact(FILE *out, const char *party, const char *purpose)
{
    if ((int)strlen(party) >= PARTY_WIDTH)
    {
        fprintf(out, "  %s\n  %-*s%s\n", party, PARTY_WIDTH, "", purpose);
    }
    else
    {
        fprintf(out, "  %-*s%s\n", PARTY_WIDTH, party, purpose);
    }
}

/* Who learned about this investigation, and from where. */
static void print_contacted(FILE *out, const domain_report *report, const report_options *options)
{
    const whois_info *whois = &report->whois;
    char purpose[FIELD_SIZE * 2];
    size_t asn_lookups = 0;

    print_section(out, "CONTACTED");

    if (strstr(report->dns.resolver, "--resolver") != NULL)
    {
        print_contact(out, "system resolver", "A/AAAA and PTR lookups");
        print_contact(out, report->dns.resolver, "NS, MX, TXT, SOA, CAA and DMARC lookups");
    }
    else
    {
        print_contact(out, report->dns.resolver, "all DNS lookups");
    }

    if (whois->iana_queried)
    {
        const char *dot = strrchr(whois->queried, '.');
        snprintf(purpose, sizeof(purpose), "WHOIS server for .%s", dot != NULL ? dot + 1 : whois->queried);
        print_contact(out, "whois.iana.org", purpose);
    }

    if (whois->server[0] != '\0')
    {
        snprintf(purpose, sizeof(purpose), "registration of %s", whois->queried);
        print_contact(out, whois->server, purpose);
    }

    for (size_t i = 0; i < report->address_count; i++)
    {
        asn_lookups += report->addresses[i].asn_status != LOOKUP_SKIPPED;
    }

    if (asn_lookups > 0)
    {
        snprintf(purpose, sizeof(purpose), "network of %zu address%s", asn_lookups, asn_lookups == 1 ? "" : "es");
        print_contact(out, "whois.cymru.com", purpose);
    }

    if (options->passive)
    {
        print_contact(out, "target", "not contacted (--passive)");
    }
    else if (report->http.status == LOOKUP_OK)
    {
        print_contact(out, report->http.endpoint, "HTTP request from your IP (target)");
    }
    else if (report->http.attempts > 0)
    {
        snprintf(purpose, sizeof(purpose), "%zu connection attempt%s from your IP on port 80", report->http.attempts,
                 report->http.attempts == 1 ? "" : "s");
        print_contact(out, "target", purpose);
    }
}

static void print_raw(FILE *out, const domain_report *report)
{
    if (report->whois.raw != NULL)
    {
        fprintf(out, "\nRAW WHOIS RESPONSE (%s)\n\n%s\n", report->whois.server, report->whois.raw);
    }

    if (report->http.raw != NULL)
    {
        fprintf(out, "\nRAW HTTP RESPONSE (%s)\n\n%s", report->http.endpoint, report->http.raw);
    }
}

static void print_domain(FILE *out, const domain_report *report, const report_options *options)
{
    fprintf(out, "\n\n%s\n%s\n%s\n", RULE, report->name, RULE);

    print_summary(out, report);
    print_signals(out, report);
    print_addresses(out, report);
    print_http(out, report, options);
    print_dns(out, report);
    print_whois(out, report);
    print_contacted(out, report, options);

    if (options->raw)
    {
        print_raw(out, report);
    }
}

static const char *strength_title(link_strength strength)
{
    switch (strength)
    {
    case LINK_STRONG:
        return "STRONG LINKS";
    case LINK_MEDIUM:
        return "MEDIUM LINKS";
    default:
        return "WEAK LINKS (usually a common provider)";
    }
}

static void print_correlation(FILE *out, const domain_report *reports, size_t count, const correlation *links)
{
    const char **names = xcalloc(count, sizeof(*names));

    fprintf(out, "\n\n%s\nCORRELATION\n%s\n\n", RULE, RULE);
    fprintf(out, "Indicators found on two or more of the %zu domains. Strong links rarely occur\n", count);
    fprintf(out, "between unrelated domains; weak links usually mean a shared provider.\n");

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

    print_section(out, "CLUSTERS (domains joined by strong links)");

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
        print_correlation(out, reports, count, links);
    }
}
