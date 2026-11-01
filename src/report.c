#include "report.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "analysis.h"
#include "dns.h"
#include "model.h"
#include "http.h"
#include "tls.h"
#include "util.h"

#define RULE "================================================================================"
#define LABEL_WIDTH 14
#define SUB_LABEL_WIDTH 12
#define KIND_WIDTH 22
#define WRAP_WIDTH 64
#define REPORT_WIDTH 80
#define TAG_WIDTH 9
#define SOURCE_INDENT 15

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

    fprintf(out, "DOMINT REPORT\n\n");
    print_field(out, "Generated", generated);
    print_field(out, "Domains", domains);

    print_field(out, "Mode", options->passive ? "passive (the targets were not contacted)"
                                              : "active (one HTTP request to each target, from your IP)");
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

    if (report->observations.count > 0)
    {
        print_field(out, "Collected", report->observations.items[0].collected_at);
    }

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

    if (report->tls.status == LOOKUP_OK)
    {
        char certificate[FIELD_SIZE * 2];
        describe_certificate(&report->tls, certificate, sizeof(certificate));
        print_field(out, "Certificate", certificate);
    }

    if (report->services.count > 0)
    {
        print_wrapped(out, 2, LABEL_WIDTH, "Services", (const char *const *)report->services.items, report->services.count);
    }

    if (report->subdomain_status == LOOKUP_SKIPPED)
    {
        print_field(out, "Subdomains", "skipped (--no-subdomains)");
    }
    else if (report->subdomains.count == 0)
    {
        print_field(out, "Subdomains", "none found (passive OSINT)");
    }
    else
    {
        size_t live = 0;
        int probed = 0;

        for (size_t i = 0; i < report->subdomains.count; i++)
        {
            if (report->subdomains.items[i].probed)
            {
                probed = 1;

                if (report->subdomains.items[i].is_live)
                {
                    live++;
                }
            }
        }

        if (probed)
        {
            snprintf(text, sizeof(text), "%zu active online (%zu discovered)", live, report->subdomains.count);
        }
        else
        {
            snprintf(text, sizeof(text), "%zu discovered (passive OSINT, not probed)", report->subdomains.count);
        }

        print_field(out, "Subdomains", text);
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

static void print_tls(FILE *out, const domain_report *report)
{
    const tls_info *tls = &report->tls;

    print_section(out, "TLS CERTIFICATE");

    if (tls->not_queried)
    {
        fprintf(out, "  Not contacted (--passive).\n");
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

    print_field(out, "Endpoint", tls->endpoint);
    print_field(out, "Subject", tls->subject[0] != '\0' ? tls->subject : "unknown");
    print_field(out, "Issuer", tls->issuer[0] != '\0' ? tls->issuer : "unknown");
    snprintf(text, sizeof(text), "%s -> %s", tls->valid_from[0] != '\0' ? tls->valid_from : "?",
             tls->valid_until[0] != '\0' ? tls->valid_until : "?");
    print_field(out, "Valid", text);
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
static void print_sources(FILE *out, const domain_report *report)
{
    char asked[FIELD_SIZE * 2];
    char source[FIELD_SIZE + 32];

    print_section(out, "SOURCES");

    for (size_t i = 0; i < report->observations.count; i++)
    {
        const observation *item = &report->observations.items[i];
        int reached_target = (strcmp(item->collector, HTTP_COLLECTOR) == 0 || strcmp(item->collector, TLS_COLLECTOR) == 0) &&
                             item->status != OBS_NOT_QUERIED;

        snprintf(asked, sizeof(asked), "%s %s", item->collector, item->query);
        snprintf(source, sizeof(source), "%s%s", item->source, reached_target ? " (target, from your IP)" : "");
        fprintf(out, "  %-12s %-34s %s\n", observation_status_name(item->status), asked, source);

        if (item->detail[0] != '\0')
        {
            print_paragraph(out, SOURCE_INDENT, "", item->detail);
        }
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

/* Lists the subdomains that were probed without answer (probed = 1) or
 * that were never probed (probed = 0). */
static void print_unanswered(FILE *out, const domain_report *report, int probed)
{
    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (sub->probed != probed || (probed && sub->is_live))
        {
            continue;
        }

        if (sub->ip[0] != '\0')
        {
            fprintf(out, "    %s (%s)\n", sub->name, sub->ip);
        }
        else
        {
            fprintf(out, "    %s\n", sub->name);
        }
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

/* Addresses shared by two or more live subdomains: the same server or the
 * same front end, worth knowing when mapping the infrastructure. */
static void print_shared_addresses(FILE *out, const domain_report *report)
{
    const subdomain_list *subs = &report->subdomains;
    int header = 0;

    for (size_t i = 0; i < subs->count; i++)
    {
        const subdomain_info *first = &subs->items[i];
        size_t users = 0;
        int seen = 0;

        if (!first->is_live || first->ip[0] == '\0')
        {
            continue;
        }

        for (size_t j = 0; j < subs->count; j++)
        {
            if (subs->items[j].is_live && strcmp(subs->items[j].ip, first->ip) == 0)
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

        if (first->asn[0] != '\0')
        {
            char network[FIELD_SIZE];
            network_label(first, network, sizeof(network));
            fprintf(out, "    %s (%s), %zu subdomains: ", first->ip, network, users);
        }
        else
        {
            fprintf(out, "    %s, %zu subdomains: ", first->ip, users);
        }

        const char *separator = "";

        for (size_t j = i; j < subs->count; j++)
        {
            const subdomain_info *sub = &subs->items[j];

            if (sub->is_live && strcmp(sub->ip, first->ip) == 0)
            {
                fprintf(out, "%s%.*s", separator, short_name(sub->name, report->name), sub->name);
                separator = ", ";
            }
        }

        fprintf(out, "\n");
    }
}

static void print_subdomains(FILE *out, const domain_report *report)
{
    print_section(out, "SUBDOMAINS");

    if (report->subdomain_status == LOOKUP_SKIPPED)
    {
        fprintf(out, "  Skipped (--no-subdomains).\n");
        return;
    }

    if (report->subdomains.count == 0)
    {
        fprintf(out, "  None found in passive OSINT sources.\n");
        return;
    }

    size_t live = 0;
    int probed = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (sub->probed)
        {
            probed = 1;

            if (sub->is_live)
            {
                live++;
            }
        }
    }

    if (!probed)
    {
        fprintf(out, "  Discovered %zu subdomain%s via passive sources (CT logs / OSINT, not probed):\n\n",
                report->subdomains.count, report->subdomains.count == 1 ? "" : "s");
        print_unanswered(out, report, 0);
        return;
    }

    if (live == 0)
    {
        fprintf(out, "  None of the %zu discovered subdomains responded to HTTP/HTTPS.\n", report->subdomains.count);
    }
    else
    {
        fprintf(out, "  %zu active subdomain%s responding to HTTP/HTTPS (%zu discovered via OSINT):\n\n",
                live, live == 1 ? "" : "s", report->subdomains.count);
    }

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (sub->probed && sub->is_live)
        {
            char code_str[32];
            snprintf(code_str, sizeof(code_str), "[%ld]", sub->http_code);

            if (sub->ip[0] != '\0' && sub->asn[0] != '\0')
            {
                char network[FIELD_SIZE];
                network_label(sub, network, sizeof(network));
                fprintf(out, "    %-6s %s://%s (%s, %s)\n", code_str, sub->protocol, sub->name, sub->ip, network);
            }
            else if (sub->ip[0] != '\0')
            {
                fprintf(out, "    %-6s %s://%s (%s)\n", code_str, sub->protocol, sub->name, sub->ip);
            }
            else
            {
                fprintf(out, "    %-6s %s://%s\n", code_str, sub->protocol, sub->name);
            }
        }
    }

    print_shared_addresses(out, report);

    size_t silent = 0;
    size_t skipped = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        if (!report->subdomains.items[i].probed)
        {
            skipped++;
        }
        else if (!report->subdomains.items[i].is_live)
        {
            silent++;
        }
    }

    if (silent > 0)
    {
        fprintf(out, "\n  No HTTP/HTTPS response (%zu):\n\n", silent);
        print_unanswered(out, report, 1);
    }

    if (skipped > 0)
    {
        fprintf(out, "\n  Not probed, over the probe limit (%zu):\n\n", skipped);
        print_unanswered(out, report, 0);
    }
}

static void print_domain(FILE *out, const domain_report *report, const report_options *options)
{
    fprintf(out, "\n\n%s\n%s\n%s\n", RULE, report->name, RULE);

    print_summary(out, report);
    print_signals(out, report);

    if (options->full)
    {
        print_addresses(out, report);
        print_http(out, report);
        print_tls(out, report);
        print_dns(out, report);
        print_whois(out, report);
        print_sources(out, report);

        if (options->raw)
        {
            print_raw(out, report);
        }
    }

    print_subdomains(out, report);
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

static void print_all_subdomains(FILE *out, const domain_report *reports, size_t count)
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

                if (sub->probed && sub->is_live)
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
        print_correlation(out, reports, count, links);
        print_all_subdomains(out, reports, count);
    }
}
