/* The detail sections of the text report: addresses, HTTP, TLS, DNS,
 * registration, reputation, lookalikes, sources and raw answers. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "collect/dns.h"
#include "collect/http.h"
#include "collect/subdomain.h"
#include "collect/tls.h"
#include "core/dates.h"
#include "output/report_internal.h"
#include "support/util.h"

/* "listed: ThreatFox (2 IOCs); URLhaus (3 URLs, 1 online)" or "no listings
 * in OTX, URLhaus, ThreatFox". */
void describe_reputation(const reputation_info *rep, char *out, size_t size)
{
    char listed[FIELD_SIZE * 2] = "";
    char asked[FIELD_SIZE] = "";
    char part[FIELD_SIZE];

    if (rep->threatfox_status == LOOKUP_OK)
    {
        report_append(asked, sizeof(asked), ", ", "ThreatFox");

        if (rep->threatfox_iocs > 0)
        {
            snprintf(part, sizeof(part), "ThreatFox (%ld IOC%s)", rep->threatfox_iocs, rep->threatfox_iocs == 1 ? "" : "s");
            report_append(listed, sizeof(listed), "; ", part);
        }
    }

    if (rep->urlhaus_status == LOOKUP_OK)
    {
        report_append(asked, sizeof(asked), ", ", "URLhaus");

        if (rep->urlhaus_urls > 0)
        {
            snprintf(part, sizeof(part), "URLhaus (%ld URL%s, %ld online)", rep->urlhaus_urls,
                     rep->urlhaus_urls == 1 ? "" : "s", rep->urlhaus_online);
            report_append(listed, sizeof(listed), "; ", part);
        }

        if (report_is_listed(rep->spamhaus_dbl))
        {
            report_append(listed, sizeof(listed), "; ", "Spamhaus DBL");
        }

        if (report_is_listed(rep->surbl))
        {
            report_append(listed, sizeof(listed), "; ", "SURBL");
        }
    }

    if (rep->otx_status == LOOKUP_OK)
    {
        report_append(asked, sizeof(asked), ", ", "OTX");

        if (rep->otx_pulses > 0 && !rep->otx_allowlisted)
        {
            snprintf(part, sizeof(part), "OTX (%ld pulse%s)", rep->otx_pulses, rep->otx_pulses == 1 ? "" : "s");
            report_append(listed, sizeof(listed), "; ", part);
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

void print_reputation(FILE *out, const domain_report *report)
{
    const reputation_info *rep = &report->reputation;
    char text[FIELD_SIZE * 3];
    char names[FIELD_SIZE * 2] = "";

    print_section(out, "REPUTATION");

    for (size_t i = 0; i < rep->threatfox_malware.count; i++)
    {
        report_append(names, sizeof(names), ", ", rep->threatfox_malware.items[i]);
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
        report_append(names, sizeof(names), "; ", rep->otx_pulse_names.items[i]);
    }

    snprintf(text, sizeof(text), "%ld pulse%s%s%s%s", rep->otx_pulses, rep->otx_pulses == 1 ? "" : "s",
             names[0] != '\0' ? ": " : "", names, rep->otx_allowlisted ? " (marked known-good)" : "");
    print_reputation_source(out, "OTX", rep->otx_status, 0, text);
}

void describe_lookalikes(const lookalike_list *list, char *out, size_t size)
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
void print_lookalikes(FILE *out, const domain_report *report)
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

void print_addresses(FILE *out, const domain_report *report)
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

void describe_certificate(const tls_info *tls, char *out, size_t size)
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

void print_tls(FILE *out, const domain_report *report)
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

void print_http(FILE *out, const domain_report *report)
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

void print_dns(FILE *out, const domain_report *report)
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

void print_whois(FILE *out, const domain_report *report)
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
void print_sources(FILE *out, const domain_report *report)
{
    print_section(out, "SOURCES");

    for (size_t i = 0; i < report->observations.count; i++)
    {
        print_source(out, &report->observations.items[i]);
    }
}

void print_raw(FILE *out, const domain_report *report)
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
