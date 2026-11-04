#include "output/report.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "core/gaps.h"
#include "support/json.h"
#include "core/model.h"
#include "collect/tls.h"

#define JSON_MAX_NESTING 16

/* A small streaming writer: two-space indentation, one value per line. */
typedef struct
{
    FILE *out;
    int depth;
    int empty[JSON_MAX_NESTING];
} writer;

static void newline(writer *w)
{
    fprintf(w->out, "\n%*s", w->depth * 2, "");
}

static void write_string(writer *w, const char *text)
{
    json_write_string(w->out, text);
}

/* Starts the next member or element: the comma, the line, and the key. */
static void next(writer *w, const char *key)
{
    if (!w->empty[w->depth])
    {
        fputc(',', w->out);
    }

    w->empty[w->depth] = 0;
    newline(w);

    if (key != NULL)
    {
        write_string(w, key);
        fputs(": ", w->out);
    }
}

static void open_value(writer *w, const char *key, char bracket)
{
    next(w, key);
    fputc(bracket, w->out);

    if (w->depth + 1 < JSON_MAX_NESTING)
    {
        w->depth++;
    }

    w->empty[w->depth] = 1;
}

static void close_value(writer *w, char bracket)
{
    int was_empty = w->empty[w->depth];

    w->depth--;

    if (!was_empty)
    {
        newline(w);
    }

    fputc(bracket, w->out);
}

static void put_string(writer *w, const char *key, const char *value)
{
    next(w, key);

    if (value == NULL)
    {
        fputs("null", w->out);
    }
    else
    {
        write_string(w, value);
    }
}

/* Empty text is written as null: "not known" rather than "known to be ''". */
static void put_text(writer *w, const char *key, const char *value)
{
    put_string(w, key, value != NULL && value[0] != '\0' ? value : NULL);
}

static void put_long(writer *w, const char *key, long value)
{
    next(w, key);
    fprintf(w->out, "%ld", value);
}

static void put_bool(writer *w, const char *key, int value)
{
    next(w, key);
    fputs(value ? "true" : "false", w->out);
}

static void put_list(writer *w, const char *key, const string_list *list)
{
    open_value(w, key, '[');

    for (size_t i = 0; i < list->count; i++)
    {
        put_string(w, NULL, list->items[i]);
    }

    close_value(w, ']');
}

static const char *status_name(lookup_status status)
{
    return status == LOOKUP_OK ? "ok" : status == LOOKUP_FAILED ? "failed" : "skipped";
}

static const char *severity_name(severity level)
{
    static const char *const names[] = {"info", "low", "medium", "high"};
    return names[level];
}

static const char *state_name(subdomain_state state)
{
    static const char *const names[] = {"not_probed", "no_answer", "cdn_edge_only", "online"};
    return names[state];
}

/* Certificate dates as ISO 8601, like every other date in the output. */
static void put_certificate_date(writer *w, const char *key, const char *text)
{
    time_t when;
    char iso[32];
    struct tm parts;

    if (tls_parse_time(text, &when) != 0)
    {
        put_text(w, key, text);
        return;
    }

    gmtime_r(&when, &parts);
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &parts);
    put_string(w, key, iso);
}

static void put_record_set(writer *w, const char *key, const record_set *set)
{
    if (set->status == LOOKUP_FAILED)
    {
        put_string(w, key, NULL);
        return;
    }

    put_list(w, key, &set->values);
}

static void write_registration(writer *w, const domain_report *report)
{
    const whois_info *whois = &report->whois;

    open_value(w, "registration", '{');
    put_string(w, "status", status_name(whois->status));
    put_text(w, "protocol", whois->protocol);
    put_text(w, "server", whois->server);
    put_bool(w, "registered", whois->registered);
    put_text(w, "registrar", whois->registrar);
    put_text(w, "created", whois->created);
    put_text(w, "updated", whois->updated);
    put_text(w, "expires", whois->expires);
    put_text(w, "registrant", whois->registrant);
    put_text(w, "registrant_country", whois->registrant_country);
    put_bool(w, "privacy_service", whois->privacy);
    put_text(w, "abuse_email", whois->abuse_email);
    put_list(w, "statuses", &whois->statuses);
    close_value(w, '}');
}

static void write_addresses(writer *w, const domain_report *report)
{
    put_text(w, "hosting", report->hosting);
    open_value(w, "addresses", '[');

    for (size_t i = 0; i < report->address_count; i++)
    {
        const address_info *address = &report->addresses[i];

        open_value(w, NULL, '{');
        put_string(w, "ip", address->ip);
        put_text(w, "ptr", address->ptr);

        if (address->asn_status == LOOKUP_OK && address->announced)
        {
            put_text(w, "asn", address->asn);
            put_text(w, "as_name", address->as_name);
            put_text(w, "prefix", address->prefix);
            put_text(w, "country", address->country);
            put_text(w, "registry", address->registry);
        }

        close_value(w, '}');
    }

    close_value(w, ']');
}

static void write_http(writer *w, const domain_report *report)
{
    const http_info *http = &report->http;

    open_value(w, "http", '{');
    put_string(w, "status", http->not_queried ? "not_contacted" : status_name(http->status));
    put_text(w, "endpoint", http->endpoint);
    put_text(w, "status_line", http->status_line);
    put_text(w, "location", http->location);
    put_text(w, "server", http->server);
    close_value(w, '}');
}

static void write_tls(writer *w, const domain_report *report)
{
    const tls_info *tls = &report->tls;

    open_value(w, "tls", '{');
    put_string(w, "status", tls->not_queried ? "not_contacted" : status_name(tls->status));
    put_text(w, "endpoint", tls->endpoint);
    put_text(w, "subject", tls->subject);
    put_text(w, "issuer", tls->issuer);
    put_certificate_date(w, "valid_from", tls->valid_from);
    put_certificate_date(w, "valid_until", tls->valid_until);
    put_bool(w, "trusted", tls->status == LOOKUP_OK && tls->trusted);
    put_text(w, "trust_error", tls->trust_error);
    put_text(w, "serial", tls->serial);
    put_list(w, "names", &tls->names);
    close_value(w, '}');
}

static void write_dns(writer *w, const domain_report *report)
{
    const dns_info *dns = &report->dns;

    open_value(w, "dns", '{');
    put_text(w, "resolver", dns->resolver);
    put_text(w, "provider", report->dns_provider);
    put_text(w, "mail_provider", report->mail_provider);
    put_record_set(w, "ns", &dns->ns);
    put_record_set(w, "mx", &dns->mx);
    put_record_set(w, "txt", &dns->txt);
    put_record_set(w, "dmarc", &dns->dmarc);
    put_record_set(w, "caa", &dns->caa);
    put_record_set(w, "ds", &dns->ds);
    put_record_set(w, "dnskey", &dns->dnskey);

    if (dns->has_soa)
    {
        open_value(w, "soa", '{');
        put_text(w, "primary", dns->soa_primary);
        put_text(w, "admin", dns->soa_admin);
        put_long(w, "serial", (long)dns->soa_serial);
        close_value(w, '}');
    }

    put_list(w, "services", &report->services);
    close_value(w, '}');
}

static void write_reputation(writer *w, const domain_report *report)
{
    const reputation_info *rep = &report->reputation;

    open_value(w, "reputation", '{');

    open_value(w, "otx", '{');
    put_string(w, "status", status_name(rep->otx_status));
    put_long(w, "pulses", rep->otx_pulses);
    put_list(w, "pulse_names", &rep->otx_pulse_names);
    put_bool(w, "known_good", rep->otx_allowlisted);
    close_value(w, '}');

    open_value(w, "urlhaus", '{');
    put_string(w, "status", rep->urlhaus_not_queried ? "needs_ABUSECH_AUTH_KEY" : status_name(rep->urlhaus_status));
    put_long(w, "urls", rep->urlhaus_urls);
    put_long(w, "urls_online", rep->urlhaus_online);
    put_list(w, "threats", &rep->urlhaus_threats);
    put_text(w, "spamhaus_dbl", rep->spamhaus_dbl);
    put_text(w, "surbl", rep->surbl);
    close_value(w, '}');

    open_value(w, "threatfox", '{');
    put_string(w, "status", rep->threatfox_not_queried ? "needs_ABUSECH_AUTH_KEY" : status_name(rep->threatfox_status));
    put_long(w, "iocs", rep->threatfox_iocs);
    put_list(w, "malware", &rep->threatfox_malware);
    close_value(w, '}');

    close_value(w, '}');
}

static void write_subdomains(writer *w, const domain_report *report)
{
    open_value(w, "subdomains", '{');
    put_string(w, "status", status_name(report->subdomain_status));
    put_text(w, "ct_first_seen", report->ct_first_seen);
    put_long(w, "discovered", (long)report->subdomains.count);
    open_value(w, "items", '[');

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];
        subdomain_state state = subdomain_state_of(sub);

        open_value(w, NULL, '{');
        put_string(w, "name", sub->name);
        put_string(w, "state", state_name(state));
        put_text(w, "cname", sub->cname);

        if (sub->cname[0] != '\0')
        {
            put_bool(w, "cname_target_missing", sub->cname_dangling);
        }

        if (state == SUBDOMAIN_ONLINE || state == SUBDOMAIN_EDGE_ONLY)
        {
            put_long(w, "http_code", sub->http_code);
            put_text(w, "protocol", sub->protocol);
            put_text(w, "title", sub->title);
            put_text(w, "server", sub->server);
            put_text(w, "location", sub->location);
        }

        if (state != SUBDOMAIN_NOT_PROBED)
        {
            put_text(w, "ip", sub->ip);
            put_text(w, "asn", sub->asn);
            put_text(w, "as_name", sub->as_name);
        }

        if (state == SUBDOMAIN_NO_ANSWER)
        {
            /* "timed out: <libcurl message>" -> "timed out". */
            char reason[FIELD_SIZE];
            snprintf(reason, sizeof(reason), "%.*s", (int)strcspn(sub->error, ":"), sub->error);
            put_text(w, "reason", reason);
        }

        close_value(w, '}');
    }

    close_value(w, ']');
    close_value(w, '}');
}

static void write_lookalikes(writer *w, const domain_report *report)
{
    const lookalike_list *list = &report->lookalikes;

    open_value(w, "lookalikes", '{');
    put_string(w, "status", status_name(list->status));
    put_long(w, "checked", (long)list->checked);
    put_long(w, "unanswered", (long)list->unanswered);
    open_value(w, "registered", '[');

    for (size_t i = 0; i < list->count; i++)
    {
        const lookalike_info *item = &list->items[i];

        open_value(w, NULL, '{');
        put_string(w, "name", item->name);
        put_string(w, "technique", item->technique);
        put_bool(w, "receives_mail", item->has_mail);
        put_bool(w, "likely_owner", item->likely_defensive);
        put_bool(w, "parked", item->parked);
        put_bool(w, "dns_fails", item->dns_fails);
        put_list(w, "addresses", &item->addresses);
        put_list(w, "nameservers", &item->nameservers);
        close_value(w, '}');
    }

    close_value(w, ']');
    close_value(w, '}');
}

/* The values worth feeding to a blocklist or a threat-intelligence
 * platform: the domain, the subdomains that serve something, and the
 * addresses behind them. */
static void write_indicators(writer *w, const domain_report *report)
{
    string_list domains = {0};
    string_list ips = {0};

    string_list_add(&domains, report->name);

    for (size_t i = 0; i < report->address_count; i++)
    {
        string_list_add_unique(&ips, report->addresses[i].ip);
    }

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (subdomain_state_of(sub) == SUBDOMAIN_ONLINE)
        {
            string_list_add_unique(&domains, sub->name);

            if (sub->ip[0] != '\0')
            {
                string_list_add_unique(&ips, sub->ip);
            }
        }
    }

    string_list lookalikes = {0};

    for (size_t i = 0; i < report->lookalikes.count; i++)
    {
        if (!report->lookalikes.items[i].likely_defensive)
        {
            string_list_add(&lookalikes, report->lookalikes.items[i].name);
        }
    }

    open_value(w, "indicators", '{');
    put_list(w, "domains", &domains);
    put_list(w, "ips", &ips);
    put_list(w, "lookalike_domains", &lookalikes);
    close_value(w, '}');

    string_list_free(&lookalikes);

    string_list_free(&domains);
    string_list_free(&ips);
}

static void write_gaps(writer *w, const domain_report *report)
{
    open_value(w, "gaps", '[');

    for (size_t i = 0; i < report->observations.count; i++)
    {
        const observation *item = &report->observations.items[i];
        int area = gap_area_of(report, item);
        char what[DOMAIN_SIZE + 16];
        char why[FIELD_SIZE];

        if (area < 0)
        {
            continue;
        }

        gap_describe(item, (gap_area)area, what, sizeof(what), why, sizeof(why));
        open_value(w, NULL, '{');
        put_string(w, "area", gap_label((gap_area)area));
        put_string(w, "source", what);
        put_string(w, "reason", why);
        close_value(w, '}');
    }

    close_value(w, ']');
}

static void write_domain(writer *w, const domain_report *report)
{
    open_value(w, NULL, '{');
    put_string(w, "name", report->name);
    put_text(w, "collected_at", report->observations.count > 0 ? report->observations.items[0].collected_at : "");

    open_value(w, "signals", '[');

    for (size_t i = 0; i < report->finding_count; i++)
    {
        open_value(w, NULL, '{');
        put_string(w, "severity", severity_name(report->findings[i].level));
        put_string(w, "text", report->findings[i].text);
        close_value(w, '}');
    }

    close_value(w, ']');
    write_gaps(w, report);

    if (report_has(report, MODULE_WHOIS))
    {
        write_registration(w, report);
    }

    if (report_has(report, MODULE_ADDRESSES))
    {
        write_addresses(w, report);
    }

    if (report_has(report, MODULE_HTTP))
    {
        write_http(w, report);
    }

    if (report_has(report, MODULE_TLS))
    {
        write_tls(w, report);
    }

    if (report_has(report, MODULE_DNS))
    {
        write_dns(w, report);
    }

    if (report_has(report, MODULE_REPUTATION))
    {
        write_reputation(w, report);
    }

    if (report_has(report, MODULE_SUBDOMAINS))
    {
        write_subdomains(w, report);
    }

    if (report_has(report, MODULE_LOOKALIKES))
    {
        write_lookalikes(w, report);
    }

    write_indicators(w, report);
    close_value(w, '}');
}

void print_report_json(FILE *out, const domain_report *reports, size_t count, const correlation *links,
                       const report_options *options)
{
    static const struct
    {
        unsigned bit;
        const char *name;
    } module_names[] = {{MODULE_ADDRESSES, "addresses"}, {MODULE_DNS, "dns"},       {MODULE_WHOIS, "whois"},
                        {MODULE_TLS, "tls"},             {MODULE_HTTP, "http"},     {MODULE_SUBDOMAINS, "subdomains"},
                        {MODULE_REPUTATION, "reputation"}, {MODULE_LOOKALIKES, "lookalikes"}};
    static const char *const strengths[] = {"weak", "medium", "strong"};
    writer w = {out, 0, {1}};
    unsigned modules = options->modules != 0 ? options->modules : MODULE_DEFAULT;
    char generated[32];
    time_t now = time(NULL);
    struct tm parts;

    gmtime_r(&now, &parts);
    strftime(generated, sizeof(generated), "%Y-%m-%dT%H:%M:%SZ", &parts);

    fputc('{', out);
    w.depth = 1;
    w.empty[1] = 1;
    put_string(&w, "tool", "domint");
    put_string(&w, "generated", generated);
    put_string(&w, "mode", options->passive ? "passive" : "active");

    open_value(&w, "modules", '[');

    for (size_t i = 0; i < sizeof(module_names) / sizeof(module_names[0]); i++)
    {
        if (modules & module_names[i].bit)
        {
            put_string(&w, NULL, module_names[i].name);
        }
    }

    close_value(&w, ']');
    open_value(&w, "domains", '[');

    for (size_t i = 0; i < count; i++)
    {
        write_domain(&w, &reports[i]);
    }

    close_value(&w, ']');

    if (count > 1 && links != NULL)
    {
        open_value(&w, "shared_indicators", '[');

        for (size_t i = 0; i < links->indicator_count; i++)
        {
            const shared_indicator *item = &links->indicators[i];

            open_value(&w, NULL, '{');
            put_string(&w, "strength", strengths[item->strength]);
            put_string(&w, "kind", item->kind);
            put_string(&w, "value", item->value);
            open_value(&w, "domains", '[');

            for (size_t j = 0; j < item->domain_count; j++)
            {
                put_string(&w, NULL, reports[item->domains[j]].name);
            }

            close_value(&w, ']');
            close_value(&w, '}');
        }

        close_value(&w, ']');
    }

    w.depth = 0;
    fputs("\n}\n", out);
}
