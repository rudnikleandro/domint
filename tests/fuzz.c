/* A mutation fuzzer for everything that reads data from the network.
 *
 * Apple's clang ships no libFuzzer, so this is a small stand-alone one: it
 * starts from valid inputs (the fixtures and samples below), corrupts them
 * (bit flips, inserted and deleted bytes, truncation, splices, structural
 * tokens, terminal escapes) and feeds the result to each parser and to the
 * report writers. Built with ASan and UBSan by `make fuzz`, any memory error
 * or undefined behaviour aborts the run; the input that caused it is saved
 * as build/fuzz-crash-<target>.bin first.
 *
 * Usage: fuzz [iterations per target] [seed] */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/analysis.h"
#include "collect/asn.h"
#include "collect/dns.h"
#include "support/domain.h"
#include "collect/http.h"
#include "support/json.h"
#include "collect/lookalike.h"
#include "core/model.h"
#include "collect/rdap.h"
#include "output/report.h"
#include "collect/reputation.h"
#include "collect/subdomain.h"
#include "collect/tls.h"
#include "support/util.h"
#include "collect/whois.h"

#define MAX_INPUT (64 * 1024)
#define MAX_SEEDS 64

void __sanitizer_set_death_callback(void (*callback)(void));

static unsigned char input[MAX_INPUT + 1];
static size_t input_length;
static const char *target_name = "none";
static uint64_t rng_state;

static void save_crash(void)
{
    char path[128];
    snprintf(path, sizeof(path), "build/fuzz-crash-%s.bin", target_name);

    FILE *out = fopen(path, "wb");

    if (out != NULL)
    {
        fwrite(input, 1, input_length, out);
        fclose(out);
        fprintf(stderr, "\nfuzz: input saved to %s (%zu bytes)\n", path, input_length);
    }
}

static uint64_t next_random(void)
{
    /* xorshift64*: fast, and reproducible from the seed. */
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1DULL;
}

static size_t below(size_t limit)
{
    return limit == 0 ? 0 : (size_t)(next_random() % limit);
}

typedef struct
{
    unsigned char *data;
    size_t length;
} seed;

static seed seeds[MAX_SEEDS];
static size_t seed_count;

static void add_seed(const void *data, size_t length)
{
    if (seed_count < MAX_SEEDS && length <= MAX_INPUT)
    {
        seeds[seed_count].data = xcalloc(length + 1, 1);
        memcpy(seeds[seed_count].data, data, length);
        seeds[seed_count].length = length;
        seed_count++;
    }
}

static void add_seed_text(const char *text)
{
    add_seed(text, strlen(text));
}

static void add_seed_file(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "tests/fixtures/%s", name);

    FILE *file = fopen(path, "rb");

    if (file == NULL)
    {
        return;
    }

    unsigned char *buffer = xcalloc(MAX_INPUT, 1);
    size_t length = fread(buffer, 1, MAX_INPUT, file);

    fclose(file);
    add_seed(buffer, length);
    free(buffer);
}

/* Fragments that make parsers take unusual paths. */
static const char *const tokens[] = {
    "{", "}", "[", "]", "\"", "\\", "\\u0000", "\\u001b[2J", "\\ud800", ":", ",", "null", "true", "-1e999",
    "99999999999999999999", "\r\n", "\r\n\r\n", "\n", "\x1b]0;owned\x07", "\x1b[31m", "%s%n%x", "\xff\xfe",
    "\xc3", "\xf0\x9f", "HTTP/1.1 ", "HTTP/1.1 100 Continue\r\n\r\n", "<title>", "</title>", "Server: ",
    "Location: ", "DNS:", "X509v3 Subject Alternative Name:", "\"not_before\":\"", "\"name_value\":\"",
    "Domain Name: ", "Creation Date: ", "Registrar: ", "Domain Status: ", "|", "\xc0\x0c", "\xc0\x00",
};

static void mutate(void)
{
    const seed *base = &seeds[below(seed_count)];

    memcpy(input, base->data, base->length);
    input_length = base->length;

    size_t rounds = 1 + below(8);

    for (size_t r = 0; r < rounds; r++)
    {
        size_t at = below(input_length + 1);

        switch (below(8))
        {
        case 0: /* flip a bit */
            if (input_length > 0)
            {
                input[below(input_length)] ^= (unsigned char)(1u << below(8));
            }
            break;
        case 1: /* random byte */
            if (input_length > 0)
            {
                input[below(input_length)] = (unsigned char)next_random();
            }
            break;
        case 2: /* delete a run */
            if (input_length > 0)
            {
                size_t count = 1 + below(input_length - at < 64 ? input_length - at + 1 : 64);
                count = at + count > input_length ? input_length - at : count;
                memmove(input + at, input + at + count, input_length - at - count);
                input_length -= count;
            }
            break;
        case 3: /* truncate */
            input_length = below(input_length + 1);
            break;
        case 4: /* insert a token */
        {
            const char *token = tokens[below(sizeof(tokens) / sizeof(tokens[0]))];
            size_t count = strlen(token);

            if (input_length + count <= MAX_INPUT)
            {
                memmove(input + at + count, input + at, input_length - at);
                memcpy(input + at, token, count);
                input_length += count;
            }
            break;
        }
        case 5: /* repeat a byte many times: long fields, deep nesting */
        {
            size_t count = 1 + below(4096);
            unsigned char byte = input_length > 0 ? input[below(input_length)] : '[';

            if (input_length + count <= MAX_INPUT)
            {
                memmove(input + at + count, input + at, input_length - at);
                memset(input + at, byte, count);
                input_length += count;
            }
            break;
        }
        case 6: /* splice in part of another seed */
        {
            const seed *other = &seeds[below(seed_count)];
            size_t from = below(other->length + 1);
            size_t count = below(other->length - from + 1);

            if (input_length + count <= MAX_INPUT)
            {
                memmove(input + at + count, input + at, input_length - at);
                memcpy(input + at, other->data + from, count);
                input_length += count;
            }
            break;
        }
        default: /* NUL in the middle */
            if (input_length > 0)
            {
                input[below(input_length)] = '\0';
            }
            break;
        }
    }

    input[input_length] = '\0';
}

/* The text form most parsers get: NUL-terminated, sanitized like
 * observation_text() does for recorded answers. */
static char *as_text(int sanitize)
{
    char *text = xcalloc(input_length + 1, 1);

    memcpy(text, input, input_length);

    if (sanitize)
    {
        sanitize_text(text, input_length, 1);
    }

    return text;
}

static void free_whois(whois_info *info)
{
    string_list_free(&info->statuses);
    free(info->raw);
}

static void fuzz_json(void)
{
    json_free(json_parse((const char *)input, input_length));
}

static void fuzz_whois(void)
{
    char *text = as_text(1);
    whois_info info = {0};
    time_t when;
    char date[32];

    whois_parse(text, &info);
    parse_whois_date(info.created, &when);
    whois_date(info.expires, date, sizeof(date));
    looks_redacted(info.registrant);
    free_whois(&info);
    free(text);
}

static void fuzz_rdap(void)
{
    whois_info info = {0};
    char service[256];

    rdap_parse((const char *)input, input_length, &info);
    rdap_find_service((const char *)input, input_length, "com", service, sizeof(service));
    free_whois(&info);
}

static void fuzz_asn(void)
{
    char *text = as_text(1);
    address_info address = {0};

    asn_parse(text, &address);
    proxy_provider_name(address.as_name);
    cloud_provider_name(address.as_name);
    free(text);
}

static void fuzz_http(void)
{
    char *text = as_text(1);
    http_info http = {0};

    http_parse(text, &http);
    free(text);
}

static void fuzz_tls(void)
{
    char *text = as_text(1);
    tls_info tls = {0};
    time_t when;

    tls_parse(text, &tls);
    tls_parse_time(tls.valid_until, &when);
    tls_parse_time(text, &when);
    string_list_free(&tls.names);
    free(text);
}

static void fuzz_dns(void)
{
    static const int types[] = {2, 5, 6, 15, 16, 43, 48, 257};

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    {
        string_list values = {0};
        dns_info info;

        memset(&info, 0, sizeof(info));
        dns_parse_answer(input, input_length, types[i], &values, &info);
        string_list_free(&values);
    }
}

static void fuzz_subdomain_sources(void)
{
    char *text = as_text(0);
    subdomain_list list = {0};

    subdomain_parse_crtsh(text, input_length, "example.com", &list);
    subdomain_parse_otx(text, input_length, "example.com", &list);
    subdomain_parse_hackertarget(text, "example.com", &list);
    subdomain_list_free(&list);
    free(text);
}

static void fuzz_reputation(void)
{
    char *text = as_text(1);
    reputation_info info = {0};

    reputation_parse_otx(text, input_length, &info);
    reputation_parse_urlhaus(text, input_length, &info);
    reputation_parse_threatfox(text, input_length, &info);
    string_list_free(&info.otx_pulse_names);
    string_list_free(&info.urlhaus_threats);
    string_list_free(&info.threatfox_malware);
    free(text);
}

static void fuzz_domain(void)
{
    char *text = as_text(0);
    char out[DOMAIN_SIZE];

    normalize_domain(text, out, sizeof(out));
    organizational_domain(text, out, sizeof(out));

    static lookalike_candidate variants[MAX_LOOKALIKES];
    lookalike_generate(text, variants, MAX_LOOKALIKES);
    free(text);
}

static void render(const domain_report *report, size_t count)
{
    static FILE *sink;
    report_options text = {.full = 1, .raw = 1, .selected = 1};
    report_options concise = {0};

    if (sink == NULL)
    {
        sink = fopen("/dev/null", "w");
    }

    print_report(sink, report, count, NULL, &text);
    print_report(sink, report, count, NULL, &concise);
    print_report_json(sink, report, count, NULL, &text);
    print_report_stix(sink, report, count, &text);
}

/* Hostile answers recorded as observations, run through the whole
 * interpret -> analyze -> report path. */
static void fuzz_pipeline(void)
{
    const char *names = "www.example.com\nmail.example.com\nold.example.com\n";
    domain_report report = {0};
    lookup_status status;

    snprintf(report.name, sizeof(report.name), "example.com");
    snprintf(report.org_domain, sizeof(report.org_domain), "example.com");

    observation_list *obs = &report.observations;

    record_observation(obs, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", "example.com", OBS_OK, NULL, names,
                       strlen(names));
    record_observation(obs, SUBDOMAIN_COLLECTOR, "crt.sh", "example.com", OBS_OK, NULL, input, input_length);
    record_observation(obs, SUBDOMAIN_PROBE_COLLECTOR, "https://192.0.2.1:443", "www.example.com", OBS_OK, NULL,
                       input, input_length);
    record_observation(obs, SUBDOMAIN_PROBE_COLLECTOR, (const char *)input, "mail.example.com", OBS_NO_RESPONSE,
                       (const char *)input, NULL, 0);
    record_observation(obs, DNS_COLLECTOR, "192.0.2.53:53", "A old.example.com", OBS_OK, NULL, input, input_length);
    record_observation(obs, "http", "192.0.2.1:80", "example.com", OBS_OK, NULL, input, input_length);
    record_observation(obs, "tls", "192.0.2.1:443", "example.com", OBS_OK, "certificate chain trusted", input,
                       input_length);
    record_observation(obs, "rdap", "rdap.example", "example.com", OBS_OK, NULL, input, input_length);
    record_observation(obs, "reputation", "otx.alienvault.com", "example.com", OBS_OK, NULL, input, input_length);
    record_observation(obs, LOOKALIKE_COLLECTOR, "configured resolver", "NS exmple.com", OBS_OK, NULL, input,
                       input_length);
    record_observation(obs, LOOKALIKE_COLLECTOR, "configured resolver", "A exmple.com", OBS_OK, NULL, input,
                       input_length);
    record_observation(obs, LOOKALIKE_COLLECTOR, "configured resolver", "MX exmple.com", OBS_OK, NULL, input,
                       input_length);
    record_observation(obs, LOOKALIKE_COLLECTOR, "configured resolver", "example.com", OBS_OK,
                       "216 variants checked: 1 registered, 0 unanswered", NULL, 0);

    subdomain_interpret("example.com", obs, &report.subdomains, &status);
    report.subdomain_status = status;
    dns_interpret_cnames(obs, &report.subdomains);
    subdomain_ct_first_seen(obs, "example.com", report.ct_first_seen, sizeof(report.ct_first_seen));
    http_interpret(obs, &report.http);
    tls_interpret(obs, &report.tls);
    rdap_interpret("example.com", obs, &report.whois);
    reputation_interpret(obs, "example.com", &report.reputation);
    lookalike_interpret("example.com", obs, &report.lookalikes);
    analyze_domain(&report);
    render(&report, 1);
    domain_report_free(&report);
}

/* Every free-text field of a report filled with hostile text, for the
 * formatting code: wrapping, column widths, escaping, truncation. */
static void fuzz_report_fields(void)
{
    domain_report reports[2];
    char *text = as_text(0);
    size_t offset = 0;

    memset(reports, 0, sizeof(reports));

    for (int r = 0; r < 2; r++)
    {
        domain_report *report = &reports[r];
#define TAKE(field)                                                                              \
    do                                                                                           \
    {                                                                                            \
        size_t n_ = input_length > 0 ? below(sizeof(field)) : 0;                                 \
        n_ = offset + n_ > input_length ? input_length - offset : n_;                            \
        memcpy(field, text + offset, n_);                                                        \
        field[n_ < sizeof(field) ? n_ : sizeof(field) - 1] = '\0';                               \
        offset = input_length > 0 ? (offset + n_) % input_length : 0;                            \
    } while (0)

        const char *name = r == 0 ? "example.com" : "example.org";

        snprintf(report->name, sizeof(report->name), "%s", name);
        snprintf(report->org_domain, sizeof(report->org_domain), "%s", name);
        report->whois.status = LOOKUP_OK;
        report->whois.registered = 1;
        TAKE(report->whois.registrar);
        TAKE(report->whois.registrant);
        TAKE(report->whois.created);
        TAKE(report->whois.note);
        report->tls.status = LOOKUP_OK;
        report->tls.trusted = (int)below(2);
        TAKE(report->tls.subject);
        TAKE(report->tls.issuer);
        TAKE(report->tls.valid_until);
        TAKE(report->tls.trust_error);
        report->http.status = LOOKUP_OK;
        TAKE(report->http.status_line);
        TAKE(report->http.server);
        TAKE(report->http.location);
        report->address_count = 1;
        snprintf(report->addresses[0].ip, sizeof(report->addresses[0].ip), "192.0.2.%d", r + 1);
        report->addresses[0].asn_status = LOOKUP_OK;
        report->addresses[0].announced = 1;
        TAKE(report->addresses[0].as_name);
        TAKE(report->addresses[0].ptr);
        report->dns.txt.status = LOOKUP_OK;
        report->dns.mx.status = LOOKUP_OK;
        report->dns.ns.status = LOOKUP_OK;

        char value[300];
        TAKE(value);
        string_list_add(&report->dns.txt.values, value);
        string_list_add(&report->dns.ns.values, value);
        string_list_add(&report->dns.mx.values, value);
        string_list_add(&report->tls.names, value);
        report->subdomain_status = LOOKUP_OK;

        for (int s = 0; s < 6; s++)
        {
            char name[DOMAIN_SIZE];
            snprintf(name, sizeof(name), "h%d.%s", s, report->name);
            subdomain_list_add(&report->subdomains, name);

            subdomain_info *sub = &report->subdomains.items[s];
            sub->probed = s < 4;
            sub->is_live = s < 3;
            sub->http_code = (long)below(1000);
            snprintf(sub->protocol, sizeof(sub->protocol), s % 2 ? "https" : "http");
            snprintf(sub->ip, sizeof(sub->ip), "192.0.2.%d", 10 + s % 2);
            TAKE(sub->as_name);
            TAKE(sub->asn);
            TAKE(sub->title);
            TAKE(sub->server);
            TAKE(sub->location);
            TAKE(sub->error);
            TAKE(sub->cname);
            sub->cname_dangling = (int)below(2);
        }

        report->reputation.otx_status = LOOKUP_OK;
        report->reputation.otx_pulses = (long)below(100);
        string_list_add(&report->reputation.otx_pulse_names, value);
        report->reputation.urlhaus_status = LOOKUP_OK;
        TAKE(report->reputation.spamhaus_dbl);
        record_observation(&report->observations, "subdomain", value, value, OBS_ERROR, value, NULL, 0);
#undef TAKE
    }

    for (int r = 0; r < 2; r++)
    {
        analyze_domain(&reports[r]);
    }

    correlation links = {0};
    correlate(reports, 2, &links);
    render(reports, 2);

    static FILE *sink;
    report_options options = {.full = 1};

    if (sink == NULL)
    {
        sink = fopen("/dev/null", "w");
    }

    print_report(sink, reports, 2, &links, &options);
    print_report_json(sink, reports, 2, &links, &options);
    correlation_free(&links);

    for (int r = 0; r < 2; r++)
    {
        domain_report_free(&reports[r]);
    }

    free(text);
}

static void load_seeds(void)
{
    static const char *const fixtures[] = {"whois_verisign_registered.txt", "whois_verisign_not_found.txt",
                                           "whois_nominet.txt",             "whois_registro_br.txt",
                                           "cymru_announced.txt",           "cymru_private.txt",
                                           "rdap_verisign.json",            "tls_certinfo.txt"};

    for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++)
    {
        add_seed_file(fixtures[i]);
    }

    add_seed_text("[{\"common_name\":\"api.example.com\",\"name_value\":\"a.example.com\\n*.b.example.com\","
                  "\"not_before\":\"2020-01-02T03:04:05\"}]");
    add_seed_text("{\"passive_dns\":[{\"hostname\":\"www.example.com\"},{\"hostname\":\"x.example.com\"}]}");
    add_seed_text("www.example.com,192.0.2.1\nmail.example.com,192.0.2.2\n");
    add_seed_text("HTTP/1.1 301 Moved\r\nServer: nginx/1.2\r\nLocation: https://www.example.com/\r\n\r\n"
                  "<html><title>Index of /</title></html>");
    add_seed_text("{\"pulse_info\":{\"count\":2,\"pulses\":[{\"name\":\"a\"}]},\"validation\":[{\"source\":\"x\"}]}");
    add_seed_text("{\"query_status\":\"ok\",\"url_count\":\"3\",\"blacklists\":{\"spamhaus_dbl\":\"listed\"},"
                  "\"urls\":[{\"url_status\":\"online\",\"threat\":\"malware_download\"}]}");
    add_seed_text("{\"query_status\":\"ok\",\"data\":[{\"malware_printable\":\"x\"}]}");
    add_seed_text("hxxps://www.example[.]com/path?q=1");

    static const unsigned char packet[] = {
        0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 3,    'i',  'a',  'm',  7,
        'e',  'x',  'a',  'm',  'p',  'l',  'e',  3,    'c',  'o',  'm',  0,    0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x06, 1,    'x',  1,    'y',  0,    0x00,
    };
    add_seed(packet, sizeof(packet));
}

typedef struct
{
    const char *name;
    void (*run)(void);
    unsigned weight; /* the pipeline and report targets are slower */
} target;

int main(int argc, char *argv[])
{
    static const target targets[] = {
        {"json", fuzz_json, 1},       {"whois", fuzz_whois, 1},           {"rdap", fuzz_rdap, 1},
        {"asn", fuzz_asn, 1},         {"http", fuzz_http, 1},             {"tls", fuzz_tls, 1},
        {"dns", fuzz_dns, 1},         {"subdomains", fuzz_subdomain_sources, 1},
        {"reputation", fuzz_reputation, 1}, {"domain", fuzz_domain, 1},  {"pipeline", fuzz_pipeline, 20},
        {"report", fuzz_report_fields, 20},
    };
    long iterations = argc > 1 ? strtol(argv[1], NULL, 10) : 20000;
    uint64_t start_seed = argc > 2 ? strtoull(argv[2], NULL, 10) : (uint64_t)time(NULL);

    __sanitizer_set_death_callback(save_crash);
    load_seeds();
    printf("fuzz: %zu seeds, seed %llu\n", seed_count, (unsigned long long)start_seed);

    for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); t++)
    {
        long runs = iterations / targets[t].weight;
        clock_t began = clock();

        rng_state = start_seed * 2654435761u + t + 1;
        target_name = targets[t].name;

        for (long i = 0; i < runs; i++)
        {
            mutate();
            targets[t].run();
        }

        printf("  %-12s %7ld inputs  ok  (%.1fs)\n", targets[t].name, runs,
               (double)(clock() - began) / CLOCKS_PER_SEC);
    }

    return 0;
}
