/* The text report: formatting, module selection, gaps and the
 * neutralization of terminal escapes. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect/reputation.h"
#include "collect/subdomain.h"
#include "core/model.h"
#include "helpers.h"
#include "output/report.h"
#include "support/json.h"
#include "support/util.h"
#include "test.h"

/* Every OSINT source failing is reported as a failure, not as no subdomains. */
static void test_subdomain_lookup_failed(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.subdomain_status = LOOKUP_FAILED;

    char *text = render(&report);

    CHECK(strstr(text, "lookup failed (no passive OSINT source answered)") != NULL);
    CHECK(strstr(text, "Lookup failed: no passive OSINT source answered.") != NULL);
    CHECK(strstr(text, "none found") == NULL);
    CHECK(strstr(text, "None found") == NULL);

    free(text);
    domain_report_free(&report);
}

/* The concise report lists only the first unanswered names; --full all. */
static void test_concise_subdomain_list(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.subdomain_status = LOOKUP_OK;

    char name[DOMAIN_SIZE];

    for (int i = 0; i < 30; i++)
    {
        snprintf(name, sizeof(name), "host%02d.example.com", i);
        subdomain_list_add(&report.subdomains, name);
    }

    char *text = render(&report);
    CHECK(strstr(text, "    host00, host01, host02") != NULL);
    CHECK(strstr(text, "host19,\n") != NULL);
    CHECK(strstr(text, "host20") == NULL);
    CHECK(strstr(text, "... and 10 more (--full lists them all)") != NULL);
    free(text);

    char *full_text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&full_text, &length);
    report_options options = {.full = 1};

    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(full_text, "host29\n") != NULL);
    CHECK(strstr(full_text, "more (--full") == NULL);
    free(full_text);

    domain_report_free(&report);
}

/* Unanswered subdomains are grouped by reason, and the SOURCES section
 * sums up the probes unless --raw asks for each request. */
static void test_probe_report_grouping(void)
{
    const char *names = "a.example.com\nb.example.com\nc.example.com\nd.example.com\n";
    const char *page = "HTTP/1.1 200 OK\r\n\r\n";
    domain_report report = {0};
    lookup_status status;

    snprintf(report.name, sizeof(report.name), "example.com");
    record_observation(&report.observations, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", "example.com", OBS_OK, "ok",
                       names, strlen(names));
    record_observation(&report.observations, SUBDOMAIN_PROBE_COLLECTOR, "https://a.example.com", "a.example.com",
                       OBS_NO_RESPONSE, "not in DNS: Could not resolve host: a.example.com", NULL, 0);
    record_observation(&report.observations, SUBDOMAIN_PROBE_COLLECTOR, "https://b.example.com", "b.example.com",
                       OBS_NO_RESPONSE, "not in DNS: Could not resolve host: b.example.com", NULL, 0);
    record_observation(&report.observations, SUBDOMAIN_PROBE_COLLECTOR, "https://c.example.com", "c.example.com",
                       OBS_NO_RESPONSE, "timed out: Connection timeout after 2000 ms", NULL, 0);
    record_observation(&report.observations, SUBDOMAIN_PROBE_COLLECTOR, "https://192.0.2.4:443", "d.example.com",
                       OBS_OK, NULL, page, strlen(page));
    record_observation(&report.observations, SUBDOMAIN_PROBE_COLLECTOR, "http-probe", "example.com", OBS_OK,
                       "Probed 4 subdomains", NULL, 0);
    record_observation(&report.observations, "asn", "whois.cymru.com:43", "192.0.2.4", OBS_OK, NULL, NULL, 0);
    subdomain_interpret("example.com", &report.observations, &report.subdomains, &status);
    report.subdomain_status = status;

    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {.full = 1};

    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(text, "    not in DNS (2)          a, b\n") != NULL);
    CHECK(strstr(text, "    timed out (1)           c\n") != NULL);
    CHECK(strstr(text, "SOURCES") == NULL);
    CHECK(strstr(text, "Gaps") == NULL);
    free(text);

    options.raw = 1;
    out = open_memstream(&text, &length);
    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(text, "subdomain-probe a.example.com") != NULL);
    CHECK(strstr(text, "asn 192.0.2.4") != NULL);
    free(text);

    domain_report_free(&report);
}

/* A picked module shows its own section and nothing of the others; with
 * --full, SOURCES lists only the sources that failed. */
static void test_module_report(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    snprintf(report.org_domain, sizeof(report.org_domain), "example.com");
    report.modules = MODULE_WHOIS;
    report.whois.status = LOOKUP_OK;
    report.whois.registered = 1;
    snprintf(report.whois.registrar, sizeof(report.whois.registrar), "Example Registrar");
    record_observation(&report.observations, "rdap", "rdap.example", "example.com", OBS_OK, NULL, NULL, 0);
    record_observation(&report.observations, "rdap-bootstrap", "data.iana.org", "com", OBS_ERROR, "HTTP 503", NULL, 0);

    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {.modules = MODULE_WHOIS, .selected = 1};

    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(text, "Modules       whois\n") != NULL);
    CHECK(strstr(text, "passive (the targets were not contacted)") != NULL);
    CHECK(strstr(text, "REGISTRATION") != NULL);
    CHECK(strstr(text, "Example Registrar") != NULL);
    CHECK(strstr(text, "DNS provider") == NULL);
    CHECK(strstr(text, "Hosting") == NULL);
    CHECK(strstr(text, "SUBDOMAINS") == NULL);
    CHECK(strstr(text, "SOURCES") == NULL);
    free(text);

    options.full = 1;
    out = open_memstream(&text, &length);
    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(text, "SOURCES") == NULL);
    /* WHOIS answered, so the failed RDAP bootstrap left nothing missing. */
    CHECK(strstr(text, "Gaps") == NULL);
    free(text);

    options.raw = 1;
    out = open_memstream(&text, &length);
    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(text, "error        rdap-bootstrap com") != NULL);
    CHECK(strstr(text, "ok           rdap example.com") != NULL);
    free(text);

    domain_report_free(&report);
}

/* Failed third-party sources are named in the SUMMARY of every mode,
 * with what they leave missing. */
static void test_gaps(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.whois.status = LOOKUP_FAILED;
    report.subdomain_status = LOOKUP_OK;
    record_observation(&report.observations, "rdap", "rdap.example", "example.com", OBS_NO_RESPONSE,
                       "Operation timed out after 15000 milliseconds", NULL, 0);
    record_observation(&report.observations, SUBDOMAIN_COLLECTOR, "crt.sh", "example.com", OBS_ERROR, "HTTP 502", NULL,
                       0);
    record_observation(&report.observations, SUBDOMAIN_COLLECTOR, "otx.alienvault.com", "example.com", OBS_LIMITED,
                       "HTTP 429", NULL, 0);
    record_observation(&report.observations, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", "example.com", OBS_OK,
                       "3 subdomains", NULL, 0);
    record_observation(&report.observations, "http", "192.0.2.1:80", "example.com", OBS_NO_RESPONSE,
                       "no answer on port 80", NULL, 0);

    char *text = render(&report);
    CHECK(strstr(text, "  Gaps          registration: rdap.example (no response)\n") != NULL);
    CHECK(strstr(text, "                subdomains: crt.sh (HTTP 502), otx.alienvault.com (HTTP 429);\n"
                       "                the list may be incomplete\n") != NULL);
    CHECK(strstr(text, "port 80") == NULL);
    free(text);

    domain_report_free(&report);
}

/* Text from third parties never reaches the terminal with control
 * characters: an OTX pulse anyone can create, an RDAP escape, a C1 CSI. */
static void test_terminal_escapes(void)
{
    const char *otx =
        "{\"pulse_info\":{\"count\":1,\"pulses\":[{\"name\":\"x\\u001b]0;owned\\u0007\\u001b[2J\\nnext\"}]},"
        "\"validation\":[]}";
    const char *rdap_name = "{\"name\":\"Owner\\u001b[31m\\u009b2J\"}";
    reputation_info info = {0};

    CHECK_INT(reputation_parse_otx(otx, strlen(otx), &info), 0);
    CHECK_STR(info.otx_pulse_names.items[0], "x?]0;owned??[2J?next");

    json_value *doc = json_parse(rdap_name, strlen(rdap_name));
    CHECK_STR(json_get_string(doc, "name"), "Owner?[31m??2J");
    json_free(doc);

    char text[] = "a\xc2\x9b"
                  "31m b\xc3\xa9 \x1b[0m\r\n";
    sanitize_text(text, strlen(text), 1);
    CHECK_STR(text, "a??31m b\xc3\xa9 ?[0m\r\n");

    string_list_free(&info.otx_pulse_names);
}

void test_report(void)
{
    test_subdomain_lookup_failed();
    test_concise_subdomain_list();
    test_probe_report_grouping();
    test_module_report();
    test_gaps();
    test_terminal_escapes();
}
