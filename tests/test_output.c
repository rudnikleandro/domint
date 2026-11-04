/* Machine-readable output: JSON and STIX 2.1. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/analysis.h"
#include "core/model.h"
#include "helpers.h"
#include "output/report.h"
#include "support/json.h"
#include "test.h"

/* The JSON output parses with the strict reader, whatever the sources sent. */
static void test_json_output(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.modules = MODULE_WHOIS | MODULE_SUBDOMAINS;
    report.whois.status = LOOKUP_OK;
    report.whois.registered = 1;
    snprintf(report.whois.registrant, sizeof(report.whois.registrant), "Caf\xe9 \"Quoted\"\tName\x01");
    report.subdomain_status = LOOKUP_OK;
    add_live(&report, "www.example.com", 200, "192.0.2.10", "64500", "EXAMPLE-AS");
    subdomain_list_add(&report.subdomains, "old.example.com");
    snprintf(report.subdomains.items[1].cname, DOMAIN_SIZE, "gone.azurewebsites.net");
    report.subdomains.items[1].cname_dangling = 1;
    analyze_domain(&report);

    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {.modules = MODULE_WHOIS | MODULE_SUBDOMAINS, .selected = 1};

    print_report_json(out, &report, 1, NULL, &options);
    fclose(out);

    json_value *doc = json_parse(text, length);
    CHECK(doc != NULL);

    const json_value *domain = json_at(json_get_array(doc, "domains"), 0);
    const json_value *registration = json_get_object(domain, "registration");
    const json_value *items = json_get_array(json_get_object(domain, "subdomains"), "items");
    const json_value *indicators = json_get_object(domain, "indicators");

    /* The control byte went out as \u0001 and the reader neutralizes it. */
    CHECK_STR(json_get_string(registration, "registrant"), "Caf\xc3\xa9 \"Quoted\"\tName?");
    CHECK_STR(json_get_string(json_at(items, 0), "state"), "online");
    CHECK_STR(json_get_string(json_at(items, 1), "cname"), "gone.azurewebsites.net");
    CHECK_INT(json_count(json_get_array(indicators, "domains")), 2);
    CHECK_STR(json_string(json_at(json_get_array(indicators, "ips"), 0)), "192.0.2.10");
    CHECK(json_get(domain, "dns") == NULL);
    CHECK_STR(json_get_string(json_at(json_get_array(domain, "signals"), 0), "severity"), "high");

    json_free(doc);
    free(text);
    domain_report_free(&report);
}

/* STIX ids of observables come from their value, as the specification
 * says, so imports merge; this one is what the OASIS stix2 library gives. */
static void test_stix_output(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.modules = MODULE_LOOKALIKES;
    report.lookalikes.status = LOOKUP_OK;
    report.lookalikes.count = 1;
    report.lookalikes.items = calloc(1, sizeof(*report.lookalikes.items));
    snprintf(report.lookalikes.items[0].name, DOMAIN_SIZE, "exmple.com");
    report.lookalikes.items[0].technique = "omission";
    report.lookalikes.items[0].has_mail = 1;
    analyze_domain(&report);

    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {0};

    print_report_stix(out, &report, 1, &options);
    fclose(out);

    json_value *doc = json_parse(text, length);
    CHECK(doc != NULL);
    CHECK_STR(json_get_string(doc, "type"), "bundle");
    CHECK(strstr(text, "\"domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7\"") != NULL);
    CHECK(strstr(text, "\"pattern\": \"[domain-name:value = 'exmple.com']\"") != NULL);
    CHECK(strstr(text, "\"indicator_types\": [\"anomalous-activity\"]") != NULL);
    CHECK(strstr(text, "\"type\": \"note\"") != NULL);
    CHECK(strstr(text, "\"type\": \"report\"") != NULL);

    json_free(doc);
    free(text);
    domain_report_free(&report);
}

void test_output(void)
{
    test_json_output();
    test_stix_output();
}
