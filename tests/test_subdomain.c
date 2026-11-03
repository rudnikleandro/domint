#include <stdlib.h>
#include <string.h>

#include "analysis.h"
#include "model.h"
#include "report.h"
#include "subdomain.h"
#include "test.h"

static void add_live(domain_report *report, const char *name, long code, const char *ip, const char *asn,
                     const char *as_name)
{
    subdomain_list_add(&report->subdomains, name);

    subdomain_info *sub = &report->subdomains.items[report->subdomains.count - 1];
    sub->probed = 1;
    sub->is_live = code != 0;
    sub->http_code = code;
    snprintf(sub->protocol, sizeof(sub->protocol), "https");
    snprintf(sub->ip, sizeof(sub->ip), "%s", ip);
    snprintf(sub->asn, sizeof(sub->asn), "%s", asn);
    snprintf(sub->as_name, sizeof(sub->as_name), "%s", as_name);
}

static const finding *find_signal(const domain_report *report, const char *text)
{
    for (size_t i = 0; i < report->finding_count; i++)
    {
        if (strstr(report->findings[i].text, text) != NULL)
        {
            return &report->findings[i];
        }
    }

    return NULL;
}

/* Non-production names, the network of each subdomain and shared addresses. */
static void test_subdomain_infrastructure(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    snprintf(report.org_domain, sizeof(report.org_domain), "example.com");
    report.subdomain_status = LOOKUP_OK;

    add_live(&report, "homol-api.example.com", 403, "192.0.2.10", "20940", "AKAMAI-ASN1, NL");
    add_live(&report, "stagging.example.com", 200, "192.0.2.10", "20940", "AKAMAI-ASN1, NL");
    add_live(&report, "collab.example.com", 200, "192.0.2.20", "64500", "EXAMPLE-AS - Example Networks Ltd, BR");
    add_live(&report, "dev2.example.com", 0, "", "", "");
    add_live(&report, "www.example.com", 200, "192.0.2.10", "20940", "AKAMAI-ASN1, NL");

    analyze_domain(&report);

    const finding *signal = find_signal(&report, "non-production");
    CHECK(signal != NULL);

    if (signal != NULL)
    {
        CHECK_INT(signal->level, SEVERITY_MEDIUM);
        CHECK(strstr(signal->text, "homol-api.example.com (403)") != NULL);
        CHECK(strstr(signal->text, "stagging.example.com (200)") != NULL);
        CHECK(strstr(signal->text, "collab") == NULL);
        CHECK(strstr(signal->text, "dev2") == NULL);
        CHECK(strstr(signal->text, "www") == NULL);
    }

    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {0};

    print_report(out, &report, 1, NULL, &options);
    fclose(out);

    CHECK(strstr(text, "[403]  https://homol-api.example.com (192.0.2.10, AS20940 Akamai)") != NULL);
    CHECK(strstr(text, "https://collab.example.com (192.0.2.20, AS64500 Example Networks Ltd)") != NULL);
    CHECK(strstr(text, "192.0.2.10 (AS20940 Akamai), 3 subdomains: homol-api, stagging, www") != NULL);
    CHECK(strstr(text, "192.0.2.20 (") == NULL);
    CHECK(strstr(text, "    dev2.example.com") != NULL);

    free(text);
    domain_report_free(&report);
}

static char *render(const domain_report *report)
{
    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {0};

    print_report(out, report, 1, NULL, &options);
    fclose(out);
    return text;
}

/* The non-production list stops before it would leave no room for ", ...". */
static void test_non_production_list_limit(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.subdomain_status = LOOKUP_OK;

    /* 43 + 8 x (2 + 40) = 379 characters: the last name fits exactly
     * without the marker, so it must be left out. */
    char name[DOMAIN_SIZE];
    snprintf(name, sizeof(name), "dev-%027d.example.com", 0);
    subdomain_list_add(&report.subdomains, name);

    for (int i = 1; i <= 9; i++)
    {
        snprintf(name, sizeof(name), "dev-%024d.example.com", i);
        subdomain_list_add(&report.subdomains, name);
    }

    analyze_domain(&report);

    const finding *signal = find_signal(&report, "non-production");
    CHECK(signal != NULL);

    if (signal != NULL)
    {
        CHECK(strstr(signal->text, "10 non-production") != NULL);
        CHECK(strstr(signal->text, "dev-000000000000000000000007.example.com, ...") != NULL);
        CHECK(strstr(signal->text, "dev-000000000000000000000008.example.com") == NULL);
    }

    domain_report_free(&report);
}

/* Keywords are looked for only in front of the investigated domain. */
static void test_sensitive_keyword_in_domain(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "portalcorp.example");
    report.subdomain_status = LOOKUP_OK;

    add_live(&report, "www.portalcorp.example", 200, "192.0.2.10", "", "");
    add_live(&report, "vpn.portalcorp.example", 200, "192.0.2.11", "", "");

    analyze_domain(&report);

    CHECK(find_signal(&report, "www.portalcorp.example") == NULL);
    CHECK(find_signal(&report, "accessible without restriction: vpn.portalcorp.example") != NULL);
    domain_report_free(&report);
}

/* A full findings list makes room for a more severe signal found late. */
static void test_findings_limit_keeps_severe(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.subdomain_status = LOOKUP_OK;

    char name[DOMAIN_SIZE];

    for (int i = 0; i < MAX_FINDINGS + 8; i++)
    {
        snprintf(name, sizeof(name), "admin%02d.example.com", i);
        add_live(&report, name, 403, "192.0.2.10", "", "");
    }

    add_live(&report, "zz.example.com", 200, "192.0.2.20", "", "");
    snprintf(report.subdomains.items[report.subdomains.count - 1].title, FIELD_SIZE, "Index of /");

    analyze_domain(&report);

    CHECK_INT(report.finding_count, MAX_FINDINGS);
    CHECK_INT(report.findings[0].level, SEVERITY_HIGH);
    CHECK(strstr(report.findings[0].text, "zz.example.com") != NULL);
    domain_report_free(&report);
}

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

/* Probe results come from the recorded attempts alone: the first answer
 * wins and nothing from a failed HTTPS attempt leaks into it. */
static void test_probe_interpretation(void)
{
    const char *names = "api.example.com\nold.example.com\nwww.example.com\n";
    const char *redirect = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 301 Moved Permanently\r\n"
                           "Location: https://www.example.com/\r\n\r\n";
    const char *page = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><title> Plain \n page </title>";
    observation_list obs = {0};
    subdomain_list list = {0};
    lookup_status status;

    record_observation(&obs, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", "example.com", OBS_OK, "ok", names,
                       strlen(names));
    record_observation(&obs, SUBDOMAIN_PROBE_COLLECTOR, "https://192.0.2.1:443", "api.example.com", OBS_OK, NULL,
                       redirect, strlen(redirect));
    record_observation(&obs, SUBDOMAIN_PROBE_COLLECTOR, "https://[2001:db8::2]:443", "www.example.com", OBS_NO_RESPONSE,
                       "Operation timed out", NULL, 0);
    record_observation(&obs, SUBDOMAIN_PROBE_COLLECTOR, "http://192.0.2.3:80", "www.example.com", OBS_OK, NULL, page,
                       strlen(page));
    record_observation(&obs, SUBDOMAIN_PROBE_COLLECTOR, "https://old.example.com", "old.example.com", OBS_NO_RESPONSE,
                       "Could not resolve host", NULL, 0);
    record_observation(&obs, SUBDOMAIN_PROBE_COLLECTOR, "http-probe", "example.com", OBS_OK, "Probed 3", NULL, 0);

    /* Twice: interpreting again gives the same list. */
    for (int round = 0; round < 2; round++)
    {
        subdomain_interpret("example.com", &obs, &list, &status);

        CHECK_INT(status, LOOKUP_OK);
        CHECK_INT(list.count, 3);

        const subdomain_info *api = &list.items[0];
        CHECK_STR(api->name, "api.example.com");
        CHECK(api->probed && api->is_live);
        CHECK_INT(api->http_code, 301);
        CHECK_STR(api->protocol, "https");
        CHECK_STR(api->ip, "192.0.2.1");
        CHECK_STR(api->location, "https://www.example.com/");

        const subdomain_info *old = &list.items[1];
        CHECK(old->probed && !old->is_live);
        CHECK_STR(old->ip, "");
        CHECK_STR(old->error, "Could not resolve host");

        const subdomain_info *www = &list.items[2];
        CHECK(www->probed && www->is_live);
        CHECK_INT(www->http_code, 200);
        CHECK_STR(www->protocol, "http");
        CHECK_STR(www->ip, "192.0.2.3");
        CHECK_STR(www->error, "");
        CHECK_STR(www->server, "");
        CHECK_STR(www->title, "Plain page");
    }

    subdomain_list_free(&list);
    observation_list_free(&obs);
}

/* Sensitive names past the probe limit are still reported. */
static void test_sensitive_over_probe_limit(void)
{
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    report.subdomain_status = LOOKUP_OK;

    char name[DOMAIN_SIZE];

    for (int i = 0; i < 50; i++)
    {
        snprintf(name, sizeof(name), "host%02d.example.com", i);
        add_live(&report, name, 0, "", "", "");
    }

    subdomain_list_add(&report.subdomains, "vpn.example.com");
    analyze_domain(&report);

    const finding *signal = find_signal(&report, "over the probe limit");
    CHECK(signal != NULL);

    if (signal != NULL)
    {
        CHECK_INT(signal->level, SEVERITY_LOW);
        CHECK(strstr(signal->text, "vpn.example.com") != NULL);
    }

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
    CHECK(strstr(text, "    host19.example.com\n") != NULL);
    CHECK(strstr(text, "host20.example.com") == NULL);
    CHECK(strstr(text, "... and 10 more (--full lists them all)") != NULL);
    free(text);

    char *full_text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&full_text, &length);
    report_options options = {0, 1, 0};

    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(full_text, "    host29.example.com\n") != NULL);
    CHECK(strstr(full_text, "more (--full") == NULL);
    free(full_text);

    domain_report_free(&report);
}

void test_subdomains(void)
{
    subdomain_list list = {0};

    /* 1. crt.sh parsing test */
    const char *crtsh_sample =
        "[\n"
        "  {\n"
        "    \"issuer_ca_id\": 16418,\n"
        "    \"issuer_name\": \"C=US, O=Let's Encrypt, CN=R3\",\n"
        "    \"common_name\": \"api.example.com\",\n"
        "    \"name_value\": \"api.example.com\\nmail.example.com\\n*.vpn.example.com\\n*.example.com\"\n"
        "  },\n"
        "  {\n"
        "    \"issuer_ca_id\": 16418,\n"
        "    \"issuer_name\": \"C=US, O=Let's Encrypt, CN=R3\",\n"
        "    \"common_name\": \"admin.example.com\",\n"
        "    \"name_value\": \"admin.example.com\\notherdomain.com\\nfakeexample.com\"\n"
        "  }\n"
        "]";

    CHECK_INT(subdomain_parse_crtsh(crtsh_sample, strlen(crtsh_sample), "example.com", &list), 0);
    subdomain_list_sort(&list);

    /* Should contain: admin.example.com, api.example.com, mail.example.com, vpn.example.com
     * Should NOT contain: otherdomain.com, fakeexample.com, example.com (apex) */
    CHECK_INT(list.count, 4);
    CHECK(subdomain_list_contains(&list, "admin.example.com"));
    CHECK(subdomain_list_contains(&list, "api.example.com"));
    CHECK(subdomain_list_contains(&list, "mail.example.com"));
    CHECK(subdomain_list_contains(&list, "vpn.example.com"));
    CHECK(!subdomain_list_contains(&list, "example.com"));
    CHECK(!subdomain_list_contains(&list, "otherdomain.com"));
    CHECK(!subdomain_list_contains(&list, "fakeexample.com"));

    subdomain_list_free(&list);

    /* 2. AlienVault OTX parsing test */
    const char *otx_sample =
        "{\n"
        "  \"passive_dns\": [\n"
        "    {\"address\": \"192.0.2.1\", \"hostname\": \"portal.example.com\", \"record_type\": \"A\"},\n"
        "    {\"address\": \"192.0.2.2\", \"hostname\": \"dev.example.com\", \"record_type\": \"A\"},\n"
        "    {\"address\": \"192.0.2.3\", \"hostname\": \"notexample.com\", \"record_type\": \"A\"}\n"
        "  ],\n"
        "  \"count\": 3\n"
        "}";

    CHECK_INT(subdomain_parse_otx(otx_sample, strlen(otx_sample), "example.com", &list), 0);
    subdomain_list_sort(&list);

    CHECK_INT(list.count, 2);
    CHECK(subdomain_list_contains(&list, "portal.example.com"));
    CHECK(subdomain_list_contains(&list, "dev.example.com"));
    CHECK(!subdomain_list_contains(&list, "notexample.com"));

    subdomain_list_free(&list);

    /* 3. HackerTarget parsing test */
    const char *ht_sample =
        "mail.example.com,192.0.2.1\n"
        "vpn.example.com,192.0.2.2\n"
        "example.com,192.0.2.3\n"
        "badsite.com,192.0.2.4\n";

    CHECK_INT(subdomain_parse_hackertarget(ht_sample, "example.com", &list), 0);
    subdomain_list_sort(&list);

    CHECK_INT(list.count, 2);
    CHECK(subdomain_list_contains(&list, "mail.example.com"));
    CHECK(subdomain_list_contains(&list, "vpn.example.com"));
    CHECK(!subdomain_list_contains(&list, "example.com"));
    CHECK(!subdomain_list_contains(&list, "badsite.com"));

    subdomain_list_free(&list);

    /* 4. Malformed input tests */
    CHECK_INT(subdomain_parse_crtsh("not json", 8, "example.com", &list), -1);
    CHECK_INT(subdomain_parse_crtsh("{}", 2, "example.com", &list), -1);
    CHECK_INT(subdomain_parse_otx("not json", 8, "example.com", &list), -1);
    CHECK_INT(subdomain_parse_otx("{}", 2, "example.com", &list), -1);
    CHECK_INT(subdomain_parse_hackertarget("error check search", "example.com", &list), -1);

    /* 5. Observation interpretation test */
    observation_list obs = {0};
    lookup_status status;

    record_observation(&obs, SUBDOMAIN_COLLECTOR, "crt.sh", "example.com", OBS_OK, "ok",
                       crtsh_sample, strlen(crtsh_sample));
    record_observation(&obs, SUBDOMAIN_COLLECTOR, "otx.alienvault.com", "example.com", OBS_OK, "ok",
                       otx_sample, strlen(otx_sample));
    record_observation(&obs, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", "example.com", OBS_OK, "ok",
                       ht_sample, strlen(ht_sample));

    subdomain_interpret("example.com", &obs, &list, &status);

    CHECK_INT(status, LOOKUP_OK);
    CHECK_INT(list.count, 6);
    CHECK_STR(list.items[0].name, "admin.example.com");
    CHECK_STR(list.items[1].name, "api.example.com");
    CHECK_STR(list.items[2].name, "dev.example.com");
    CHECK_STR(list.items[3].name, "mail.example.com");
    CHECK_STR(list.items[4].name, "portal.example.com");
    CHECK_STR(list.items[5].name, "vpn.example.com");

    /* 6. Probed data simulation and risk analysis */
    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "example.com");
    snprintf(report.org_domain, sizeof(report.org_domain), "example.com");
    report.subdomain_status = LOOKUP_OK;
    report.subdomains = list;

    /* Simulate probe outcomes:
     * admin: 403 Forbidden (restricted)
     * api: 200 OK (open)
     * dev: 200 OK (sensitive & open!)
     * mail: 301 Redirect (redirect)
     * portal: offline
     * vpn: offline */
    report.subdomains.items[0].probed = 1;
    report.subdomains.items[0].is_live = 1;
    report.subdomains.items[0].http_code = 403;
    snprintf(report.subdomains.items[0].server, sizeof(report.subdomains.items[0].server), "cloudflare");

    report.subdomains.items[1].probed = 1;
    report.subdomains.items[1].is_live = 1;
    report.subdomains.items[1].http_code = 200;

    report.subdomains.items[2].probed = 1;
    report.subdomains.items[2].is_live = 1;
    report.subdomains.items[2].http_code = 200;
    snprintf(report.subdomains.items[2].server, sizeof(report.subdomains.items[2].server), "nginx");
    snprintf(report.subdomains.items[2].title, sizeof(report.subdomains.items[2].title), "Index of /");

    report.subdomains.items[3].probed = 1;
    report.subdomains.items[3].is_live = 1;
    report.subdomains.items[3].http_code = 301;
    snprintf(report.subdomains.items[3].location, sizeof(report.subdomains.items[3].location), "https://outlook.com");

    report.subdomains.items[4].probed = 1;
    report.subdomains.items[4].is_live = 0;

    report.subdomains.items[5].probed = 1;
    report.subdomains.items[5].is_live = 0;

    analyze_domain(&report);

    /* Finding count should include:
     * - directory listing (HIGH)
     * - dev.example.com open (MEDIUM)
     * - admin.example.com restricted (LOW)
     * - liveness summary (INFO) */
    CHECK(report.finding_count >= 4);

    int found_high = 0;
    int found_medium = 0;
    int found_low = 0;
    int found_liveness = 0;

    for (size_t i = 0; i < report.finding_count; i++)
    {
        if (strstr(report.findings[i].text, "directory listing") != NULL &&
            report.findings[i].level == SEVERITY_HIGH)
        {
            found_high = 1;
        }
        if (strstr(report.findings[i].text, "dev.example.com") != NULL &&
            report.findings[i].level == SEVERITY_MEDIUM)
        {
            found_medium = 1;
        }
        if (strstr(report.findings[i].text, "admin.example.com") != NULL &&
            report.findings[i].level == SEVERITY_LOW)
        {
            found_low = 1;
        }
        if (strstr(report.findings[i].text, "Subdomain liveness check") != NULL &&
            report.findings[i].level == SEVERITY_INFO)
        {
            found_liveness = 1;
        }
    }

    CHECK(found_high);
    CHECK(found_medium);
    CHECK(found_low);
    CHECK(found_liveness);

    observation_list_free(&obs);
    domain_report_free(&report);

    test_subdomain_infrastructure();
    test_non_production_list_limit();
    test_sensitive_keyword_in_domain();
    test_findings_limit_keeps_severe();
    test_subdomain_lookup_failed();
    test_probe_interpretation();
    test_sensitive_over_probe_limit();
    test_concise_subdomain_list();
}
