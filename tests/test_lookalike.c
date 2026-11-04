/* Lookalike domains: variant generation, interpretation and signals. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect/lookalike.h"
#include "core/analysis.h"
#include "core/model.h"
#include "helpers.h"
#include "output/report.h"
#include "support/domain.h"
#include "test.h"

/* Variants of a name: the usual typo and phishing patterns, never the
 * name itself, always valid host names. */
static void test_lookalike_generation(void)
{
    lookalike_candidate *items = calloc(MAX_LOOKALIKES, sizeof(*items));
    size_t count = lookalike_generate("www.example.com", items, MAX_LOOKALIKES);
    const char *expected[][2] = {{"exmple.com", "omission"},       {"exaample.com", "repetition"},
                                 {"exmaple.com", "transposition"}, {"examp1e.com", "homoglyph"},
                                 {"exampel.com", "transposition"}, {"example-login.com", "phishing-word"},
                                 {"example.net", "tld-swap"},      {"exampie.com", "homoglyph"}};

    CHECK(count > 150);

    for (size_t e = 0; e < sizeof(expected) / sizeof(expected[0]); e++)
    {
        int found = 0;

        for (size_t i = 0; i < count; i++)
        {
            found |= strcmp(items[i].name, expected[e][0]) == 0 && strcmp(items[i].technique, expected[e][1]) == 0;
        }

        CHECK(found);
    }

    int bad = 0;

    for (size_t i = 0; i < count; i++)
    {
        char normalized[DOMAIN_SIZE];
        bad |= strcmp(items[i].name, "example.com") == 0;
        bad |= normalize_domain(items[i].name, normalized, sizeof(normalized)) != 0;
    }

    CHECK(!bad);

    /* A second-level suffix stays whole: example.com.br -> exemple.com.br. */
    count = lookalike_generate("example.com.br", items, MAX_LOOKALIKES);
    int kept = 0;

    for (size_t i = 0; i < count; i++)
    {
        kept |= strcmp(items[i].name, "exemple.com.br") == 0;
    }

    CHECK(kept);
    CHECK_INT(lookalike_generate("localhost", items, MAX_LOOKALIKES), 0);
    free(items);
}

/* Registered variants are read back from the answers and sorted by risk:
 * mail first, the owner's own registrations last. */
static void test_lookalike_analysis(void)
{
    static const unsigned char parking_ns[] = {3, 'n', 's', '1', 8, 'a', 'f', 't', 'e', 'r', 'n', 'i', 'c', 3, 'c', 'o', 'm', 0};
    static const unsigned char other_ns[] = {3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
    static const unsigned char own_ns[] = {3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    static const unsigned char address[] = {192, 0, 2, 66};
    static const unsigned char mail[] = {0, 10, 2, 'm', 'x', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
    domain_report report = {0};

    snprintf(report.name, sizeof(report.name), "example.com");
    snprintf(report.org_domain, sizeof(report.org_domain), "example.com");
    report.modules = MODULE_LOOKALIKES | MODULE_DNS;
    report.dns.ns.status = LOOKUP_OK;
    string_list_add(&report.dns.ns.values, "ns1.example.com");

    observation_list *obs = &report.observations;
    record_lookalike(obs, "NS", "exmple.com", 2, 0, other_ns, sizeof(other_ns));
    record_lookalike(obs, "A", "exmple.com", 1, 0, address, sizeof(address));
    record_lookalike(obs, "MX", "exmple.com", 15, 0, mail, sizeof(mail));
    record_lookalike(obs, "NS", "exaample.com", 2, 0, parking_ns, sizeof(parking_ns));
    record_lookalike(obs, "NS", "example.net", 2, 0, own_ns, sizeof(own_ns));
    record_lookalike(obs, "NS", "exampel.com", 2, 2, NULL, 0);
    record_observation(obs, LOOKALIKE_COLLECTOR, "configured resolver", "example.com", OBS_OK,
                       "216 variants checked: 4 registered, 3 unanswered", NULL, 0);

    lookalike_interpret("example.com", obs, &report.lookalikes);
    CHECK_INT(report.lookalikes.status, LOOKUP_OK);
    CHECK_INT(report.lookalikes.checked, 216);
    CHECK_INT(report.lookalikes.count, 4);

    analyze_domain(&report);

    const lookalike_list *list = &report.lookalikes;
    CHECK_STR(list->items[0].name, "exmple.com");
    CHECK_INT(list->items[0].has_mail, 1);
    CHECK_STR(list->items[0].addresses.items[0], "192.0.2.66");
    CHECK_STR(list->items[1].name, "exampel.com");
    CHECK_INT(list->items[1].dns_fails, 1);
    CHECK_STR(list->items[2].name, "exaample.com");
    CHECK_INT(list->items[2].parked, 1);
    CHECK_STR(list->items[3].name, "example.net");
    CHECK_INT(list->items[3].likely_defensive, 1);

    CHECK(has_signal(&report, SEVERITY_MEDIUM, "1 lookalike domain can receive mail (MX)"));
    CHECK(find_signal(&report, "exmple.com (omission)") != NULL);
    CHECK(has_signal(&report, SEVERITY_INFO, "1 lookalike domain is parked or for sale"));
    CHECK(has_signal(&report, SEVERITY_INFO, "1 lookalike domain shares the same nameservers"));

    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {.full = 1};

    print_report(out, &report, 1, NULL, &options);
    fclose(out);
    CHECK(strstr(text, "Lookalikes    4 registered of 216 variants (1 can receive mail, 1 parked") != NULL);
    CHECK(strstr(text, "    exaample.com  repetition     -     -                ns1.afternic.com  (parked/for sale)\n") !=
          NULL);
    CHECK(strstr(text, "    exampel.com   transposition  -     -                (its DNS does not answer)\n") != NULL);
    free(text);

    domain_report_free(&report);
}

void test_lookalikes(void)
{
    test_lookalike_generation();
    test_lookalike_analysis();
}
