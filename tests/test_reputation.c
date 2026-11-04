/* Reputation feeds: the OTX, URLhaus and ThreatFox parsers and their signals. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect/reputation.h"
#include "core/analysis.h"
#include "core/model.h"
#include "helpers.h"
#include "test.h"

/* Threat-intelligence answers, as the APIs send them. */
static void test_reputation_parsers(void)
{
    reputation_info info = {0};
    const char *otx = "{\"pulse_info\":{\"count\":2,\"pulses\":[{\"name\":\"Phishing kit\"},{\"name\":\"C2\"}]},"
                      "\"validation\":[]}";
    const char *urlhaus = "{\"query_status\":\"ok\",\"url_count\":\"3\",\"blacklists\":{\"spamhaus_dbl\":"
                          "\"abused_legit_malware\",\"surbl\":\"not listed\"},\"urls\":[{\"url_status\":\"online\","
                          "\"threat\":\"malware_download\"},{\"url_status\":\"offline\",\"threat\":\"malware_download\"}]}";
    const char *threatfox = "{\"query_status\":\"ok\",\"data\":[{\"malware_printable\":\"Cobalt Strike\"}]}";

    CHECK_INT(reputation_parse_otx(otx, strlen(otx), &info), 0);
    CHECK_INT(info.otx_pulses, 2);
    CHECK(string_list_contains(&info.otx_pulse_names, "Phishing kit"));
    CHECK_INT(info.otx_allowlisted, 0);

    CHECK_INT(reputation_parse_urlhaus(urlhaus, strlen(urlhaus), &info), 0);
    CHECK_INT(info.urlhaus_urls, 3);
    CHECK_INT(info.urlhaus_online, 1);
    CHECK_STR(info.spamhaus_dbl, "abused_legit_malware");

    CHECK_INT(reputation_parse_threatfox(threatfox, strlen(threatfox), &info), 0);
    CHECK_INT(info.threatfox_iocs, 1);

    const char *no_urls = "{\"query_status\":\"no_results\"}";
    const char *no_iocs = "{\"query_status\":\"no_result\"}";
    CHECK_INT(reputation_parse_urlhaus(no_urls, strlen(no_urls), &info), 0);
    CHECK_INT(reputation_parse_threatfox(no_iocs, strlen(no_iocs), &info), 0);
    CHECK_INT(reputation_parse_otx("[]", 2, &info), -1);

    /* Counts out of range, from a broken or hostile answer, are clamped. */
    reputation_info odd = {0};
    const char *huge = "{\"pulse_info\":{\"count\":-1e9992,\"pulses\":[]},\"validation\":[]}";
    const char *infinite = "{\"pulse_info\":{\"count\":1e999,\"pulses\":[]},\"validation\":[]}";
    const char *negative = "{\"query_status\":\"ok\",\"url_count\":\"-5\",\"urls\":[]}";

    CHECK_INT(reputation_parse_otx(huge, strlen(huge), &odd), 0);
    CHECK_INT(odd.otx_pulses, 0);
    CHECK_INT(reputation_parse_otx(infinite, strlen(infinite), &odd), 0);
    CHECK_INT(odd.otx_pulses, 1000000000L);
    CHECK_INT(reputation_parse_urlhaus(negative, strlen(negative), &odd), 0);
    CHECK_INT(odd.urlhaus_urls, 0);

    domain_report report = {0};
    snprintf(report.name, sizeof(report.name), "bad.example");
    report.modules = MODULE_REPUTATION;
    report.reputation = info;
    report.reputation.otx_status = LOOKUP_OK;
    report.reputation.urlhaus_status = LOOKUP_OK;
    report.reputation.threatfox_status = LOOKUP_OK;
    analyze_domain(&report);

    CHECK(has_signal(&report, SEVERITY_HIGH, "ThreatFox lists this domain as an indicator of compromise (1 entry: "
                                             "Cobalt Strike)"));
    CHECK(has_signal(&report, SEVERITY_HIGH, "URLhaus has 3 malware URLs on this host, 1 still online"));
    CHECK(has_signal(&report, SEVERITY_HIGH, "Spamhaus DBL"));
    CHECK(has_signal(&report, SEVERITY_LOW, "Referenced in 2 AlienVault OTX pulses"));

    char *text = render(&report);
    CHECK(strstr(text, "Reputation    listed: ThreatFox (1 IOC); URLhaus (3 URLs, 1 online);") != NULL);
    CHECK(strstr(text, "REPUTATION") == NULL);
    free(text);

    domain_report_free(&report);
}

void test_reputation(void)
{
    test_reputation_parsers();
}
