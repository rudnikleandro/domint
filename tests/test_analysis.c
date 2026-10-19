#include <stdlib.h>
#include <time.h>

#include "analysis.h"
#include "model.h"
#include "test.h"

static const char *as_date(const char *text)
{
    static char out[64];

    whois_date(text, out, sizeof(out));
    return out;
}

static const char *age(long days)
{
    static char out[64];

    describe_age(days, out, sizeof(out));
    return out;
}

void test_dates(void)
{
    time_t parsed;

    CHECK_STR(as_date("2001-10-02T18:10:32Z"), "2001-10-02");
    CHECK_STR(as_date("20231116 #27073734"), "2023-11-16");
    CHECK_STR(as_date("20340424"), "2034-04-24");
    CHECK_STR(as_date("15-Dec-1996"), "1996-12-15");
    CHECK_STR(as_date("2001.10.02"), "2001-10-02");
    CHECK_STR(as_date("2001/10/02"), "2001-10-02");
    CHECK_STR(as_date("before Aug-1996"), "before Aug-1996");
    CHECK_STR(as_date(""), "unknown");

    CHECK_INT(parse_whois_date("2001-13-01", &parsed), -1);
    CHECK_INT(parse_whois_date("1234", &parsed), -1);
    CHECK_INT(parse_whois_date("31-Foo-2020", &parsed), -1);

    CHECK_STR(age(0), "0 days");
    CHECK_STR(age(1), "1 day");
    CHECK_STR(age(59), "59 days");
    CHECK_STR(age(60), "2 months");
    CHECK_STR(age(300), "10 months");
    CHECK_STR(age(365), "1 year");
    CHECK_STR(age(760), "2 years, 1 month");
    CHECK_STR(age(1066), "2 years, 11 months");
    CHECK_STR(age(9131), "25 years");

    CHECK(is_verification_token("google-site-verification=abc"));
    CHECK(is_verification_token("MS=ms40192081"));
    CHECK(is_verification_token("_globalsign-domain-verification=xyz"));
    CHECK(!is_verification_token("v=spf1 include:_spf.google.com ~all"));
    CHECK(!is_verification_token("docusign=1234"));
    CHECK(!is_verification_token("5fnm79lyb330pg223w4zouc1qqd6ke2"));

    CHECK_STR(dns_provider_name("isla.ns.cloudflare.com"), "Cloudflare");
    CHECK_STR(dns_provider_name("ns-1536.awsdns-00.co.uk"), "Amazon Route 53");
    CHECK(dns_provider_name("ns1.example.net") == NULL);
    CHECK_STR(mail_provider_name("aspmx.l.google.com"), "Google Workspace");
    CHECK_STR(mail_provider_name("example-com.mail.protection.outlook.com"), "Microsoft 365");
    CHECK(mail_provider_name("mx.example.net") == NULL);
}

/* A registered domain with mail, an enforcing DMARC policy and a strict SPF
 * record: the baseline that produces no mail signals. Tests change one thing. */
static void make_report(domain_report *report, const char *name, long age_days)
{
    char created[32];
    time_t when = time(NULL) - age_days * 86400;
    struct tm parts;

    memset(report, 0, sizeof(*report));
    snprintf(report->name, sizeof(report->name), "%s", name);
    snprintf(report->org_domain, sizeof(report->org_domain), "%s", name);

    gmtime_r(&when, &parts);
    strftime(created, sizeof(created), "%Y-%m-%dT00:00:00Z", &parts);

    report->whois.status = LOOKUP_OK;
    report->whois.registered = 1;
    snprintf(report->whois.created, sizeof(report->whois.created), "%s", created);

    report->resolve_status = LOOKUP_OK;
    report->dns.ns.status = LOOKUP_OK;
    report->dns.mx.status = LOOKUP_OK;
    report->dns.txt.status = LOOKUP_OK;
    report->dns.caa.status = LOOKUP_OK;
    report->dns.dmarc.status = LOOKUP_OK;
    report->dns.soa_status = LOOKUP_OK;

    string_list_add(&report->dns.mx.values, "00010 mx.example.net");
    string_list_add(&report->dns.txt.values, "v=spf1 mx -all");
    string_list_add(&report->dns.dmarc.values, "v=DMARC1; p=reject");
    string_list_add(&report->dns.caa.values, "issue \"letsencrypt.org\"");
    snprintf(report->dns.dmarc_name, sizeof(report->dns.dmarc_name), "_dmarc.%s", name);
}

static int has_finding(const domain_report *report, severity level, const char *text)
{
    for (size_t i = 0; i < report->finding_count; i++)
    {
        if (report->findings[i].level == level && strstr(report->findings[i].text, text) != NULL)
        {
            return 1;
        }
    }

    return 0;
}

static void replace_list(string_list *list, const char *value)
{
    string_list_free(list);

    if (value != NULL)
    {
        string_list_add(list, value);
    }
}

void test_signals(void)
{
    domain_report report;

    /* WHOIS dates are read as noon UTC, so depending on the time of day the
     * computed age can be one day less than requested. */
    make_report(&report, "baseline.example", 3650);
    analyze_domain(&report);
    CHECK_INT(report.finding_count, 0);
    CHECK(report.age_days == 3649 || report.age_days == 3650);
    domain_report_free(&report);

    make_report(&report, "new.example", 10);
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_HIGH, "days ago"));
    domain_report_free(&report);

    make_report(&report, "young.example", 90);
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_MEDIUM, "days ago"));
    domain_report_free(&report);

    make_report(&report, "openspf.example", 3650);
    replace_list(&report.dns.txt.values, "v=spf1 +all");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_HIGH, "+all"));
    domain_report_free(&report);

    make_report(&report, "implicitall.example", 3650);
    replace_list(&report.dns.txt.values, "v=spf1 a mx all");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_HIGH, "+all"));
    domain_report_free(&report);

    make_report(&report, "nomail.example", 3650);
    replace_list(&report.dns.txt.values, NULL);
    replace_list(&report.dns.dmarc.values, NULL);
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_MEDIUM, "No SPF record"));
    CHECK(has_finding(&report, SEVERITY_MEDIUM, "No DMARC policy"));
    domain_report_free(&report);

    /* An enforcing DMARC policy rejects unauthenticated mail on its own. */
    make_report(&report, "dmarconly.example", 3650);
    replace_list(&report.dns.txt.values, NULL);
    analyze_domain(&report);
    CHECK(!has_finding(&report, SEVERITY_MEDIUM, "No SPF record"));
    CHECK(!has_finding(&report, SEVERITY_LOW, "No SPF record"));
    domain_report_free(&report);

    /* A subdomain inheriting the organizational record follows sp=. */
    make_report(&report, "www.inherit.example", 3650);
    snprintf(report.org_domain, sizeof(report.org_domain), "inherit.example");
    snprintf(report.dns.dmarc_name, sizeof(report.dns.dmarc_name), "_dmarc.inherit.example");
    replace_list(&report.dns.dmarc.values, "v=DMARC1; p=reject; sp=none");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_LOW, "p=none"));
    domain_report_free(&report);

    make_report(&report, "softfail.example", 3650);
    replace_list(&report.dns.txt.values, "v=spf1 mx ~all");
    replace_list(&report.dns.dmarc.values, "v=DMARC1; p=none");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_LOW, "~all"));
    CHECK(has_finding(&report, SEVERITY_LOW, "monitoring mode"));
    domain_report_free(&report);

    make_report(&report, "twospf.example", 3650);
    string_list_add(&report.dns.txt.values, "v=spf1 -all");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_MEDIUM, "2 SPF records"));
    domain_report_free(&report);

    make_report(&report, "txtfail.example", 3650);
    report.dns.txt.status = LOOKUP_FAILED;
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_INFO, "TXT lookup failed"));
    CHECK(!has_finding(&report, SEVERITY_MEDIUM, "No SPF record"));
    domain_report_free(&report);

    /* Mail checks mean nothing for a name nobody owns. */
    make_report(&report, "unregistered.example", 3650);
    report.whois.registered = 0;
    report.resolve_status = LOOKUP_FAILED;
    replace_list(&report.dns.txt.values, NULL);
    replace_list(&report.dns.dmarc.values, NULL);
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_INFO, "Not registered"));
    CHECK(!has_finding(&report, SEVERITY_MEDIUM, "No SPF record"));
    CHECK(!has_finding(&report, SEVERITY_LOW, "No DMARC policy"));
    domain_report_free(&report);

    make_report(&report, "sinkhole.example", 3650);
    report.address_count = 1;
    snprintf(report.addresses[0].ip, sizeof(report.addresses[0].ip), "127.0.0.1");
    report.addresses[0].asn_status = LOOKUP_OK;
    report.addresses[0].announced = 0;
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_MEDIUM, "private or unannounced"));
    domain_report_free(&report);

    make_report(&report, "behindcdn.example", 3650);
    report.address_count = 1;
    report.addresses[0].asn_status = LOOKUP_OK;
    report.addresses[0].announced = 1;
    snprintf(report.addresses[0].as_name, sizeof(report.addresses[0].as_name), "CLOUDFLARENET - Cloudflare, Inc., US");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_INFO, "Served through Cloudflare"));
    domain_report_free(&report);

    make_report(&report, "banner.example", 3650);
    report.http.status = LOOKUP_OK;
    snprintf(report.http.server, sizeof(report.http.server), "Apache/2.4.29 (Ubuntu)");
    snprintf(report.http.location, sizeof(report.http.location), "https://login.other-site.example/path");
    analyze_domain(&report);
    CHECK(has_finding(&report, SEVERITY_LOW, "announces its version"));
    CHECK(has_finding(&report, SEVERITY_INFO, "Redirects to another domain: login.other-site.example"));
    domain_report_free(&report);

    /* Expiry: something to watch at 8-30 days, low when imminent, medium once
     * past. Offsets are in whole days plus half a day to stay clear of the
     * day boundary. */
    struct
    {
        double days;
        severity level;
        const char *text;
    } expiry_cases[] = {
        {20.5, SEVERITY_INFO, "worth checking again"},
        {3.5, SEVERITY_LOW, "has not been renewed yet"},
        {-5.5, SEVERITY_MEDIUM, "grace period"},
    };

    for (size_t i = 0; i < sizeof(expiry_cases) / sizeof(expiry_cases[0]); i++)
    {
        time_t when = time(NULL) + (time_t)(expiry_cases[i].days * 86400);
        struct tm parts;

        make_report(&report, "expiry.example", 3650);
        gmtime_r(&when, &parts);
        strftime(report.whois.expires, sizeof(report.whois.expires), "%Y-%m-%d", &parts);
        analyze_domain(&report);
        CHECK(has_finding(&report, expiry_cases[i].level, expiry_cases[i].text));
        domain_report_free(&report);
    }

    make_report(&report, "farexpiry.example", 3650);
    snprintf(report.whois.expires, sizeof(report.whois.expires), "2099-01-01");
    analyze_domain(&report);
    CHECK_INT(report.finding_count, 0);
    domain_report_free(&report);

    /* Signals come out most severe first. */
    make_report(&report, "order.example", 10);
    replace_list(&report.dns.caa.values, NULL);
    analyze_domain(&report);
    CHECK(report.finding_count >= 2);
    CHECK_INT(report.findings[0].level, SEVERITY_HIGH);
    CHECK_INT(report.findings[report.finding_count - 1].level, SEVERITY_INFO);
    domain_report_free(&report);
}
