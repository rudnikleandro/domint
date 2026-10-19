#include <stdlib.h>

#include "correlate.h"
#include "model.h"
#include "test.h"

static void make_domain(domain_report *report, const char *name)
{
    memset(report, 0, sizeof(*report));
    snprintf(report->name, sizeof(report->name), "%s", name);
    snprintf(report->org_domain, sizeof(report->org_domain), "%s", name);
}

static void add_address(domain_report *report, const char *ip, const char *asn, const char *as_name, const char *prefix)
{
    address_info *address = &report->addresses[report->address_count];
    report->address_count++;

    snprintf(address->ip, sizeof(address->ip), "%s", ip);
    address->asn_status = LOOKUP_OK;
    address->announced = 1;
    snprintf(address->asn, sizeof(address->asn), "%s", asn);
    snprintf(address->as_name, sizeof(address->as_name), "%s", as_name);
    snprintf(address->prefix, sizeof(address->prefix), "%s", prefix);
}

static void set_soa(domain_report *report, const char *primary, const char *admin)
{
    report->dns.has_soa = 1;
    snprintf(report->dns.soa_primary, sizeof(report->dns.soa_primary), "%s", primary);
    snprintf(report->dns.soa_admin, sizeof(report->dns.soa_admin), "%s", admin);
}

/* Strength of the shared indicator (kind, value), or -1 when not shared. */
static int strength_of(const correlation *links, const char *kind, const char *value)
{
    for (size_t i = 0; i < links->indicator_count; i++)
    {
        if (strcmp(links->indicators[i].kind, kind) == 0 && strcmp(links->indicators[i].value, value) == 0)
        {
            return (int)links->indicators[i].strength;
        }
    }

    return -1;
}

static void run(domain_report *reports, size_t count, correlation *links)
{
    correlate(reports, count, links);
}

static void release(domain_report *reports, size_t count, correlation *links)
{
    correlation_free(links);

    for (size_t i = 0; i < count; i++)
    {
        domain_report_free(&reports[i]);
    }
}

void test_correlate(void)
{
    domain_report reports[3];
    correlation links;

    /* Unrelated sites behind the same CDN edge: weak, and no group. */
    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    add_address(&reports[0], "104.16.1.1", "13335", "CLOUDFLARENET - Cloudflare, Inc., US", "104.16.0.0/13");
    add_address(&reports[1], "104.16.1.1", "13335", "CLOUDFLARENET - Cloudflare, Inc., US", "104.16.0.0/13");
    run(reports, 2, &links);
    CHECK_INT(strength_of(&links, "IP address", "104.16.1.1"), LINK_WEAK);
    CHECK_INT(strength_of(&links, "BGP prefix", "104.16.0.0/13"), LINK_WEAK);
    CHECK_INT(links.cluster_count, 0);
    release(reports, 2, &links);

    /* Cloud addresses get reassigned: medium, and no group. */
    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    add_address(&reports[0], "3.5.1.1", "16509", "AMAZON-02 - Amazon.com, Inc., US", "3.5.0.0/16");
    add_address(&reports[1], "3.5.1.1", "16509", "AMAZON-02 - Amazon.com, Inc., US", "3.5.0.0/16");
    run(reports, 2, &links);
    CHECK_INT(strength_of(&links, "IP address", "3.5.1.1"), LINK_MEDIUM);
    CHECK_INT(strength_of(&links, "BGP prefix", "3.5.0.0/16"), LINK_WEAK);
    CHECK_INT(links.cluster_count, 0);
    release(reports, 2, &links);

    /* A shared address on an ordinary network is specific: candidate group. */
    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    make_domain(&reports[2], "c.example");
    add_address(&reports[0], "198.51.100.7", "64500", "EXAMPLE-HOSTING", "198.51.100.0/24");
    add_address(&reports[1], "198.51.100.7", "64500", "EXAMPLE-HOSTING", "198.51.100.0/24");
    add_address(&reports[2], "203.0.113.9", "64501", "OTHER-NET", "203.0.113.0/24");
    run(reports, 3, &links);
    CHECK_INT(strength_of(&links, "IP address", "198.51.100.7"), LINK_STRONG);
    CHECK_INT(strength_of(&links, "BGP prefix", "198.51.100.0/24"), LINK_MEDIUM);
    CHECK_INT(links.cluster_count, 1);
    CHECK(links.cluster_of[0] == links.cluster_of[1]);
    CHECK(links.cluster_of[2] == NO_CLUSTER);
    release(reports, 3, &links);

    /* Private addresses are shared by every sinkholed domain. */
    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    add_address(&reports[0], "127.0.0.1", "", "", "");
    add_address(&reports[1], "127.0.0.1", "", "", "");
    reports[0].addresses[0].announced = 0;
    reports[1].addresses[0].announced = 0;
    run(reports, 2, &links);
    CHECK_INT(strength_of(&links, "IP address", "127.0.0.1"), LINK_WEAK);
    CHECK_INT(links.cluster_count, 0);
    release(reports, 2, &links);

    /* Provider-default SOA contacts, including Route 53's, are weak. */
    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    set_soa(&reports[0], "ns-1536.awsdns-00.co.uk", "awsdns-hostmaster.amazon.com");
    set_soa(&reports[1], "ns-2000.awsdns-10.org", "awsdns-hostmaster.amazon.com");
    run(reports, 2, &links);
    CHECK_INT(strength_of(&links, "SOA contact", "awsdns-hostmaster.amazon.com"), LINK_WEAK);
    release(reports, 2, &links);

    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    set_soa(&reports[0], "ns1.self-hosted.example", "hostmaster.operator.example");
    set_soa(&reports[1], "ns2.self-hosted.example", "hostmaster.operator.example");
    run(reports, 2, &links);
    CHECK_INT(strength_of(&links, "SOA contact", "hostmaster.operator.example"), LINK_MEDIUM);
    release(reports, 2, &links);

    /* A reused verification token is specific; tokens are case-sensitive. */
    make_domain(&reports[0], "a.example");
    make_domain(&reports[1], "b.example");
    make_domain(&reports[2], "c.example");
    string_list_add(&reports[0].dns.txt.values, "google-site-verification=AbC123");
    string_list_add(&reports[1].dns.txt.values, "google-site-verification=AbC123");
    string_list_add(&reports[2].dns.txt.values, "google-site-verification=abc123");
    run(reports, 3, &links);
    CHECK_INT(strength_of(&links, "Verification token", "google-site-verification=AbC123"), LINK_STRONG);
    CHECK_INT(links.indicator_count, 1);
    CHECK_INT(links.cluster_count, 1);
    CHECK(links.cluster_of[2] == NO_CLUSTER);
    release(reports, 3, &links);
}
