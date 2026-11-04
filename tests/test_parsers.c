#include <stdlib.h>

#include "collect/asn.h"
#include "collect/dns.h"
#include "collect/whois.h"
#include "core/model.h"
#include "test.h"

/* A DNS response for "example.com TXT" holding "v=spf1 -all". */
static const unsigned char txt_packet[] = {
    0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 7,    'e',  'x',  'a',  'm',  'p',
    'l',  'e',  3,    'c',  'o',  'm',  0,    0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00,
    0x00, 0x01, 0x2c, 0x00, 0x0c, 11,   'v',  '=',  's',  'p',  'f',  '1',  ' ',  '-',  'a',  'l',  'l',
};

static void parse_fixture(const char *name, whois_info *info)
{
    char *response = read_fixture(name);

    string_list_free(&info->statuses);
    memset(info, 0, sizeof(*info));
    CHECK(response != NULL);

    if (response != NULL)
    {
        whois_parse(response, info);
        free(response);
    }
}

void test_whois_parse(void)
{
    whois_info info = {0};

    parse_fixture("whois_verisign_registered.txt", &info);
    CHECK_INT(info.registered, 1);
    CHECK_STR(info.registrar, "MarkMonitor Inc.");
    CHECK_STR(info.created, "1997-09-15T04:00:00Z");
    CHECK_STR(info.updated, "2019-09-09T15:39:04Z");
    CHECK_STR(info.expires, "2028-09-14T04:00:00Z");
    CHECK_STR(info.registrant, "");
    CHECK_INT(info.privacy, 0);

    parse_fixture("whois_verisign_not_found.txt", &info);
    CHECK_INT(info.registered, 0);
    CHECK_STR(info.registrar, "");

    /* Nominet puts some values on the line after the field name. */
    parse_fixture("whois_nominet.txt", &info);
    CHECK_INT(info.registered, 1);
    CHECK_STR(info.registrar, "British Broadcasting Corporation [Tag = BBC]");
    CHECK_STR(info.created, "before Aug-1996");
    CHECK_STR(info.expires, "13-Dec-2034");
    CHECK_STR(info.updated, "29-Oct-2025");

    /* registro.br: no registrar, owner as registrant, contact blocks with
     * their own created/changed lines that must not win over the domain's. */
    parse_fixture("whois_registro_br.txt", &info);
    CHECK_INT(info.registered, 1);
    CHECK_STR(info.registrar, "");
    CHECK_STR(info.registrant, "Universo Online S.A.");
    CHECK_STR(info.created, "19960424 #7137");
    CHECK_STR(info.updated, "20240827");
    CHECK_STR(info.expires, "20340424");
    CHECK_INT(info.privacy, 0);

    string_list_free(&info.statuses);
    memset(&info, 0, sizeof(info));
    whois_parse("Registrant Organization: Privacy service provided by Withheld for Privacy ehf\n", &info);
    CHECK_INT(info.privacy, 1);
    string_list_free(&info.statuses);
}

void test_asn_parse(void)
{
    address_info address;
    char *response = read_fixture("cymru_announced.txt");

    memset(&address, 0, sizeof(address));
    CHECK(response != NULL);

    if (response != NULL)
    {
        asn_parse(response, &address);
        free(response);
    }

    CHECK_INT(address.asn_status, LOOKUP_OK);
    CHECK_INT(address.announced, 1);
    CHECK_STR(address.asn, "15169");
    CHECK_STR(address.prefix, "8.8.8.0/24");
    CHECK_STR(address.country, "US");
    CHECK_STR(address.registry, "arin");
    CHECK_STR(address.allocated, "2023-12-28");
    CHECK_STR(address.as_name, "GOOGLE - Google LLC, US");

    response = read_fixture("cymru_private.txt");
    memset(&address, 0, sizeof(address));

    if (response != NULL)
    {
        asn_parse(response, &address);
        free(response);
    }

    CHECK_INT(address.asn_status, LOOKUP_OK);
    CHECK_INT(address.announced, 0);
    CHECK_STR(address.asn, "");

    char garbage[] = "Error: no ASN or IP match on line 1.\n";
    memset(&address, 0, sizeof(address));
    asn_parse(garbage, &address);
    CHECK_INT(address.asn_status, LOOKUP_FAILED);
}

void test_dns_helpers(void)
{
    CHECK_INT(mx_priority("00010 smtp.google.com"), 10);
    CHECK_STR(mx_host("00010 smtp.google.com"), "smtp.google.com");
    CHECK_INT(mx_is_null("00010 smtp.google.com"), 0);
    CHECK_INT(mx_is_null("00000 ."), 1);
    CHECK_INT(mx_is_null("00000 "), 1);

    /* Header with ARCOUNT 0, followed by the question "a." type A class IN. */
    unsigned char query[64] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x01, 'a',  0x00, 0x00, 0x01, 0x00, 0x01};
    const unsigned char expected_opt[EDNS0_OPT_SIZE] = {0x00, 0x00, 0x29, 0x04, 0xd0, 0x00,
                                                        0x00, 0x00, 0x00, 0x00, 0x00};
    int query_len = 19;

    CHECK_INT(dns_append_edns0(query, query_len, sizeof(query)), query_len + EDNS0_OPT_SIZE);
    CHECK_INT(query[11], 1);
    CHECK(memcmp(query + query_len, expected_opt, EDNS0_OPT_SIZE) == 0);
    CHECK_INT(dns_append_edns0(query, query_len, query_len + EDNS0_OPT_SIZE - 1), -1);
    CHECK_INT(dns_append_edns0(query, 5, sizeof(query)), -1);
}

void test_dns_packet(void)
{
    string_list values = {0};

    CHECK_INT(dns_parse_answer(txt_packet, sizeof(txt_packet), 16, &values, NULL), 1);
    CHECK(values.count == 1 && strcmp(values.items[0], "v=spf1 -all") == 0);
    CHECK_INT(dns_parse_answer(txt_packet, sizeof(txt_packet), 2, NULL, NULL), 0);
    CHECK_INT(dns_parse_answer(txt_packet, 20, 16, NULL, NULL), -1);
    string_list_free(&values);
}
