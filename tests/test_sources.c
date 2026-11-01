#include <stdlib.h>
#include <time.h>

#include "dns.h"
#include "model.h"
#include "rdap.h"
#include "test.h"
#include "tls.h"
#include "whois.h"

/* Answers for "a." with one DS (key tag 12345, algorithm 13, digest type 2)
 * and one DNSKEY (flags 257, protocol 3, algorithm 13). */
static const unsigned char ds_packet[] = {
    0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    1, 'a', 0, 0x00, 0x2b, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x2b, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x08,
    0x30, 0x39, 13, 2, 0xde, 0xad, 0xbe, 0xef,
};

static const unsigned char dnskey_packet[] = {
    0x00, 0x03, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    1, 'a', 0, 0x00, 0x30, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x30, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x08,
    0x01, 0x01, 3, 13, 0x01, 0x02, 0x03, 0x04,
};

static void free_registration(whois_info *info)
{
    string_list_free(&info->statuses);
}

void test_sources(void)
{
    whois_info info;
    char service[256];

    /* RDAP: a real Verisign answer. */
    char *text = read_fixture("rdap_verisign.json");
    CHECK(text != NULL);
    memset(&info, 0, sizeof(info));

    if (text != NULL)
    {
        CHECK_INT(rdap_parse(text, strlen(text), &info), 0);
        free(text);
    }

    CHECK_INT(info.registered, 1);
    CHECK_STR(info.registrar, "MarkMonitor Inc.");
    CHECK_STR(info.abuse_email, "abusecomplaints@markmonitor.com");
    CHECK_STR(info.created, "1997-09-15T04:00:00Z");
    CHECK_STR(info.expires, "2028-09-14T04:00:00Z");
    CHECK_STR(info.updated, "2019-09-09T15:39:04Z");
    CHECK_INT(info.statuses.count, 6);
    CHECK(string_list_contains(&info.statuses, "client transfer prohibited"));
    free_registration(&info);

    memset(&info, 0, sizeof(info));
    CHECK_INT(rdap_parse("not json", 8, &info), -1);
    CHECK_INT(rdap_parse("[1]", 3, &info), -1);
    free_registration(&info);

    /* A registrant hidden by a privacy service is flagged. */
    const char *redacted = "{\"entities\":[{\"roles\":[\"registrant\"],\"vcardArray\":[\"vcard\",[[\"fn\",{},\"text\","
                           "\"REDACTED FOR PRIVACY\"]]]}]}";
    memset(&info, 0, sizeof(info));
    CHECK_INT(rdap_parse(redacted, strlen(redacted), &info), 0);
    CHECK_STR(info.registrant, "REDACTED FOR PRIVACY");
    CHECK_INT(info.privacy, 1);
    free_registration(&info);

    /* Bootstrap lookup: case-insensitive TLD, only https:// services. */
    const char *bootstrap = "{\"services\":[[[\"com\",\"net\"],[\"https://rdap.example/com/\"]],"
                            "[[\"plain\"],[\"http://rdap.example/\"]],[[\"br\"],[\"https://rdap.registro.br/\"]]]}";
    CHECK_INT(rdap_find_service(bootstrap, strlen(bootstrap), "NET", service, sizeof(service)), 1);
    CHECK_STR(service, "https://rdap.example/com/");
    CHECK_INT(rdap_find_service(bootstrap, strlen(bootstrap), "br", service, sizeof(service)), 1);
    CHECK_STR(service, "https://rdap.registro.br/");
    CHECK_INT(rdap_find_service(bootstrap, strlen(bootstrap), "plain", service, sizeof(service)), 0);
    CHECK_INT(rdap_find_service(bootstrap, strlen(bootstrap), "io", service, sizeof(service)), 0);
    CHECK_INT(rdap_find_service("{", 1, "com", service, sizeof(service)), -1);

    /* WHOIS: status codes and the abuse contact. */
    text = read_fixture("whois_verisign_registered.txt");
    memset(&info, 0, sizeof(info));

    if (text != NULL)
    {
        whois_parse(text, &info);
        free(text);
    }

    CHECK_INT(info.statuses.count, 6);
    CHECK(string_list_contains(&info.statuses, "clientDeleteProhibited"));
    CHECK_STR(info.abuse_email, "abusecomplaints@markmonitor.com");
    free_registration(&info);

    /* TLS: libcurl's certificate description. */
    tls_info tls;
    time_t until;

    text = read_fixture("tls_certinfo.txt");
    memset(&tls, 0, sizeof(tls));

    if (text != NULL)
    {
        tls_parse(text, &tls);
        free(text);
    }

    CHECK_STR(tls.subject, "CN = example.com");
    CHECK_STR(tls.issuer, "C = US, O = SSL Corporation, CN = Cloudflare TLS Issuing ECC CA 3");
    CHECK_STR(tls.valid_until, "Dec 25 22:56:35 2026 GMT");
    CHECK_STR(tls.serial, "01eee6aabb521d5e14fc315fd9985690");
    CHECK_INT(tls_parse_time(tls.valid_until, &until), 0);
    CHECK_INT((long)until, 1798239395L);
    CHECK_INT(tls_parse_time("garbage", &until), -1);
    CHECK_INT(tls_parse_time("Foo 12 11:11:15 2027 GMT", &until), -1);

    /* DNSSEC records. */
    string_list values = {0};
    CHECK_INT(dns_parse_answer(ds_packet, sizeof(ds_packet), 43, &values, NULL), 1);
    CHECK(values.count == 1 && strcmp(values.items[0], "key tag 12345, algorithm 13, digest type 2") == 0);
    string_list_free(&values);
    CHECK_INT(dns_parse_answer(dnskey_packet, sizeof(dnskey_packet), 48, &values, NULL), 1);
    CHECK(values.count == 1 && strcmp(values.items[0], "flags 257 (key-signing), algorithm 13") == 0);
    string_list_free(&values);
}
