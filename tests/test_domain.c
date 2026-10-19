#include "domain.h"
#include "test.h"

static const char *normalized(const char *input)
{
    static char out[256];

    if (normalize_domain(input, out, sizeof(out)) != 0)
    {
        return "(rejected)";
    }

    return out;
}

static const char *organizational(const char *domain)
{
    static char out[256];

    organizational_domain(domain, out, sizeof(out));
    return out;
}

void test_domain(void)
{
    char out[256];
    char long_label[80];

    CHECK_STR(normalized("Example.COM"), "example.com");
    CHECK_STR(normalized("  example.com.  "), "example.com");
    CHECK_STR(normalized("hxxps://example[.]org/login"), "example.org");
    CHECK_STR(normalized("example(.)com"), "example.com");
    CHECK_STR(normalized("example[dot]com"), "example.com");
    CHECK_STR(normalized("https://user@www.example.com:8443/path?q=1#x"), "www.example.com");
    CHECK_STR(normalized("_dmarc.example.com"), "_dmarc.example.com");

    CHECK_INT(normalize_domain("8.8.8.8", out, sizeof(out)), DOMAIN_IS_IP);
    CHECK_INT(normalize_domain("not a domain", out, sizeof(out)), DOMAIN_INVALID);
    CHECK_INT(normalize_domain("localhost", out, sizeof(out)), DOMAIN_INVALID);
    CHECK_INT(normalize_domain("a..example.com", out, sizeof(out)), DOMAIN_INVALID);
    CHECK_INT(normalize_domain("", out, sizeof(out)), DOMAIN_INVALID);
    CHECK_INT(normalize_domain("exa mple.com", out, sizeof(out)), DOMAIN_INVALID);
    CHECK_INT(normalize_domain("example.com\r\nHost: evil", out, sizeof(out)), 0);
    CHECK_STR(out, "example.com");

    memset(long_label, 'a', 64);
    snprintf(long_label + 64, sizeof(long_label) - 64, ".com");
    CHECK_INT(normalize_domain(long_label, out, sizeof(out)), DOMAIN_INVALID);

    CHECK_STR(organizational("www.example.com"), "example.com");
    CHECK_STR(organizational("example.com"), "example.com");
    CHECK_STR(organizational("www.example.co.uk"), "example.co.uk");
    CHECK_STR(organizational("a.b.uol.com.br"), "uol.com.br");
    CHECK_STR(organizational("uol.com.br"), "uol.com.br");
    CHECK_STR(organizational("x.y.example.io"), "example.io");
    CHECK_STR(organizational("dns.google"), "dns.google");
    CHECK_STR(organizational("co.uk"), "co.uk");
}
