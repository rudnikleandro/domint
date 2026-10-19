#include "test.h"
#include "util.h"

void test_text(void)
{
    char escape[] = "a\x1b[31mb";
    sanitize_text(escape, strlen(escape), 0);
    CHECK_STR(escape, "a?[31mb");

    char lines[] = "line1\r\nline2\tx\n";
    sanitize_text(lines, strlen(lines), 1);
    CHECK_STR(lines, "line1\r\nline2\tx\n");

    char lone_cr[] = "real\rfake";
    sanitize_text(lone_cr, strlen(lone_cr), 1);
    CHECK_STR(lone_cr, "real?fake");

    char single_line[] = "a\nb\tc";
    sanitize_text(single_line, strlen(single_line), 0);
    CHECK_STR(single_line, "a?b?c");

    char embedded_nul[] = {'a', '\0', 'b', '\x7f', '\0'};
    sanitize_text(embedded_nul, 4, 0);
    CHECK_STR(embedded_nul, "a?b?");

    CHECK(starts_with_ci("V=SPF1 -all", "v=spf1"));
    CHECK(!starts_with_ci("v=spf", "v=spf1"));
    CHECK(contains_ci("CLOUDFLARENET - Cloudflare", "cloudflare"));
    CHECK(!contains_ci("AKAMAI", "cloudflare"));

    char mixed[] = "MiXeD.Example.COM";
    to_lower(mixed);
    CHECK_STR(mixed, "mixed.example.com");
}
