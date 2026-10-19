#include <stdio.h>
#include <stdlib.h>

#include "test.h"

#define FIXTURE_DIR "tests/fixtures/"

int test_checks;
int test_failures;

char *read_fixture(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s%s", FIXTURE_DIR, name);

    FILE *file = fopen(path, "rb");

    if (file == NULL)
    {
        fprintf(stderr, "cannot open fixture %s (run the tests from the project root)\n", path);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    char *content = malloc((size_t)size + 1);

    if (content != NULL)
    {
        size_t read = fread(content, 1, (size_t)size, file);
        content[read] = '\0';
    }

    fclose(file);
    return content;
}

int main(void)
{
    struct
    {
        const char *name;
        void (*run)(void);
    } suites[] = {
        {"domain", test_domain},
        {"text", test_text},
        {"dates", test_dates},
        {"signals", test_signals},
        {"whois_parse", test_whois_parse},
        {"whois_query", test_whois_query},
        {"asn_parse", test_asn_parse},
        {"dns_helpers", test_dns_helpers},
        {"correlate", test_correlate},
        {"dns_packet", test_dns_packet},
    };

    for (size_t i = 0; i < sizeof(suites) / sizeof(suites[0]); i++)
    {
        int failures_before = test_failures;
        int checks_before = test_checks;

        suites[i].run();

        printf("  %-14s %3d checks  %s\n", suites[i].name, test_checks - checks_before,
               test_failures == failures_before ? "ok" : "FAILED");
    }

    printf("%d checks, %d failed\n", test_checks, test_failures);
    return test_failures == 0 ? 0 : 1;
}
