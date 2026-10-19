#ifndef EXPOSUREPROOF_TEST_H
#define EXPOSUREPROOF_TEST_H

#include <stdio.h>
#include <string.h>

/* A minimal assertion harness: failures are reported and counted, and the
 * run continues so one broken check does not hide the others. */

extern int test_checks;
extern int test_failures;

#define CHECK(condition)                                                                  \
    do                                                                                    \
    {                                                                                     \
        test_checks++;                                                                    \
        if (!(condition))                                                                 \
        {                                                                                 \
            test_failures++;                                                              \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
        }                                                                                 \
    } while (0)

#define CHECK_STR(actual, expected)                                                                     \
    do                                                                                                  \
    {                                                                                                   \
        const char *actual_ = (actual);                                                                 \
        const char *expected_ = (expected);                                                             \
        test_checks++;                                                                                  \
        if (actual_ == NULL || strcmp(actual_, expected_) != 0)                                         \
        {                                                                                               \
            test_failures++;                                                                            \
            fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__, expected_,      \
                    actual_ != NULL ? actual_ : "(null)");                                              \
        }                                                                                               \
    } while (0)

#define CHECK_INT(actual, expected)                                                                     \
    do                                                                                                  \
    {                                                                                                   \
        long actual_ = (long)(actual);                                                                  \
        long expected_ = (long)(expected);                                                              \
        test_checks++;                                                                                  \
        if (actual_ != expected_)                                                                       \
        {                                                                                               \
            test_failures++;                                                                            \
            fprintf(stderr, "%s:%d: expected %ld, got %ld\n", __FILE__, __LINE__, expected_, actual_); \
        }                                                                                               \
    } while (0)

/* Returns the contents of tests/fixtures/<name> (caller frees), or NULL. */
char *read_fixture(const char *name);

void test_domain(void);
void test_text(void);
void test_dates(void);
void test_signals(void);
void test_whois_parse(void);
void test_whois_query(void);
void test_asn_parse(void);
void test_dns_helpers(void);
void test_correlate(void);
void test_dns_packet(void);

#endif
