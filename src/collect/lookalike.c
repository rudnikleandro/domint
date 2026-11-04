#include "collect/lookalike.h"

#include <arpa/nameser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "collect/dns.h"
#include "core/model.h"
#include "support/domain.h"
#include "support/util.h"

#define MAX_LABEL 63
#define SUMMARY_FORMAT "%zu variants checked: %zu registered, %zu unanswered"

typedef struct
{
    lookalike_candidate *items;
    size_t count;
    size_t capacity;
    const char *suffix;
    const char *original;
} candidate_set;

static int valid_label(const char *label)
{
    size_t length = strlen(label);

    if (length == 0 || length > MAX_LABEL || label[0] == '-' || label[length - 1] == '-' ||
        strncmp(label, "xn--", 4) == 0)
    {
        return 0;
    }

    for (const char *c = label; *c != '\0'; c++)
    {
        if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '-'))
        {
            return 0;
        }
    }

    return 1;
}

static void add(candidate_set *set, const char *label, const char *suffix, const char *technique)
{
    char name[DOMAIN_SIZE];

    if (set->count == set->capacity || !valid_label(label) ||
        (size_t)snprintf(name, sizeof(name), "%s.%s", label, suffix) >= sizeof(name) ||
        strcmp(name, set->original) == 0)
    {
        return;
    }

    for (size_t i = 0; i < set->count; i++)
    {
        if (strcmp(set->items[i].name, name) == 0)
        {
            return;
        }
    }

    memcpy(set->items[set->count].name, name, strlen(name) + 1);
    set->items[set->count].technique = technique;
    set->count++;
}

static void add_variant(candidate_set *set, const char *label, const char *technique)
{
    add(set, label, set->suffix, technique);
}

/* Keys next to each one on a QWERTY keyboard: the usual slip of a finger. */
static const char *neighbours(char c)
{
    static const char *const letters[26] = {
        "qwsz",   "vghn",  "xdfv", "erfcxs", "wrsd", "rtgvcd", "tyhbvf", "yujnbg", "uojk",
        "uikmnh", "iolmj", "opk",  "njk",    "bhjm", "iplk",   "ol",     "wa",     "etdf",
        "weadzx", "ryfg",  "yihj", "cfgb",   "qeas", "zsdc",   "tugh",   "asx",
    };
    static const char *const digits[10] = {"9p", "2q", "13w", "24e", "35r", "46t", "57y", "68u", "79i", "80o"};

    if (c >= 'a' && c <= 'z')
    {
        return letters[c - 'a'];
    }

    return c >= '0' && c <= '9' ? digits[c - '0'] : "";
}

/* Characters that read alike in most fonts, both ways. */
static const char *const homoglyphs[][2] = {
    {"o", "0"},  {"0", "o"},  {"l", "1"},  {"1", "l"},  {"i", "1"},  {"i", "l"}, {"l", "i"}, {"m", "rn"},
    {"rn", "m"}, {"w", "vv"}, {"vv", "w"}, {"d", "cl"}, {"cl", "d"}, {"g", "q"}, {"q", "g"}, {"u", "v"},
    {"v", "u"},  {"n", "m"},  {"m", "n"},  {"s", "5"},  {"e", "3"},  {"a", "4"}, {"b", "6"}, {"t", "7"},
};

/* Words phishing domains put next to a brand. */
static const char *const words[] = {"login",  "secure", "account", "support", "portal", "mail", "online",  "app",
                                    "verify", "update", "auth",    "sso",     "pay",    "help", "service", "access"};

static const char *const tlds[] = {"com",  "net", "org", "info", "biz", "co",  "io",   "xyz", "online", "site",
                                   "shop", "app", "me",  "us",   "cc",  "top", "live", "br",  "com.br", "net.br"};

static void generate(candidate_set *set, const char *label)
{
    size_t n = strlen(label);
    /* Room for two full labels: the compiler cannot see they are at most 63. */
    char variant[DOMAIN_SIZE * 2 + 8];

    for (size_t i = 0; i < n; i++)
    {
        /* omission: exmple */
        snprintf(variant, sizeof(variant), "%.*s%s", (int)i, label, label + i + 1);
        add_variant(set, variant, "omission");

        /* repetition: exaample */
        snprintf(variant, sizeof(variant), "%.*s%c%s", (int)i + 1, label, label[i], label + i + 1);
        add_variant(set, variant, "repetition");

        /* transposition: examlpe */
        if (i + 1 < n)
        {
            snprintf(variant, sizeof(variant), "%s", label);
            variant[i] = label[i + 1];
            variant[i + 1] = label[i];
            add_variant(set, variant, "transposition");
        }

        /* hyphenation: exam-ple */
        if (i > 0)
        {
            snprintf(variant, sizeof(variant), "%.*s-%s", (int)i, label, label + i);
            add_variant(set, variant, "hyphenation");
        }

        for (const char *key = neighbours(label[i]); *key != '\0'; key++)
        {
            /* replacement: exanple */
            snprintf(variant, sizeof(variant), "%s", label);
            variant[i] = *key;
            add_variant(set, variant, "replacement");

            /* insertion: exampnle */
            snprintf(variant, sizeof(variant), "%.*s%c%s", (int)i, label, *key, label + i);
            add_variant(set, variant, "insertion");
        }

        /* vowel swap: exomple */
        if (strchr("aeiou", label[i]) != NULL)
        {
            for (const char *vowel = "aeiou"; *vowel != '\0'; vowel++)
            {
                snprintf(variant, sizeof(variant), "%s", label);
                variant[i] = *vowel;
                add_variant(set, variant, "vowel-swap");
            }
        }

        /* bitsquatting: a bit flipped in memory or on the wire */
        for (int bit = 0; bit < 8; bit++)
        {
            char flipped = (char)(label[i] ^ (1 << bit));

            snprintf(variant, sizeof(variant), "%s", label);
            variant[i] = flipped;
            add_variant(set, variant, "bitsquatting");
        }
    }

    for (size_t h = 0; h < sizeof(homoglyphs) / sizeof(homoglyphs[0]); h++)
    {
        size_t from_length = strlen(homoglyphs[h][0]);

        for (const char *at = strstr(label, homoglyphs[h][0]); at != NULL; at = strstr(at + 1, homoglyphs[h][0]))
        {
            snprintf(variant, sizeof(variant), "%.*s%s%s", (int)(at - label), label, homoglyphs[h][1],
                     at + from_length);
            add_variant(set, variant, "homoglyph");
        }
    }

    /* addition: examplex */
    for (const char *c = "abcdefghijklmnopqrstuvwxyz0123456789"; *c != '\0'; c++)
    {
        snprintf(variant, sizeof(variant), "%s%c", label, *c);
        add_variant(set, variant, "addition");
    }

    for (size_t w = 0; w < sizeof(words) / sizeof(words[0]); w++)
    {
        snprintf(variant, sizeof(variant), "%s-%s", label, words[w]);
        add_variant(set, variant, "phishing-word");
        snprintf(variant, sizeof(variant), "%s-%s", words[w], label);
        add_variant(set, variant, "phishing-word");
        snprintf(variant, sizeof(variant), "%s%s", label, words[w]);
        add_variant(set, variant, "phishing-word");
    }

    for (size_t t = 0; t < sizeof(tlds) / sizeof(tlds[0]); t++)
    {
        add(set, label, tlds[t], "tld-swap");
    }
}

size_t lookalike_generate(const char *domain, lookalike_candidate *out, size_t capacity)
{
    char org[DOMAIN_SIZE];
    char label[DOMAIN_SIZE];

    organizational_domain(domain, org, sizeof(org));
    to_lower(org);

    const char *dot = strchr(org, '.');

    if (dot == NULL || (size_t)(dot - org) > MAX_LABEL)
    {
        return 0;
    }

    snprintf(label, sizeof(label), "%.*s", (int)(dot - org), org);

    candidate_set set = {out, 0, capacity, dot + 1, org};
    generate(&set, label);
    return set.count;
}

static void record_answer(observation_list *observations, const char *type, const char *name,
                          const unsigned char *answer, int length)
{
    char query[DOMAIN_SIZE + 16];

    snprintf(query, sizeof(query), "%s %s", type, name);

    if (answer == NULL)
    {
        record_observation(observations, LOOKALIKE_COLLECTOR, "configured resolver", query, OBS_NO_RESPONSE,
                           "no usable answer", NULL, 0);
        return;
    }

    record_observation(observations, LOOKALIKE_COLLECTOR, "configured resolver", query, OBS_OK, NULL, answer,
                       (size_t)length);
}

static void free_answers(unsigned char **answers, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        free(answers[i]);
    }
}

void lookalike_collect(const char *domain, const struct in_addr *custom_resolver, observation_list *observations)
{
    lookalike_candidate *candidates = xcalloc(MAX_LOOKALIKES, sizeof(*candidates));
    size_t count = lookalike_generate(domain, candidates, MAX_LOOKALIKES);
    const char **names = xcalloc(count + 1, sizeof(*names));
    unsigned char **answers = xcalloc(count + 1, sizeof(*answers));
    int *lengths = xcalloc(count + 1, sizeof(*lengths));
    size_t registered = 0;
    size_t unanswered = 0;

    for (size_t i = 0; i < count; i++)
    {
        names[i] = candidates[i].name;
    }

    /* NXDOMAIN for the NS query means nobody registered the name. */
    dns_query_many(names, count, ns_t_ns, custom_resolver, answers, lengths);

    const char **found = xcalloc(count + 1, sizeof(*found));

    for (size_t i = 0; i < count; i++)
    {
        if (answers[i] == NULL)
        {
            unanswered++;
        }
        else if ((answers[i][3] & 0x0f) != ns_r_nxdomain)
        {
            record_answer(observations, "NS", names[i], answers[i], lengths[i]);
            found[registered++] = names[i];
        }
    }

    free_answers(answers, count);

    static const struct
    {
        int type;
        const char *name;
    } details[] = {{ns_t_a, "A"}, {ns_t_mx, "MX"}};

    for (size_t d = 0; d < sizeof(details) / sizeof(details[0]); d++)
    {
        dns_query_many(found, registered, details[d].type, custom_resolver, answers, lengths);

        for (size_t i = 0; i < registered; i++)
        {
            record_answer(observations, details[d].name, found[i], answers[i], lengths[i]);
        }

        free_answers(answers, registered);
    }

    char detail[FIELD_SIZE];
    observation_status status = count > 0 && unanswered == count ? OBS_NO_RESPONSE
                                : unanswered * 10 > count        ? OBS_LIMITED
                                                                 : OBS_OK;

    snprintf(detail, sizeof(detail), SUMMARY_FORMAT, count, registered, unanswered);
    record_observation(observations, LOOKALIKE_COLLECTOR, "configured resolver", domain, status, detail, NULL, 0);

    free(found);
    free(lengths);
    free(answers);
    free(names);
    free(candidates);
}

/* The values of `type` in the recorded answer for "<TYPE> <name>", and the
 * answer's rcode (-1 when nothing was recorded or nothing came back). */
static int recorded_values(const observation_list *observations, const char *type_name, int type, const char *name,
                           string_list *values)
{
    char query[DOMAIN_SIZE + 16];

    snprintf(query, sizeof(query), "%s %s", type_name, name);

    const observation *item = find_observation(observations, LOOKALIKE_COLLECTOR, query);

    if (item == NULL || item->status != OBS_OK || item->content == NULL || item->content_length < NS_HFIXEDSZ)
    {
        return -1;
    }

    if (values != NULL)
    {
        dns_parse_answer(item->content, item->content_length, type, values, NULL);
    }

    return item->content[3] & 0x0f;
}

void lookalike_interpret(const char *domain, const observation_list *observations, lookalike_list *list)
{
    const observation *summary = find_observation(observations, LOOKALIKE_COLLECTOR, domain);
    size_t registered = 0;

    list->status = LOOKUP_SKIPPED;

    if (summary == NULL)
    {
        return;
    }

    if (sscanf(summary->detail, SUMMARY_FORMAT, &list->checked, &registered, &list->unanswered) != 3 ||
        summary->status == OBS_NO_RESPONSE)
    {
        list->status = LOOKUP_FAILED;
        return;
    }

    list->status = LOOKUP_OK;

    lookalike_candidate *candidates = xcalloc(MAX_LOOKALIKES, sizeof(*candidates));
    size_t count = lookalike_generate(domain, candidates, MAX_LOOKALIKES);

    for (size_t i = 0; i < count; i++)
    {
        string_list nameservers = {0};
        int rcode = recorded_values(observations, "NS", ns_t_ns, candidates[i].name, &nameservers);

        if (rcode < 0)
        {
            string_list_free(&nameservers);
            continue;
        }

        if (list->count == list->capacity)
        {
            list->capacity = list->capacity == 0 ? 8 : list->capacity * 2;
            list->items = xrealloc(list->items, list->capacity * sizeof(*list->items));
        }

        lookalike_info *item = &list->items[list->count++];
        string_list mail = {0};

        memset(item, 0, sizeof(*item));
        snprintf(item->name, sizeof(item->name), "%s", candidates[i].name);
        item->technique = candidates[i].technique;
        item->nameservers = nameservers;
        item->dns_fails = rcode != ns_r_noerror;
        recorded_values(observations, "A", ns_t_a, item->name, &item->addresses);
        recorded_values(observations, "MX", ns_t_mx, item->name, &mail);

        for (size_t m = 0; m < mail.count; m++)
        {
            item->has_mail |= !mx_is_null(mail.items[m]);
        }

        string_list_free(&mail);
    }

    free(candidates);
}
