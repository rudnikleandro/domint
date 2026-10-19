#include "domain.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "util.h"

#define MAX_DOMAIN_LENGTH 253
#define MAX_LABEL_LENGTH 63

/* Undoes the usual defanging notations: example[.]com, example(.)com, example[dot]com. */
static void refang(const char *input, char *out, size_t out_size)
{
    size_t len = 0;

    while (*input != '\0' && len < out_size - 1)
    {
        if (strncmp(input, "[.]", 3) == 0 || strncmp(input, "(.)", 3) == 0 || strncmp(input, "{.}", 3) == 0)
        {
            out[len++] = '.';
            input += 3;
        }
        else if (strncasecmp(input, "[dot]", 5) == 0)
        {
            out[len++] = '.';
            input += 5;
        }
        else
        {
            out[len++] = *input;
            input++;
        }
    }

    out[len] = '\0';
}

static int valid_labels(const char *name)
{
    size_t label_len = 0;

    for (const char *c = name;; c++)
    {
        if (*c == '.' || *c == '\0')
        {
            if (label_len == 0 || label_len > MAX_LABEL_LENGTH)
            {
                return 0;
            }

            if (*c == '\0')
            {
                return 1;
            }

            label_len = 0;
        }
        else if (isalnum((unsigned char)*c) || *c == '-' || *c == '_')
        {
            label_len++;
        }
        else
        {
            return 0;
        }
    }
}

int normalize_domain(const char *input, char *out, size_t out_size)
{
    char buffer[1024];
    refang(input, buffer, sizeof(buffer));

    char *start = buffer;

    while (isspace((unsigned char)*start))
    {
        start++;
    }

    /* Any scheme, including defanged ones such as hxxps://. */
    char *scheme_end = strstr(start, "://");

    if (scheme_end != NULL)
    {
        start = scheme_end + 3;
    }

    start[strcspn(start, "/?#")] = '\0';

    char *at = strrchr(start, '@');

    if (at != NULL)
    {
        start = at + 1;
    }

    start[strcspn(start, ": \t\r\n")] = '\0';

    size_t len = strlen(start);

    while (len > 0 && start[len - 1] == '.')
    {
        len--;
        start[len] = '\0';
    }

    to_lower(start);

    struct in_addr ipv4;

    if (inet_pton(AF_INET, start, &ipv4) == 1)
    {
        return DOMAIN_IS_IP;
    }

    if (len == 0 || len > MAX_DOMAIN_LENGTH || len >= out_size || strchr(start, '.') == NULL || !valid_labels(start))
    {
        return DOMAIN_INVALID;
    }

    memcpy(out, start, len + 1);
    return 0;
}

/* Without the Public Suffix List this is an approximation: the last two
 * labels, or three when the TLD is a country code and the second level is a
 * common category such as co.uk or com.br. */
void organizational_domain(const char *domain, char *out, size_t out_size)
{
    static const char *const second_levels[] = {"ac", "co", "com", "edu", "gob", "gov", "mil", "net", "ne", "nom", "or", "org", "go"};

    const char *last_dot = strrchr(domain, '.');
    const char *second_dot = NULL;
    const char *third_dot = NULL;

    for (const char *c = domain; last_dot != NULL && c < last_dot; c++)
    {
        if (*c == '.')
        {
            third_dot = second_dot;
            second_dot = c;
        }
    }

    const char *start = second_dot != NULL ? second_dot + 1 : domain;

    if (second_dot != NULL && strlen(last_dot + 1) == 2)
    {
        size_t second_len = (size_t)(last_dot - (second_dot + 1));

        for (size_t i = 0; i < sizeof(second_levels) / sizeof(second_levels[0]); i++)
        {
            if (strlen(second_levels[i]) == second_len && strncmp(second_dot + 1, second_levels[i], second_len) == 0)
            {
                start = third_dot != NULL ? third_dot + 1 : domain;
                break;
            }
        }
    }

    snprintf(out, out_size, "%s", start);
}
