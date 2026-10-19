#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

static void out_of_memory(void)
{
    fprintf(stderr, "exposureproof: out of memory\n");
    exit(1);
}

void *xcalloc(size_t count, size_t size)
{
    void *pointer = calloc(count, size);

    if (pointer == NULL && count != 0 && size != 0)
    {
        out_of_memory();
    }

    return pointer;
}

void *xrealloc(void *pointer, size_t size)
{
    void *resized = realloc(pointer, size);

    if (resized == NULL && size != 0)
    {
        out_of_memory();
    }

    return resized;
}

char *xstrdup(const char *text)
{
    char *copy = strdup(text);

    if (copy == NULL)
    {
        out_of_memory();
    }

    return copy;
}

/* Everything printed comes from servers the investigated party may control,
 * so control bytes are replaced before they reach the analyst's terminal. */
void sanitize_text(char *text, size_t length, int keep_newlines)
{
    for (size_t i = 0; i < length; i++)
    {
        unsigned char byte = (unsigned char)text[i];

        if (keep_newlines &&
            (byte == '\n' || byte == '\t' || (byte == '\r' && i + 1 < length && text[i + 1] == '\n')))
        {
            continue;
        }

        if (byte < 0x20 || byte == 0x7f)
        {
            text[i] = '?';
        }
    }
}

int starts_with_ci(const char *text, const char *prefix)
{
    return strncasecmp(text, prefix, strlen(prefix)) == 0;
}

int contains_ci(const char *text, const char *needle)
{
    size_t needle_len = strlen(needle);

    for (; *text != '\0'; text++)
    {
        if (strncasecmp(text, needle, needle_len) == 0)
        {
            return 1;
        }
    }

    return 0;
}

void to_lower(char *text)
{
    for (; *text != '\0'; text++)
    {
        *text = (char)tolower((unsigned char)*text);
    }
}

void utc_timestamp(char *out, size_t size)
{
    time_t now = time(NULL);
    struct tm parts;

    gmtime_r(&now, &parts);
    strftime(out, size, "%Y-%m-%dT%H:%M:%SZ", &parts);
}
