#include "text.h"

#include <ctype.h>
#include <string.h>
#include <strings.h>

/* Everything printed here comes from servers the investigated party may
 * control, so control bytes (terminal escape sequences, embedded NULs) are
 * replaced before they reach the analyst's terminal. */
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
