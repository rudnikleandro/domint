/* Registration dates in the many formats registries use. */

#include "core/dates.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "support/util.h"

static const char *const month_names[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                          "jul", "aug", "sep", "oct", "nov", "dec"};

int parse_whois_date(const char *text, time_t *out)
{
    int year = 0;
    int month = 0;
    int day = 0;
    char month_name[4] = "";

    while (*text == ' ')
    {
        text++;
    }

    if (sscanf(text, "%4d-%2d-%2d", &year, &month, &day) == 3 ||
        sscanf(text, "%4d.%2d.%2d", &year, &month, &day) == 3 ||
        sscanf(text, "%4d/%2d/%2d", &year, &month, &day) == 3)
    {
        /* year-month-day */
    }
    else if (sscanf(text, "%2d-%3[A-Za-z]-%4d", &day, month_name, &year) == 3)
    {
        for (size_t i = 0; i < ARRAY_COUNT(month_names); i++)
        {
            if (strcasecmp(month_name, month_names[i]) == 0)
            {
                month = (int)i + 1;
            }
        }
    }
    else if (strlen(text) >= 8 && isdigit((unsigned char)text[7]) && sscanf(text, "%4d%2d%2d", &year, &month, &day) == 3)
    {
        /* yyyymmdd, as used by registro.br */
    }

    if (year < 1980 || year > 2200 || month < 1 || month > 12 || day < 1 || day > 31)
    {
        return -1;
    }

    struct tm date;
    memset(&date, 0, sizeof(date));
    date.tm_year = year - 1900;
    date.tm_mon = month - 1;
    date.tm_mday = day;
    date.tm_hour = 12;

    *out = timegm(&date);
    return 0;
}

void whois_date(const char *text, char *out, size_t size)
{
    time_t date;

    if (parse_whois_date(text, &date) == 0)
    {
        struct tm parts;
        gmtime_r(&date, &parts);
        strftime(out, size, "%Y-%m-%d", &parts);
    }
    else
    {
        snprintf(out, size, "%s", text[0] != '\0' ? text : "unknown");
    }
}

void describe_age(long days, char *out, size_t size)
{
    if (days < 0)
    {
        days = 0;
    }

    long years = days / 365;
    long months = (days % 365) / 30;

    /* 360-364 leftover days would otherwise read as "12 months". */
    if (months > 11)
    {
        months = 11;
    }

    if (days < 60)
    {
        snprintf(out, size, "%ld day%s", days, days == 1 ? "" : "s");
    }
    else if (years == 0)
    {
        snprintf(out, size, "%ld months", days / 30);
    }
    else if (months == 0)
    {
        snprintf(out, size, "%ld year%s", years, years == 1 ? "" : "s");
    }
    else
    {
        snprintf(out, size, "%ld year%s, %ld month%s", years, years == 1 ? "" : "s", months, months == 1 ? "" : "s");
    }
}
