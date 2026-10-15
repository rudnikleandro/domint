#include "model.h"

#include <stdlib.h>
#include <string.h>

#include "memory.h"

void string_list_add(string_list *list, const char *value)
{
    if (list->count == list->capacity)
    {
        list->capacity = list->capacity == 0 ? 8 : list->capacity * 2;
        list->items = xrealloc(list->items, list->capacity * sizeof(*list->items));
    }

    list->items[list->count] = xstrdup(value);
    list->count++;
}

void string_list_add_unique(string_list *list, const char *value)
{
    if (!string_list_contains(list, value))
    {
        string_list_add(list, value);
    }
}

int string_list_contains(const string_list *list, const char *value)
{
    for (size_t i = 0; i < list->count; i++)
    {
        if (strcmp(list->items[i], value) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static int compare_strings(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

void string_list_sort(string_list *list)
{
    if (list->count > 1)
    {
        qsort(list->items, list->count, sizeof(*list->items), compare_strings);
    }
}

void string_list_free(string_list *list)
{
    for (size_t i = 0; i < list->count; i++)
    {
        free(list->items[i]);
    }

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void domain_report_free(domain_report *report)
{
    free(report->http.raw);
    free(report->whois.raw);
    string_list_free(&report->dns.ns.values);
    string_list_free(&report->dns.mx.values);
    string_list_free(&report->dns.txt.values);
    string_list_free(&report->dns.caa.values);
    string_list_free(&report->dns.dmarc.values);
    string_list_free(&report->services);
}
