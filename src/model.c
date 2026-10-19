#include "model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

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

void observation_list_free(observation_list *list)
{
    for (size_t i = 0; i < list->count; i++)
    {
        free(list->items[i].content);
    }

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static const char *const status_names[] = {"ok", "empty", "no_response", "limited", "error", "not_queried"};

const char *observation_status_name(observation_status status)
{
    return status_names[status];
}

observation *record_observation(observation_list *list, const char *collector, const char *source, const char *query,
                                observation_status status, const char *detail, const void *content, size_t length)
{
    if (list->count == list->capacity)
    {
        list->capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        list->items = xrealloc(list->items, list->capacity * sizeof(*list->items));
    }

    observation *item = &list->items[list->count];
    list->count++;

    memset(item, 0, sizeof(*item));
    snprintf(item->collector, sizeof(item->collector), "%s", collector);
    snprintf(item->source, sizeof(item->source), "%s", source);
    snprintf(item->query, sizeof(item->query), "%s", query);
    snprintf(item->detail, sizeof(item->detail), "%s", detail != NULL ? detail : "");
    utc_timestamp(item->collected_at, sizeof(item->collected_at));
    item->status = status;

    if (content != NULL)
    {
        /* One extra NUL so text answers can be read as strings. */
        item->content = xcalloc(length + 1, 1);
        memcpy(item->content, content, length);
        item->content_length = length;
    }

    return item;
}

const observation *find_observation(const observation_list *observations, const char *collector, const char *query)
{
    for (size_t i = 0; i < observations->count; i++)
    {
        if (strcmp(observations->items[i].collector, collector) == 0 && strcmp(observations->items[i].query, query) == 0)
        {
            return &observations->items[i];
        }
    }

    return NULL;
}

char *observation_text(const observation *item)
{
    char *text = xcalloc(item->content_length + 1, 1);

    if (item->content != NULL)
    {
        memcpy(text, item->content, item->content_length);
        sanitize_text(text, item->content_length, 1);
    }

    return text;
}

void domain_report_free(domain_report *report)
{
    observation_list_free(&report->observations);
    free(report->http.raw);
    free(report->whois.raw);
    string_list_free(&report->dns.ns.values);
    string_list_free(&report->dns.mx.values);
    string_list_free(&report->dns.txt.values);
    string_list_free(&report->dns.caa.values);
    string_list_free(&report->dns.dmarc.values);
    string_list_free(&report->services);
}
