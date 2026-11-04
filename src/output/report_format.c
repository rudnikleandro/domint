/* Formatting primitives of the text report: labelled fields, sections,
 * word wrapping and short names. */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "core/providers.h"
#include "output/report_internal.h"

const char *severity_tag(severity level)
{
    switch (level)
    {
    case SEVERITY_HIGH:
        return "[HIGH]";
    case SEVERITY_MEDIUM:
        return "[MEDIUM]";
    case SEVERITY_LOW:
        return "[LOW]";
    default:
        return "[INFO]";
    }
}

/* A long value with spaces (a DMARC record, a SOA line) wraps under itself. */
void print_field(FILE *out, const char *label, const char *value)
{
    if (2 + LABEL_WIDTH + strlen(value) > REPORT_WIDTH && strchr(value, ' ') != NULL)
    {
        print_paragraph(out, 2 + LABEL_WIDTH, label, value);
        return;
    }

    fprintf(out, "  %-*s%s\n", LABEL_WIDTH, label, value);
}

void print_sub_field(FILE *out, const char *label, const char *value)
{
    fprintf(out, "    %-*s%s\n", SUB_LABEL_WIDTH, label, value);
}

void print_section(FILE *out, const char *title)
{
    fprintf(out, "\n%s\n", title);
}

/* Prints a comma-separated list, wrapping onto lines aligned under the first. */
void print_wrapped(FILE *out, int indent, int label_width, const char *label, const char *const *items, size_t count)
{
    char line[1024];
    size_t len = 0;

    for (size_t i = 0; i < count; i++)
    {
        int last = i + 1 == count;
        size_t needed = strlen(items[i]) + (last ? 0 : 1);

        if (len > 0 && len + 1 + needed > WRAP_WIDTH)
        {
            fprintf(out, "%*s%-*s%s\n", indent, "", label_width, label, line);
            label = "";
            len = 0;
        }

        int written = snprintf(line + len, sizeof(line) - len, "%s%s%s", len > 0 ? " " : "", items[i], last ? "" : ",");

        len += written > 0 ? (size_t)written : 0;

        if (len >= sizeof(line))
        {
            len = sizeof(line) - 1;
        }
    }

    if (len > 0)
    {
        fprintf(out, "%*s%-*s%s\n", indent, "", label_width, label, line);
    }
}

/* Word-wraps `text` to the report width, starting at column `indent` after
 * `tag` and indenting continuation lines the same way: "  [MEDIUM] text ...". */
void print_paragraph(FILE *out, int indent, const char *tag, const char *text)
{
    int column = fprintf(out, "  %-*s", indent - 2, tag);

    while (*text != '\0')
    {
        size_t word_len = strcspn(text, " ");

        if (column > indent && column + 1 + (int)word_len > REPORT_WIDTH)
        {
            column = fprintf(out, "\n%*s", indent, "") - 1;
        }
        else if (column > indent)
        {
            column += fprintf(out, " ");
        }

        column += fprintf(out, "%.*s", (int)word_len, text);
        text += word_len;

        while (*text == ' ')
        {
            text++;
        }
    }

    fprintf(out, "\n");
}

void print_list(FILE *out, const char *label, const char *const *items, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        print_field(out, i == 0 ? label : "", items[i]);
    }
}

void print_record_set(FILE *out, const char *label, const record_set *set)
{
    if (set->status == LOOKUP_FAILED)
    {
        print_field(out, label, "lookup failed");
    }
    else if (set->values.count == 0)
    {
        print_field(out, label, "none");
    }
    else
    {
        print_list(out, label, (const char *const *)set->values.items, set->values.count);
    }
}

void report_append(char *out, size_t size, const char *separator, const char *text)
{
    if (out[0] != '\0')
    {
        strncat(out, separator, size - strlen(out) - 1);
    }

    strncat(out, text, size - strlen(out) - 1);
}

int report_is_listed(const char *verdict)
{
    return verdict[0] != '\0' && strcasecmp(verdict, "not listed") != 0;
}

/* "AS8075 Microsoft Azure"; for unknown networks the organization part of
 * the AS name ("NAME - Org, CC" -> "Org"). */
void network_label(const subdomain_info *sub, char *out, size_t size)
{
    const char *provider = proxy_provider_name(sub->as_name);

    if (provider == NULL)
    {
        provider = cloud_provider_name(sub->as_name);
    }

    if (provider != NULL)
    {
        snprintf(out, size, "AS%s %s", sub->asn, provider);
        return;
    }

    const char *name = strstr(sub->as_name, " - ");
    name = name != NULL ? name + 3 : sub->as_name;

    size_t length = strlen(name);
    const char *comma = strrchr(name, ',');

    if (comma != NULL && strlen(comma) <= 4)
    {
        length = (size_t)(comma - name);
    }

    snprintf(out, size, "AS%s %.*s", sub->asn, (int)(length > 80 ? 80 : length), name);
}

/* "www" for "www.example.com" when the report is for example.com. */
int report_short_name(const char *name, const char *domain)
{
    size_t name_length = strlen(name);
    size_t domain_length = strlen(domain);

    if (name_length > domain_length + 1 && strcmp(name + name_length - domain_length, domain) == 0 &&
        name[name_length - domain_length - 1] == '.')
    {
        return (int)(name_length - domain_length - 1);
    }

    return (int)name_length;
}
