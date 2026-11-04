#include "collect/subdomain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "collect/probe.h"
#include "core/model.h"
#include "support/domain.h"
#include "support/https.h"
#include "support/json.h"
#include "support/status.h"
#include "support/util.h"

#define SUBDOMAIN_MAX_SIZE (4 * 1024 * 1024)
/* crt.sh answers with every certificate ever logged, which for large
 * organizations is tens of megabytes sent slowly. */
#define CRTSH_MAX_SIZE (64 * 1024 * 1024)
#define CRTSH_TIMEOUT_SECONDS 60L

static void add_candidate(string_list *names, const char *candidate, const char *target_domain)
{
    if (candidate == NULL || target_domain == NULL)
    {
        return;
    }

    const char *start = candidate;

    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
    {
        start++;
    }

    /* Strip wildcard prefixes (*.) */
    while (start[0] == '*' && start[1] == '.')
    {
        start += 2;
    }

    while (*start == '.')
    {
        start++;
    }

    char buffer[DOMAIN_SIZE];
    snprintf(buffer, sizeof(buffer), "%s", start);

    size_t len = strlen(buffer);

    while (len > 0 && (buffer[len - 1] == ' ' || buffer[len - 1] == '\t' || buffer[len - 1] == '\r' ||
                       buffer[len - 1] == '\n' || buffer[len - 1] == '.'))
    {
        buffer[--len] = '\0';
    }

    if (len == 0 || len >= DOMAIN_SIZE)
    {
        return;
    }

    to_lower(buffer);

    size_t target_len = strlen(target_domain);

    /* Must be strictly longer than target_domain and end with .target_domain */
    if (len <= target_len + 1)
    {
        return;
    }

    if (buffer[len - target_len - 1] != '.')
    {
        return;
    }

    if (strcasecmp(buffer + (len - target_len), target_domain) != 0)
    {
        return;
    }

    /* Check if buffer is a valid domain using normalize_domain */
    char normalized[DOMAIN_SIZE];

    if (normalize_domain(buffer, normalized, sizeof(normalized)) != 0)
    {
        return;
    }

    string_list_add(names, normalized);
}

/* Appends the distinct names to `subdomains`. Sorting first keeps this
 * linear in the size of the answer, which for crt.sh repeats each name
 * once per certificate. */
static void add_names(subdomain_list *subdomains, string_list *names)
{
    string_list_sort(names);

    for (size_t i = 0; i < names->count; i++)
    {
        if (i == 0 || strcmp(names->items[i - 1], names->items[i]) != 0)
        {
            subdomain_list_add(subdomains, names->items[i]);
        }
    }

    string_list_free(names);
    subdomain_list_dedupe(subdomains);
}

static void extract_from_crtsh_text(string_list *names, const char *text, const char *target_domain)
{
    if (text == NULL)
    {
        return;
    }

    const char *line_start = text;

    while (*line_start != '\0')
    {
        size_t len = strcspn(line_start, "\r\n");
        char buffer[DOMAIN_SIZE];

        if (len > 0 && len < sizeof(buffer))
        {
            memcpy(buffer, line_start, len);
            buffer[len] = '\0';
            add_candidate(names, buffer, target_domain);
        }

        line_start += len;

        while (*line_start == '\r' || *line_start == '\n')
        {
            line_start++;
        }
    }
}

int subdomain_parse_crtsh(const char *json_text, size_t length, const char *target_domain, subdomain_list *subdomains)
{
    if (json_text == NULL || length == 0)
    {
        return -1;
    }

    json_value *doc = json_parse(json_text, length);

    if (doc == NULL)
    {
        return -1;
    }

    if (doc->type != JSON_ARRAY)
    {
        json_free(doc);
        return -1;
    }

    size_t count = json_count(doc);
    string_list names = {0};

    for (size_t i = 0; i < count; i++)
    {
        const json_value *entry = json_at(doc, i);

        if (entry == NULL || entry->type != JSON_OBJECT)
        {
            continue;
        }

        const char *common_name = json_get_string(entry, "common_name");

        if (common_name != NULL)
        {
            extract_from_crtsh_text(&names, common_name, target_domain);
        }

        const char *name_value = json_get_string(entry, "name_value");

        if (name_value != NULL)
        {
            extract_from_crtsh_text(&names, name_value, target_domain);
        }
    }

    json_free(doc);
    add_names(subdomains, &names);
    return 0;
}

int subdomain_parse_otx(const char *json_text, size_t length, const char *target_domain, subdomain_list *subdomains)
{
    if (json_text == NULL || length == 0)
    {
        return -1;
    }

    json_value *doc = json_parse(json_text, length);

    if (doc == NULL)
    {
        return -1;
    }

    const json_value *passive_dns = json_get_array(doc, "passive_dns");

    if (passive_dns == NULL)
    {
        json_free(doc);
        return -1;
    }

    size_t count = json_count(passive_dns);
    string_list names = {0};

    for (size_t i = 0; i < count; i++)
    {
        const json_value *record = json_at(passive_dns, i);

        if (record == NULL || record->type != JSON_OBJECT)
        {
            continue;
        }

        const char *hostname = json_get_string(record, "hostname");

        if (hostname != NULL)
        {
            add_candidate(&names, hostname, target_domain);
        }
    }

    json_free(doc);
    add_names(subdomains, &names);
    return 0;
}

int subdomain_parse_hackertarget(const char *text, const char *target_domain, subdomain_list *subdomains)
{
    if (text == NULL)
    {
        return -1;
    }

    if (strncmp(text, "error", 5) == 0 || strncmp(text, "No DNS", 6) == 0)
    {
        return -1;
    }

    const char *line = text;
    string_list names = {0};

    while (*line != '\0')
    {
        size_t line_len = strcspn(line, "\r\n");

        if (line_len > 0)
        {
            const char *comma = memchr(line, ',', line_len);
            size_t host_len = comma != NULL ? (size_t)(comma - line) : line_len;
            char buffer[DOMAIN_SIZE];

            if (host_len > 0 && host_len < sizeof(buffer))
            {
                memcpy(buffer, line, host_len);
                buffer[host_len] = '\0';
                add_candidate(&names, buffer, target_domain);
            }
        }

        line += line_len;

        while (*line == '\r' || *line == '\n')
        {
            line++;
        }
    }

    add_names(subdomains, &names);
    return 0;
}

/* Moves the names in `from` into `to`, keeping `to` free of repeats. */
static void merge_names(subdomain_list *to, subdomain_list *from)
{
    for (size_t i = 0; i < from->count; i++)
    {
        subdomain_list_add(to, from->items[i].name);
    }

    subdomain_list_free(from);
    subdomain_list_dedupe(to);
}

void subdomain_collect(const char *domain, observation_list *observations, subdomain_list *found)
{
    char url[512];
    char detail[FIELD_SIZE];

    /* 1. Certificate Transparency via crt.sh */
    status_step("subdomains: crt.sh");
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%25.%s&output=json", domain);
    https_response crtsh = https_get_timeout(url, CRTSH_MAX_SIZE, CRTSH_TIMEOUT_SECONDS);

    if (crtsh.status == OBS_OK)
    {
        subdomain_list temp = {0};
        int res = subdomain_parse_crtsh(crtsh.data, crtsh.length, domain, &temp);

        if (res == 0)
        {
            snprintf(detail, sizeof(detail), "%zu subdomain%s discovered in Certificate Transparency logs", temp.count,
                     temp.count == 1 ? "" : "s");
        }
        else
        {
            snprintf(detail, sizeof(detail), "invalid JSON or HTML error response from crt.sh");
            crtsh.status = OBS_ERROR;
        }

        merge_names(found, &temp);
    }
    else if (crtsh.status == OBS_LIMITED && crtsh.http_code != 429)
    {
        snprintf(detail, sizeof(detail), "%.180s; no Certificate Transparency names were collected", crtsh.error);
    }
    else
    {
        snprintf(detail, sizeof(detail), "%s", crtsh.error[0] != '\0' ? crtsh.error : "query failed");
    }

    record_observation(observations, SUBDOMAIN_COLLECTOR, "crt.sh", domain, crtsh.status, detail, crtsh.data,
                       crtsh.length);
    free(crtsh.data);

    /* 2. AlienVault OTX Passive DNS */
    status_step("subdomains: AlienVault OTX");
    snprintf(url, sizeof(url), "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain);
    https_response otx = https_get(url, SUBDOMAIN_MAX_SIZE);

    if (otx.status == OBS_OK)
    {
        subdomain_list temp = {0};
        int res = subdomain_parse_otx(otx.data, otx.length, domain, &temp);

        if (res == 0)
        {
            snprintf(detail, sizeof(detail), "%zu subdomain%s discovered in AlienVault passive DNS", temp.count,
                     temp.count == 1 ? "" : "s");
        }
        else
        {
            snprintf(detail, sizeof(detail), "no passive DNS telemetry or invalid response");
            otx.status = OBS_EMPTY;
        }

        merge_names(found, &temp);
    }
    else
    {
        snprintf(detail, sizeof(detail), "%s", otx.error[0] != '\0' ? otx.error : "query failed");
    }

    record_observation(observations, SUBDOMAIN_COLLECTOR, "otx.alienvault.com", domain, otx.status, detail, otx.data,
                       otx.length);
    free(otx.data);

    /* 3. HackerTarget Host Search */
    status_step("subdomains: HackerTarget");
    snprintf(url, sizeof(url), "https://api.hackertarget.com/hostsearch/?q=%s", domain);
    https_response ht = https_get(url, SUBDOMAIN_MAX_SIZE);

    if (ht.status == OBS_OK)
    {
        subdomain_list temp = {0};
        int res = subdomain_parse_hackertarget(ht.data, domain, &temp);

        if (res == 0)
        {
            snprintf(detail, sizeof(detail), "%zu subdomain%s discovered in HackerTarget host search", temp.count,
                     temp.count == 1 ? "" : "s");
        }
        else
        {
            snprintf(detail, sizeof(detail), "no host search records or API limit reached");
            ht.status = OBS_EMPTY;
        }

        merge_names(found, &temp);
    }
    else
    {
        snprintf(detail, sizeof(detail), "%s", ht.error[0] != '\0' ? ht.error : "query failed");
    }

    record_observation(observations, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", domain, ht.status, detail, ht.data,
                       ht.length);
    free(ht.data);
}

void subdomain_ct_first_seen(const observation_list *observations, const char *domain, char *out, size_t size)
{
    static const char key[] = "\"not_before\":\"";

    out[0] = '\0';

    for (size_t i = 0; i < observations->count; i++)
    {
        const observation *obs = &observations->items[i];

        if (strcmp(obs->collector, SUBDOMAIN_COLLECTOR) != 0 || strcmp(obs->source, "crt.sh") != 0 ||
            strcmp(obs->query, domain) != 0 || obs->status != OBS_OK || obs->content == NULL)
        {
            continue;
        }

        /* Every entry carries an ISO 8601 "not_before", which sorts as text;
         * a plain scan avoids parsing what can be megabytes of JSON again. */
        char *text = observation_text(obs);
        char earliest[32] = "";

        for (const char *p = strstr(text, key); p != NULL; p = strstr(p, key))
        {
            p += sizeof(key) - 1;

            size_t length = strcspn(p, "\"");

            if (length >= 10 && length < sizeof(earliest) && (earliest[0] == '\0' || strncmp(p, earliest, length) < 0))
            {
                memcpy(earliest, p, length);
                earliest[length] = '\0';
            }
        }

        free(text);
        snprintf(out, size, "%.10s", earliest);
        return;
    }
}

void subdomain_interpret(const char *domain, const observation_list *observations, subdomain_list *subdomains,
                         lookup_status *status)
{
    subdomain_list_free(subdomains);

    int queried = 0;
    int success = 0;

    for (size_t i = 0; i < observations->count; i++)
    {
        const observation *obs = &observations->items[i];

        if (strcmp(obs->collector, SUBDOMAIN_COLLECTOR) != 0 || strcmp(obs->query, domain) != 0)
        {
            continue;
        }

        if (obs->status == OBS_NOT_QUERIED)
        {
            *status = LOOKUP_SKIPPED;
            return;
        }

        queried = 1;

        if (obs->status == OBS_OK && obs->content != NULL)
        {
            if (strcmp(obs->source, "crt.sh") == 0)
            {
                if (subdomain_parse_crtsh((const char *)obs->content, obs->content_length, domain, subdomains) == 0)
                {
                    success = 1;
                }
            }
            else if (strcmp(obs->source, "otx.alienvault.com") == 0)
            {
                if (subdomain_parse_otx((const char *)obs->content, obs->content_length, domain, subdomains) == 0)
                {
                    success = 1;
                }
            }
            else if (strcmp(obs->source, "api.hackertarget.com") == 0)
            {
                if (subdomain_parse_hackertarget((const char *)obs->content, domain, subdomains) == 0)
                {
                    success = 1;
                }
            }
        }
    }

    subdomain_list_dedupe(subdomains);
    subdomain_apply_probes(observations, subdomains);

    if (!queried)
    {
        *status = LOOKUP_SKIPPED;
    }
    else if (success || subdomains->count > 0)
    {
        *status = LOOKUP_OK;
    }
    else
    {
        *status = LOOKUP_FAILED;
    }
}
