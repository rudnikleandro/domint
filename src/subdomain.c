#include "subdomain.h"

#include <ctype.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "domain.h"
#include "http.h"
#include "https.h"
#include "json.h"
#include "model.h"
#include "util.h"

#define SUBDOMAIN_MAX_SIZE (4 * 1024 * 1024)
#define MAX_PROBED_SUBDOMAINS 50
#define PROBE_CONNECT_TIMEOUT 2L
#define PROBE_TOTAL_TIMEOUT 3L

static void add_candidate(subdomain_list *subdomains, const char *candidate, const char *target_domain)
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

    while (len > 0 && (buffer[len - 1] == ' ' || buffer[len - 1] == '\t' ||
                       buffer[len - 1] == '\r' || buffer[len - 1] == '\n' ||
                       buffer[len - 1] == '.'))
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

    subdomain_list_add_unique(subdomains, normalized);
}

static void extract_from_crtsh_text(subdomain_list *subdomains, const char *text, const char *target_domain)
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
            add_candidate(subdomains, buffer, target_domain);
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
            extract_from_crtsh_text(subdomains, common_name, target_domain);
        }

        const char *name_value = json_get_string(entry, "name_value");

        if (name_value != NULL)
        {
            extract_from_crtsh_text(subdomains, name_value, target_domain);
        }
    }

    json_free(doc);
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
            add_candidate(subdomains, hostname, target_domain);
        }
    }

    json_free(doc);
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
                add_candidate(subdomains, buffer, target_domain);
            }
        }

        line += line_len;

        while (*line == '\r' || *line == '\n')
        {
            line++;
        }
    }

    return 0;
}

void subdomain_collect(const char *domain, observation_list *observations)
{
    char url[512];
    char detail[FIELD_SIZE];

    /* 1. Certificate Transparency via crt.sh */
    snprintf(url, sizeof(url), "https://crt.sh/?q=%%25.%s&output=json", domain);
    https_response crtsh = https_get(url, SUBDOMAIN_MAX_SIZE);

    if (crtsh.status == OBS_OK)
    {
        subdomain_list temp = {0};
        int res = subdomain_parse_crtsh(crtsh.data, crtsh.length, domain, &temp);

        if (res == 0)
        {
            snprintf(detail, sizeof(detail), "%zu subdomain%s discovered in Certificate Transparency logs",
                     temp.count, temp.count == 1 ? "" : "s");
        }
        else
        {
            snprintf(detail, sizeof(detail), "invalid JSON or HTML error response from crt.sh");
            crtsh.status = OBS_ERROR;
        }

        subdomain_list_free(&temp);
    }
    else
    {
        snprintf(detail, sizeof(detail), "%s", crtsh.error[0] != '\0' ? crtsh.error : "query failed");
    }

    record_observation(observations, SUBDOMAIN_COLLECTOR, "crt.sh", domain,
                       crtsh.status, detail, crtsh.data, crtsh.length);
    free(crtsh.data);

    /* 2. AlienVault OTX Passive DNS */
    snprintf(url, sizeof(url), "https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain);
    https_response otx = https_get(url, SUBDOMAIN_MAX_SIZE);

    if (otx.status == OBS_OK)
    {
        subdomain_list temp = {0};
        int res = subdomain_parse_otx(otx.data, otx.length, domain, &temp);

        if (res == 0)
        {
            snprintf(detail, sizeof(detail), "%zu subdomain%s discovered in AlienVault passive DNS",
                     temp.count, temp.count == 1 ? "" : "s");
        }
        else
        {
            snprintf(detail, sizeof(detail), "no passive DNS telemetry or invalid response");
            otx.status = OBS_EMPTY;
        }

        subdomain_list_free(&temp);
    }
    else
    {
        snprintf(detail, sizeof(detail), "%s", otx.error[0] != '\0' ? otx.error : "query failed");
    }

    record_observation(observations, SUBDOMAIN_COLLECTOR, "otx.alienvault.com", domain,
                       otx.status, detail, otx.data, otx.length);
    free(otx.data);

    /* 3. HackerTarget Host Search */
    snprintf(url, sizeof(url), "https://api.hackertarget.com/hostsearch/?q=%s", domain);
    https_response ht = https_get(url, SUBDOMAIN_MAX_SIZE);

    if (ht.status == OBS_OK)
    {
        subdomain_list temp = {0};
        int res = subdomain_parse_hackertarget(ht.data, domain, &temp);

        if (res == 0)
        {
            snprintf(detail, sizeof(detail), "%zu subdomain%s discovered in HackerTarget host search",
                     temp.count, temp.count == 1 ? "" : "s");
        }
        else
        {
            snprintf(detail, sizeof(detail), "no host search records or API limit reached");
            ht.status = OBS_EMPTY;
        }

        subdomain_list_free(&temp);
    }
    else
    {
        snprintf(detail, sizeof(detail), "%s", ht.error[0] != '\0' ? ht.error : "query failed");
    }

    record_observation(observations, SUBDOMAIN_COLLECTOR, "api.hackertarget.com", domain,
                       ht.status, detail, ht.data, ht.length);
    free(ht.data);
}

void subdomain_interpret(const char *domain, const observation_list *observations,
                         subdomain_list *subdomains, lookup_status *status)
{
    /* If already populated (e.g. earlier in pipeline), preserve existing items and their probe results */
    if (subdomains->count > 0)
    {
        *status = LOOKUP_OK;
        return;
    }

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

    subdomain_list_sort(subdomains);

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

static size_t probe_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
    subdomain_info *info = userdata;
    size_t len = size * nitems;

    if (strncasecmp(buffer, "server:", 7) == 0)
    {
        const char *val = buffer + 7;

        while (*val == ' ' || *val == '\t')
        {
            val++;
        }

        size_t val_len = strcspn(val, "\r\n");

        if (val_len > 0 && val_len < sizeof(info->server))
        {
            memcpy(info->server, val, val_len);
            info->server[val_len] = '\0';
        }
    }

    return len;
}

typedef struct
{
    char body[8192];
    size_t body_len;
} probe_body;

static size_t probe_body_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    probe_body *b = userdata;
    size_t bytes = size * nmemb;
    size_t space = sizeof(b->body) - 1 - b->body_len;

    if (space > 0)
    {
        size_t to_copy = bytes < space ? bytes : space;
        memcpy(b->body + b->body_len, ptr, to_copy);
        b->body_len += to_copy;
        b->body[b->body_len] = '\0';
    }

    return bytes;
}

static void extract_title(const char *body, char *out, size_t max_size)
{
    out[0] = '\0';

    if (body == NULL)
    {
        return;
    }

    const char *p = body;
    const char *title_start = NULL;

    while (*p != '\0')
    {
        if (p[0] == '<' && (p[1] == 't' || p[1] == 'T') &&
            strncasecmp(p, "<title", 6) == 0)
        {
            const char *gt = strchr(p + 6, '>');

            if (gt != NULL)
            {
                title_start = gt + 1;
                break;
            }
        }

        p++;
    }

    if (title_start == NULL)
    {
        return;
    }

    const char *end = title_start;
    const char *title_end = NULL;

    while (*end != '\0')
    {
        if (end[0] == '<' && (end[1] == '/' || end[1] == ' ') &&
            strncasecmp(end, "</title", 7) == 0)
        {
            title_end = end;
            break;
        }

        end++;
    }

    size_t len = title_end != NULL ? (size_t)(title_end - title_start) : strlen(title_start);

    if (len >= max_size)
    {
        len = max_size - 1;
    }

    char buf[FIELD_SIZE];
    size_t out_len = 0;
    int in_space = 0;

    for (size_t i = 0; i < len && out_len < sizeof(buf) - 1; i++)
    {
        char c = title_start[i];

        if (c == '\r' || c == '\n' || c == '\t' || c == ' ')
        {
            if (!in_space && out_len > 0)
            {
                buf[out_len++] = ' ';
                in_space = 1;
            }
        }
        else if ((unsigned char)c >= 32 && (unsigned char)c <= 126)
        {
            buf[out_len++] = c;
            in_space = 0;
        }
    }

    while (out_len > 0 && buf[out_len - 1] == ' ')
    {
        out_len--;
    }

    buf[out_len] = '\0';

    if (out_len > 0)
    {
        snprintf(out, max_size, "%s", buf);
    }
}

static int probe_url(const char *url, subdomain_info *info, int is_https)
{
    CURL *curl = curl_easy_init();

    if (curl == NULL)
    {
        return -1;
    }

    probe_body b;
    memset(&b, 0, sizeof(b));

    char error_buffer[CURL_ERROR_SIZE] = "";

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, PROBE_CONNECT_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, PROBE_TOTAL_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, HTTP_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, probe_header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, info);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, probe_body_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);

    CURLcode code = curl_easy_perform(curl);

    if (code == CURLE_OK)
    {
        long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        info->http_code = response_code;
        info->is_live = 1;
        snprintf(info->protocol, sizeof(info->protocol), "%s", is_https ? "https" : "http");

        extract_title(b.body, info->title, sizeof(info->title));

        char *primary_ip = NULL;

        if (curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK && primary_ip != NULL && primary_ip[0] != '\0')
        {
            snprintf(info->ip, sizeof(info->ip), "%s", primary_ip);
        }

        char *redirect_url = NULL;

        if (curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url) == CURLE_OK && redirect_url != NULL && redirect_url[0] != '\0')
        {
            snprintf(info->location, sizeof(info->location), "%s", redirect_url);
        }

        curl_easy_cleanup(curl);
        return 0;
    }

    if (info->error[0] == '\0')
    {
        snprintf(info->error, sizeof(info->error), "%s",
                 error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(code));
    }

    curl_easy_cleanup(curl);
    return -1;
}

static void probe_subdomain(subdomain_info *info)
{
    char url[512];

    info->probed = 1;
    info->is_live = 0;
    info->http_code = 0;
    info->error[0] = '\0';
    info->server[0] = '\0';
    info->location[0] = '\0';
    info->title[0] = '\0';
    info->ip[0] = '\0';

    /* Try HTTPS first */
    snprintf(url, sizeof(url), "https://%s/", info->name);

    if (probe_url(url, info, 1) == 0)
    {
        return;
    }

    /* If HTTPS fails, try plain HTTP */
    snprintf(url, sizeof(url), "http://%s/", info->name);

    if (probe_url(url, info, 0) == 0)
    {
        return;
    }

    info->is_live = 0;
}

void subdomain_probe(subdomain_list *subdomains, int passive, int no_probe,
                     observation_list *observations, const char *domain)
{
    if (passive)
    {
        record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, "target", domain, OBS_NOT_QUERIED,
                           "--passive: subdomain targets are not contacted", NULL, 0);
        return;
    }

    if (no_probe)
    {
        record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, "target", domain, OBS_NOT_QUERIED,
                           "--no-probe: subdomain HTTP probing skipped", NULL, 0);
        return;
    }

    if (subdomains->count == 0)
    {
        return;
    }

    size_t to_probe = subdomains->count > MAX_PROBED_SUBDOMAINS ? MAX_PROBED_SUBDOMAINS : subdomains->count;
    size_t live_count = 0;
    size_t code_200 = 0;
    size_t code_403 = 0;
    size_t code_redir = 0;

    for (size_t i = 0; i < to_probe; i++)
    {
        probe_subdomain(&subdomains->items[i]);

        if (subdomains->items[i].is_live)
        {
            live_count++;

            if (subdomains->items[i].http_code == 200)
            {
                code_200++;
            }
            else if (subdomains->items[i].http_code == 401 || subdomains->items[i].http_code == 403)
            {
                code_403++;
            }
            else if (subdomains->items[i].http_code >= 300 && subdomains->items[i].http_code < 400)
            {
                code_redir++;
            }
        }
    }

    char detail[FIELD_SIZE];
    snprintf(detail, sizeof(detail), "Probed %zu subdomains: %zu online (%zu open 200, %zu restricted 403/401, %zu redirect), %zu offline",
             to_probe, live_count, code_200, code_403, code_redir, to_probe - live_count);

    record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, "http-probe", domain, OBS_OK, detail, NULL, 0);
}
