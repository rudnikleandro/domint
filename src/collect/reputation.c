#include "collect/reputation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/model.h"
#include "support/https.h"
#include "support/json.h"
#include "support/util.h"

#define OTX_SOURCE "otx.alienvault.com"
#define URLHAUS_SOURCE "urlhaus-api.abuse.ch"
#define THREATFOX_SOURCE "threatfox-api.abuse.ch"
#define REPUTATION_MAX_SIZE (2 * 1024 * 1024)
#define REPUTATION_TIMEOUT_SECONDS 15L
#define MAX_LISTED_NAMES 5
/* Pulse titles are free text written by OTX users: a few, kept short. */
#define MAX_PULSE_NAMES 2
#define MAX_PULSE_NAME_LENGTH 40

static const char abusech_missing[] = "set ABUSECH_AUTH_KEY to query it (free key at https://auth.abuse.ch)";

/* Counts above this are clamped: no source has that many entries, and a
 * double past LONG_MAX (or NaN, or infinity) cannot be converted. */
#define MAX_COUNT 1000000000L

/* A count that the APIs send either as a number or as a numeric string;
 * anything negative or not a number reads as 0. */
static long json_long(const json_value *object, const char *key)
{
    const json_value *value = json_get(object, key);
    long count = 0;

    if (value != NULL && value->type == JSON_NUMBER)
    {
        if (value->number >= (double)MAX_COUNT)
        {
            return MAX_COUNT;
        }

        /* The comparison is false for NaN, which then stays 0. */
        count = value->number > 0 ? (long)value->number : 0;
    }
    else if (value != NULL && value->type == JSON_STRING)
    {
        count = strtol(value->string, NULL, 10);
    }

    return count < 0 ? 0 : count > MAX_COUNT ? MAX_COUNT : count;
}

/* Names from these sources are free text shown on one line of the report:
 * newlines and tabs written by their authors are neutralized too. */
static void add_line(string_list *list, const char *value)
{
    char line[FIELD_SIZE];

    snprintf(line, sizeof(line), "%s", value);
    sanitize_text(line, strlen(line), 0);
    string_list_add_unique(list, line);
}

static void add_limited(string_list *list, const char *value)
{
    if (value != NULL && value[0] != '\0' && list->count < MAX_LISTED_NAMES)
    {
        add_line(list, value);
    }
}

static void record_answer(observation_list *observations, const char *source, const char *domain,
                          const https_response *response, const char *summary)
{
    record_observation(observations, REPUTATION_COLLECTOR, source, domain, response->status,
                       response->status == OBS_OK ? summary : response->error, response->data, response->length);
}

/* A key from the environment goes into a request header: one with a line
 * break would inject headers of its own, so it is not used. */
static const char *usable_key(const char *name)
{
    const char *key = getenv(name);

    if (key == NULL || key[0] == '\0' || strpbrk(key, "\r\n") != NULL)
    {
        return NULL;
    }

    return key;
}

void reputation_collect(const char *domain, observation_list *observations)
{
    char url[512];
    char header[FIELD_SIZE];
    const char *otx_key = usable_key("OTX_API_KEY");
    const char *otx_headers[2] = {NULL, NULL};

    if (otx_key != NULL)
    {
        snprintf(header, sizeof(header), "X-OTX-API-KEY: %s", otx_key);
        otx_headers[0] = header;
    }

    snprintf(url, sizeof(url), "https://otx.alienvault.com/api/v1/indicators/domain/%s/general", domain);
    https_response otx = https_request(url, REPUTATION_MAX_SIZE, REPUTATION_TIMEOUT_SECONDS, otx_headers, NULL);
    record_answer(observations, OTX_SOURCE, domain, &otx, "pulses and allowlist validation");
    free(otx.data);

    const char *key = usable_key("ABUSECH_AUTH_KEY");

    if (key == NULL)
    {
        record_observation(observations, REPUTATION_COLLECTOR, URLHAUS_SOURCE, domain, OBS_NOT_QUERIED, abusech_missing,
                           NULL, 0);
        record_observation(observations, REPUTATION_COLLECTOR, THREATFOX_SOURCE, domain, OBS_NOT_QUERIED,
                           abusech_missing, NULL, 0);
        return;
    }

    char auth[FIELD_SIZE];
    char body[DOMAIN_SIZE + 96];

    snprintf(auth, sizeof(auth), "Auth-Key: %s", key);

    /* The key travels in a header only; it is never recorded. */
    const char *form_headers[] = {auth, "Content-Type: application/x-www-form-urlencoded", NULL};
    snprintf(body, sizeof(body), "host=%s", domain);
    https_response urlhaus = https_request("https://urlhaus-api.abuse.ch/v1/host/", REPUTATION_MAX_SIZE,
                                           REPUTATION_TIMEOUT_SECONDS, form_headers, body);
    record_answer(observations, URLHAUS_SOURCE, domain, &urlhaus, "host lookup");
    free(urlhaus.data);

    const char *json_headers[] = {auth, "Content-Type: application/json", NULL};
    snprintf(body, sizeof(body), "{\"query\":\"search_ioc\",\"search_term\":\"%s\",\"exact_match\":true}", domain);
    https_response threatfox = https_request("https://threatfox-api.abuse.ch/api/v1/", REPUTATION_MAX_SIZE,
                                             REPUTATION_TIMEOUT_SECONDS, json_headers, body);
    record_answer(observations, THREATFOX_SOURCE, domain, &threatfox, "IOC search");
    free(threatfox.data);
}

int reputation_parse_otx(const char *text, size_t length, reputation_info *info)
{
    json_value *doc = json_parse(text, length);
    const json_value *pulse_info = doc != NULL ? json_get_object(doc, "pulse_info") : NULL;

    if (pulse_info == NULL)
    {
        json_free(doc);
        return -1;
    }

    info->otx_pulses = json_long(pulse_info, "count");

    const json_value *pulses = json_get_array(pulse_info, "pulses");

    for (size_t i = 0; i < json_count(pulses) && info->otx_pulse_names.count < MAX_PULSE_NAMES; i++)
    {
        const char *name = json_get_string(json_at(pulses, i), "name");
        char shortened[MAX_PULSE_NAME_LENGTH + 4];

        if (name == NULL || name[0] == '\0')
        {
            continue;
        }

        snprintf(shortened, sizeof(shortened), strlen(name) > MAX_PULSE_NAME_LENGTH ? "%.37s..." : "%s", name);
        add_line(&info->otx_pulse_names, shortened);
    }

    /* "validation" lists the reasons OTX treats the domain as known-good
     * (popularity rankings, its own allowlist). */
    info->otx_allowlisted = json_count(json_get_array(doc, "validation")) > 0;

    json_free(doc);
    return 0;
}

int reputation_parse_urlhaus(const char *text, size_t length, reputation_info *info)
{
    json_value *doc = json_parse(text, length);
    const char *status = doc != NULL ? json_get_string(doc, "query_status") : NULL;

    if (status == NULL)
    {
        json_free(doc);
        return -1;
    }

    if (strcmp(status, "no_results") == 0)
    {
        json_free(doc);
        return 0;
    }

    if (strcmp(status, "ok") != 0)
    {
        json_free(doc);
        return -1;
    }

    info->urlhaus_urls = json_long(doc, "url_count");

    const json_value *urls = json_get_array(doc, "urls");

    for (size_t i = 0; i < json_count(urls); i++)
    {
        const json_value *entry = json_at(urls, i);
        const char *url_status = json_get_string(entry, "url_status");

        info->urlhaus_online += url_status != NULL && strcmp(url_status, "online") == 0;
        add_limited(&info->urlhaus_threats, json_get_string(entry, "threat"));
    }

    const json_value *blacklists = json_get_object(doc, "blacklists");
    const char *dbl = json_get_string(blacklists, "spamhaus_dbl");
    const char *surbl = json_get_string(blacklists, "surbl");

    snprintf(info->spamhaus_dbl, sizeof(info->spamhaus_dbl), "%s", dbl != NULL ? dbl : "");
    snprintf(info->surbl, sizeof(info->surbl), "%s", surbl != NULL ? surbl : "");

    json_free(doc);
    return 0;
}

int reputation_parse_threatfox(const char *text, size_t length, reputation_info *info)
{
    json_value *doc = json_parse(text, length);
    const char *status = doc != NULL ? json_get_string(doc, "query_status") : NULL;

    if (status == NULL)
    {
        json_free(doc);
        return -1;
    }

    if (strcmp(status, "no_result") == 0 || strcmp(status, "no_results") == 0)
    {
        json_free(doc);
        return 0;
    }

    if (strcmp(status, "ok") != 0)
    {
        json_free(doc);
        return -1;
    }

    const json_value *data = json_get_array(doc, "data");

    info->threatfox_iocs = (long)json_count(data);

    for (size_t i = 0; i < json_count(data); i++)
    {
        add_limited(&info->threatfox_malware, json_get_string(json_at(data, i), "malware_printable"));
    }

    json_free(doc);
    return 0;
}

/* Reads the answer of one source; `not_queried` is set for a source that
 * needs a key nobody gave. */
static lookup_status interpret_source(const observation_list *observations, const char *source, const char *domain,
                                      int (*parse)(const char *, size_t, reputation_info *), reputation_info *info,
                                      int *not_queried)
{
    for (size_t i = 0; i < observations->count; i++)
    {
        const observation *item = &observations->items[i];

        if (strcmp(item->collector, REPUTATION_COLLECTOR) != 0 || strcmp(item->source, source) != 0 ||
            strcmp(item->query, domain) != 0)
        {
            continue;
        }

        if (item->status == OBS_NOT_QUERIED)
        {
            if (not_queried != NULL)
            {
                *not_queried = 1;
            }

            return LOOKUP_SKIPPED;
        }

        if (item->status != OBS_OK || item->content == NULL)
        {
            return LOOKUP_FAILED;
        }

        char *text = observation_text(item);
        int result = parse(text, item->content_length, info);

        free(text);
        return result == 0 ? LOOKUP_OK : LOOKUP_FAILED;
    }

    return LOOKUP_SKIPPED;
}

void reputation_interpret(const observation_list *observations, const char *domain, reputation_info *info)
{
    info->otx_status = interpret_source(observations, OTX_SOURCE, domain, reputation_parse_otx, info, NULL);
    info->urlhaus_status = interpret_source(observations, URLHAUS_SOURCE, domain, reputation_parse_urlhaus, info,
                                            &info->urlhaus_not_queried);
    info->threatfox_status = interpret_source(observations, THREATFOX_SOURCE, domain, reputation_parse_threatfox, info,
                                              &info->threatfox_not_queried);
}
