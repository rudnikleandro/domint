#include "collect/rdap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "support/https.h"
#include "support/json.h"
#include "support/util.h"
#include "collect/whois.h"

#define BOOTSTRAP_URL "https://data.iana.org/rdap/dns.json"
#define BOOTSTRAP_COLLECTOR "rdap-bootstrap"
#define BOOTSTRAP_MAX_SIZE (2 * 1024 * 1024)
#define RDAP_MAX_SIZE (1024 * 1024)

/* The bootstrap file is fetched once per run. */
static int bootstrap_state; /* 0 not fetched, 1 loaded, -1 failed */
static char *bootstrap_text;
static size_t bootstrap_length;
static char bootstrap_error[FIELD_SIZE];

int rdap_find_service(const char *bootstrap, size_t length, const char *tld, char *out, size_t size)
{
    json_value *document = json_parse(bootstrap, length);
    const json_value *services = json_get_array(document, "services");
    int found = document == NULL || services == NULL ? -1 : 0;

    /* "services": [ [ ["com", "net"], ["https://rdap.example/"] ], ... ] */
    for (size_t i = 0; found == 0 && i < json_count(services); i++)
    {
        const json_value *service = json_at(services, i);
        const json_value *tlds = json_at(service, 0);
        const json_value *urls = json_at(service, 1);

        for (size_t j = 0; found == 0 && j < json_count(tlds); j++)
        {
            const char *name = json_string(json_at(tlds, j));

            if (name == NULL || strcasecmp(name, tld) != 0)
            {
                continue;
            }

            for (size_t k = 0; k < json_count(urls); k++)
            {
                const char *url = json_string(json_at(urls, k));

                if (url != NULL && strncmp(url, "https://", 8) == 0)
                {
                    snprintf(out, size, "%s", url);
                    found = 1;
                    break;
                }
            }
        }
    }

    json_free(document);
    return found;
}

static void load_bootstrap(void)
{
    if (bootstrap_state != 0)
    {
        return;
    }

    https_response response = https_get(BOOTSTRAP_URL, BOOTSTRAP_MAX_SIZE);

    if (response.status == OBS_OK)
    {
        bootstrap_text = response.data;
        bootstrap_length = response.length;
        bootstrap_state = 1;
    }
    else
    {
        snprintf(bootstrap_error, sizeof(bootstrap_error), "%s", response.error);
        bootstrap_state = -1;
    }
}

int rdap_collect(const char *domain, observation_list *observations)
{
    const char *dot = strrchr(domain, '.');
    const char *tld = dot != NULL ? dot + 1 : domain;
    char service[FIELD_SIZE] = "";
    char detail[FIELD_SIZE * 2];

    load_bootstrap();

    if (bootstrap_state < 0)
    {
        record_observation(observations, BOOTSTRAP_COLLECTOR, "data.iana.org", tld, OBS_NO_RESPONSE, bootstrap_error,
                           NULL, 0);
        return 0;
    }

    int found = rdap_find_service(bootstrap_text, bootstrap_length, tld, service, sizeof(service));

    /* The 70 KB file itself is not kept per domain; the entry used is. */
    if (found < 0)
    {
        record_observation(observations, BOOTSTRAP_COLLECTOR, "data.iana.org", tld, OBS_ERROR,
                           "the bootstrap file is not valid JSON", NULL, 0);
        return 0;
    }

    if (found == 0)
    {
        snprintf(detail, sizeof(detail), "no RDAP service listed for .%s", tld);
        record_observation(observations, BOOTSTRAP_COLLECTOR, "data.iana.org", tld, OBS_EMPTY, detail, NULL, 0);
        return 0;
    }

    snprintf(detail, sizeof(detail), "RDAP service for .%s: %s", tld, service);
    record_observation(observations, BOOTSTRAP_COLLECTOR, "data.iana.org", tld, OBS_OK, detail, NULL, 0);

    char url[FIELD_SIZE * 2];
    char host[FIELD_SIZE];

    snprintf(url, sizeof(url), "%s%sdomain/%s", service, service[strlen(service) - 1] == '/' ? "" : "/", domain);
    url_host(url, host, sizeof(host));

    https_response response = https_get(url, RDAP_MAX_SIZE);

    /* An answer that is not JSON is unusable; WHOIS gets a chance instead. */
    if (response.status == OBS_OK)
    {
        whois_info check;

        memset(&check, 0, sizeof(check));

        if (rdap_parse(response.data, response.length, &check) != 0)
        {
            response.status = OBS_ERROR;
            snprintf(response.error, sizeof(response.error), "the answer is not a valid RDAP object");
        }

        string_list_free(&check.statuses);
    }

    record_observation(observations, RDAP_COLLECTOR, host, domain, response.status,
                       response.status == OBS_EMPTY ? "the registry has no record of this domain (HTTP 404)" : response.error,
                       response.data, response.length);
    free(response.data);

    return response.status == OBS_OK || response.status == OBS_EMPTY;
}

/* vCard properties are ["name", {params}, "type", value]. */
static const char *vcard_property(const json_value *entity, const char *name)
{
    const json_value *properties = json_at(json_get_array(entity, "vcardArray"), 1);

    for (size_t i = 0; i < json_count(properties); i++)
    {
        const json_value *property = json_at(properties, i);
        const char *property_name = json_string(json_at(property, 0));
        const char *value = json_string(json_at(property, 3));

        if (property_name != NULL && strcmp(property_name, name) == 0 && value != NULL && value[0] != '\0')
        {
            return value;
        }
    }

    return NULL;
}

static int has_role(const json_value *entity, const char *role)
{
    const json_value *roles = json_get_array(entity, "roles");

    for (size_t i = 0; i < json_count(roles); i++)
    {
        const char *name = json_string(json_at(roles, i));

        if (name != NULL && strcmp(name, role) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static void copy_once(char *field, size_t size, const char *value)
{
    if (field[0] == '\0' && value != NULL)
    {
        snprintf(field, size, "%s", value);
        sanitize_text(field, strlen(field), 0);
    }
}

/* Entities nest (the abuse contact sits inside the registrar). */
static void read_entities(const json_value *entities, whois_info *info, int depth)
{
    for (size_t i = 0; i < json_count(entities) && depth < 4; i++)
    {
        const json_value *entity = json_at(entities, i);

        if (has_role(entity, "registrar"))
        {
            const char *name = vcard_property(entity, "fn");
            copy_once(info->registrar, sizeof(info->registrar), name != NULL ? name : json_get_string(entity, "handle"));
        }

        if (has_role(entity, "abuse"))
        {
            copy_once(info->abuse_email, sizeof(info->abuse_email), vcard_property(entity, "email"));
        }

        if (has_role(entity, "registrant"))
        {
            const char *name = vcard_property(entity, "org");
            copy_once(info->registrant, sizeof(info->registrant), name != NULL ? name : vcard_property(entity, "fn"));
        }

        read_entities(json_get_array(entity, "entities"), info, depth + 1);
    }
}

int rdap_parse(const char *text, size_t length, whois_info *info)
{
    json_value *document = json_parse(text, length);

    if (document == NULL || document->type != JSON_OBJECT)
    {
        json_free(document);
        return -1;
    }

    info->registered = 1;

    const json_value *events = json_get_array(document, "events");

    for (size_t i = 0; i < json_count(events); i++)
    {
        const json_value *event = json_at(events, i);
        const char *action = json_get_string(event, "eventAction");
        const char *date = json_get_string(event, "eventDate");

        if (action == NULL || date == NULL)
        {
            continue;
        }

        if (strcmp(action, "registration") == 0)
        {
            copy_once(info->created, sizeof(info->created), date);
        }
        else if (strcmp(action, "expiration") == 0)
        {
            copy_once(info->expires, sizeof(info->expires), date);
        }
        else if (strcmp(action, "last changed") == 0)
        {
            copy_once(info->updated, sizeof(info->updated), date);
        }
    }

    const json_value *statuses = json_get_array(document, "status");

    for (size_t i = 0; i < json_count(statuses); i++)
    {
        const char *status = json_string(json_at(statuses, i));

        if (status != NULL)
        {
            char clean[FIELD_SIZE];
            snprintf(clean, sizeof(clean), "%s", status);
            sanitize_text(clean, strlen(clean), 0);
            string_list_add_unique(&info->statuses, clean);
        }
    }

    read_entities(json_get_array(document, "entities"), info, 0);
    info->privacy = looks_redacted(info->registrant);

    json_free(document);
    return 0;
}

int rdap_interpret(const char *domain, const observation_list *observations, whois_info *info)
{
    const observation *item = find_observation(observations, RDAP_COLLECTOR, domain);

    if (item == NULL || (item->status != OBS_OK && item->status != OBS_EMPTY))
    {
        return -1;
    }

    snprintf(info->protocol, sizeof(info->protocol), "RDAP");
    snprintf(info->queried, sizeof(info->queried), "%s", domain);
    snprintf(info->server, sizeof(info->server), "%s", item->source);
    info->status = LOOKUP_OK;

    if (item->status == OBS_EMPTY)
    {
        info->registered = 0;
        return 0;
    }

    rdap_parse((const char *)item->content, item->content_length, info);
    info->raw = observation_text(item);
    return 0;
}
