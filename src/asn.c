#include "asn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "model.h"
#include "whois.h"

#define CYMRU_WHOIS_SERVER "whois.cymru.com"
#define ASN_COLLECTOR "asn"
#define CYMRU_FIELD_COUNT 7

static void trim_spaces(char *str)
{
    char *start = str;

    while (*start == ' ')
    {
        start++;
    }

    memmove(str, start, strlen(start) + 1);

    size_t len = strlen(str);

    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\r'))
    {
        len--;
        str[len] = '\0';
    }
}

void asn_collect(const char *ip, observation_list *observations)
{
    char query[128];
    snprintf(query, sizeof(query), " -v %s", ip);

    whois_response response = whois_query(CYMRU_WHOIS_SERVER, query);

    record_observation(observations, ASN_COLLECTOR, CYMRU_WHOIS_SERVER ":43", ip, response.status, response.error,
                       response.data, response.length);
    free(response.data);
}

void asn_interpret(const observation_list *observations, address_info *address)
{
    const observation *item = find_observation(observations, ASN_COLLECTOR, address->ip);

    if (item == NULL)
    {
        address->asn_status = LOOKUP_SKIPPED;
        return;
    }

    address->asn_status = LOOKUP_FAILED;

    if (item->status == OBS_OK)
    {
        char *text = observation_text(item);
        asn_parse(text, address);
        free(text);
    }
}

/* Team Cymru answers " -v <ip>" with a header line followed by one line of
 * "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name". */
void asn_parse(char *response, address_info *address)
{
    address->asn_status = LOOKUP_FAILED;

    char *data_line = strchr(response, '\n');
    char *fields[CYMRU_FIELD_COUNT];
    int field_count = 0;

    if (data_line != NULL)
    {
        data_line++;

        char *line_end = strchr(data_line, '\n');

        if (line_end != NULL)
        {
            *line_end = '\0';
        }

        char *saveptr;

        for (char *token = strtok_r(data_line, "|", &saveptr);
             token != NULL && field_count < CYMRU_FIELD_COUNT;
             token = strtok_r(NULL, "|", &saveptr))
        {
            trim_spaces(token);
            fields[field_count] = token;
            field_count++;
        }
    }

    if (field_count == CYMRU_FIELD_COUNT)
    {
        address->asn_status = LOOKUP_OK;
        address->announced = strcmp(fields[0], "NA") != 0;

        if (address->announced)
        {
            snprintf(address->asn, sizeof(address->asn), "%s", fields[0]);
            snprintf(address->prefix, sizeof(address->prefix), "%s", fields[2]);
            snprintf(address->country, sizeof(address->country), "%s", fields[3]);
            snprintf(address->registry, sizeof(address->registry), "%s", fields[4]);
            snprintf(address->allocated, sizeof(address->allocated), "%s", fields[5]);
            snprintf(address->as_name, sizeof(address->as_name), "%s", fields[6]);
        }
    }
}
