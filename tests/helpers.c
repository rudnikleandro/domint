/* Helpers shared by the test files. */

#include "helpers.h"

#include <stdio.h>
#include <string.h>

#include "collect/lookalike.h"
#include "output/report.h"

void add_live(domain_report *report, const char *name, long code, const char *ip, const char *asn, const char *as_name)
{
    subdomain_list_add(&report->subdomains, name);

    subdomain_info *sub = &report->subdomains.items[report->subdomains.count - 1];
    sub->probed = 1;
    sub->is_live = code != 0;
    sub->http_code = code;
    snprintf(sub->protocol, sizeof(sub->protocol), "https");
    snprintf(sub->ip, sizeof(sub->ip), "%s", ip);
    snprintf(sub->asn, sizeof(sub->asn), "%s", asn);
    snprintf(sub->as_name, sizeof(sub->as_name), "%s", as_name);
}

const finding *find_signal(const domain_report *report, const char *text)
{
    for (size_t i = 0; i < report->finding_count; i++)
    {
        if (strstr(report->findings[i].text, text) != NULL)
        {
            return &report->findings[i];
        }
    }

    return NULL;
}

int has_signal(const domain_report *report, severity level, const char *text)
{
    const finding *signal = find_signal(report, text);
    return signal != NULL && signal->level == level;
}

char *render(const domain_report *report)
{
    char *text = NULL;
    size_t length = 0;
    FILE *out = open_memstream(&text, &length);
    report_options options = {0};

    print_report(out, report, 1, NULL, &options);
    fclose(out);
    return text;
}

/* A DNS answer for `name` with one record of `type` holding `rdata`. */
size_t build_answer(unsigned char *out, const char *name, int type, int rcode, const unsigned char *rdata,
                    size_t rdata_length)
{
    size_t n = 0;
    const unsigned char header[] = {0x00, 0x01, 0x81, (unsigned char)(0x80 | rcode),
                                    0x00, 0x01, 0x00, rdata_length > 0 ? 0x01 : 0x00,
                                    0x00, 0x00, 0x00, 0x00};

    memcpy(out, header, sizeof(header));
    n = sizeof(header);

    for (const char *label = name; *label != '\0';)
    {
        size_t length = strcspn(label, ".");
        out[n++] = (unsigned char)length;
        memcpy(out + n, label, length);
        n += length;
        label += length + (label[length] == '.');
    }

    out[n++] = 0;
    out[n++] = 0;
    out[n++] = (unsigned char)type;
    out[n++] = 0;
    out[n++] = 1;

    if (rdata_length > 0)
    {
        const unsigned char answer[] = {0xc0, 0x0c, 0x00, (unsigned char)type,        0x00, 0x01, 0x00, 0x00,
                                        0x01, 0x2c, 0x00, (unsigned char)rdata_length};
        memcpy(out + n, answer, sizeof(answer));
        n += sizeof(answer);
        memcpy(out + n, rdata, rdata_length);
        n += rdata_length;
    }

    return n;
}

void record_lookalike(observation_list *obs, const char *type_name, const char *name, int type, int rcode,
                      const unsigned char *rdata, size_t rdata_length)
{
    unsigned char packet[512];
    char query[DOMAIN_SIZE + 8];
    size_t length = build_answer(packet, name, type, rcode, rdata, rdata_length);

    snprintf(query, sizeof(query), "%s %s", type_name, name);
    record_observation(obs, LOOKALIKE_COLLECTOR, "configured resolver", query, OBS_OK, NULL, packet, length);
}
