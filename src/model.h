#ifndef EXPOSUREPROOF_MODEL_H
#define EXPOSUREPROOF_MODEL_H

#include <stddef.h>

#define DOMAIN_SIZE 256
#define FIELD_SIZE 256
#define IP_SIZE 46
#define MAX_ADDRESSES 32
#define MAX_FINDINGS 32

#define EXPOSUREPROOF_VERSION "0.3.0"

/* Zero is SKIPPED, so a zero-initialized report means "nothing ran yet". */
typedef enum
{
    LOOKUP_SKIPPED,
    LOOKUP_OK,
    LOOKUP_FAILED
} lookup_status;

typedef struct
{
    size_t count;
    size_t capacity;
    char **items;
} string_list;

typedef struct
{
    char ip[IP_SIZE];
    char ptr[FIELD_SIZE];
    lookup_status asn_status;
    int announced;
    char asn[16];
    char as_name[FIELD_SIZE];
    char prefix[64];
    char country[8];
    char registry[16];
    char allocated[16];
} address_info;

typedef struct
{
    lookup_status status;
    int not_queried;
    size_t attempts;
    char endpoint[FIELD_SIZE];
    char status_line[FIELD_SIZE];
    char location[512];
    char server[FIELD_SIZE];
    char *raw;
} http_info;

typedef struct
{
    lookup_status status;
    string_list values;
} record_set;

typedef struct
{
    char resolver[FIELD_SIZE];
    record_set ns;
    record_set mx;
    record_set txt;
    record_set caa;
    record_set dmarc;
    char dmarc_name[DOMAIN_SIZE + 8];
    lookup_status soa_status;
    int has_soa;
    char soa_primary[FIELD_SIZE];
    char soa_admin[FIELD_SIZE];
    unsigned long soa_serial;
} dns_info;

typedef struct
{
    lookup_status status;
    char note[FIELD_SIZE * 4];
    char queried[DOMAIN_SIZE];
    int iana_queried;
    char server[FIELD_SIZE];
    int registered;
    char registrar[FIELD_SIZE];
    char created[64];
    char updated[64];
    char expires[64];
    char registrant[FIELD_SIZE];
    char registrant_country[64];
    int privacy;
    char *raw;
} whois_info;

/* What happened when a source was asked. These are deliberately distinct:
 * "the source said there is nothing" is not "the source did not answer". */
typedef enum
{
    OBS_OK,
    OBS_EMPTY,
    OBS_NO_RESPONSE,
    OBS_LIMITED,
    OBS_ERROR,
    OBS_NOT_QUERIED
} observation_status;

/* One question put to one source, with the exact answer kept as evidence. */
typedef struct
{
    char collector[16];
    char source[FIELD_SIZE];
    char query[DOMAIN_SIZE + 16];
    char collected_at[32];
    observation_status status;
    char detail[FIELD_SIZE * 2];
    unsigned char *content;
    size_t content_length;
} observation;

typedef struct
{
    size_t count;
    size_t capacity;
    observation *items;
} observation_list;

typedef enum
{
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH
} severity;

typedef struct
{
    severity level;
    char text[512];
} finding;

typedef struct
{
    char name[DOMAIN_SIZE];
    char org_domain[DOMAIN_SIZE];

    lookup_status resolve_status;
    char resolve_error[FIELD_SIZE * 2];
    size_t address_count;
    address_info addresses[MAX_ADDRESSES];

    http_info http;
    dns_info dns;
    whois_info whois;

    /* Every query made for this domain, in order, with its raw answer. */
    observation_list observations;

    /* Filled in by analyze_domain(). */
    char hosting[FIELD_SIZE];
    char dns_provider[FIELD_SIZE];
    char mail_provider[FIELD_SIZE];
    string_list services;
    long age_days;
    size_t finding_count;
    finding findings[MAX_FINDINGS];

    double elapsed_seconds;
} domain_report;

void string_list_add(string_list *list, const char *value);
void string_list_add_unique(string_list *list, const char *value);
int string_list_contains(const string_list *list, const char *value);
void string_list_sort(string_list *list);
void string_list_free(string_list *list);

/* Appends an observation stamped with the current UTC time; `content`
 * (may be NULL) is copied byte for byte. */
observation *record_observation(observation_list *list, const char *collector, const char *source, const char *query,
                                observation_status status, const char *detail, const void *content, size_t length);

/* The first observation from `collector` for exactly `query`, or NULL. */
const observation *find_observation(const observation_list *observations, const char *collector, const char *query);

/* The content as a sanitized, NUL-terminated string the caller frees. */
char *observation_text(const observation *item);

/* "ok", "empty", "no_response", "limited", "error", "not_queried". */
const char *observation_status_name(observation_status status);

void observation_list_free(observation_list *list);

void domain_report_free(domain_report *report);

#endif
