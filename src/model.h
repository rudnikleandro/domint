#ifndef EXPOSUREPROOF_MODEL_H
#define EXPOSUREPROOF_MODEL_H

#include <stddef.h>

#define DOMAIN_SIZE 256
#define FIELD_SIZE 256
#define IP_SIZE 46
#define MAX_ADDRESSES 32
#define MAX_FINDINGS 32

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
    size_t attempts;
    char endpoint[IP_SIZE + 8];
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
    char note[FIELD_SIZE * 2];
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
    char resolve_error[FIELD_SIZE];
    size_t address_count;
    address_info addresses[MAX_ADDRESSES];

    http_info http;
    dns_info dns;
    whois_info whois;

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

void domain_report_free(domain_report *report);

#endif
