#ifndef DOMINT_MODEL_H
#define DOMINT_MODEL_H

#include <stddef.h>

#define DOMAIN_SIZE 256
#define FIELD_SIZE 256
#define IP_SIZE 46
#define MAX_ADDRESSES 32
#define MAX_FINDINGS 32

#define DOMINT_VERSION "1.0.0"

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
    char name[DOMAIN_SIZE];
    int probed;       /* 1 if probed for HTTP liveness, 0 otherwise */
    int is_live;      /* 1 if responded to HTTP/HTTPS, 0 if unreachable */
    long http_code;   /* e.g. 200, 403, 301, 404, 500, or 0 */
    char protocol[8]; /* "https" or "http" */
    char ip[IP_SIZE]; /* IP address connected to */
    char asn[16];     /* network announcing `ip`, from Team Cymru */
    char as_name[FIELD_SIZE];
    char location[256];      /* Location header for redirects */
    char server[FIELD_SIZE]; /* Server banner header */
    char title[FIELD_SIZE];  /* HTML <title> tag content */
    char error[FIELD_SIZE];  /* Error message if unreachable */
    char cname[DOMAIN_SIZE]; /* alias target, from a CNAME lookup */
    int cname_dangling;      /* the alias target does not exist (NXDOMAIN) */
    int edge_only;           /* a CDN answers for the name but serves no site for it */
} subdomain_info;

/* How a subdomain ended up, for the report and the JSON output. */
typedef enum
{
    SUBDOMAIN_NOT_PROBED,
    SUBDOMAIN_NO_ANSWER,
    SUBDOMAIN_EDGE_ONLY,
    SUBDOMAIN_ONLINE
} subdomain_state;

typedef struct
{
    size_t count;
    size_t capacity;
    subdomain_info *items;
} subdomain_list;

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
    record_set ds;
    record_set dnskey;
    lookup_status soa_status;
    int has_soa;
    char soa_primary[FIELD_SIZE];
    char soa_admin[FIELD_SIZE];
    unsigned long soa_serial;
} dns_info;

/* Registration data, from RDAP when the registry offers it, else WHOIS. */
typedef struct
{
    lookup_status status;
    char protocol[8];
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
    char abuse_email[FIELD_SIZE];
    string_list statuses;
    char *raw;
} whois_info;

typedef struct
{
    lookup_status status;
    int not_queried;
    char endpoint[FIELD_SIZE];
    int trusted;
    char trust_error[FIELD_SIZE * 2];
    char subject[FIELD_SIZE * 2];
    char issuer[FIELD_SIZE * 2];
    char valid_from[64];
    char valid_until[64];
    char signature[FIELD_SIZE];
    char serial[FIELD_SIZE];
    string_list names; /* subject alternative names (DNS entries) */
} tls_info;

/* A registered domain that imitates the investigated one. */
typedef struct
{
    char name[DOMAIN_SIZE];
    const char *technique; /* how it was made: "homoglyph", "tld-swap"... */
    int dns_fails;         /* registered, but its nameservers do not answer */
    string_list nameservers;
    string_list addresses;
    int has_mail;         /* it has MX records: it can receive mail */
    int likely_defensive; /* same nameservers or addresses as the domain */
    int parked;           /* served by a parking or domain-sale service */
} lookalike_info;

typedef struct
{
    lookup_status status;
    size_t checked;
    size_t unanswered;
    size_t count;
    size_t capacity;
    lookalike_info *items;
} lookalike_list;

/* What threat-intelligence sources know about the domain. */
typedef struct
{
    lookup_status otx_status;
    long otx_pulses;
    string_list otx_pulse_names;
    int otx_allowlisted;

    lookup_status urlhaus_status;
    int urlhaus_not_queried;
    long urlhaus_urls;
    long urlhaus_online;
    char spamhaus_dbl[64];
    char surbl[64];
    string_list urlhaus_threats;

    lookup_status threatfox_status;
    int threatfox_not_queried;
    long threatfox_iocs;
    string_list threatfox_malware;
} reputation_info;

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

/* The lookups a report is made of, chosen with -a, -d, -w, -t, -H, -s. */
#define MODULE_ADDRESSES 0x01u
#define MODULE_DNS 0x02u
#define MODULE_WHOIS 0x04u
#define MODULE_TLS 0x08u
#define MODULE_HTTP 0x10u
#define MODULE_SUBDOMAINS 0x20u
#define MODULE_REPUTATION 0x40u
#define MODULE_LOOKALIKES 0x80u
#define MODULE_ALL 0xffu
/* Without module flags: everything but the lookalikes, which take a
 * thousand DNS queries per domain and are asked for with -l. */
#define MODULE_DEFAULT (MODULE_ALL & ~MODULE_LOOKALIKES)

typedef struct
{
    char name[DOMAIN_SIZE];
    char org_domain[DOMAIN_SIZE];

    /* MODULE_* bits of the lookups to run and report; 0 means all. */
    unsigned modules;

    lookup_status resolve_status;
    char resolve_error[FIELD_SIZE * 2];
    size_t address_count;
    address_info addresses[MAX_ADDRESSES];

    http_info http;
    tls_info tls;
    dns_info dns;
    whois_info whois;
    reputation_info reputation;
    lookalike_list lookalikes;

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

    /* Discovered subdomains from passive OSINT and liveness status. */
    lookup_status subdomain_status;
    subdomain_list subdomains;
    char ct_first_seen[32]; /* earliest certificate logged for the domain */

    double elapsed_seconds;
} domain_report;

static inline int report_has(const domain_report *report, unsigned module)
{
    return report->modules == 0 || (report->modules & module) != 0;
}

static inline subdomain_state subdomain_state_of(const subdomain_info *sub)
{
    if (!sub->probed)
    {
        return SUBDOMAIN_NOT_PROBED;
    }

    if (!sub->is_live)
    {
        return SUBDOMAIN_NO_ANSWER;
    }

    return sub->edge_only ? SUBDOMAIN_EDGE_ONLY : SUBDOMAIN_ONLINE;
}

void string_list_add(string_list *list, const char *value);
void string_list_add_unique(string_list *list, const char *value);
int string_list_contains(const string_list *list, const char *value);
void string_list_sort(string_list *list);
void string_list_free(string_list *list);

void subdomain_list_add(subdomain_list *list, const char *name);
void subdomain_list_add_unique(subdomain_list *list, const char *name);
int subdomain_list_contains(const subdomain_list *list, const char *name);
void subdomain_list_sort(subdomain_list *list);
/* Sorts and drops repeated names (case-insensitive), keeping the first. */
void subdomain_list_dedupe(subdomain_list *list);
void subdomain_list_free(subdomain_list *list);

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
