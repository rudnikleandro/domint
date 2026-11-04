#include "collect/dns.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <poll.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "core/model.h"
#include "support/net.h"
#include "support/util.h"

/* Not every resolver header defines ns_t_caa. */
#define DNS_TYPE_CAA 257
#define DNS_TYPE_DS 43
#define DNS_TYPE_DNSKEY 48
#define DNSKEY_FLAG_SEP 0x0001
#define CAA_FLAG_CRITICAL 0x80
#define TXT_VALUE_SIZE 2048

/* The size recommended by DNS Flag Day 2020: large enough for most answers,
 * small enough to avoid IP fragmentation, which many networks drop. */
#define EDNS0_UDP_PAYLOAD 1232

unsigned mx_priority(const char *entry)
{
    return (unsigned)strtoul(entry, NULL, 10);
}

const char *mx_host(const char *entry)
{
    const char *space = strchr(entry, ' ');
    return space != NULL ? space + 1 : entry;
}

int mx_is_null(const char *entry)
{
    const char *host = mx_host(entry);
    return host[0] == '\0' || strcmp(host, ".") == 0;
}

static int expand_name(ns_msg handle, const unsigned char *data, char *out, size_t size)
{
    return dn_expand(ns_msg_base(handle), ns_msg_end(handle), data, out, (int)size) < 0 ? -1 : 0;
}

static int format_mx(ns_msg handle, ns_rr rr, char *out, size_t size)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    char exchange[NS_MAXDNAME];

    if (ns_rr_rdlen(rr) < 3 || expand_name(handle, rdata + 2, exchange, sizeof(exchange)) != 0)
    {
        return -1;
    }

    /* Zero-padded so that sorting the strings sorts by priority. */
    snprintf(out, size, "%05u %s", ns_get16(rdata), exchange);
    return 0;
}

/* TXT rdata is one or more length-prefixed strings, which are meant to be
 * read concatenated (long SPF/DKIM values are split this way). */
static int format_txt(ns_rr rr, char *out, size_t size)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    size_t rdlen = ns_rr_rdlen(rr);
    size_t text_len = 0;
    size_t offset = 0;

    while (offset < rdlen)
    {
        size_t segment_len = rdata[offset];
        offset++;

        if (offset + segment_len > rdlen)
        {
            segment_len = rdlen - offset;
        }

        size_t copy_len = segment_len;

        if (text_len + copy_len > size - 1)
        {
            copy_len = size - 1 - text_len;
        }

        memcpy(out + text_len, rdata + offset, copy_len);
        text_len += copy_len;
        offset += segment_len;
    }

    sanitize_text(out, text_len, 0);
    out[text_len] = '\0';
    return 0;
}

static int format_caa(ns_rr rr, char *out, size_t size)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    size_t rdlen = ns_rr_rdlen(rr);

    if (rdlen < 2 || (size_t)rdata[1] + 2 > rdlen)
    {
        return -1;
    }

    size_t tag_len = rdata[1];
    size_t value_len = rdlen - 2 - tag_len;
    char tag[256];
    char value[512];

    memcpy(tag, rdata + 2, tag_len);
    sanitize_text(tag, tag_len, 0);
    tag[tag_len] = '\0';

    if (value_len > sizeof(value) - 1)
    {
        value_len = sizeof(value) - 1;
    }

    memcpy(value, rdata + 2 + tag_len, value_len);
    sanitize_text(value, value_len, 0);
    value[value_len] = '\0';

    snprintf(out, size, "%s \"%s\"%s", tag, value, (rdata[0] & CAA_FLAG_CRITICAL) != 0 ? " (critical)" : "");
    return 0;
}

/* DS: key tag (2 bytes), algorithm, digest type, digest. */
static int format_ds(ns_rr rr, char *out, size_t size)
{
    const unsigned char *rdata = ns_rr_rdata(rr);

    if (ns_rr_rdlen(rr) < 4)
    {
        return -1;
    }

    snprintf(out, size, "key tag %u, algorithm %u, digest type %u", ns_get16(rdata), rdata[2], rdata[3]);
    return 0;
}

/* DNSKEY: flags (2 bytes), protocol, algorithm, key. */
static int format_dnskey(ns_rr rr, char *out, size_t size)
{
    const unsigned char *rdata = ns_rr_rdata(rr);

    if (ns_rr_rdlen(rr) < 4)
    {
        return -1;
    }

    unsigned flags = ns_get16(rdata);
    snprintf(out, size, "flags %u (%s), algorithm %u", flags, (flags & DNSKEY_FLAG_SEP) != 0 ? "key-signing" : "zone-signing",
             rdata[3]);
    return 0;
}

static int read_soa(ns_msg handle, ns_rr rr, dns_info *info)
{
    const unsigned char *rdata = ns_rr_rdata(rr);
    const unsigned char *rdata_end = rdata + ns_rr_rdlen(rr);

    int consumed = dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, info->soa_primary, sizeof(info->soa_primary));

    if (consumed < 0)
    {
        return -1;
    }

    rdata += consumed;
    consumed = dn_expand(ns_msg_base(handle), ns_msg_end(handle), rdata, info->soa_admin, sizeof(info->soa_admin));

    if (consumed < 0 || rdata + consumed + 4 > rdata_end)
    {
        return -1;
    }

    rdata += consumed;
    info->soa_serial = ns_get32(rdata);
    info->has_soa = 1;

    return 0;
}

static int dns_exchange_udp(const struct sockaddr_in *nameserver, const unsigned char *query, int query_len,
                            unsigned char *response, int response_size)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (sockfd == -1)
    {
        return -1;
    }

    set_socket_timeout(sockfd);

    ssize_t len = -1;

    /* connect() on a UDP socket makes the kernel drop replies from anyone else. */
    if (connect(sockfd, (const struct sockaddr *)nameserver, sizeof(*nameserver)) == 0 &&
        send(sockfd, query, (size_t)query_len, 0) == query_len)
    {
        len = recv(sockfd, response, (size_t)response_size, 0);
    }

    close(sockfd);

    if (len < NS_HFIXEDSZ || memcmp(query, response, 2) != 0)
    {
        return -1;
    }

    return (int)len;
}

/* DNS over TCP prefixes each message with its length as a 16-bit big-endian integer. */
static int dns_exchange_tcp(const struct sockaddr_in *nameserver, const unsigned char *query, int query_len,
                            unsigned char *response, int response_size)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        return -1;
    }

    set_socket_timeout(sockfd);

    unsigned char prefix[2] = {(unsigned char)(query_len >> 8), (unsigned char)(query_len & 0xff)};
    int len = -1;

    if (connect_with_timeout(sockfd, (const struct sockaddr *)nameserver, sizeof(*nameserver)) == 0 &&
        send(sockfd, prefix, sizeof(prefix), 0) == (ssize_t)sizeof(prefix) &&
        send(sockfd, query, (size_t)query_len, 0) == query_len &&
        recv_exact(sockfd, prefix, sizeof(prefix)) == 0)
    {
        int message_len = (prefix[0] << 8) | prefix[1];

        if (message_len >= NS_HFIXEDSZ && message_len <= response_size &&
            recv_exact(sockfd, response, (size_t)message_len) == 0)
        {
            len = message_len;
        }
    }

    close(sockfd);

    return len;
}

/* Asks each nameserver in turn, over UDP first and over TCP when the answer
 * is truncated. Done with our own sockets because libresolv's TCP fallback
 * has no read timeout and hangs on nameservers that accept the connection
 * but never answer. Returns the response length or -1. */
int dns_append_edns0(unsigned char *query, int query_len, int capacity)
{
    /* OPT pseudo-record (RFC 6891): root owner name, type 41, the UDP payload
     * size in the class field, zero extended RCODE/version/flags, no data. */
    const unsigned char opt[EDNS0_OPT_SIZE] = {
        0x00,
        0x00, 0x29,
        (unsigned char)(EDNS0_UDP_PAYLOAD >> 8), (unsigned char)(EDNS0_UDP_PAYLOAD & 0xff),
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    };

    if (query_len < NS_HFIXEDSZ || query_len + EDNS0_OPT_SIZE > capacity)
    {
        return -1;
    }

    unsigned additional = ((unsigned)query[10] << 8) | query[11];
    additional++;
    query[10] = (unsigned char)(additional >> 8);
    query[11] = (unsigned char)(additional & 0xff);

    memcpy(query + query_len, opt, sizeof(opt));
    return query_len + EDNS0_OPT_SIZE;
}

/* Asks each nameserver in turn and writes the one that answered, as
 * "ip:53", into `answered_by`. Returns the response length or -1. */
static int dns_query(res_state resolver, const char *name, int type, unsigned char *response, int response_size,
                     char *answered_by, size_t answered_by_size)
{
    unsigned char query[NS_PACKETSZ];
    unsigned char query_edns[NS_PACKETSZ];
    int query_len = res_nmkquery(resolver, ns_o_query, name, ns_c_in, type, NULL, 0, NULL, query, sizeof(query));

    if (query_len < 0)
    {
        return -1;
    }

    memcpy(query_edns, query, (size_t)query_len);
    int query_edns_len = dns_append_edns0(query_edns, query_len, sizeof(query_edns));

    /* nsaddr_list holds MAXNS entries; nscount comes from the system. */
    for (int i = 0; i < resolver->nscount && i < MAXNS; i++)
    {
        const struct sockaddr_in *nameserver = &resolver->nsaddr_list[i];

        if (nameserver->sin_family != AF_INET)
        {
            continue;
        }

        /* EDNS0 lets answers up to EDNS0_UDP_PAYLOAD bytes come back over
         * UDP instead of forcing the TCP fallback, which some home routers
         * do not answer. Servers that reject EDNS0 get the plain query. */
        int len = -1;

        if (query_edns_len > 0)
        {
            len = dns_exchange_udp(nameserver, query_edns, query_edns_len, response, response_size);
        }

        if (len < 0 || (response[3] & 0x0f) == ns_r_formerr)
        {
            len = dns_exchange_udp(nameserver, query, query_len, response, response_size);
        }

        if (len >= 0 && (response[2] & 0x02) != 0)
        {
            len = dns_exchange_tcp(nameserver, query, query_len, response, response_size);
        }

        /* SERVFAIL, REFUSED and the like say nothing about the domain, so
         * they count as a failed lookup rather than as "no records". */
        if (len >= 0)
        {
            int rcode = response[3] & 0x0f;

            if (rcode == ns_r_noerror || rcode == ns_r_nxdomain)
            {
                char ip[INET_ADDRSTRLEN] = "?";

                inet_ntop(AF_INET, &nameserver->sin_addr, ip, sizeof(ip));
                snprintf(answered_by, answered_by_size, "%s:%d", ip, NS_DEFAULTPORT);
                return len;
            }
        }
    }

    return -1;
}

int dns_parse_answer(const unsigned char *packet, size_t length, int type, string_list *values, dns_info *info)
{
    ns_msg handle;

    if (ns_initparse(packet, (int)length, &handle) < 0)
    {
        return -1;
    }

    int count = ns_msg_count(handle, ns_s_an);
    int matched = 0;

    for (int i = 0; i < count; i++)
    {
        ns_rr rr;

        if (ns_parserr(&handle, ns_s_an, i, &rr) != 0 || (int)ns_rr_type(rr) != type)
        {
            continue;
        }

        char value[TXT_VALUE_SIZE];
        int formatted = -1;

        switch (type)
        {
        case ns_t_ns:
        case ns_t_cname:
            formatted = expand_name(handle, ns_rr_rdata(rr), value, sizeof(value));
            break;
        case ns_t_a:
            formatted = ns_rr_rdlen(rr) == 4 && inet_ntop(AF_INET, ns_rr_rdata(rr), value, sizeof(value)) != NULL ? 0 : -1;
            break;
        case ns_t_mx:
            formatted = format_mx(handle, rr, value, sizeof(value));
            break;
        case ns_t_txt:
            formatted = format_txt(rr, value, sizeof(value));
            break;
        case DNS_TYPE_CAA:
            formatted = format_caa(rr, value, sizeof(value));
            break;
        case DNS_TYPE_DS:
            formatted = format_ds(rr, value, sizeof(value));
            break;
        case DNS_TYPE_DNSKEY:
            formatted = format_dnskey(rr, value, sizeof(value));
            break;
        case ns_t_soa:
            if (info != NULL && read_soa(handle, rr, info) == 0)
            {
                matched++;
            }
            break;
        default:
            break;
        }

        if (formatted == 0)
        {
            matched++;

            if (values != NULL)
            {
                string_list_add_unique(values, value);
            }
        }
    }

    return matched;
}

static const char *type_name(int type)
{
    switch (type)
    {
    case ns_t_ns:
        return "NS";
    case ns_t_cname:
        return "CNAME";
    case ns_t_a:
        return "A";
    case ns_t_mx:
        return "MX";
    case ns_t_txt:
        return "TXT";
    case ns_t_soa:
        return "SOA";
    case DNS_TYPE_CAA:
        return "CAA";
    case DNS_TYPE_DS:
        return "DS";
    case DNS_TYPE_DNSKEY:
        return "DNSKEY";
    default:
        return "?";
    }
}

/* Observations are keyed by "<TYPE> <name>", e.g. "TXT _dmarc.example.com". */
static void dns_query_label(int type, const char *name, char *out, size_t size)
{
    snprintf(out, size, "%s %s", type_name(type), name);
}

/* Queries one record type and records the exchange with the raw packet.
 * Returns the number of matching records, or -1 when nobody answered. */
static int collect_records(res_state resolver, const char *name, int type, observation_list *observations,
                           string_list *values)
{
    static unsigned char response[NS_MAXMSG];
    char label[DOMAIN_SIZE + 16];
    char answered_by[64] = "configured nameservers";

    dns_query_label(type, name, label, sizeof(label));

    int len = dns_query(resolver, name, type, response, sizeof(response), answered_by, sizeof(answered_by));

    if (len < 0)
    {
        record_observation(observations, DNS_COLLECTOR, answered_by, label, OBS_NO_RESPONSE,
                           "no nameserver gave a usable answer", NULL, 0);
        return -1;
    }

    dns_info scratch;
    memset(&scratch, 0, sizeof(scratch));

    int matched = dns_parse_answer(response, (size_t)len, type, values, &scratch);
    int nxdomain = (response[3] & 0x0f) == ns_r_nxdomain;
    observation_status status = OBS_OK;
    const char *detail = NULL;

    if (matched < 0)
    {
        status = OBS_ERROR;
        detail = "malformed DNS response";
    }
    else if (nxdomain)
    {
        status = OBS_EMPTY;
        detail = "NXDOMAIN: the name does not exist";
    }
    else if (matched == 0)
    {
        status = OBS_EMPTY;
        detail = "no records of this type";
    }

    record_observation(observations, DNS_COLLECTOR, answered_by, label, status, detail, response, (size_t)len);
    return matched;
}

static int is_dmarc(const char *txt)
{
    return starts_with_ci(txt, "v=DMARC1");
}

static int count_dmarc(const string_list *records)
{
    int count = 0;

    for (size_t i = 0; i < records->count; i++)
    {
        count += is_dmarc(records->items[i]);
    }

    return count;
}

static void describe_resolvers(const struct __res_state *resolver, int custom, char *out, size_t size)
{
    size_t len = (size_t)snprintf(out, size, "%s", custom ? "" : "system");
    const char *separator = custom ? "" : " (";

    for (int i = 0; i < resolver->nscount && i < MAXNS && len < size; i++)
    {
        char ip[INET_ADDRSTRLEN];

        if (resolver->nsaddr_list[i].sin_family != AF_INET ||
            inet_ntop(AF_INET, &resolver->nsaddr_list[i].sin_addr, ip, sizeof(ip)) == NULL)
        {
            continue;
        }

        len += (size_t)snprintf(out + len, size - len, "%s%s", separator, ip);
        separator = ", ";
    }

    if (len < size)
    {
        snprintf(out + len, size - len, "%s", custom ? " (--resolver)" : strcmp(separator, ", ") == 0 ? ")" : "");
    }
}

/* Reads the system resolver configuration, pointing it at `custom_resolver`
 * when one is given. It is only used for the nameserver list and to build
 * query packets. Returns -1 when the configuration cannot be read. */
static int open_resolver(res_state resolver, const struct in_addr *custom_resolver)
{
    memset(resolver, 0, sizeof(*resolver));

    if (res_ninit(resolver) != 0)
    {
        return -1;
    }

    if (custom_resolver != NULL)
    {
        memset(&resolver->nsaddr_list[0], 0, sizeof(resolver->nsaddr_list[0]));
        resolver->nsaddr_list[0].sin_family = AF_INET;
        resolver->nsaddr_list[0].sin_port = htons(NS_DEFAULTPORT);
        resolver->nsaddr_list[0].sin_addr = *custom_resolver;
        resolver->nscount = 1;
    }

    return 0;
}

/* On macOS res_nclose() only closes sockets and res_ndestroy() frees what
 * res_ninit() allocated; glibc has no res_ndestroy() and its res_nclose()
 * frees everything. */
static void close_resolver(res_state resolver)
{
#ifdef __APPLE__
    res_ndestroy(resolver);
#else
    res_nclose(resolver);
#endif
}

void dns_collect(const char *domain, const char *org_domain, const struct in_addr *custom_resolver,
                 observation_list *observations)
{
    struct __res_state resolver;
    char description[FIELD_SIZE];

    if (open_resolver(&resolver, custom_resolver) != 0)
    {
        record_observation(observations, DNS_CONFIG_COLLECTOR, "system configuration", "nameservers", OBS_ERROR,
                           "could not read the resolver configuration", NULL, 0);
        return;
    }

    describe_resolvers(&resolver, custom_resolver != NULL, description, sizeof(description));
    record_observation(observations, DNS_CONFIG_COLLECTOR, custom_resolver != NULL ? "--resolver" : "system configuration",
                       "nameservers", OBS_OK, NULL, description, strlen(description));

    const int types[] = {ns_t_ns, ns_t_mx, ns_t_txt, ns_t_soa, DNS_TYPE_CAA};

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    {
        collect_records(&resolver, domain, types[i], observations, NULL);
    }

    /* DNSSEC is decided per zone: the DS set comes from the parent (the
     * registry), the DNSKEY set from the zone itself. */
    collect_records(&resolver, org_domain, DNS_TYPE_DS, observations, NULL);
    collect_records(&resolver, org_domain, DNS_TYPE_DNSKEY, observations, NULL);

    /* DMARC lives at _dmarc.<name>; receivers fall back to the organizational
     * domain when a subdomain publishes none. */
    const char *candidates[2] = {domain, org_domain};
    size_t candidate_count = strcmp(domain, org_domain) == 0 ? 1 : 2;

    for (size_t i = 0; i < candidate_count; i++)
    {
        char name[DOMAIN_SIZE + 8];
        string_list records = {0};

        snprintf(name, sizeof(name), "_dmarc.%s", candidates[i]);

        int matched = collect_records(&resolver, name, ns_t_txt, observations, &records);
        int found = count_dmarc(&records) > 0;

        string_list_free(&records);

        if (matched < 0 || found)
        {
            break;
        }
    }

    close_resolver(&resolver);
}

/* Asks for the address of `name` and records the answer under "A <name>".
 * A CNAME query would return the alias alone; the address query makes the
 * resolver follow the chain, so a target that is gone comes back as
 * NXDOMAIN together with the alias that points to it. */
static void collect_alias(res_state resolver, const char *name, observation_list *observations)
{
    static unsigned char response[NS_MAXMSG];
    char label[DOMAIN_SIZE + 16];
    char answered_by[64] = "configured nameservers";

    dns_query_label(ns_t_a, name, label, sizeof(label));

    int len = dns_query(resolver, name, ns_t_a, response, sizeof(response), answered_by, sizeof(answered_by));

    if (len < 0)
    {
        record_observation(observations, DNS_COLLECTOR, answered_by, label, OBS_NO_RESPONSE,
                           "no nameserver gave a usable answer", NULL, 0);
        return;
    }

    int aliases = dns_parse_answer(response, (size_t)len, ns_t_cname, NULL, NULL);
    int nxdomain = (response[3] & 0x0f) == ns_r_nxdomain;
    observation_status status = OBS_OK;
    const char *detail = NULL;

    if (aliases < 0)
    {
        status = OBS_ERROR;
        detail = "malformed DNS response";
    }
    else if (nxdomain && aliases > 0)
    {
        detail = "NXDOMAIN: the alias target does not exist";
    }
    else if (nxdomain)
    {
        status = OBS_EMPTY;
        detail = "NXDOMAIN: the name does not exist";
    }
    else if (aliases == 0)
    {
        detail = "no alias";
    }

    record_observation(observations, DNS_COLLECTOR, answered_by, label, status, detail, response, (size_t)len);
}

void dns_collect_cnames(const subdomain_list *subdomains, const struct in_addr *custom_resolver,
                        observation_list *observations)
{
    struct __res_state resolver;

    if (subdomains->count == 0 || open_resolver(&resolver, custom_resolver) != 0)
    {
        return;
    }

    size_t count = subdomains->count > MAX_CNAME_LOOKUPS ? MAX_CNAME_LOOKUPS : subdomains->count;

    for (size_t i = 0; i < count; i++)
    {
        collect_alias(&resolver, subdomains->items[i].name, observations);
    }

    close_resolver(&resolver);
}

void dns_interpret_cnames(const observation_list *observations, subdomain_list *subdomains)
{
    for (size_t i = 0; i < subdomains->count; i++)
    {
        subdomain_info *sub = &subdomains->items[i];
        char label[DOMAIN_SIZE + 16];
        string_list values = {0};

        dns_query_label(ns_t_a, sub->name, label, sizeof(label));

        const observation *item = find_observation(observations, DNS_COLLECTOR, label);

        if (item == NULL || item->content == NULL || item->content_length < 4)
        {
            continue;
        }

        if (dns_parse_answer(item->content, item->content_length, ns_t_cname, &values, NULL) > 0)
        {
            /* The first record is the alias of the name itself; any others
             * continue the chain. */
            snprintf(sub->cname, sizeof(sub->cname), "%s", values.items[0]);
            sub->cname_dangling = (item->content[3] & 0x0f) == ns_r_nxdomain;
        }

        string_list_free(&values);
    }
}

/* Reads the recorded answer for one query into `values` (and SOA fields
 * into `info`). */
static lookup_status interpret_records(const observation_list *observations, const char *name, int type,
                                       string_list *values, dns_info *info)
{
    char label[DOMAIN_SIZE + 16];
    dns_query_label(type, name, label, sizeof(label));

    const observation *item = find_observation(observations, DNS_COLLECTOR, label);

    if (item == NULL)
    {
        return LOOKUP_SKIPPED;
    }

    if ((item->status != OBS_OK && item->status != OBS_EMPTY) || item->content == NULL)
    {
        return LOOKUP_FAILED;
    }

    return dns_parse_answer(item->content, item->content_length, type, values, info) < 0 ? LOOKUP_FAILED : LOOKUP_OK;
}

void dns_interpret(const char *domain, const char *org_domain, const observation_list *observations, dns_info *info)
{
    const observation *config = find_observation(observations, DNS_CONFIG_COLLECTOR, "nameservers");

    if (config != NULL && config->status == OBS_OK)
    {
        char *text = observation_text(config);
        snprintf(info->resolver, sizeof(info->resolver), "%s", text);
        free(text);
    }
    else
    {
        snprintf(info->resolver, sizeof(info->resolver), "unavailable");
    }

    info->ns.status = interpret_records(observations, domain, ns_t_ns, &info->ns.values, info);
    info->mx.status = interpret_records(observations, domain, ns_t_mx, &info->mx.values, info);
    info->txt.status = interpret_records(observations, domain, ns_t_txt, &info->txt.values, info);
    info->soa_status = interpret_records(observations, domain, ns_t_soa, NULL, info);
    info->caa.status = interpret_records(observations, domain, DNS_TYPE_CAA, &info->caa.values, info);
    info->ds.status = interpret_records(observations, org_domain, DNS_TYPE_DS, &info->ds.values, info);
    info->dnskey.status = interpret_records(observations, org_domain, DNS_TYPE_DNSKEY, &info->dnskey.values, info);

    const char *candidates[2] = {domain, org_domain};
    size_t candidate_count = strcmp(domain, org_domain) == 0 ? 1 : 2;

    info->dmarc.status = LOOKUP_SKIPPED;

    for (size_t i = 0; i < candidate_count; i++)
    {
        char name[DOMAIN_SIZE + 8];
        string_list records = {0};

        snprintf(name, sizeof(name), "_dmarc.%s", candidates[i]);

        lookup_status status = interpret_records(observations, name, ns_t_txt, &records, NULL);

        if (status == LOOKUP_SKIPPED)
        {
            string_list_free(&records);
            break;
        }

        info->dmarc.status = status;

        for (size_t j = 0; j < records.count; j++)
        {
            if (is_dmarc(records.items[j]))
            {
                string_list_add(&info->dmarc.values, records.items[j]);
            }
        }

        string_list_free(&records);

        if (status == LOOKUP_FAILED || info->dmarc.values.count > 0)
        {
            if (info->dmarc.values.count > 0)
            {
                snprintf(info->dmarc_name, sizeof(info->dmarc_name), "%s", name);
            }

            break;
        }
    }

    /* Nameservers rotate the order of their answers; sorting keeps reports comparable. */
    string_list_sort(&info->ns.values);
    string_list_sort(&info->mx.values);
    string_list_sort(&info->txt.values);
    string_list_sort(&info->caa.values);
}

#define MANY_WINDOW 32
#define MANY_TIMEOUT_MS 1500
#define MANY_TRIES 2

static long milliseconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000L + now.tv_nsec / 1000000L;
}

typedef struct
{
    unsigned char query[NS_PACKETSZ];
    int query_length;
    int tries;
    long sent_at;
    int done;
} pending_query;

/* Sends query `i` with the DNS id i + 1, so an answer names its query. */
static void send_query(int sockfd, pending_query *item)
{
    if (send(sockfd, item->query, (size_t)item->query_length, 0) == item->query_length)
    {
        item->tries++;
        item->sent_at = milliseconds();
    }
    else
    {
        item->tries = MANY_TRIES;
        item->sent_at = 0;
    }
}

void dns_query_many(const char *const *names, size_t count, int type, const struct in_addr *custom_resolver,
                    unsigned char **answers, int *lengths)
{
    struct __res_state resolver;

    for (size_t i = 0; i < count; i++)
    {
        answers[i] = NULL;
        lengths[i] = -1;
    }

    if (count == 0 || count >= 0xffff || open_resolver(&resolver, custom_resolver) != 0)
    {
        return;
    }

    const struct sockaddr_in *nameserver = NULL;

    for (int i = 0; i < resolver.nscount && i < MAXNS && nameserver == NULL; i++)
    {
        nameserver = resolver.nsaddr_list[i].sin_family == AF_INET ? &resolver.nsaddr_list[i] : NULL;
    }

    int sockfd = nameserver != NULL ? socket(AF_INET, SOCK_DGRAM, 0) : -1;

    /* connect() makes the kernel drop datagrams from anyone but the resolver. */
    if (sockfd < 0 || connect(sockfd, (const struct sockaddr *)nameserver, sizeof(*nameserver)) != 0 ||
        fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) != 0)
    {
        if (sockfd >= 0)
        {
            close(sockfd);
        }

        close_resolver(&resolver);
        return;
    }

    pending_query *items = xcalloc(count, sizeof(*items));

    for (size_t i = 0; i < count; i++)
    {
        items[i].query_length = res_nmkquery(&resolver, ns_o_query, names[i], ns_c_in, type, NULL, 0, NULL,
                                             items[i].query, sizeof(items[i].query));

        if (items[i].query_length < NS_HFIXEDSZ)
        {
            items[i].done = 1;
            continue;
        }

        items[i].query[0] = (unsigned char)((i + 1) >> 8);
        items[i].query[1] = (unsigned char)((i + 1) & 0xff);
    }

    static unsigned char response[NS_MAXMSG];
    size_t next = 0;
    size_t finished = 0;

    for (size_t i = 0; i < count; i++)
    {
        finished += items[i].done;
    }

    while (finished < count)
    {
        size_t in_flight = 0;
        long now = milliseconds();

        /* Retry or give up on queries whose answer is late, then keep the
         * window full with new ones. */
        for (size_t i = 0; i < next; i++)
        {
            pending_query *item = &items[i];

            if (item->done || now - item->sent_at < MANY_TIMEOUT_MS)
            {
                in_flight += !item->done;
                continue;
            }

            if (item->tries >= MANY_TRIES)
            {
                item->done = 1;
                finished++;
                continue;
            }

            send_query(sockfd, item);
            in_flight++;
        }

        while (in_flight < MANY_WINDOW && next < count)
        {
            if (!items[next].done)
            {
                send_query(sockfd, &items[next]);
                in_flight++;
            }

            next++;
        }

        struct pollfd waiting = {sockfd, POLLIN, 0};

        if (poll(&waiting, 1, 100) <= 0)
        {
            continue;
        }

        ssize_t length;

        while ((length = recv(sockfd, response, sizeof(response), 0)) >= NS_HFIXEDSZ)
        {
            size_t id = ((size_t)response[0] << 8 | response[1]);

            if (id == 0 || id > count || items[id - 1].done || items[id - 1].tries == 0)
            {
                continue;
            }

            pending_query *item = &items[id - 1];
            int rcode = response[3] & 0x0f;

            /* SERVFAIL and REFUSED say nothing about the name; let the
             * retry ask again. */
            if (rcode != ns_r_noerror && rcode != ns_r_nxdomain && item->tries < MANY_TRIES)
            {
                continue;
            }

            answers[id - 1] = xcalloc((size_t)length, 1);
            memcpy(answers[id - 1], response, (size_t)length);
            lengths[id - 1] = (int)length;
            item->done = 1;
            finished++;
        }
    }

    free(items);
    close(sockfd);
    close_resolver(&resolver);
}
