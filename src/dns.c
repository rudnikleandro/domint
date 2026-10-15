#include "dns.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net.h"
#include "text.h"

/* Not every resolver header defines ns_t_caa. */
#define DNS_TYPE_CAA 257
#define CAA_FLAG_CRITICAL 0x80
#define TXT_VALUE_SIZE 2048

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
static int dns_query(res_state resolver, const char *name, int type, unsigned char *response, int response_size)
{
    unsigned char query[NS_PACKETSZ];
    int query_len = res_nmkquery(resolver, ns_o_query, name, ns_c_in, type, NULL, 0, NULL, query, sizeof(query));

    if (query_len < 0)
    {
        return -1;
    }

    for (int i = 0; i < resolver->nscount; i++)
    {
        const struct sockaddr_in *nameserver = &resolver->nsaddr_list[i];

        if (nameserver->sin_family != AF_INET)
        {
            continue;
        }

        int len = dns_exchange_udp(nameserver, query, query_len, response, response_size);

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
                return len;
            }
        }
    }

    return -1;
}

/* Adds the answers of `type` for `name` to `values` (SOA goes into `info`). */
static lookup_status query_records(res_state resolver, const char *name, int type, string_list *values, dns_info *info)
{
    static unsigned char response[NS_MAXMSG];
    int len = dns_query(resolver, name, type, response, sizeof(response));
    ns_msg handle;

    if (len < 0 || ns_initparse(response, len, &handle) < 0)
    {
        return LOOKUP_FAILED;
    }

    int count = ns_msg_count(handle, ns_s_an);

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
            formatted = expand_name(handle, ns_rr_rdata(rr), value, sizeof(value));
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
        case ns_t_soa:
            read_soa(handle, rr, info);
            break;
        default:
            break;
        }

        if (formatted == 0 && values != NULL)
        {
            string_list_add_unique(values, value);
        }
    }

    return LOOKUP_OK;
}

/* DMARC lives at _dmarc.<name>; receivers fall back to the organizational
 * domain when a subdomain publishes none. */
static void collect_dmarc(res_state resolver, const char *domain, const char *org_domain, dns_info *info)
{
    const char *candidates[2] = {domain, org_domain};
    size_t candidate_count = strcmp(domain, org_domain) == 0 ? 1 : 2;

    info->dmarc.status = LOOKUP_OK;

    for (size_t i = 0; i < candidate_count; i++)
    {
        char name[DOMAIN_SIZE + 8];
        string_list records = {0};

        snprintf(name, sizeof(name), "_dmarc.%s", candidates[i]);

        if (query_records(resolver, name, ns_t_txt, &records, info) != LOOKUP_OK)
        {
            info->dmarc.status = LOOKUP_FAILED;
            string_list_free(&records);
            return;
        }

        for (size_t j = 0; j < records.count; j++)
        {
            if (starts_with_ci(records.items[j], "v=DMARC1"))
            {
                string_list_add(&info->dmarc.values, records.items[j]);
            }
        }

        string_list_free(&records);

        if (info->dmarc.values.count > 0)
        {
            snprintf(info->dmarc_name, sizeof(info->dmarc_name), "%s", name);
            return;
        }
    }
}

static void describe_system_resolvers(const struct __res_state *resolver, char *out, size_t size)
{
    size_t len = (size_t)snprintf(out, size, "system");
    const char *separator = " (";

    for (int i = 0; i < resolver->nscount && len < size; i++)
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

    if (strcmp(separator, ", ") == 0 && len < size)
    {
        snprintf(out + len, size - len, ")");
    }
}

void dns_collect(const char *domain, const char *org_domain, const struct in_addr *custom_resolver, dns_info *info)
{
    /* Only used for the nameserver list and to build query packets. */
    struct __res_state resolver;

    memset(&resolver, 0, sizeof(resolver));

    if (res_ninit(&resolver) != 0)
    {
        snprintf(info->resolver, sizeof(info->resolver), "unavailable");
        info->ns.status = LOOKUP_FAILED;
        info->mx.status = LOOKUP_FAILED;
        info->txt.status = LOOKUP_FAILED;
        info->caa.status = LOOKUP_FAILED;
        info->dmarc.status = LOOKUP_FAILED;
        info->soa_status = LOOKUP_FAILED;
        return;
    }

    if (custom_resolver != NULL)
    {
        char ip[INET_ADDRSTRLEN];

        memset(&resolver.nsaddr_list[0], 0, sizeof(resolver.nsaddr_list[0]));
        resolver.nsaddr_list[0].sin_family = AF_INET;
        resolver.nsaddr_list[0].sin_port = htons(NS_DEFAULTPORT);
        resolver.nsaddr_list[0].sin_addr = *custom_resolver;
        resolver.nscount = 1;

        inet_ntop(AF_INET, custom_resolver, ip, sizeof(ip));
        snprintf(info->resolver, sizeof(info->resolver), "%s (--resolver)", ip);
    }
    else
    {
        describe_system_resolvers(&resolver, info->resolver, sizeof(info->resolver));
    }

    info->ns.status = query_records(&resolver, domain, ns_t_ns, &info->ns.values, info);
    info->mx.status = query_records(&resolver, domain, ns_t_mx, &info->mx.values, info);
    info->txt.status = query_records(&resolver, domain, ns_t_txt, &info->txt.values, info);
    info->soa_status = query_records(&resolver, domain, ns_t_soa, NULL, info);
    info->caa.status = query_records(&resolver, domain, DNS_TYPE_CAA, &info->caa.values, info);
    collect_dmarc(&resolver, domain, org_domain, info);

    /* Nameservers rotate the order of their answers; sorting keeps reports comparable. */
    string_list_sort(&info->ns.values);
    string_list_sort(&info->mx.values);
    string_list_sort(&info->txt.values);
    string_list_sort(&info->caa.values);

    /* On macOS res_nclose() only closes sockets; res_ndestroy() also frees
     * what res_ninit() allocated. */
    res_ndestroy(&resolver);
}
