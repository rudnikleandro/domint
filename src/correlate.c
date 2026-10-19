#include "correlate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "analysis.h"
#include "dns.h"
#include "domain.h"
#include "util.h"

static const char KIND_TOKEN[] = "Verification token";
static const char KIND_IP[] = "IP address";
static const char KIND_PREFIX[] = "BGP prefix";
static const char KIND_ASN[] = "Network (ASN)";
static const char KIND_NAMESERVER[] = "Nameserver";
static const char KIND_MAIL[] = "Mail server";
static const char KIND_SOA[] = "SOA contact";
static const char KIND_CREATED[] = "Creation date";
static const char KIND_REGISTRAR[] = "Registrar";

typedef struct
{
    link_strength strength;
    const char *kind;
    char *value;
    size_t domain;
} pivot;

typedef struct
{
    size_t count;
    size_t capacity;
    pivot *items;
} pivot_list;

static void add_pivot(pivot_list *list, link_strength strength, const char *kind, const char *value, size_t domain)
{
    if (value[0] == '\0')
    {
        return;
    }

    if (list->count == list->capacity)
    {
        list->capacity = list->capacity == 0 ? 64 : list->capacity * 2;
        list->items = xrealloc(list->items, list->capacity * sizeof(*list->items));
    }

    pivot *item = &list->items[list->count];
    list->count++;

    item->strength = strength;
    item->kind = kind;
    item->value = xstrdup(value);
    item->domain = domain;

    if (kind == KIND_NAMESERVER || kind == KIND_MAIL || kind == KIND_SOA)
    {
        to_lower(item->value);
    }
}

/* Tokens are case-sensitive secrets; names and labels are compared ignoring case. */
static int compare_values(const char *kind, const char *a, const char *b)
{
    return kind == KIND_TOKEN ? strcmp(a, b) : strcasecmp(a, b);
}

/* Big shared providers (GoDaddy DNS, Google Workspace...) link countless
 * unrelated domains, so they only count as weak links. Cloudflare is the
 * exception for nameservers: it assigns each account its own pair. */
static link_strength nameserver_strength(const char *nameserver)
{
    const char *provider = dns_provider_name(nameserver);
    return provider == NULL || strcmp(provider, "Cloudflare") == 0 ? LINK_MEDIUM : LINK_WEAK;
}

/* The SOA contact of a zone hosted by a known DNS provider is that
 * provider's default (dns.cloudflare.com, awsdns-hostmaster.amazon.com), as
 * is one under the primary nameserver's own domain. Only a custom contact
 * says something about the owner. */
static link_strength soa_strength(const dns_info *dns)
{
    char admin_org[DOMAIN_SIZE];
    char primary_org[DOMAIN_SIZE];

    if (dns_provider_name(dns->soa_primary) != NULL)
    {
        return LINK_WEAK;
    }

    organizational_domain(dns->soa_admin, admin_org, sizeof(admin_org));
    organizational_domain(dns->soa_primary, primary_org, sizeof(primary_org));

    return strcasecmp(admin_org, primary_org) == 0 ? LINK_WEAK : LINK_MEDIUM;
}

/* A shared address only narrows things down when it is not a CDN edge
 * (shared by every customer) or a cloud address (routinely reassigned). */
static link_strength address_strength(const address_info *address)
{
    if (address->asn_status != LOOKUP_OK)
    {
        return LINK_MEDIUM;
    }

    if (!address->announced || proxy_provider_name(address->as_name) != NULL)
    {
        return LINK_WEAK;
    }

    return cloud_provider_name(address->as_name) != NULL ? LINK_MEDIUM : LINK_STRONG;
}

static link_strength prefix_strength(const address_info *address)
{
    if (proxy_provider_name(address->as_name) != NULL || cloud_provider_name(address->as_name) != NULL)
    {
        return LINK_WEAK;
    }

    return LINK_MEDIUM;
}

static void collect_pivots(const domain_report *reports, size_t count, pivot_list *pivots)
{
    for (size_t d = 0; d < count; d++)
    {
        const domain_report *report = &reports[d];

        for (size_t i = 0; i < report->address_count; i++)
        {
            const address_info *address = &report->addresses[i];

            /* Private addresses such as 127.0.0.1 are shared by every
             * sinkholed domain; address_strength() makes them weak. */
            add_pivot(pivots, address_strength(address), KIND_IP, address->ip, d);

            if (address->asn_status == LOOKUP_OK && address->announced)
            {
                char network[FIELD_SIZE * 2];
                snprintf(network, sizeof(network), "AS%s %s", address->asn, address->as_name);

                add_pivot(pivots, prefix_strength(address), KIND_PREFIX, address->prefix, d);
                add_pivot(pivots, LINK_WEAK, KIND_ASN, network, d);
            }
        }

        const dns_info *dns = &report->dns;

        for (size_t i = 0; i < dns->ns.values.count; i++)
        {
            add_pivot(pivots, nameserver_strength(dns->ns.values.items[i]), KIND_NAMESERVER, dns->ns.values.items[i], d);
        }

        for (size_t i = 0; i < dns->mx.values.count; i++)
        {
            const char *host = mx_host(dns->mx.values.items[i]);

            if (!mx_is_null(dns->mx.values.items[i]))
            {
                add_pivot(pivots, mail_provider_name(host) != NULL ? LINK_WEAK : LINK_MEDIUM, KIND_MAIL, host, d);
            }
        }

        for (size_t i = 0; i < dns->txt.values.count; i++)
        {
            if (is_verification_token(dns->txt.values.items[i]))
            {
                add_pivot(pivots, LINK_STRONG, KIND_TOKEN, dns->txt.values.items[i], d);
            }
        }

        if (dns->has_soa)
        {
            add_pivot(pivots, soa_strength(dns), KIND_SOA, dns->soa_admin, d);
        }

        const whois_info *whois = &report->whois;

        if (whois->status == LOOKUP_OK && whois->registered)
        {
            time_t created;

            if (parse_whois_date(whois->created, &created) == 0)
            {
                char date[16];
                whois_date(whois->created, date, sizeof(date));
                add_pivot(pivots, LINK_MEDIUM, KIND_CREATED, date, d);
            }

            add_pivot(pivots, LINK_WEAK, KIND_REGISTRAR, whois->registrar, d);
        }
    }
}

static int compare_pivots(const void *a, const void *b)
{
    const pivot *x = a;
    const pivot *y = b;
    int order = strcmp(x->kind, y->kind);

    if (order == 0)
    {
        order = compare_values(x->kind, x->value, y->value);
    }

    if (order == 0)
    {
        order = (x->domain > y->domain) - (x->domain < y->domain);
    }

    return order;
}

static int compare_indicators(const void *a, const void *b)
{
    const shared_indicator *x = a;
    const shared_indicator *y = b;

    if (x->strength != y->strength)
    {
        return (int)y->strength - (int)x->strength;
    }

    if (x->domain_count != y->domain_count)
    {
        return x->domain_count < y->domain_count ? 1 : -1;
    }

    int order = strcmp(x->kind, y->kind);
    return order != 0 ? order : strcmp(x->value, y->value);
}

/* Sorting puts equal (kind, value) pairs next to each other; every run that
 * spans two or more domains becomes a shared indicator. */
static void build_indicators(pivot_list *pivots, correlation *out)
{
    qsort(pivots->items, pivots->count, sizeof(*pivots->items), compare_pivots);

    size_t start = 0;

    while (start < pivots->count)
    {
        size_t end = start;

        while (end < pivots->count && pivots->items[end].kind == pivots->items[start].kind &&
               compare_values(pivots->items[start].kind, pivots->items[end].value, pivots->items[start].value) == 0)
        {
            end++;
        }

        size_t *domains = xcalloc(end - start, sizeof(*domains));
        size_t domain_count = 0;
        link_strength strength = LINK_WEAK;

        for (size_t i = start; i < end; i++)
        {
            if (i == start || pivots->items[i].domain != pivots->items[i - 1].domain)
            {
                domains[domain_count] = pivots->items[i].domain;
                domain_count++;
            }

            if (pivots->items[i].strength > strength)
            {
                strength = pivots->items[i].strength;
            }
        }

        if (domain_count >= 2)
        {
            out->indicators = xrealloc(out->indicators, (out->indicator_count + 1) * sizeof(*out->indicators));

            shared_indicator *indicator = &out->indicators[out->indicator_count];
            out->indicator_count++;

            indicator->strength = strength;
            indicator->kind = pivots->items[start].kind;
            indicator->value = xstrdup(pivots->items[start].value);
            indicator->domain_count = domain_count;
            indicator->domains = domains;
        }
        else
        {
            free(domains);
        }

        start = end;
    }

    if (out->indicator_count > 1)
    {
        qsort(out->indicators, out->indicator_count, sizeof(*out->indicators), compare_indicators);
    }
}

static size_t find_root(size_t *parent, size_t node)
{
    while (parent[node] != node)
    {
        parent[node] = parent[parent[node]];
        node = parent[node];
    }

    return node;
}

/* Union-find over strong links only: medium links such as a shared hosting
 * prefix would chain unrelated domains into one big group. */
static void build_clusters(size_t count, correlation *out)
{
    size_t *parent = xcalloc(count, sizeof(*parent));
    size_t *members = xcalloc(count, sizeof(*members));
    size_t *cluster_of_root = xcalloc(count, sizeof(*cluster_of_root));

    for (size_t i = 0; i < count; i++)
    {
        parent[i] = i;
        cluster_of_root[i] = NO_CLUSTER;
    }

    for (size_t i = 0; i < out->indicator_count; i++)
    {
        const shared_indicator *indicator = &out->indicators[i];

        if (indicator->strength != LINK_STRONG)
        {
            continue;
        }

        size_t first = find_root(parent, indicator->domains[0]);

        for (size_t j = 1; j < indicator->domain_count; j++)
        {
            size_t other = find_root(parent, indicator->domains[j]);

            if (other != first)
            {
                parent[other] = first;
            }
        }
    }

    for (size_t i = 0; i < count; i++)
    {
        members[find_root(parent, i)]++;
    }

    out->cluster_of = xcalloc(count, sizeof(*out->cluster_of));

    for (size_t i = 0; i < count; i++)
    {
        size_t root = find_root(parent, i);

        if (members[root] < 2)
        {
            out->cluster_of[i] = NO_CLUSTER;
            continue;
        }

        if (cluster_of_root[root] == NO_CLUSTER)
        {
            cluster_of_root[root] = out->cluster_count;
            out->cluster_count++;
        }

        out->cluster_of[i] = cluster_of_root[root];
    }

    free(parent);
    free(members);
    free(cluster_of_root);
}

void correlate(const domain_report *reports, size_t count, correlation *out)
{
    pivot_list pivots = {0};

    memset(out, 0, sizeof(*out));

    collect_pivots(reports, count, &pivots);
    build_indicators(&pivots, out);
    build_clusters(count, out);

    for (size_t i = 0; i < pivots.count; i++)
    {
        free(pivots.items[i].value);
    }

    free(pivots.items);
}

void correlation_free(correlation *links)
{
    for (size_t i = 0; i < links->indicator_count; i++)
    {
        free(links->indicators[i].value);
        free(links->indicators[i].domains);
    }

    free(links->indicators);
    free(links->cluster_of);
    memset(links, 0, sizeof(*links));
}
