/* Signals about subdomains: exposed environments, takeover risk, stale
 * records and Certificate Transparency. */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/analysis_internal.h"
#include "core/dates.h"
#include "core/providers.h"
#include "support/util.h"

/* Copies the labels in front of the investigated domain, lowercased, so
 * keyword checks never match the domain itself. Returns 0 when there are none. */
static int subdomain_prefix(const char *name, const char *domain, char *out, size_t size)
{
    size_t name_length = strlen(name);
    size_t domain_length = strlen(domain);

    if (name_length <= domain_length + 1)
    {
        return 0;
    }

    size_t prefix_length = name_length - domain_length - 1;
    snprintf(out, size, "%.*s", (int)prefix_length, name);
    to_lower(out);
    return 1;
}

/* Development, test and homologation names: a label equal to a short
 * keyword ("dev", "qa") or containing a long one ("homol-api"). */
static int is_non_production(const char *name, const char *domain)
{
    static const char *const exact[] = {"dev", "develop", "development", "test", "testing", "tst", "qa",
                                        "uat", "hml", "hom", "stg", "stage", "lab", "demo", "beta", "sandbox"};
    static const char *const partial[] = {"staging", "stagging", "homolog", "homol", "preprod", "sandbox"};
    char prefix[DOMAIN_SIZE];

    if (!subdomain_prefix(name, domain, prefix, sizeof(prefix)))
    {
        return 0;
    }

    for (size_t i = 0; i < ARRAY_COUNT(partial); i++)
    {
        if (strstr(prefix, partial[i]) != NULL)
        {
            return 1;
        }
    }

    char *saveptr = NULL;

    for (char *token = strtok_r(prefix, ".-_", &saveptr); token != NULL; token = strtok_r(NULL, ".-_", &saveptr))
    {
        /* "dev2", "qa01": trailing digits do not change the meaning. */
        size_t length = strlen(token);

        while (length > 0 && token[length - 1] >= '0' && token[length - 1] <= '9')
        {
            length--;
        }

        token[length] = '\0';

        for (size_t i = 0; i < ARRAY_COUNT(exact); i++)
        {
            if (strcmp(token, exact[i]) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}

/* Non-production environments answering on the internet: usually less
 * hardened and monitored than production. */
static void analyze_non_production(domain_report *report)
{
    char list[384] = "";
    size_t found = 0;
    int reachable = 0;
    int probed = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        probed |= sub->probed;

        if ((sub->probed && (!sub->is_live || sub->edge_only)) || !is_non_production(sub->name, report->name))
        {
            continue;
        }

        char entry[DOMAIN_SIZE + 16];

        if (sub->probed)
        {
            snprintf(entry, sizeof(entry), "%s%s (%ld)", found > 0 ? ", " : "", sub->name, sub->http_code);
            reachable |= sub->http_code == 200;
        }
        else
        {
            snprintf(entry, sizeof(entry), "%s%s", found > 0 ? ", " : "", sub->name);
        }

        /* Leave room for the ", ..." marker after this entry. */
        if (strlen(list) + strlen(entry) + strlen(", ...") < sizeof(list))
        {
            strcat(list, entry);
        }
        else if (strstr(list, "...") == NULL)
        {
            strcat(list, ", ...");
        }

        found++;
    }

    if (found == 0)
    {
        return;
    }

    if (probed)
    {
        add_finding(report, reachable ? SEVERITY_MEDIUM : SEVERITY_LOW,
                    "%zu non-production environment%s (dev/test/homologation) answer%s on the internet: %s.", found,
                    found == 1 ? "" : "s", found == 1 ? "s" : "", list);
    }
    else
    {
        add_finding(report, SEVERITY_INFO, "%zu non-production environment name%s (dev/test/homologation) in public records: %s.",
                    found, found == 1 ? "" : "s", list);
    }
}

/* A CDN that answers 400, 409 or 421 for a name is refusing a host it has
 * no site for: the DNS record still points at the CDN, nothing is served. */
static int is_edge_only(const subdomain_info *sub)
{
    return sub->probed && sub->is_live &&
           (sub->http_code == 400 || sub->http_code == 409 || sub->http_code == 421) &&
           proxy_provider_name(sub->as_name) != NULL;
}

/* Hosting services where a name pointing at a deleted resource can be
 * claimed by anyone who creates a resource with that name. */
static int is_claimable(const char *target)
{
    static const char *const suffixes[] = {
        ".azurewebsites.net", ".cloudapp.net",      ".cloudapp.azure.com", ".trafficmanager.net",
        ".blob.core.windows.net", ".azureedge.net", ".azurefd.net",        ".herokuapp.com",
        ".herokudns.com",     ".github.io",         ".s3.amazonaws.com",   ".elasticbeanstalk.com",
        ".cloudfront.net",    ".netlify.app",       ".pantheonsite.io",    ".myshopify.com",
        ".zendesk.com",       ".ghost.io",          ".surge.sh",           ".bitbucket.io",
        ".readthedocs.io",    ".statuspage.io",     ".helpscoutdocs.com",  ".wordpress.com",
        ".fly.dev",           ".vercel.app",        ".firebaseapp.com",    ".web.app",
    };
    size_t length = strlen(target);

    for (size_t i = 0; i < ARRAY_COUNT(suffixes); i++)
    {
        size_t suffix_length = strlen(suffixes[i]);

        if (length > suffix_length && strcasecmp(target + length - suffix_length, suffixes[i]) == 0)
        {
            return 1;
        }
    }

    return 0;
}

/* Short names ("www", "dev.api") of the subdomains `match` picks, joined
 * with ", " and cut with "..." when they do not fit. With `arrows`, each
 * is followed by " -> <alias target>". Returns how many matched. */
static size_t join_subdomains(const domain_report *report, int (*match)(const subdomain_info *), int arrows,
                              char *out, size_t size)
{
    size_t count = 0;
    size_t length = 0;
    int cut = 0;

    out[0] = '\0';

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];
        char prefix[DOMAIN_SIZE];
        char entry[DOMAIN_SIZE * 2 + 8];

        if (!match(sub))
        {
            continue;
        }

        count++;

        if (cut)
        {
            continue;
        }

        if (!subdomain_prefix(sub->name, report->name, prefix, sizeof(prefix)))
        {
            snprintf(prefix, sizeof(prefix), "%s", sub->name);
        }

        /* A long generated target (a tenant id) would swamp the sentence;
         * the SUBDOMAINS section has it in full. */
        char target[64] = "";

        if (arrows)
        {
            snprintf(target, sizeof(target), strlen(sub->cname) > 48 ? " -> %.45s..." : " -> %s", sub->cname);
        }

        snprintf(entry, sizeof(entry), "%s%s%s", count > 1 ? ", " : "", prefix, target);

        if (length + strlen(entry) + 5 < size)
        {
            memcpy(out + length, entry, strlen(entry) + 1);
            length += strlen(entry);
        }
        else
        {
            snprintf(out + length, size - length, ", ...");
            cut = 1;
        }
    }

    return count;
}

static int is_edge(const subdomain_info *sub)
{
    return sub->edge_only;
}

static int is_claimable_dangling(const subdomain_info *sub)
{
    return sub->cname_dangling && is_claimable(sub->cname);
}

static int is_other_dangling(const subdomain_info *sub)
{
    return sub->cname_dangling && !is_claimable(sub->cname);
}

/* DNS records left behind: names whose alias target is gone, and names a
 * CDN still answers for without serving anything. */
static void analyze_stale_records(domain_report *report)
{
    char names[400];
    size_t count = join_subdomains(report, is_claimable_dangling, 1, names, sizeof(names));

    if (count > 0)
    {
        add_finding(report, SEVERITY_HIGH,
                    "Subdomain takeover risk: %zu alias%s point%s to a deleted resource on a service where anyone can "
                    "claim the name: %s.",
                    count, count == 1 ? "" : "es", count == 1 ? "s" : "", names);
    }

    count = join_subdomains(report, is_other_dangling, 1, names, sizeof(names));

    if (count > 0)
    {
        add_finding(report, SEVERITY_MEDIUM, "%zu dangling alias%s: the CNAME target no longer exists: %s.", count,
                    count == 1 ? "" : "es", names);
    }

    count = join_subdomains(report, is_edge, 0, names, sizeof(names));

    if (count > 0)
    {
        const char *provider = NULL;

        for (size_t i = 0; i < report->subdomains.count && provider == NULL; i++)
        {
            if (report->subdomains.items[i].edge_only)
            {
                provider = proxy_provider_name(report->subdomains.items[i].as_name);
            }
        }

        add_finding(report, SEVERITY_LOW,
                    "%zu subdomain%s still point%s to %s, which serves no site for %s: stale DNS records worth "
                    "removing: %s.",
                    count, count == 1 ? "" : "s", count == 1 ? "s" : "", provider != NULL ? provider : "a CDN",
                    count == 1 ? "it" : "them", names);
    }
}

void analyze_subdomains(domain_report *report)
{
    if (report->subdomains.count == 0)
    {
        return;
    }

    int any_probed = 0;

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        subdomain_info *sub = &report->subdomains.items[i];

        any_probed |= sub->probed;
        sub->edge_only = is_edge_only(sub);
    }

    analyze_stale_records(report);

    static const char *const sensitive_keywords[] = {
        "vpn", "admin", "internal",
        "corp", "portal", "cpanel", "jenkins", "jira", "grafana", "gitlab"
    };

    string_list sensitive = {0};

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];

        if (sub->is_live && sub->title[0] != '\0')
        {
            if (strstr(sub->title, "Index of /") != NULL || strstr(sub->title, "Directory Listing") != NULL)
            {
                add_finding(report, SEVERITY_HIGH,
                            "Subdomain exposes open directory listing: %s (Title: \"%s\").",
                            sub->name, sub->title);
            }
        }

        char prefix[DOMAIN_SIZE];

        if (!subdomain_prefix(sub->name, report->name, prefix, sizeof(prefix)))
        {
            continue;
        }

        for (size_t k = 0; k < ARRAY_COUNT(sensitive_keywords); k++)
        {
            if (strstr(prefix, sensitive_keywords[k]) != NULL)
            {
                if (sub->probed && sub->is_live && !sub->edge_only)
                {
                    if (sub->http_code == 200)
                    {
                        char extra[FIELD_SIZE + 16] = "";

                        if (sub->title[0] != '\0')
                        {
                            snprintf(extra, sizeof(extra), ", title: \"%s\"", sub->title);
                        }
                        else if (sub->server[0] != '\0')
                        {
                            snprintf(extra, sizeof(extra), ", server: %s", sub->server);
                        }

                        add_finding(report, SEVERITY_MEDIUM,
                                    "Sensitive subdomain is actively online and accessible without restriction: %s (HTTP 200 OK%s).",
                                    sub->name, extra);
                    }
                    else if (sub->http_code == 401 || sub->http_code == 403)
                    {
                        add_finding(report, SEVERITY_LOW,
                                    "Sensitive subdomain is online with access control enforced: %s (HTTP %ld).",
                                    sub->name, sub->http_code);
                    }
                    else if (sub->http_code >= 300 && sub->http_code < 400 && sub->location[0] != '\0')
                    {
                        add_finding(report, SEVERITY_INFO,
                                    "Sensitive subdomain is online and redirects: %s (HTTP %ld -> %s).",
                                    sub->name, sub->http_code, sub->location);
                    }
                }
                else if (!sub->probed)
                {
                    string_list_add_unique(&sensitive, sub->name);
                }
                break;
            }
        }
    }

    /* Unprobed sensitive names: all of them in passive mode, or those past
     * the probe limit when probing ran. */
    if (sensitive.count > 0)
    {
        char sample[256] = "";
        size_t shown = sensitive.count > 3 ? 3 : sensitive.count;

        for (size_t i = 0; i < shown; i++)
        {
            strncat(sample, sensitive.items[i], sizeof(sample) - strlen(sample) - 1);

            if (i + 1 < shown)
            {
                strncat(sample, ", ", sizeof(sample) - strlen(sample) - 1);
            }
        }

        if (sensitive.count > 3)
        {
            strncat(sample, "...", sizeof(sample) - strlen(sample) - 1);
        }

        if (any_probed)
        {
            add_finding(report, SEVERITY_LOW,
                        "Potentially sensitive or internal subdomains over the probe limit, not checked (%zu found: %s).",
                        sensitive.count, sample);
        }
        else
        {
            add_finding(report, SEVERITY_LOW,
                        "Potentially sensitive or internal subdomains exposed in public logs (%zu found: %s).",
                        sensitive.count, sample);
        }
    }

    string_list_free(&sensitive);
    analyze_non_production(report);
}

/* A domain whose first certificate is days old is newly deployed, which
 * matters for a name that looks established. */
void analyze_ct(domain_report *report, time_t now)
{
    time_t first;

    if (report->ct_first_seen[0] == '\0' || parse_whois_date(report->ct_first_seen, &first) != 0)
    {
        return;
    }

    long days = (long)((now - first) / SECONDS_PER_DAY);

    if (days >= 0 && days <= NEW_DOMAIN_DAYS)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "The first certificate for this domain was logged %ld day%s ago (%s): newly deployed "
                    "infrastructure.",
                    days, days == 1 ? "" : "s", report->ct_first_seen);
    }
}
