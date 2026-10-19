#include "analysis.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns.h"
#include "domain.h"
#include "util.h"

#define SECONDS_PER_DAY 86400
#define NEW_DOMAIN_DAYS 30
#define YOUNG_DOMAIN_DAYS 180
#define EXPIRY_WARNING_DAYS 30
#define EXPIRY_IMMINENT_DAYS 7
#define TXT_COPY_SIZE 2048

#define COUNT(array) (sizeof(array) / sizeof((array)[0]))

typedef struct
{
    const char *pattern;
    const char *name;
} provider;

static const provider dns_providers[] = {
    {"cloudflare.com", "Cloudflare"},
    {"awsdns-", "Amazon Route 53"},
    {"azure-dns.", "Azure DNS"},
    {"ns-cloud-", "Google Cloud DNS"},
    {"googledomains.com", "Google Domains"},
    {"domaincontrol.com", "GoDaddy"},
    {"registrar-servers.com", "Namecheap"},
    {"digitalocean.com", "DigitalOcean"},
    {"nsone.net", "NS1"},
    {"ultradns.", "UltraDNS"},
    {"akam.net", "Akamai"},
    {"dnsimple.com", "DNSimple"},
    {"hostinger", "Hostinger"},
    {"wixdns.net", "Wix"},
    {"squarespacedns.com", "Squarespace"},
    {"linode.com", "Linode"},
    {"hetzner.com", "Hetzner"},
    {"ovh.net", "OVHcloud"},
    {"vercel-dns.com", "Vercel"},
};

static const provider mail_providers[] = {
    {"aspmx.l.google.com", "Google Workspace"},
    {"googlemail.com", "Google Workspace"},
    {"smtp.google.com", "Google Workspace"},
    {"mail.protection.outlook.com", "Microsoft 365"},
    {"pphosted.com", "Proofpoint"},
    {"mimecast.com", "Mimecast"},
    {"zoho.", "Zoho Mail"},
    {"protonmail.ch", "Proton Mail"},
    {"messagingengine.com", "Fastmail"},
    {"secureserver.net", "GoDaddy"},
    {"mailgun.org", "Mailgun"},
    {"amazonaws.com", "Amazon SES"},
    {"barracudanetworks.com", "Barracuda"},
    {"iphmx.com", "Cisco Secure Email"},
    {"emailsrvr.com", "Rackspace"},
    {"yandex.net", "Yandex"},
    {"mx.cloudflare.net", "Cloudflare Email Routing"},
};

/* Matched against the AS name of each address. */
static const provider proxy_providers[] = {
    {"CLOUDFLARE", "Cloudflare"},
    {"AKAMAI", "Akamai"},
    {"FASTLY", "Fastly"},
    {"INCAPSULA", "Imperva"},
    {"SUCURI", "Sucuri"},
    {"STACKPATH", "StackPath"},
    {"DDOS-GUARD", "DDoS-Guard"},
};

/* Matched against the AS name. Addresses in these networks are frequently
 * reassigned or shared, so they say little about who runs a domain. */
static const provider cloud_providers[] = {
    {"AMAZON", "Amazon Web Services"},
    {"GOOGLE", "Google Cloud"},
    {"MICROSOFT", "Microsoft Azure"},
    {"ORACLE", "Oracle Cloud"},
    {"DIGITALOCEAN", "DigitalOcean"},
    {"LINODE", "Linode"},
    {"OVH", "OVHcloud"},
    {"HETZNER", "Hetzner"},
    {"CHOOPA", "Vultr"},
    {"ALIBABA", "Alibaba Cloud"},
    {"TENCENT", "Tencent Cloud"},
};

static const char *const month_names[] = {"jan", "feb", "mar", "apr", "may", "jun",
                                          "jul", "aug", "sep", "oct", "nov", "dec"};

static const char *match_provider(const char *text, const provider *table, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        if (contains_ci(text, table[i].pattern))
        {
            return table[i].name;
        }
    }

    return NULL;
}

const char *dns_provider_name(const char *nameserver)
{
    return match_provider(nameserver, dns_providers, COUNT(dns_providers));
}

const char *mail_provider_name(const char *mail_host)
{
    return match_provider(mail_host, mail_providers, COUNT(mail_providers));
}

const char *proxy_provider_name(const char *as_name)
{
    return match_provider(as_name, proxy_providers, COUNT(proxy_providers));
}

const char *cloud_provider_name(const char *as_name)
{
    return match_provider(as_name, cloud_providers, COUNT(cloud_providers));
}

int parse_whois_date(const char *text, time_t *out)
{
    int year = 0;
    int month = 0;
    int day = 0;
    char month_name[4] = "";

    while (*text == ' ')
    {
        text++;
    }

    if (sscanf(text, "%4d-%2d-%2d", &year, &month, &day) == 3 ||
        sscanf(text, "%4d.%2d.%2d", &year, &month, &day) == 3 ||
        sscanf(text, "%4d/%2d/%2d", &year, &month, &day) == 3)
    {
        /* year-month-day */
    }
    else if (sscanf(text, "%2d-%3[A-Za-z]-%4d", &day, month_name, &year) == 3)
    {
        for (size_t i = 0; i < COUNT(month_names); i++)
        {
            if (strcasecmp(month_name, month_names[i]) == 0)
            {
                month = (int)i + 1;
            }
        }
    }
    else if (strlen(text) >= 8 && isdigit((unsigned char)text[7]) && sscanf(text, "%4d%2d%2d", &year, &month, &day) == 3)
    {
        /* yyyymmdd, as used by registro.br */
    }

    if (year < 1980 || year > 2200 || month < 1 || month > 12 || day < 1 || day > 31)
    {
        return -1;
    }

    struct tm date;
    memset(&date, 0, sizeof(date));
    date.tm_year = year - 1900;
    date.tm_mon = month - 1;
    date.tm_mday = day;
    date.tm_hour = 12;

    *out = timegm(&date);
    return 0;
}

void whois_date(const char *text, char *out, size_t size)
{
    time_t date;

    if (parse_whois_date(text, &date) == 0)
    {
        struct tm parts;
        gmtime_r(&date, &parts);
        strftime(out, size, "%Y-%m-%d", &parts);
    }
    else
    {
        snprintf(out, size, "%s", text[0] != '\0' ? text : "unknown");
    }
}

void describe_age(long days, char *out, size_t size)
{
    if (days < 0)
    {
        days = 0;
    }

    long years = days / 365;
    long months = (days % 365) / 30;

    /* 360-364 leftover days would otherwise read as "12 months". */
    if (months > 11)
    {
        months = 11;
    }

    if (days < 60)
    {
        snprintf(out, size, "%ld day%s", days, days == 1 ? "" : "s");
    }
    else if (years == 0)
    {
        snprintf(out, size, "%ld months", days / 30);
    }
    else if (months == 0)
    {
        snprintf(out, size, "%ld year%s", years, years == 1 ? "" : "s");
    }
    else
    {
        snprintf(out, size, "%ld year%s, %ld month%s", years, years == 1 ? "" : "s", months, months == 1 ? "" : "s");
    }
}

int is_verification_token(const char *txt)
{
    if (starts_with_ci(txt, "MS="))
    {
        return 1;
    }

    const char *equals = strchr(txt, '=');

    if (equals == NULL)
    {
        return 0;
    }

    char key[128];
    size_t key_len = (size_t)(equals - txt);

    if (key_len >= sizeof(key))
    {
        return 0;
    }

    memcpy(key, txt, key_len);
    key[key_len] = '\0';

    return contains_ci(key, "verif");
}

/* "google-site-verification=..." -> "google", "MS=ms123" -> "microsoft". */
static int service_from_token(const char *txt, char *out, size_t size)
{
    if (starts_with_ci(txt, "MS="))
    {
        snprintf(out, size, "microsoft");
        return 1;
    }

    if (!is_verification_token(txt))
    {
        return 0;
    }

    const char *start = txt;

    while (*start == '_')
    {
        start++;
    }

    size_t len = strcspn(start, "-_=");

    if (len == 0)
    {
        return 0;
    }

    if (len >= size)
    {
        len = size - 1;
    }

    memcpy(out, start, len);
    out[len] = '\0';
    to_lower(out);
    return 1;
}

static void add_finding(domain_report *report, severity level, const char *format, ...)
    __attribute__((format(printf, 3, 4)));

static void add_finding(domain_report *report, severity level, const char *format, ...)
{
    if (report->finding_count == MAX_FINDINGS)
    {
        return;
    }

    finding *item = &report->findings[report->finding_count];
    report->finding_count++;
    item->level = level;

    va_list args;
    va_start(args, format);
    vsnprintf(item->text, sizeof(item->text), format, args);
    va_end(args);
}

static void summarize(domain_report *report)
{
    string_list networks = {0};

    for (size_t i = 0; i < report->address_count; i++)
    {
        const address_info *address = &report->addresses[i];

        if (address->asn_status == LOOKUP_OK && address->announced)
        {
            char label[FIELD_SIZE * 2];
            snprintf(label, sizeof(label), "AS%s %s", address->asn, address->as_name);
            string_list_add_unique(&networks, label);
        }
    }

    if (networks.count == 1)
    {
        snprintf(report->hosting, sizeof(report->hosting), "%s", networks.items[0]);
    }
    else if (networks.count > 1)
    {
        snprintf(report->hosting, sizeof(report->hosting), "%s (+%zu more)", networks.items[0], networks.count - 1);
    }

    string_list_free(&networks);

    if (report->dns.ns.values.count > 0)
    {
        const char *nameserver = report->dns.ns.values.items[0];
        const char *name = dns_provider_name(nameserver);

        if (name != NULL)
        {
            snprintf(report->dns_provider, sizeof(report->dns_provider), "%s", name);
        }
        else
        {
            organizational_domain(nameserver, report->dns_provider, sizeof(report->dns_provider));
            to_lower(report->dns_provider);
        }
    }

    /* MX entries are sorted by priority, so the first is the preferred server. */
    if (report->dns.mx.values.count > 0)
    {
        const char *entry = report->dns.mx.values.items[0];
        const char *name = mail_provider_name(mx_host(entry));

        if (mx_is_null(entry))
        {
            snprintf(report->mail_provider, sizeof(report->mail_provider), "accepts no mail (null MX)");
        }
        else if (name != NULL)
        {
            snprintf(report->mail_provider, sizeof(report->mail_provider), "%s", name);
        }
        else
        {
            organizational_domain(mx_host(entry), report->mail_provider, sizeof(report->mail_provider));
            to_lower(report->mail_provider);
        }
    }

    for (size_t i = 0; i < report->dns.txt.values.count; i++)
    {
        char service[64];

        if (service_from_token(report->dns.txt.values.items[i], service, sizeof(service)))
        {
            string_list_add_unique(&report->services, service);
        }
    }

    string_list_sort(&report->services);
}

static void analyze_registration(domain_report *report, time_t now)
{
    const whois_info *whois = &report->whois;

    report->age_days = -1;

    if (whois->status != LOOKUP_OK)
    {
        add_finding(report, SEVERITY_INFO, "Registration data unavailable: %s.", whois->note);
        return;
    }

    if (!whois->registered)
    {
        if (report->resolve_status == LOOKUP_OK)
        {
            add_finding(report, SEVERITY_MEDIUM, "The registry has no record of %s, yet the name resolves.", whois->queried);
        }
        else
        {
            add_finding(report, SEVERITY_INFO, "Not registered: the registry has no record of %s.", whois->queried);
        }

        return;
    }

    time_t created;
    char date[16];

    if (parse_whois_date(whois->created, &created) == 0)
    {
        report->age_days = (long)((now - created) / SECONDS_PER_DAY);
        whois_date(whois->created, date, sizeof(date));

        if (report->age_days < NEW_DOMAIN_DAYS)
        {
            add_finding(report, SEVERITY_HIGH,
                        "Registered %ld days ago (%s). Newly registered domains are a common phishing and malware indicator.",
                        report->age_days, date);
        }
        else if (report->age_days < YOUNG_DOMAIN_DAYS)
        {
            add_finding(report, SEVERITY_MEDIUM, "Registered %ld days ago (%s): a young domain.", report->age_days, date);
        }
    }

    time_t expires;

    if (parse_whois_date(whois->expires, &expires) == 0)
    {
        long days_left = (long)((expires - now) / SECONDS_PER_DAY);
        whois_date(whois->expires, date, sizeof(date));

        /* Renewing in the last weeks is routine, and registries hold an
         * expired name for a grace period before releasing it, so only an
         * imminent or past expiry is more than something to watch. */
        if (expires < now)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "The registration expired on %s. Once the registry's grace period ends, the name can be registered by anyone.",
                        date);
        }
        else if (days_left <= EXPIRY_IMMINENT_DAYS)
        {
            add_finding(report, SEVERITY_LOW,
                        "The registration expires in %ld day%s (%s) and has not been renewed yet.", days_left,
                        days_left == 1 ? "" : "s", date);
        }
        else if (days_left <= EXPIRY_WARNING_DAYS)
        {
            add_finding(report, SEVERITY_INFO,
                        "The registration expires in %ld days (%s). Renewal often happens close to the date; worth checking again later.",
                        days_left, date);
        }
    }

    if (whois->privacy)
    {
        add_finding(report, SEVERITY_INFO, "The registrant's identity is hidden behind a privacy service.");
    }
}

static void analyze_addresses(domain_report *report)
{
    const char *proxies_seen[COUNT(proxy_providers)];
    size_t proxy_count = 0;

    for (size_t i = 0; i < report->address_count; i++)
    {
        const address_info *address = &report->addresses[i];

        if (address->asn_status != LOOKUP_OK)
        {
            continue;
        }

        if (!address->announced)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "Resolves to %s, a private or unannounced address: the domain may be sinkholed, parked or exposing an internal host.",
                        address->ip);
            continue;
        }

        const char *proxy = match_provider(address->as_name, proxy_providers, COUNT(proxy_providers));
        int seen = 0;

        for (size_t j = 0; j < proxy_count; j++)
        {
            seen |= proxies_seen[j] == proxy;
        }

        if (proxy != NULL && !seen)
        {
            proxies_seen[proxy_count] = proxy;
            proxy_count++;
            add_finding(report, SEVERITY_INFO, "Served through %s, which hides the origin server's real address.", proxy);
        }
    }

    if (report->resolve_status == LOOKUP_FAILED && report->whois.status == LOOKUP_OK && report->whois.registered)
    {
        add_finding(report, SEVERITY_INFO, "No A/AAAA records: nothing is hosted on this name (mail-only, parked or unused).");
    }
}

static int is_spf(const char *txt)
{
    return starts_with_ci(txt, "v=spf1") && (txt[6] == ' ' || txt[6] == '\0');
}

/* Returns the qualifier of the SPF "all" mechanism ('+', '-', '~', '?'),
 * or 0 when the record has none. */
static char spf_all_qualifier(const char *spf)
{
    char copy[TXT_COPY_SIZE];
    char *saveptr;

    snprintf(copy, sizeof(copy), "%s", spf);

    for (char *term = strtok_r(copy, " ", &saveptr); term != NULL; term = strtok_r(NULL, " ", &saveptr))
    {
        char qualifier = '+';

        if (strchr("+-~?", term[0]) != NULL)
        {
            qualifier = term[0];
            term++;
        }

        if (strcasecmp(term, "all") == 0)
        {
            return qualifier;
        }
    }

    return 0;
}

/* Copies the value of a DMARC tag ("p", "sp") into `out`; empty when absent. */
static void dmarc_tag(const char *record, const char *name, char *out, size_t size)
{
    size_t name_len = strlen(name);
    const char *tag = record;

    out[0] = '\0';

    while (*tag != '\0')
    {
        tag += strspn(tag, " \t;");

        if (strncasecmp(tag, name, name_len) == 0 && tag[name_len] == '=')
        {
            const char *value = tag + name_len + 1;
            size_t len = strcspn(value, "; \t");

            if (len >= size)
            {
                len = size - 1;
            }

            memcpy(out, value, len);
            out[len] = '\0';
            return;
        }

        tag += strcspn(tag, ";");
    }
}

/* The policy that applies to this name: a subdomain that inherits the
 * organizational record follows its sp= tag when there is one. */
static void dmarc_policy(const domain_report *report, char *out, size_t size)
{
    const dns_info *dns = &report->dns;

    out[0] = '\0';

    if (dns->dmarc.status != LOOKUP_OK || dns->dmarc.values.count == 0)
    {
        return;
    }

    const char *record = dns->dmarc.values.items[0];
    int inherited = strcmp(dns->dmarc_name + strlen("_dmarc."), report->name) != 0;

    if (inherited)
    {
        dmarc_tag(record, "sp", out, size);
    }

    if (out[0] == '\0')
    {
        dmarc_tag(record, "p", out, size);
    }
}

static void analyze_email(domain_report *report)
{
    const dns_info *dns = &report->dns;
    int handles_mail = 0;

    for (size_t i = 0; i < dns->mx.values.count; i++)
    {
        handles_mail |= !mx_is_null(dns->mx.values.items[i]);
    }

    /* Mail checks mean nothing for a name nobody owns. */
    if (report->whois.status == LOOKUP_OK && !report->whois.registered)
    {
        return;
    }

    char policy[32];
    dmarc_policy(report, policy, sizeof(policy));

    int dmarc_enforced = strcasecmp(policy, "quarantine") == 0 || strcasecmp(policy, "reject") == 0;

    if (dns->txt.status != LOOKUP_OK)
    {
        add_finding(report, SEVERITY_INFO, "The TXT lookup failed, so SPF and verification tokens could not be checked.");
    }
    else
    {
        size_t spf_count = 0;
        const char *spf = NULL;

        for (size_t i = 0; i < dns->txt.values.count; i++)
        {
            if (is_spf(dns->txt.values.items[i]))
            {
                spf = dns->txt.values.items[i];
                spf_count++;
            }
        }

        if (spf_count == 0)
        {
            /* With an enforcing DMARC policy, mail that passes neither SPF
             * nor DKIM is rejected anyway, so a missing SPF record is not a
             * spoofing gap. */
            if (!dmarc_enforced)
            {
                add_finding(report, handles_mail ? SEVERITY_MEDIUM : SEVERITY_LOW,
                            "No SPF record and no enforcing DMARC policy: nothing stops others from sending mail as @%s.",
                            report->name);
            }
        }
        else if (spf_count > 1)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "%zu SPF records are published; receivers treat that as an error and ignore SPF.", spf_count);
        }
        else
        {
            char qualifier = spf_all_qualifier(spf);

            if (qualifier == '+')
            {
                add_finding(report, SEVERITY_HIGH, "SPF ends in +all: any server on the internet may send mail as @%s.",
                            report->name);
            }
            else if (qualifier == '?')
            {
                add_finding(report, SEVERITY_MEDIUM, "SPF ends in ?all (neutral), which neither authorizes nor rejects anyone.");
            }
            else if (qualifier == '~' && !dmarc_enforced)
            {
                add_finding(report, SEVERITY_LOW,
                            "SPF ends in ~all (softfail) with no enforcing DMARC policy behind it: spoofed mail is usually still delivered.");
            }
            else if (qualifier == 0 && !contains_ci(spf, "redirect="))
            {
                add_finding(report, SEVERITY_LOW, "SPF has no \"all\" mechanism, so mail from unlisted servers is not rejected.");
            }
        }
    }

    if (dns->dmarc.status != LOOKUP_OK)
    {
        add_finding(report, SEVERITY_INFO, "The DMARC lookup failed, so the mail policy could not be checked.");
    }
    else if (dns->dmarc.values.count == 0)
    {
        add_finding(report, handles_mail ? SEVERITY_MEDIUM : SEVERITY_LOW,
                    "No DMARC policy: receivers get no instruction for mail that fails SPF and DKIM.");
    }
    else if (strcasecmp(policy, "none") == 0)
    {
        add_finding(report, SEVERITY_LOW, "DMARC is in monitoring mode (p=none): mail that fails authentication is still delivered.");
    }
}

static void analyze_web(domain_report *report)
{
    const http_info *http = &report->http;

    if (http->status != LOOKUP_OK)
    {
        return;
    }

    const char *slash = strchr(http->server, '/');

    if (slash != NULL && isdigit((unsigned char)slash[1]))
    {
        add_finding(report, SEVERITY_LOW,
                    "The web server announces its version (%s), which makes it easy to match against known vulnerabilities.",
                    http->server);
    }

    char host[DOMAIN_SIZE];
    char host_org[DOMAIN_SIZE];

    if (http->location[0] != '\0' && normalize_domain(http->location, host, sizeof(host)) == 0)
    {
        organizational_domain(host, host_org, sizeof(host_org));

        if (strcmp(host_org, report->org_domain) != 0)
        {
            add_finding(report, SEVERITY_INFO, "Redirects to another domain: %s.", host);
        }
    }
}

static void analyze_dns(domain_report *report)
{
    const dns_info *dns = &report->dns;

    /* CAA is inherited from parent names, so only judge it at the registrable domain. */
    if (dns->caa.status == LOOKUP_OK && dns->caa.values.count == 0 && strcmp(report->name, report->org_domain) == 0 &&
        report->whois.registered)
    {
        add_finding(report, SEVERITY_INFO, "No CAA record: any certificate authority may issue certificates for this domain.");
    }

    char failed[64] = "";
    const struct
    {
        const char *name;
        lookup_status status;
    } lookups[] = {{"NS", dns->ns.status}, {"MX", dns->mx.status}, {"SOA", dns->soa_status}, {"CAA", dns->caa.status}};

    for (size_t i = 0; i < COUNT(lookups); i++)
    {
        if (lookups[i].status == LOOKUP_FAILED)
        {
            size_t len = strlen(failed);
            snprintf(failed + len, sizeof(failed) - len, "%s%s", len > 0 ? ", " : "", lookups[i].name);
        }
    }

    if (failed[0] != '\0')
    {
        add_finding(report, SEVERITY_INFO, "DNS lookups failed for %s; those records are missing from this report.", failed);
    }
}

/* Most severe first. Insertion sort because it is stable: signals of equal
 * severity keep the order they were found in, so reports are reproducible. */
static void sort_findings(domain_report *report)
{
    for (size_t i = 1; i < report->finding_count; i++)
    {
        finding current = report->findings[i];
        size_t j = i;

        while (j > 0 && report->findings[j - 1].level < current.level)
        {
            report->findings[j] = report->findings[j - 1];
            j--;
        }

        report->findings[j] = current;
    }
}

void analyze_domain(domain_report *report)
{
    time_t now = time(NULL);

    summarize(report);
    analyze_registration(report, now);
    analyze_addresses(report);
    analyze_email(report);
    analyze_web(report);
    analyze_dns(report);
    sort_findings(report);
}
