#include "analysis.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dns.h"
#include "domain.h"
#include "tls.h"
#include "util.h"

#define SECONDS_PER_DAY 86400
#define NEW_DOMAIN_DAYS 30
#define YOUNG_DOMAIN_DAYS 180
#define EXPIRY_WARNING_DAYS 30
#define EXPIRY_IMMINENT_DAYS 7
#define CERTIFICATE_WARNING_DAYS 14
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
        /* Full: drop the latest of the least severe findings to make room,
         * so a late HIGH signal is not lost to earlier INFO entries. */
        size_t weakest = 0;

        for (size_t i = 1; i < report->finding_count; i++)
        {
            if (report->findings[i].level <= report->findings[weakest].level)
            {
                weakest = i;
            }
        }

        if (report->findings[weakest].level >= level)
        {
            return;
        }

        memmove(&report->findings[weakest], &report->findings[weakest + 1],
                (report->finding_count - weakest - 1) * sizeof(report->findings[0]));
        report->finding_count--;
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

    /* Status codes are written "clientHold" in EPP/WHOIS and "client hold"
     * in RDAP; compare them without spaces or case. */
    for (size_t i = 0; i < whois->statuses.count; i++)
    {
        const char *status = whois->statuses.items[i];
        char compact[FIELD_SIZE];
        size_t length = 0;

        for (const char *c = status; *c != '\0' && length < sizeof(compact) - 1; c++)
        {
            if (*c != ' ')
            {
                compact[length++] = *c;
            }
        }

        compact[length] = '\0';

        if (strcasecmp(compact, "clientHold") == 0 || strcasecmp(compact, "serverHold") == 0)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "The registry lists the domain as \"%s\": it is withdrawn from DNS, which usually follows a "
                        "takedown, a dispute or unpaid fees.",
                        status);
        }
        else if (strcasecmp(compact, "pendingDelete") == 0 || strcasecmp(compact, "redemptionPeriod") == 0)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "The domain is being deleted (\"%s\"); it will soon be open for anyone to register.", status);
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

static void analyze_tls(domain_report *report, time_t now)
{
    const tls_info *tls = &report->tls;
    time_t until;

    if (tls->status != LOOKUP_OK)
    {
        return;
    }

    int dated = tls_parse_time(tls->valid_until, &until) == 0;
    long days_left = dated ? (long)((until - now) / SECONDS_PER_DAY) : 0;

    if (dated && until < now)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "The TLS certificate expired %ld day%s ago (%s); visitors get a warning, which often means the "
                    "site is no longer maintained.",
                    -days_left, days_left == -1 ? "" : "s", tls->valid_until);
    }
    else if (!tls->trusted)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "The TLS certificate is not trusted (%s): self-signed, wrong name or incomplete chain.",
                    tls->trust_error);
    }
    else if (dated && days_left <= CERTIFICATE_WARNING_DAYS)
    {
        add_finding(report, SEVERITY_LOW, "The TLS certificate expires in %ld day%s (%s).", days_left,
                    days_left == 1 ? "" : "s", tls->valid_until);
    }
}

/* Whether the name is registered, as far as this report knows: without the
 * WHOIS module the registry was not asked, so it is taken as registered. */
static int is_registered(const domain_report *report)
{
    return !report_has(report, MODULE_WHOIS) || report->whois.registered;
}

static void analyze_dns(domain_report *report)
{
    const dns_info *dns = &report->dns;

    /* CAA is inherited from parent names, so only judge it at the registrable domain. */
    if (dns->caa.status == LOOKUP_OK && dns->caa.values.count == 0 && strcmp(report->name, report->org_domain) == 0 &&
        is_registered(report))
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

    /* DNSSEC: DS at the parent with no DNSKEY in the zone breaks resolution
     * for validating resolvers; no DS at all just means unsigned. */
    if (dns->ds.status == LOOKUP_OK && dns->dnskey.status == LOOKUP_OK && is_registered(report))
    {
        if (dns->ds.values.count > 0 && dns->dnskey.values.count == 0)
        {
            add_finding(report, SEVERITY_MEDIUM,
                        "DNSSEC is broken: the registry publishes DS records but the zone has no DNSKEY, so validating "
                        "resolvers will refuse to resolve %s.",
                        report->org_domain);
        }
        else if (dns->ds.values.count == 0)
        {
            add_finding(report, SEVERITY_INFO,
                        "Not signed with DNSSEC: anyone able to tamper with DNS traffic can forge answers for this domain.");
        }
    }
}

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

    for (size_t i = 0; i < COUNT(partial); i++)
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

        for (size_t i = 0; i < COUNT(exact); i++)
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

    for (size_t i = 0; i < COUNT(suffixes); i++)
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

static void analyze_subdomains(domain_report *report)
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

        for (size_t k = 0; k < COUNT(sensitive_keywords); k++)
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

/* Other registrable domains on the certificate share an owner or a
 * hosting account with this one: a pivot to related infrastructure. */
static void analyze_certificate_names(domain_report *report)
{
    string_list others = {0};

    for (size_t i = 0; i < report->tls.names.count; i++)
    {
        const char *name = report->tls.names.items[i];
        char org[DOMAIN_SIZE];

        organizational_domain(name[0] == '*' && name[1] == '.' ? name + 2 : name, org, sizeof(org));

        if (strcasecmp(org, report->org_domain) != 0)
        {
            string_list_add_unique(&others, org);
        }
    }

    if (others.count > 0)
    {
        char list[400] = "";

        for (size_t i = 0; i < others.count; i++)
        {
            if (strlen(list) + strlen(others.items[i]) + 6 >= sizeof(list))
            {
                strncat(list, ", ...", sizeof(list) - strlen(list) - 1);
                break;
            }

            if (i > 0)
            {
                strncat(list, ", ", sizeof(list) - strlen(list) - 1);
            }

            strncat(list, others.items[i], sizeof(list) - strlen(list) - 1);
        }

        add_finding(report, SEVERITY_INFO, "The TLS certificate also covers %zu other domain%s, a lead to related "
                    "infrastructure: %s.", others.count, others.count == 1 ? "" : "s", list);
    }

    string_list_free(&others);
}

/* A domain whose first certificate is days old is newly deployed, which
 * matters for a name that looks established. */
static void analyze_ct(domain_report *report, time_t now)
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

static void join_list(const string_list *list, char *out, size_t size)
{
    out[0] = '\0';

    for (size_t i = 0; i < list->count; i++)
    {
        if (i > 0)
        {
            strncat(out, ", ", size - strlen(out) - 1);
        }

        strncat(out, list->items[i], size - strlen(out) - 1);
    }
}

/* Pulse titles quoted one by one: "a", "b". */
static void join_pulses(const string_list *list, char *out, size_t size)
{
    out[0] = '\0';

    for (size_t i = 0; i < list->count; i++)
    {
        if (i > 0)
        {
            strncat(out, "\", \"", size - strlen(out) - 1);
        }

        strncat(out, list->items[i], size - strlen(out) - 1);
    }
}

static int is_listed(const char *verdict)
{
    return verdict[0] != '\0' && strcasecmp(verdict, "not listed") != 0;
}

static void analyze_reputation(domain_report *report)
{
    const reputation_info *rep = &report->reputation;
    char names[256];

    if (rep->threatfox_status == LOOKUP_OK && rep->threatfox_iocs > 0)
    {
        join_list(&rep->threatfox_malware, names, sizeof(names));
        add_finding(report, SEVERITY_HIGH, "ThreatFox lists this domain as an indicator of compromise (%ld entr%s%s%s).",
                    rep->threatfox_iocs, rep->threatfox_iocs == 1 ? "y" : "ies", names[0] != '\0' ? ": " : "", names);
    }

    if (rep->urlhaus_status == LOOKUP_OK && rep->urlhaus_urls > 0)
    {
        join_list(&rep->urlhaus_threats, names, sizeof(names));
        add_finding(report, rep->urlhaus_online > 0 ? SEVERITY_HIGH : SEVERITY_MEDIUM,
                    "URLhaus has %ld malware URL%s on this host, %ld still online%s%s.", rep->urlhaus_urls,
                    rep->urlhaus_urls == 1 ? "" : "s", rep->urlhaus_online, names[0] != '\0' ? "; threat: " : "",
                    names);
    }

    if (rep->urlhaus_status == LOOKUP_OK && is_listed(rep->spamhaus_dbl))
    {
        add_finding(report, SEVERITY_HIGH, "Listed on the Spamhaus DBL (%s).", rep->spamhaus_dbl);
    }

    if (rep->urlhaus_status == LOOKUP_OK && is_listed(rep->surbl))
    {
        add_finding(report, SEVERITY_MEDIUM, "Listed on SURBL (%s).", rep->surbl);
    }

    /* Pulses also collect benign infrastructure that malware talks to, so
     * they are a lead to read, not a verdict; for a domain OTX itself marks
     * as known-good they are noise. */
    if (rep->otx_status == LOOKUP_OK && rep->otx_pulses > 0 && !rep->otx_allowlisted)
    {
        join_pulses(&rep->otx_pulse_names, names, sizeof(names));
        add_finding(report, SEVERITY_LOW, "Referenced in %ld AlienVault OTX pulse%s%s%s%s.", rep->otx_pulses,
                    rep->otx_pulses == 1 ? "" : "s", names[0] != '\0' ? " (e.g. \"" : "", names,
                    names[0] != '\0' ? "\")" : "");
    }
}

/* A lookalike on the domain's own nameservers or addresses was most
 * likely registered by its owner to keep it from others. */
static int shares_infrastructure(const domain_report *report, const lookalike_info *item)
{
    for (size_t i = 0; i < item->nameservers.count; i++)
    {
        if (string_list_contains(&report->dns.ns.values, item->nameservers.items[i]))
        {
            return 1;
        }
    }

    for (size_t i = 0; i < item->addresses.count; i++)
    {
        for (size_t j = 0; j < report->address_count; j++)
        {
            if (strcmp(item->addresses.items[i], report->addresses[j].ip) == 0)
            {
                return 1;
            }
        }
    }

    return 0;
}

/* Nameservers of parking and domain-sale services: a lookalike there is
 * held for resale, not set up for a campaign. */
static int is_parking(const lookalike_info *item)
{
    static const char *const markers[] = {"afternic",    "namefind",   "parklogic",   "abovedomains", "above.com",
                                          "sedoparking", "bodis",      "dyna-ns",     "namebrightdns", "parkingcrew",
                                          "hugedomains", "dan.com",    "uniregistry", "fabulous.com", "parking",
                                          "domainmarket", "undeveloped", "cashparking", "voodoo.com",  "smartname"};

    for (size_t i = 0; i < item->nameservers.count; i++)
    {
        for (size_t m = 0; m < COUNT(markers); m++)
        {
            if (strstr(item->nameservers.items[i], markers[m]) != NULL)
            {
                return 1;
            }
        }
    }

    return 0;
}

/* The group a registered lookalike falls in, most worrying first. */
static int lookalike_kind(const lookalike_info *item)
{
    if (item->likely_defensive)
    {
        return 4;
    }

    if (item->parked)
    {
        return 3;
    }

    return item->has_mail ? 0 : item->addresses.count > 0 ? 1 : 2;
}

#define LISTED_LOOKALIKES 6

/* "examp1e.com (homoglyph), example-login.com (phishing-word) and 4 more"
 * for the lookalikes of kind `wanted`. Returns how many there are. */
static size_t join_lookalikes(const domain_report *report, int wanted, char *out, size_t size)
{
    size_t count = 0;

    out[0] = '\0';

    for (size_t i = 0; i < report->lookalikes.count; i++)
    {
        const lookalike_info *item = &report->lookalikes.items[i];
        char entry[DOMAIN_SIZE + 40];

        if (lookalike_kind(item) != wanted)
        {
            continue;
        }

        if (count < LISTED_LOOKALIKES)
        {
            snprintf(entry, sizeof(entry), "%s%s (%s)", count > 0 ? ", " : "", item->name, item->technique);
            strncat(out, entry, size - strlen(out) - 1);
        }

        count++;
    }

    if (count > LISTED_LOOKALIKES)
    {
        char more[32];
        snprintf(more, sizeof(more), " and %zu more", count - LISTED_LOOKALIKES);
        strncat(out, more, size - strlen(out) - 1);
    }

    return count;
}

static int compare_lookalikes(const void *a, const void *b)
{
    const lookalike_info *x = a;
    const lookalike_info *y = b;
    int kind = lookalike_kind(x) - lookalike_kind(y);

    return kind != 0 ? kind : strcmp(x->name, y->name);
}

static void analyze_lookalikes(domain_report *report)
{
    char names[400];
    size_t count;

    for (size_t i = 0; i < report->lookalikes.count; i++)
    {
        lookalike_info *item = &report->lookalikes.items[i];

        item->likely_defensive = shares_infrastructure(report, item);
        item->parked = is_parking(item);
    }

    /* qsort() with a NULL array is undefined even for zero items. */
    if (report->lookalikes.count > 1)
    {
        qsort(report->lookalikes.items, report->lookalikes.count, sizeof(*report->lookalikes.items),
              compare_lookalikes);
    }

    if ((count = join_lookalikes(report, 0, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_MEDIUM,
                    "%zu lookalike domain%s can receive mail (MX), the setup used for phishing and invoice fraud: %s.",
                    count, count == 1 ? "" : "s", names);
    }

    if ((count = join_lookalikes(report, 1, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_LOW, "%zu lookalike domain%s registered and pointing to a server: %s.", count,
                    count == 1 ? " is" : "s are", names);
    }

    if ((count = join_lookalikes(report, 2, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_INFO, "%zu lookalike domain%s registered with no server or mail: %s.", count,
                    count == 1 ? " is" : "s are", names);
    }

    if ((count = join_lookalikes(report, 3, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_INFO, "%zu lookalike domain%s parked or for sale at a domain marketplace: %s.",
                    count, count == 1 ? " is" : "s are", names);
    }

    if ((count = join_lookalikes(report, 4, names, sizeof(names))) > 0)
    {
        add_finding(report, SEVERITY_INFO,
                    "%zu lookalike domain%s the same nameservers or addresses as this one, likely registered by its "
                    "owner: %s.",
                    count, count == 1 ? " shares" : "s share", names);
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

    report->age_days = -1;
    summarize(report);

    /* Only the modules that ran: a lookup that was not made must not read
     * as "no records". */
    if (report_has(report, MODULE_WHOIS))
    {
        analyze_registration(report, now);
    }

    if (report_has(report, MODULE_ADDRESSES))
    {
        analyze_addresses(report);
    }

    if (report_has(report, MODULE_DNS))
    {
        analyze_email(report);
    }

    if (report_has(report, MODULE_HTTP))
    {
        analyze_web(report);
    }

    if (report_has(report, MODULE_TLS))
    {
        analyze_tls(report, now);
        analyze_certificate_names(report);
    }

    if (report_has(report, MODULE_REPUTATION))
    {
        analyze_reputation(report);
    }

    if (report_has(report, MODULE_DNS))
    {
        analyze_dns(report);
    }

    if (report_has(report, MODULE_SUBDOMAINS))
    {
        analyze_subdomains(report);
        analyze_ct(report, now);
    }

    if (report_has(report, MODULE_LOOKALIKES))
    {
        analyze_lookalikes(report);
    }

    sort_findings(report);
}
