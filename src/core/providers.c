/* Catalog of well-known providers (DNS, mail, CDN, cloud) and of the
 * TXT tokens services use to verify domain ownership. */

#include "core/providers.h"

#include <stdio.h>
#include <string.h>

#include "support/util.h"

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
    {"CLOUDFLARE", "Cloudflare"}, {"AKAMAI", "Akamai"},       {"FASTLY", "Fastly"},         {"INCAPSULA", "Imperva"},
    {"SUCURI", "Sucuri"},         {"STACKPATH", "StackPath"}, {"DDOS-GUARD", "DDoS-Guard"},
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
    return match_provider(nameserver, dns_providers, ARRAY_COUNT(dns_providers));
}

const char *mail_provider_name(const char *mail_host)
{
    return match_provider(mail_host, mail_providers, ARRAY_COUNT(mail_providers));
}

const char *proxy_provider_name(const char *as_name)
{
    return match_provider(as_name, proxy_providers, ARRAY_COUNT(proxy_providers));
}

const char *cloud_provider_name(const char *as_name)
{
    return match_provider(as_name, cloud_providers, ARRAY_COUNT(cloud_providers));
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
int service_from_token(const char *txt, char *out, size_t size)
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
