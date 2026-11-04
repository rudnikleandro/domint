/* Signals about mail spoofing protection: SPF and DMARC. */

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "collect/dns.h"
#include "core/analysis_internal.h"
#include "support/util.h"

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

void analyze_email(domain_report *report)
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
