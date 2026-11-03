#include "tls.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "http.h"
#include "util.h"

#define TLS_PORT 443
#define CONNECT_TIMEOUT_SECONDS 5L
#define TOTAL_TIMEOUT_SECONDS 10L
#define TRUSTED_DETAIL "certificate chain trusted"
#define UNTRUSTED_PREFIX "not trusted: "

static const char *const month_names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

typedef struct
{
    CURLcode code;
    char error[CURL_ERROR_SIZE];
    char *certificate;
} handshake;

/* Joins the leaf certificate's "Field:value" lines into one text. */
static char *leaf_certificate(CURL *curl)
{
    struct curl_certinfo *info = NULL;

    if (curl_easy_getinfo(curl, CURLINFO_CERTINFO, &info) != CURLE_OK || info == NULL || info->num_of_certs < 1)
    {
        return NULL;
    }

    size_t length = 0;
    char *text = xcalloc(1, 1);

    for (struct curl_slist *line = info->certinfo[0]; line != NULL; line = line->next)
    {
        /* The PEM copy of the certificate adds nothing readable. */
        if (strncmp(line->data, "Cert:", 5) == 0)
        {
            continue;
        }

        size_t line_length = strlen(line->data);
        text = xrealloc(text, length + line_length + 2);
        memcpy(text + length, line->data, line_length);
        length += line_length;
        text[length++] = '\n';
        text[length] = '\0';
    }

    return text;
}

static handshake connect_tls(const char *host, const char *ip, int verify)
{
    handshake result = {CURLE_OK, "", NULL};
    char url[DOMAIN_SIZE + 16];
    char pin[DOMAIN_SIZE + IP_SIZE + 16];
    CURL *curl = curl_easy_init();

    if (curl == NULL)
    {
        result.code = CURLE_FAILED_INIT;
        return result;
    }

    /* Connect to the address already resolved, so the evidence names it. */
    snprintf(url, sizeof(url), "https://%s/", host);
    snprintf(pin, sizeof(pin), strchr(ip, ':') != NULL ? "%s:%d:[%s]" : "%s:%d:%s", host, TLS_PORT, ip);
    struct curl_slist *resolve = curl_slist_append(NULL, pin);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify ? 2L : 0L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TOTAL_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, HTTP_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, result.error);

    result.code = curl_easy_perform(curl);
    result.certificate = leaf_certificate(curl);

    if (result.error[0] == '\0' && result.code != CURLE_OK)
    {
        snprintf(result.error, sizeof(result.error), "%s", curl_easy_strerror(result.code));
    }

    curl_slist_free_all(resolve);
    curl_easy_cleanup(curl);
    return result;
}

static int is_trust_failure(CURLcode code)
{
    return code == CURLE_PEER_FAILED_VERIFICATION || code == CURLE_SSL_CACERT_BADFILE;
}

void tls_collect(const char *host, const address_info *addresses, size_t count, observation_list *observations)
{
    for (size_t i = 0; i < count; i++)
    {
        const char *ip = addresses[i].ip;
        char endpoint[IP_SIZE + 16];
        char detail[FIELD_SIZE * 2];

        snprintf(endpoint, sizeof(endpoint), strchr(ip, ':') != NULL ? "[%s]:%d" : "%s:%d", ip, TLS_PORT);

        handshake verified = connect_tls(host, ip, 1);
        handshake used = verified;

        snprintf(detail, sizeof(detail), "%s", TRUSTED_DETAIL);

        /* A certificate that fails verification is still worth reading:
         * expired, self-signed or wrong-name certificates are findings. */
        if (is_trust_failure(verified.code))
        {
            free(verified.certificate);
            used = connect_tls(host, ip, 0);
            snprintf(detail, sizeof(detail), "%s%s", UNTRUSTED_PREFIX, verified.error);
        }

        if (used.certificate != NULL)
        {
            record_observation(observations, TLS_COLLECTOR, endpoint, host, OBS_OK, detail, used.certificate,
                               strlen(used.certificate));
            free(used.certificate);
            return;
        }

        int unreachable = used.code == CURLE_COULDNT_CONNECT || used.code == CURLE_OPERATION_TIMEDOUT;
        record_observation(observations, TLS_COLLECTOR, endpoint, host, unreachable ? OBS_NO_RESPONSE : OBS_ERROR,
                           unreachable ? "no answer on port 443" : used.error, NULL, 0);
    }
}

int tls_parse_time(const char *text, time_t *out)
{
    char month[4] = "";
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int year = 0;

    if (sscanf(text, "%3s %d %d:%d:%d %d", month, &day, &hour, &minute, &second, &year) != 6)
    {
        return -1;
    }

    for (int i = 0; i < 12; i++)
    {
        if (strcasecmp(month, month_names[i]) == 0)
        {
            struct tm parts;

            memset(&parts, 0, sizeof(parts));
            parts.tm_year = year - 1900;
            parts.tm_mon = i;
            parts.tm_mday = day;
            parts.tm_hour = hour;
            parts.tm_min = minute;
            parts.tm_sec = second;
            *out = timegm(&parts);
            return 0;
        }
    }

    return -1;
}

static void copy_field(const char *line, const char *name, char *out, size_t size)
{
    size_t name_length = strlen(name);

    if (strncmp(line, name, name_length) == 0 && line[name_length] == ':')
    {
        const char *value = line + name_length + 1;
        snprintf(out, size, "%.*s", (int)strcspn(value, "\r\n"), value);
    }
}

/* "DNS:a.example, DNS:b.example, IP Address:192.0.2.1" -> the DNS names. */
static void read_alt_names(const char *line, string_list *names)
{
    static const char field[] = "X509v3 Subject Alternative Name:";

    if (strncmp(line, field, sizeof(field) - 1) != 0)
    {
        return;
    }

    const char *p = line + sizeof(field) - 1;
    const char *end = p + strcspn(p, "\r\n");

    while (p < end)
    {
        while (p < end && (*p == ' ' || *p == ','))
        {
            p++;
        }

        size_t length = 0;

        while (p + length < end && p[length] != ',')
        {
            length++;
        }

        if (length > 4 && strncmp(p, "DNS:", 4) == 0 && length - 4 < DOMAIN_SIZE)
        {
            char name[DOMAIN_SIZE];
            snprintf(name, sizeof(name), "%.*s", (int)(length - 4), p + 4);
            string_list_add_unique(names, name);
        }

        p += length;
    }
}

void tls_parse(const char *certificate, tls_info *tls)
{
    const char *line = certificate;

    while (line != NULL && *line != '\0')
    {
        read_alt_names(line, &tls->names);
        copy_field(line, "Subject", tls->subject, sizeof(tls->subject));
        copy_field(line, "Issuer", tls->issuer, sizeof(tls->issuer));
        copy_field(line, "Start date", tls->valid_from, sizeof(tls->valid_from));
        copy_field(line, "Expire date", tls->valid_until, sizeof(tls->valid_until));
        copy_field(line, "Signature Algorithm", tls->signature, sizeof(tls->signature));
        copy_field(line, "Serial Number", tls->serial, sizeof(tls->serial));

        const char *next_line = strchr(line, '\n');
        line = next_line != NULL ? next_line + 1 : NULL;
    }
}

void tls_interpret(const observation_list *observations, tls_info *tls)
{
    tls->status = LOOKUP_SKIPPED;

    for (size_t i = 0; i < observations->count; i++)
    {
        const observation *item = &observations->items[i];

        if (strcmp(item->collector, TLS_COLLECTOR) != 0)
        {
            continue;
        }

        if (item->status == OBS_NOT_QUERIED)
        {
            tls->not_queried = 1;
            continue;
        }

        tls->status = LOOKUP_FAILED;
        snprintf(tls->endpoint, sizeof(tls->endpoint), "%s", item->source);

        if (item->status != OBS_OK)
        {
            snprintf(tls->trust_error, sizeof(tls->trust_error), "%s", item->detail);
            continue;
        }

        char *certificate = observation_text(item);

        tls->status = LOOKUP_OK;
        tls->trusted = strncmp(item->detail, UNTRUSTED_PREFIX, strlen(UNTRUSTED_PREFIX)) != 0;
        tls->trust_error[0] = '\0';

        if (!tls->trusted)
        {
            snprintf(tls->trust_error, sizeof(tls->trust_error), "%s", item->detail + strlen(UNTRUSTED_PREFIX));
        }

        tls_parse(certificate, tls);
        free(certificate);
        return;
    }
}
