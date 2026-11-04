/* Liveness probes of subdomains: up to MAX_PROBED_SUBDOMAINS of them, the
 * likeliest to matter first, over HTTPS and then HTTP, PROBE_PARALLEL at a
 * time with curl_multi. Each attempt is recorded as an observation and the
 * results are rebuilt from those observations alone. */

#include "collect/probe.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "collect/http.h"
#include "collect/subdomain.h"
#include "support/https.h"
#include "support/status.h"
#include "support/util.h"

#define MAX_PROBED_SUBDOMAINS 100
#define PROBE_PARALLEL 16
#define PROBE_CONNECT_TIMEOUT 2L
#define PROBE_TOTAL_TIMEOUT 3L
/* Headers and the start of the body are enough for the status, the
 * Server and Location headers and the <title>. */
#define PROBE_HEADER_MAX 8192
#define PROBE_BODY_MAX 8192

static void extract_title(const char *body, char *out, size_t max_size)
{
    out[0] = '\0';

    if (body == NULL)
    {
        return;
    }

    const char *p = body;
    const char *title_start = NULL;

    while (*p != '\0')
    {
        if (p[0] == '<' && (p[1] == 't' || p[1] == 'T') &&
            strncasecmp(p, "<title", 6) == 0)
        {
            const char *gt = strchr(p + 6, '>');

            if (gt != NULL)
            {
                title_start = gt + 1;
                break;
            }
        }

        p++;
    }

    if (title_start == NULL)
    {
        return;
    }

    const char *end = title_start;
    const char *title_end = NULL;

    while (*end != '\0')
    {
        if (end[0] == '<' && (end[1] == '/' || end[1] == ' ') &&
            strncasecmp(end, "</title", 7) == 0)
        {
            title_end = end;
            break;
        }

        end++;
    }

    size_t len = title_end != NULL ? (size_t)(title_end - title_start) : strlen(title_start);

    if (len >= max_size)
    {
        len = max_size - 1;
    }

    char buf[FIELD_SIZE];
    size_t out_len = 0;
    int in_space = 0;

    for (size_t i = 0; i < len && out_len < sizeof(buf) - 1; i++)
    {
        char c = title_start[i];

        if (c == '\r' || c == '\n' || c == '\t' || c == ' ')
        {
            if (!in_space && out_len > 0)
            {
                buf[out_len++] = ' ';
                in_space = 1;
            }
        }
        else if ((unsigned char)c >= 32 && (unsigned char)c <= 126)
        {
            buf[out_len++] = c;
            in_space = 0;
        }
    }

    while (out_len > 0 && buf[out_len - 1] == ' ')
    {
        out_len--;
    }

    buf[out_len] = '\0';

    if (out_len > 0)
    {
        snprintf(out, max_size, "%s", buf);
    }
}

/* One HTTP or HTTPS request to one subdomain. The raw answer (headers and
 * the start of the body) is recorded as the observation. */
typedef struct
{
    const char *name;
    int is_https;
    CURL *curl;
    CURLcode result;
    char error[CURL_ERROR_SIZE];
    char ip[IP_SIZE];
    char *data;
    size_t length;
    size_t header_length;
    size_t body_length;
    int body_full;
} probe;

static void probe_append(probe *p, const char *chunk, size_t length)
{
    p->data = xrealloc(p->data, p->length + length + 1);
    memcpy(p->data + p->length, chunk, length);
    p->length += length;
    p->data[p->length] = '\0';
}

static size_t probe_header_callback(char *buffer, size_t size, size_t nitems, void *userdata)
{
    probe *p = userdata;
    size_t length = size * nitems;

    if (p->header_length + length <= PROBE_HEADER_MAX)
    {
        probe_append(p, buffer, length);
        p->header_length += length;
    }

    return length;
}

/* Stops the transfer once enough of the body is in: a large page would
 * otherwise run into the timeout and count as no answer. */
static size_t probe_body_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    probe *p = userdata;
    size_t length = size * nmemb;
    size_t space = PROBE_BODY_MAX - p->body_length;

    probe_append(p, ptr, length < space ? length : space);
    p->body_length += length < space ? length : space;

    if (p->body_length == PROBE_BODY_MAX)
    {
        p->body_full = 1;
        return 0;
    }

    return length;
}

static int probe_start(probe *p)
{
    char url[DOMAIN_SIZE + 16];

    p->curl = curl_easy_init();

    if (p->curl == NULL)
    {
        p->result = CURLE_FAILED_INIT;
        return -1;
    }

    snprintf(url, sizeof(url), "%s://%s/", p->is_https ? "https" : "http", p->name);

    curl_easy_setopt(p->curl, CURLOPT_URL, url);
    curl_easy_setopt(p->curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(p->curl, CURLOPT_CONNECTTIMEOUT, PROBE_CONNECT_TIMEOUT);
    curl_easy_setopt(p->curl, CURLOPT_TIMEOUT, PROBE_TOTAL_TIMEOUT);
    curl_easy_setopt(p->curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(p->curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(p->curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(p->curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(p->curl, CURLOPT_USERAGENT, DOMINT_USER_AGENT);
    curl_easy_setopt(p->curl, CURLOPT_HEADERFUNCTION, probe_header_callback);
    curl_easy_setopt(p->curl, CURLOPT_HEADERDATA, p);
    curl_easy_setopt(p->curl, CURLOPT_WRITEFUNCTION, probe_body_callback);
    curl_easy_setopt(p->curl, CURLOPT_WRITEDATA, p);
    curl_easy_setopt(p->curl, CURLOPT_ERRORBUFFER, p->error);
    curl_easy_setopt(p->curl, CURLOPT_PRIVATE, p);
    return 0;
}

static void probe_finish(probe *p, CURLcode result)
{
    char *primary_ip = NULL;

    /* Stopping at PROBE_BODY_MAX surfaces as a write error, or over HTTP/2
     * as a receive error; either way the response had arrived. */
    p->result = p->body_full ? CURLE_OK : result;

    if (curl_easy_getinfo(p->curl, CURLINFO_PRIMARY_IP, &primary_ip) == CURLE_OK && primary_ip != NULL)
    {
        snprintf(p->ip, sizeof(p->ip), "%s", primary_ip);
    }

    curl_easy_cleanup(p->curl);
    p->curl = NULL;
}

/* Runs the probes PROBE_PARALLEL at a time: the timeouts then overlap
 * instead of adding up for subdomains that do not answer. */
static void probe_run(probe *probes, size_t count)
{
    CURLM *multi = curl_multi_init();
    size_t next = 0;
    size_t running = 0;
    size_t done = 0;

    if (multi == NULL)
    {
        for (size_t i = 0; i < count; i++)
        {
            probes[i].result = CURLE_FAILED_INIT;
        }

        return;
    }

    while (next < count || running > 0)
    {
        while (running < PROBE_PARALLEL && next < count)
        {
            if (probe_start(&probes[next]) == 0)
            {
                curl_multi_add_handle(multi, probes[next].curl);
                running++;
            }

            next++;
        }

        int still_running = 0;
        int queued = 0;
        CURLMsg *message;

        curl_multi_perform(multi, &still_running);

        while ((message = curl_multi_info_read(multi, &queued)) != NULL)
        {
            if (message->msg != CURLMSG_DONE)
            {
                continue;
            }

            char *private = NULL;
            CURL *easy = message->easy_handle;
            CURLcode result = message->data.result;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &private);
            curl_multi_remove_handle(multi, easy);
            probe_finish((probe *)private, result);
            running--;
            done++;
        }

        status_detail("probing subdomains over %s (%zu/%zu)", probes[0].is_https ? "HTTPS" : "HTTP", done, count);

        if (running > 0)
        {
            curl_multi_poll(multi, NULL, 0, 1000, NULL);
        }
    }

    curl_multi_cleanup(multi);
}

static int is_no_answer(CURLcode code)
{
    return code == CURLE_COULDNT_RESOLVE_HOST || code == CURLE_COULDNT_CONNECT || code == CURLE_OPERATION_TIMEDOUT ||
           code == CURLE_RECV_ERROR || code == CURLE_SEND_ERROR || code == CURLE_GOT_NOTHING;
}

/* A short reason for a failed probe, so the report can group them. */
static const char *probe_reason(CURLcode code)
{
    switch (code)
    {
    case CURLE_COULDNT_RESOLVE_HOST:
        return "not in DNS";
    case CURLE_OPERATION_TIMEDOUT:
        return "timed out";
    case CURLE_COULDNT_CONNECT:
        return "connection refused";
    case CURLE_SSL_CONNECT_ERROR:
        return "TLS handshake failed";
    case CURLE_RECV_ERROR:
    case CURLE_SEND_ERROR:
        return "connection reset";
    case CURLE_GOT_NOTHING:
        return "empty reply";
    default:
        return "error";
    }
}

/* Source "https://192.0.2.10:443": the scheme and the address that
 * answered, or the name when no connection was made. */
static void probe_record(const probe *p, observation_list *observations)
{
    const char *scheme = p->is_https ? "https" : "http";
    const char *port = p->is_https ? "443" : "80";
    char source[DOMAIN_SIZE + 16];

    if (p->ip[0] == '\0')
    {
        snprintf(source, sizeof(source), "%s://%s", scheme, p->name);
    }
    else if (strchr(p->ip, ':') != NULL)
    {
        snprintf(source, sizeof(source), "%s://[%s]:%s", scheme, p->ip, port);
    }
    else
    {
        snprintf(source, sizeof(source), "%s://%s:%s", scheme, p->ip, port);
    }

    if (p->result == CURLE_OK)
    {
        record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, source, p->name, OBS_OK, NULL, p->data, p->length);
        return;
    }

    /* "<reason>: <libcurl message>"; the report groups by the reason. */
    char detail[FIELD_SIZE + CURL_ERROR_SIZE];
    snprintf(detail, sizeof(detail), "%s: %s", probe_reason(p->result),
             p->error[0] != '\0' ? p->error : curl_easy_strerror(p->result));

    record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, source, p->name,
                       is_no_answer(p->result) ? OBS_NO_RESPONSE : OBS_ERROR, detail, NULL, 0);
}

/* The address in a probe source, or "" when it names the host. */
static void probe_source_ip(const char *source, char *scheme, size_t scheme_size, char *ip, size_t ip_size)
{
    const char *host = strstr(source, "://");
    char address[IP_SIZE];
    unsigned char binary[sizeof(struct in6_addr)];

    scheme[0] = '\0';
    ip[0] = '\0';

    if (host == NULL)
    {
        return;
    }

    snprintf(scheme, scheme_size, "%.*s", (int)(host - source), source);
    host += 3;

    if (*host == '[')
    {
        snprintf(address, sizeof(address), "%.*s", (int)strcspn(host + 1, "]"), host + 1);
    }
    else
    {
        snprintf(address, sizeof(address), "%.*s", (int)strcspn(host, ":"), host);
    }

    if (inet_pton(AF_INET, address, binary) == 1 || inet_pton(AF_INET6, address, binary) == 1)
    {
        snprintf(ip, ip_size, "%s", address);
    }
}

/* Fills `sub` from a recorded answer. A 1xx interim response is skipped
 * for the final one that follows it. */
static void probe_parse(const char *text, subdomain_info *sub)
{
    const char *response = text;
    http_info http;

    while (strncmp(response, "HTTP/", 5) == 0)
    {
        const char *code = strchr(response, ' ');
        const char *end = strstr(response, "\r\n\r\n");

        if (code == NULL || code[1] != '1' || end == NULL)
        {
            break;
        }

        response = end + 4;
    }

    memset(&http, 0, sizeof(http));
    http_parse(response, &http);

    const char *code = strchr(http.status_line, ' ');
    sub->http_code = code != NULL ? strtol(code + 1, NULL, 10) : 0;
    snprintf(sub->server, sizeof(sub->server), "%s", http.server);
    snprintf(sub->location, sizeof(sub->location), "%.*s", (int)sizeof(sub->location) - 1, http.location);

    const char *body = strstr(response, "\r\n\r\n");
    extract_title(body != NULL ? body + 4 : "", sub->title, sizeof(sub->title));
}

/* Clears what a previous attempt left, keeping the name and its alias. */
static void reset_probe(subdomain_info *sub)
{
    sub->probed = 0;
    sub->is_live = 0;
    sub->http_code = 0;
    sub->protocol[0] = '\0';
    sub->ip[0] = '\0';
    sub->asn[0] = '\0';
    sub->as_name[0] = '\0';
    sub->location[0] = '\0';
    sub->server[0] = '\0';
    sub->title[0] = '\0';
    sub->error[0] = '\0';
}

static int compare_name(const void *key, const void *item)
{
    return strcasecmp(key, ((const subdomain_info *)item)->name);
}

/* Builds the probe results of each subdomain from its recorded attempts:
 * the first answer wins (HTTPS is recorded before HTTP), otherwise the
 * last failure is kept. `subdomains` must be sorted. */
void subdomain_apply_probes(const observation_list *observations, subdomain_list *subdomains)
{
    for (size_t i = 0; i < observations->count; i++)
    {
        const observation *obs = &observations->items[i];

        if (strcmp(obs->collector, SUBDOMAIN_PROBE_COLLECTOR) != 0 || obs->status == OBS_NOT_QUERIED ||
            strstr(obs->source, "://") == NULL)
        {
            continue;
        }

        subdomain_info *sub = bsearch(obs->query, subdomains->items, subdomains->count, sizeof(*subdomains->items),
                                      compare_name);

        if (sub == NULL || sub->is_live)
        {
            continue;
        }

        reset_probe(sub);
        sub->probed = 1;
        probe_source_ip(obs->source, sub->protocol, sizeof(sub->protocol), sub->ip, sizeof(sub->ip));

        if (obs->status == OBS_OK)
        {
            char *text = observation_text(obs);
            sub->is_live = 1;
            probe_parse(text, sub);
            free(text);
        }
        else
        {
            snprintf(sub->error, sizeof(sub->error), "%.*s", (int)sizeof(sub->error) - 1, obs->detail);
        }
    }
}

/* Names an analyst checks first: the main web and mail hosts, then remote
 * access, admin panels and non-production environments. */
static int probe_priority(const char *name, const char *domain)
{
    static const char *const first[] = {"www", "mail", "webmail", "owa", "autodiscover", "vpn", "remote", "portal",
                                        "login", "sso", "auth", "admin", "api", "app"};
    static const char *const keywords[] = {"admin", "vpn", "portal", "intranet", "internal", "corp", "jenkins", "jira",
                                           "grafana", "gitlab", "git", "kibana", "sso", "login", "auth", "api", "dev",
                                           "test", "stag", "hml", "homol", "uat", "qa", "sandbox", "beta", "backup"};
    size_t name_length = strlen(name);
    size_t domain_length = strlen(domain);

    if (name_length <= domain_length + 1)
    {
        return 2;
    }

    char prefix[DOMAIN_SIZE];
    snprintf(prefix, sizeof(prefix), "%.*s", (int)(name_length - domain_length - 1), name);

    for (size_t i = 0; i < sizeof(first) / sizeof(first[0]); i++)
    {
        if (strcmp(prefix, first[i]) == 0)
        {
            return 0;
        }
    }

    for (size_t i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++)
    {
        if (strstr(prefix, keywords[i]) != NULL)
        {
            return 1;
        }
    }

    return 2;
}

typedef struct
{
    size_t index;
    int priority;
    int depth;
    const char *name;
} probe_candidate;

/* Priority, then names closer to the domain, then alphabetical. */
static int compare_candidates(const void *a, const void *b)
{
    const probe_candidate *x = a;
    const probe_candidate *y = b;

    if (x->priority != y->priority)
    {
        return x->priority - y->priority;
    }

    if (x->depth != y->depth)
    {
        return x->depth - y->depth;
    }

    return strcmp(x->name, y->name);
}

static int label_count(const char *name)
{
    int count = 1;

    for (const char *p = name; *p != '\0'; p++)
    {
        count += *p == '.';
    }

    return count;
}

void subdomain_probe(subdomain_list *subdomains, int passive, int no_probe,
                     observation_list *observations, const char *domain)
{
    if (no_probe)
    {
        record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, "target", domain, OBS_NOT_QUERIED,
                           "--no-probe: subdomain HTTP probing skipped", NULL, 0);
        return;
    }

    if (passive)
    {
        record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, "target", domain, OBS_NOT_QUERIED,
                           "passive mode: subdomains are not contacted (--active to probe them)", NULL, 0);
        return;
    }

    if (subdomains->count == 0)
    {
        return;
    }

    size_t to_probe = subdomains->count > MAX_PROBED_SUBDOMAINS ? MAX_PROBED_SUBDOMAINS : subdomains->count;
    probe_candidate *candidates = xcalloc(subdomains->count, sizeof(*candidates));

    for (size_t i = 0; i < subdomains->count; i++)
    {
        candidates[i].index = i;
        candidates[i].name = subdomains->items[i].name;
        candidates[i].priority = probe_priority(subdomains->items[i].name, domain);
        candidates[i].depth = label_count(subdomains->items[i].name);
    }

    qsort(candidates, subdomains->count, sizeof(*candidates), compare_candidates);

    probe *secure = xcalloc(to_probe, sizeof(*secure));
    probe *plain = xcalloc(to_probe, sizeof(*plain));
    size_t plain_count = 0;

    /* HTTPS first; plain HTTP only for the names that did not answer. */
    for (size_t i = 0; i < to_probe; i++)
    {
        secure[i].name = subdomains->items[candidates[i].index].name;
        secure[i].is_https = 1;
    }

    free(candidates);

    probe_run(secure, to_probe);

    for (size_t i = 0; i < to_probe; i++)
    {
        if (secure[i].result != CURLE_OK)
        {
            plain[plain_count++].name = secure[i].name;
        }
    }

    probe_run(plain, plain_count);

    for (size_t i = 0, j = 0; i < to_probe; i++)
    {
        probe_record(&secure[i], observations);

        if (secure[i].result != CURLE_OK)
        {
            probe_record(&plain[j++], observations);
        }
    }

    for (size_t i = 0; i < to_probe; i++)
    {
        free(secure[i].data);
    }

    for (size_t i = 0; i < plain_count; i++)
    {
        free(plain[i].data);
    }

    free(secure);
    free(plain);

    subdomain_apply_probes(observations, subdomains);

    size_t live_count = 0;
    size_t code_200 = 0;
    size_t code_403 = 0;
    size_t code_redir = 0;

    for (size_t i = 0; i < subdomains->count; i++)
    {
        const subdomain_info *sub = &subdomains->items[i];

        if (sub->probed && sub->is_live)
        {
            live_count++;

            if (sub->http_code == 200)
            {
                code_200++;
            }
            else if (sub->http_code == 401 || sub->http_code == 403)
            {
                code_403++;
            }
            else if (sub->http_code >= 300 && sub->http_code < 400)
            {
                code_redir++;
            }
        }
    }

    char detail[FIELD_SIZE];
    snprintf(detail, sizeof(detail), "Probed %zu subdomains: %zu online (%zu open 200, %zu restricted 403/401, %zu redirect), %zu offline",
             to_probe, live_count, code_200, code_403, code_redir, to_probe - live_count);

    record_observation(observations, SUBDOMAIN_PROBE_COLLECTOR, "http-probe", domain, OBS_OK, detail, NULL, 0);
}
