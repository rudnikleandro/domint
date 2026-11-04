#include "support/https.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "support/util.h"

#define CONNECT_TIMEOUT_SECONDS 5L
#define TOTAL_TIMEOUT_SECONDS 15L
#define MAX_REDIRECTS 3L

typedef struct
{
    char *data;
    size_t length;
    size_t max_size;
    int too_large;
} body;

static size_t collect_body(char *chunk, size_t size, size_t count, void *context)
{
    body *buffer = context;
    size_t length = size * count;

    /* Returning less than `length` makes libcurl abort the transfer. */
    if (buffer->length + length > buffer->max_size)
    {
        buffer->too_large = 1;
        return 0;
    }

    buffer->data = xrealloc(buffer->data, buffer->length + length + 1);
    memcpy(buffer->data + buffer->length, chunk, length);
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return length;
}

int https_init(void)
{
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? 0 : -1;
}

void https_cleanup(void)
{
    curl_global_cleanup();
}

void url_host(const char *url, char *out, size_t size)
{
    const char *start = strstr(url, "://");

    start = start != NULL ? start + 3 : url;
    snprintf(out, size, "%.*s", (int)strcspn(start, "/:?#"), start);
}

static int is_no_response(CURLcode code)
{
    return code == CURLE_COULDNT_RESOLVE_HOST || code == CURLE_COULDNT_CONNECT || code == CURLE_OPERATION_TIMEDOUT ||
           code == CURLE_RECV_ERROR || code == CURLE_SEND_ERROR || code == CURLE_GOT_NOTHING;
}

https_response https_get(const char *url, size_t max_size)
{
    return https_request(url, max_size, TOTAL_TIMEOUT_SECONDS, NULL, NULL);
}

https_response https_get_timeout(const char *url, size_t max_size, long timeout_seconds)
{
    return https_request(url, max_size, timeout_seconds, NULL, NULL);
}

https_response https_request(const char *url, size_t max_size, long timeout_seconds, const char *const *headers,
                             const char *post_body)
{
    https_response response;
    body buffer = {NULL, 0, max_size, 0};
    char error_buffer[CURL_ERROR_SIZE] = "";

    memset(&response, 0, sizeof(response));

    if (strncmp(url, "https://", 8) != 0)
    {
        response.status = OBS_ERROR;
        snprintf(response.error, sizeof(response.error), "refused a non-HTTPS URL");
        return response;
    }

    CURL *curl = curl_easy_init();

    if (curl == NULL)
    {
        response.status = OBS_ERROR;
        snprintf(response.error, sizeof(response.error), "could not start libcurl");
        return response;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, MAX_REDIRECTS);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, DOMINT_USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);

    struct curl_slist *header_list =
        curl_slist_append(NULL, "Accept: application/rdap+json, application/json, text/plain, */*");

    for (size_t i = 0; headers != NULL && headers[i] != NULL; i++)
    {
        header_list = curl_slist_append(header_list, headers[i]);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);

    if (post_body != NULL)
    {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);
    }

    CURLcode code = curl_easy_perform(curl);

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.http_code);
    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);

    if (buffer.too_large)
    {
        free(buffer.data);
        response.status = OBS_LIMITED;
        snprintf(response.error, sizeof(response.error), "response larger than %zu bytes", max_size);
        return response;
    }

    if (code != CURLE_OK)
    {
        free(buffer.data);
        response.status = is_no_response(code) ? OBS_NO_RESPONSE : OBS_ERROR;
        snprintf(response.error, sizeof(response.error), "%s",
                 error_buffer[0] != '\0' ? error_buffer : curl_easy_strerror(code));
        return response;
    }

    if (response.http_code >= 200 && response.http_code < 300)
    {
        response.status = OBS_OK;
        response.data = buffer.data != NULL ? buffer.data : xcalloc(1, 1);
        response.length = buffer.length;
        return response;
    }

    /* The body of an error page is not needed as evidence. */
    free(buffer.data);
    snprintf(response.error, sizeof(response.error), "HTTP %ld", response.http_code);
    response.status = response.http_code == 404 ? OBS_EMPTY : response.http_code == 429 ? OBS_LIMITED : OBS_ERROR;
    return response;
}
