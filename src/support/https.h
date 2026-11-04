#ifndef DOMINT_HTTPS_H
#define DOMINT_HTTPS_H

#include <stddef.h>

#include "core/model.h"

/* Sent with every HTTP request, so a target sees who asked. */
#define DOMINT_USER_AGENT "domint/" DOMINT_VERSION

typedef struct
{
    observation_status status;
    long http_code;
    char *data;
    size_t length;
    char error[FIELD_SIZE];
} https_response;

/* Call once at startup and exit (wraps curl_global_init/cleanup). */
int https_init(void);
void https_cleanup(void);

/* GETs `url` over HTTPS with the certificate verified. Redirects are
 * followed only to other HTTPS URLs, and the body is capped at `max_size`
 * bytes. `data` (raw bytes plus a NUL) must be freed. Status: ok (2xx),
 * empty (404), limited (429 or too large), no_response, or error. */
https_response https_get(const char *url, size_t max_size);

/* https_get() with a total time limit other than the default 15 seconds,
 * for sources that send large answers slowly. */
https_response https_get_timeout(const char *url, size_t max_size, long timeout_seconds);

/* The general form: extra request `headers` (NULL-terminated, may be NULL)
 * and, when `post_body` is not NULL, a POST of it instead of a GET. */
https_response https_request(const char *url, size_t max_size, long timeout_seconds, const char *const *headers,
                             const char *post_body);

/* The host part of an https:// URL, for reporting the source. */
void url_host(const char *url, char *out, size_t size);

#endif
