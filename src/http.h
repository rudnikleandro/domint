#ifndef EXPOSUREPROOF_HTTP_H
#define EXPOSUREPROOF_HTTP_H

#include <stddef.h>

#include "model.h"

#define HTTP_USER_AGENT "ExposureProof-C/0.3"
#define HTTP_COLLECTOR "http"

/* Sends one HEAD request to the first address that answers on port 80,
 * recording every attempt. This is the only step that contacts the target. */
void http_collect(const char *host, const address_info *addresses, size_t count, observation_list *observations);

/* Builds `http` from the recorded attempts. */
void http_interpret(const observation_list *observations, http_info *http);

/* Reads the status line, Location and Server from a sanitized response. */
void http_parse(const char *response, http_info *http);

#endif
