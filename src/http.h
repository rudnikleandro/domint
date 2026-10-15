#ifndef EXPOSUREPROOF_HTTP_H
#define EXPOSUREPROOF_HTTP_H

#include "model.h"

#define HTTP_USER_AGENT "ExposureProof-C/0.2"

/* Sends one HEAD request to the first resolved address that accepts a
 * connection on port 80. This is the only step that contacts the target. */
void http_probe(domain_report *report);

#endif
