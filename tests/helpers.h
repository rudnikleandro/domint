#ifndef DOMINT_TEST_HELPERS_H
#define DOMINT_TEST_HELPERS_H

#include <stddef.h>

#include "core/model.h"

/* Adds a probed subdomain that answered with HTTP `code` (0: no answer)
 * from `ip`, in the network `asn` named `as_name`. */
void add_live(domain_report *report, const char *name, long code, const char *ip, const char *asn, const char *as_name);

/* The first signal whose text contains `text`, or NULL. */
const finding *find_signal(const domain_report *report, const char *text);

/* Whether a signal of severity `level` contains `text`. */
int has_signal(const domain_report *report, severity level, const char *text);

/* The concise text report of `report`; the caller frees it. */
char *render(const domain_report *report);

/* A DNS answer for `name` with response code `rcode` and one record of
 * `type` holding `rdata` (no record when `rdata_length` is 0). Returns its
 * length. */
size_t build_answer(unsigned char *out, const char *name, int type, int rcode, const unsigned char *rdata,
                    size_t rdata_length);

/* Records that answer as the lookalike module would, under
 * "<type_name> <name>". */
void record_lookalike(observation_list *obs, const char *type_name, const char *name, int type, int rcode,
                      const unsigned char *rdata, size_t rdata_length);

#endif
