#ifndef EXPOSUREPROOF_CORRELATE_H
#define EXPOSUREPROOF_CORRELATE_H

#include <stddef.h>
#include <stdint.h>

#include "model.h"

typedef enum
{
    LINK_WEAK,
    LINK_MEDIUM,
    LINK_STRONG
} link_strength;

/* One value (an IP, a nameserver, a verification token...) found on two or
 * more of the investigated domains. */
typedef struct
{
    link_strength strength;
    const char *kind;
    char *value;
    size_t domain_count;
    size_t *domains;
} shared_indicator;

#define NO_CLUSTER SIZE_MAX

typedef struct
{
    size_t indicator_count;
    shared_indicator *indicators;
    size_t cluster_count;
    size_t *cluster_of;
} correlation;

/* Finds shared indicators across `reports` and groups the domains that
 * strong indicators tie together. `cluster_of[i]` is the cluster of domain
 * i, or NO_CLUSTER. */
void correlate(const domain_report *reports, size_t count, correlation *out);
void correlation_free(correlation *links);

#endif
