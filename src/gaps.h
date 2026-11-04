#ifndef DOMINT_GAPS_H
#define DOMINT_GAPS_H

#include <stddef.h>

#include "model.h"

/* Third-party sources whose failure leaves part of the report empty. A
 * target that does not answer on port 80 or 443 is a fact about the target,
 * not a gap, and a failed RDAP lookup that WHOIS made up for costs nothing. */
typedef enum
{
    GAP_ADDRESSES,
    GAP_NETWORK,
    GAP_DNS,
    GAP_REGISTRATION,
    GAP_REPUTATION,
    GAP_SUBDOMAINS,
    GAP_ALIASES,
    GAP_LOOKALIKES,
    GAP_COUNT
} gap_area;

/* "subdomains", and what the failure means ("the list may be incomplete",
 * or NULL when the label says enough). */
const char *gap_label(gap_area area);
const char *gap_impact(gap_area area);

/* The area `item` leaves incomplete, or -1 when it is not a gap. */
int gap_area_of(const domain_report *report, const observation *item);

/* What was asked ("crt.sh", "TXT _dmarc.example.com") and why it failed
 * ("HTTP 502", "no response"). */
void gap_describe(const observation *item, gap_area area, char *what, size_t what_size, char *why, size_t why_size);

/* Whether `ip` is one of the investigated domain's own addresses. */
int is_target_address(const domain_report *report, const char *ip);

#endif
