#ifndef EXPOSUREPROOF_RESOLVE_H
#define EXPOSUREPROOF_RESOLVE_H

#include "model.h"

/* Resolves the report's name to its IPv4/IPv6 addresses and their PTR names. */
void resolve_addresses(domain_report *report);

#endif
