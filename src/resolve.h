#ifndef EXPOSUREPROOF_RESOLVE_H
#define EXPOSUREPROOF_RESOLVE_H

#include "model.h"

/* Resolves `name` to its IPv4/IPv6 addresses and their PTR names through
 * the system resolver, recording the result. */
void resolve_collect(const char *name, observation_list *observations);

/* Fills the report's addresses from the recorded result. */
void resolve_interpret(const observation_list *observations, domain_report *report);

#endif
