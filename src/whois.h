#ifndef EXPOSUREPROOF_WHOIS_H
#define EXPOSUREPROOF_WHOIS_H

#include "model.h"

/* Returns the full NUL-terminated response, which the caller must free(), or NULL. */
char *whois_query(const char *server, const char *query);

/* Looks up the registration of `domain`, which should be a registrable
 * domain (example.com, not www.example.com). */
void whois_collect(const char *domain, whois_info *info);

#endif
