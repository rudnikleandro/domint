#ifndef EXPOSUREPROOF_UTIL_H
#define EXPOSUREPROOF_UTIL_H

#include <stddef.h>

/* Allocation wrappers that exit with a message instead of returning NULL. */
void *xcalloc(size_t count, size_t size);
void *xrealloc(void *pointer, size_t size);
char *xstrdup(const char *text);

/* Replaces control bytes (terminal escapes, NULs) in text that came from a
 * server; `keep_newlines` keeps \n, \t and \r\n for multi-line answers. */
void sanitize_text(char *text, size_t length, int keep_newlines);

int starts_with_ci(const char *text, const char *prefix);
int contains_ci(const char *text, const char *needle);
void to_lower(char *text);

/* Current time as 2026-10-17T18:30:00Z. */
void utc_timestamp(char *out, size_t size);

#endif
