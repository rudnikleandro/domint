#ifndef EXPOSUREPROOF_MEMORY_H
#define EXPOSUREPROOF_MEMORY_H

#include <stddef.h>

/* Allocation wrappers that exit with a message instead of returning NULL. */
void *xcalloc(size_t count, size_t size);
void *xrealloc(void *pointer, size_t size);
char *xstrdup(const char *text);

#endif
