#include "memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void out_of_memory(void)
{
    fprintf(stderr, "exposureproof: out of memory\n");
    exit(1);
}

void *xcalloc(size_t count, size_t size)
{
    void *pointer = calloc(count, size);

    if (pointer == NULL && count != 0 && size != 0)
    {
        out_of_memory();
    }

    return pointer;
}

void *xrealloc(void *pointer, size_t size)
{
    void *resized = realloc(pointer, size);

    if (resized == NULL && size != 0)
    {
        out_of_memory();
    }

    return resized;
}

char *xstrdup(const char *text)
{
    char *copy = strdup(text);

    if (copy == NULL)
    {
        out_of_memory();
    }

    return copy;
}
