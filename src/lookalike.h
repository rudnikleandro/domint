#ifndef DOMINT_LOOKALIKE_H
#define DOMINT_LOOKALIKE_H

#include <netinet/in.h>
#include <stddef.h>

#include "model.h"

#define LOOKALIKE_COLLECTOR "lookalike"

/* Variants are capped so one long name cannot cost tens of thousands of
 * queries. */
#define MAX_LOOKALIKES 2000

typedef struct
{
    char name[DOMAIN_SIZE];
    const char *technique;
} lookalike_candidate;

/* The variants of `domain`'s registrable name that a typo or a phishing
 * campaign would use: omission, repetition, transposition, keyboard
 * neighbours, insertion, homoglyphs, vowel swaps, hyphens, bit flips, an
 * extra character, phishing words and other TLDs. Each appears once, the
 * domain itself never. Returns how many were written to `out` (at most
 * `capacity`). */
size_t lookalike_generate(const char *domain, lookalike_candidate *out, size_t capacity);

/* Asks the resolver which variants are registered (NS), and for those, their
 * addresses (A) and mail servers (MX). Only the resolver is contacted, never
 * the variants' own servers. */
void lookalike_collect(const char *domain, const struct in_addr *custom_resolver, observation_list *observations);

/* Builds the list of registered variants from the recorded answers. */
void lookalike_interpret(const char *domain, const observation_list *observations, lookalike_list *list);

#endif
