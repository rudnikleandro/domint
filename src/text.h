#ifndef EXPOSUREPROOF_TEXT_H
#define EXPOSUREPROOF_TEXT_H

#include <stddef.h>

void sanitize_text(char *text, size_t length, int keep_newlines);

int starts_with_ci(const char *text, const char *prefix);
int contains_ci(const char *text, const char *needle);
void to_lower(char *text);

#endif
