#ifndef EXPOSUREPROOF_JSON_H
#define EXPOSUREPROOF_JSON_H

#include <stddef.h>

/* A small JSON reader for untrusted input (RDAP answers): it parses at most
 * `length` bytes, rejects anything that is not strict JSON, caps nesting
 * depth, and decodes \u escapes to UTF-8. */

typedef enum
{
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type;

typedef struct json_value json_value;

struct json_value
{
    json_type type;
    int boolean;
    double number;
    char *string;
    /* Arrays: items. Objects: items with keys[i] naming items[i]. */
    size_t count;
    json_value **items;
    char **keys;
};

#define JSON_MAX_DEPTH 64

/* Returns the parsed document (free with json_free) or NULL when the text
 * is not valid JSON. */
json_value *json_parse(const char *text, size_t length);
void json_free(json_value *value);

/* Lookups return NULL when the value is missing or of another type. */
const json_value *json_get(const json_value *object, const char *key);
const json_value *json_get_array(const json_value *object, const char *key);
const json_value *json_get_object(const json_value *object, const char *key);
const char *json_get_string(const json_value *object, const char *key);
const json_value *json_at(const json_value *array, size_t index);
const char *json_string(const json_value *value);
size_t json_count(const json_value *array);

#endif
