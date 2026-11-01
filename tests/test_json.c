#include <stdlib.h>

#include "json.h"
#include "test.h"

static json_value *parse(const char *text)
{
    return json_parse(text, strlen(text));
}

static int rejects(const char *text)
{
    json_value *value = parse(text);
    json_free(value);
    return value == NULL;
}

void test_json(void)
{
    json_value *document = parse(" {\"a\": [1, -2.5e3, true, false, null], \"b\": {\"c\": \"d\"}, \"e\": \"\"} ");

    CHECK(document != NULL && document->type == JSON_OBJECT);
    CHECK_INT(json_count(json_get_array(document, "a")), 5);
    CHECK(json_at(json_get_array(document, "a"), 1)->number == -2500.0);
    CHECK_INT(json_at(json_get_array(document, "a"), 2)->boolean, 1);
    CHECK_INT(json_at(json_get_array(document, "a"), 3)->boolean, 0);
    CHECK_INT(json_at(json_get_array(document, "a"), 4)->type, JSON_NULL);
    CHECK_STR(json_get_string(json_get_object(document, "b"), "c"), "d");
    CHECK_STR(json_get_string(document, "e"), "");
    CHECK(json_get(document, "missing") == NULL);
    CHECK(json_get_array(document, "b") == NULL);
    CHECK(json_at(json_get_array(document, "a"), 99) == NULL);
    json_free(document);

    /* Escapes, including \u to UTF-8 and a surrogate pair. */
    document = parse("[\"q\\\"b\\\\s\\/n\\n\", \"\\u00e9\\u4e2d\", \"\\ud83d\\ude00\"]");
    CHECK(document != NULL);
    CHECK_STR(json_string(json_at(document, 0)), "q\"b\\s/n\n");
    CHECK_STR(json_string(json_at(document, 1)), "\xc3\xa9\xe4\xb8\xad");
    CHECK_STR(json_string(json_at(document, 2)), "\xf0\x9f\x98\x80");
    json_free(document);

    /* The input that overflowed the c-project parser: a truncated \u escape. */
    CHECK(rejects("\"\\u\"abcdefghijklmnopqrstuvwxyz\""));
    CHECK(rejects("\"\\u12\""));
    CHECK(rejects("\"\\u12"));
    CHECK(rejects("\"\\ud83d\""));
    CHECK(rejects("\"\\ude00\""));
    CHECK(rejects("\"\\x\""));
    CHECK(rejects("\"raw\ncontrol\""));
    CHECK(rejects("\"unterminated"));

    /* Only strict JSON. */
    CHECK(rejects(""));
    CHECK(rejects("[1,]"));
    CHECK(rejects("{\"a\":1,}"));
    CHECK(rejects("{\"a\" 1}"));
    CHECK(rejects("{a:1}"));
    CHECK(rejects("[1] trailing"));
    CHECK(rejects("01"));
    CHECK(rejects("1."));
    CHECK(rejects("-"));
    CHECK(rejects("0x10"));
    CHECK(rejects("inf"));
    CHECK(rejects("nan"));
    CHECK(rejects("tru"));
    CHECK(rejects("[1 2]"));

    /* Nesting is capped so a hostile answer cannot exhaust the stack. */
    char deep[2 * (JSON_MAX_DEPTH + 2) + 1];
    size_t depth = JSON_MAX_DEPTH;

    memset(deep, '[', depth);
    memset(deep + depth, ']', depth);
    deep[2 * depth] = '\0';
    document = parse(deep);
    CHECK(document != NULL);
    json_free(document);

    depth = JSON_MAX_DEPTH + 2;
    memset(deep, '[', depth);
    memset(deep + depth, ']', depth);
    deep[2 * depth] = '\0';
    CHECK(rejects(deep));

    /* Parsing stops at the given length, not at a NUL. */
    const char padded[] = "[1, 2]GARBAGE";
    document = json_parse(padded, 6);
    CHECK(document != NULL && json_count(document) == 2);
    json_free(document);
    CHECK(json_parse("[1, 2]", 4) == NULL);
}
