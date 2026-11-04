#include "json.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"

typedef struct
{
    const char *text;
    size_t length;
    size_t position;
} parser;

static json_value *parse_value(parser *p, int depth);

static int at_end(const parser *p)
{
    return p->position >= p->length;
}

static char peek(const parser *p)
{
    return at_end(p) ? '\0' : p->text[p->position];
}

static void skip_whitespace(parser *p)
{
    while (peek(p) == ' ' || peek(p) == '\t' || peek(p) == '\r' || peek(p) == '\n')
    {
        p->position++;
    }
}

static int consume_literal(parser *p, const char *literal)
{
    size_t length = strlen(literal);

    if (p->length - p->position < length || memcmp(p->text + p->position, literal, length) != 0)
    {
        return 0;
    }

    p->position += length;
    return 1;
}

static json_value *new_value(json_type type)
{
    json_value *value = xcalloc(1, sizeof(*value));
    value->type = type;
    return value;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }

    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }

    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }

    return -1;
}

/* Reads the 4 hex digits after "\u"; -1 when they are not all there. */
static long read_hex4(parser *p)
{
    long value = 0;

    if (p->length - p->position < 4)
    {
        return -1;
    }

    for (int i = 0; i < 4; i++)
    {
        int digit = hex_digit(p->text[p->position + (size_t)i]);

        if (digit < 0)
        {
            return -1;
        }

        value = value * 16 + digit;
    }

    p->position += 4;
    return value;
}

static size_t encode_utf8(unsigned long code, char *out)
{
    if (code < 0x80)
    {
        out[0] = (char)code;
        return 1;
    }

    if (code < 0x800)
    {
        out[0] = (char)(0xc0 | (code >> 6));
        out[1] = (char)(0x80 | (code & 0x3f));
        return 2;
    }

    if (code < 0x10000)
    {
        out[0] = (char)(0xe0 | (code >> 12));
        out[1] = (char)(0x80 | ((code >> 6) & 0x3f));
        out[2] = (char)(0x80 | (code & 0x3f));
        return 3;
    }

    out[0] = (char)(0xf0 | (code >> 18));
    out[1] = (char)(0x80 | ((code >> 12) & 0x3f));
    out[2] = (char)(0x80 | ((code >> 6) & 0x3f));
    out[3] = (char)(0x80 | (code & 0x3f));
    return 4;
}

/* Parses a string starting at the opening quote into a new UTF-8 buffer.
 * Every read is bounds-checked against the input length. */
static char *parse_string_raw(parser *p)
{
    if (peek(p) != '"')
    {
        return NULL;
    }

    p->position++;

    size_t capacity = 16;
    size_t length = 0;
    char *out = xcalloc(capacity, 1);

    while (!at_end(p))
    {
        char c = p->text[p->position++];
        char encoded[4];
        size_t encoded_length = 1;

        if (c == '"')
        {
            /* Escapes such as \u001b decode to control characters that
             * would reach the analyst's terminal; every string read here
             * comes from a third party, so neutralize them now. */
            out[length] = '\0';
            sanitize_text(out, length, 1);
            return out;
        }

        /* Raw control characters are not allowed inside JSON strings. */
        if ((unsigned char)c < 0x20)
        {
            break;
        }

        if (c != '\\')
        {
            encoded[0] = c;
        }
        else
        {
            if (at_end(p))
            {
                break;
            }

            char escape = p->text[p->position++];

            switch (escape)
            {
            case '"':
            case '\\':
            case '/':
                encoded[0] = escape;
                break;
            case 'b':
                encoded[0] = '\b';
                break;
            case 'f':
                encoded[0] = '\f';
                break;
            case 'n':
                encoded[0] = '\n';
                break;
            case 'r':
                encoded[0] = '\r';
                break;
            case 't':
                encoded[0] = '\t';
                break;
            case 'u':
            {
                long code = read_hex4(p);

                if (code < 0)
                {
                    free(out);
                    return NULL;
                }

                /* A high surrogate must be followed by a low one. */
                if (code >= 0xd800 && code <= 0xdbff)
                {
                    long low = -1;

                    if (consume_literal(p, "\\u"))
                    {
                        low = read_hex4(p);
                    }

                    if (low < 0xdc00 || low > 0xdfff)
                    {
                        free(out);
                        return NULL;
                    }

                    code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                }
                else if (code >= 0xdc00 && code <= 0xdfff)
                {
                    free(out);
                    return NULL;
                }

                encoded_length = encode_utf8((unsigned long)code, encoded);
                break;
            }
            default:
                free(out);
                return NULL;
            }
        }

        if (length + encoded_length + 1 > capacity)
        {
            while (length + encoded_length + 1 > capacity)
            {
                capacity *= 2;
            }

            out = xrealloc(out, capacity);
        }

        memcpy(out + length, encoded, encoded_length);
        length += encoded_length;
    }

    free(out);
    return NULL;
}

/* JSON numbers: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? */
static json_value *parse_number(parser *p)
{
    size_t start = p->position;
    char buffer[64];

    if (peek(p) == '-')
    {
        p->position++;
    }

    if (peek(p) == '0')
    {
        p->position++;
    }
    else if (peek(p) >= '1' && peek(p) <= '9')
    {
        while (peek(p) >= '0' && peek(p) <= '9')
        {
            p->position++;
        }
    }
    else
    {
        return NULL;
    }

    if (peek(p) == '.')
    {
        p->position++;

        if (!(peek(p) >= '0' && peek(p) <= '9'))
        {
            return NULL;
        }

        while (peek(p) >= '0' && peek(p) <= '9')
        {
            p->position++;
        }
    }

    if (peek(p) == 'e' || peek(p) == 'E')
    {
        p->position++;

        if (peek(p) == '+' || peek(p) == '-')
        {
            p->position++;
        }

        if (!(peek(p) >= '0' && peek(p) <= '9'))
        {
            return NULL;
        }

        while (peek(p) >= '0' && peek(p) <= '9')
        {
            p->position++;
        }
    }

    size_t length = p->position - start;

    if (length >= sizeof(buffer))
    {
        return NULL;
    }

    memcpy(buffer, p->text + start, length);
    buffer[length] = '\0';

    json_value *value = new_value(JSON_NUMBER);
    value->number = strtod(buffer, NULL);
    return value;
}

static void append_item(json_value *container, json_value *item, char *key)
{
    container->items = xrealloc(container->items, (container->count + 1) * sizeof(*container->items));
    container->items[container->count] = item;

    if (container->type == JSON_OBJECT)
    {
        container->keys = xrealloc(container->keys, (container->count + 1) * sizeof(*container->keys));
        container->keys[container->count] = key;
    }

    container->count++;
}

static json_value *parse_container(parser *p, int depth, json_type type)
{
    char close = type == JSON_ARRAY ? ']' : '}';
    json_value *container = new_value(type);

    p->position++;
    skip_whitespace(p);

    if (peek(p) == close)
    {
        p->position++;
        return container;
    }

    while (!at_end(p))
    {
        char *key = NULL;

        if (type == JSON_OBJECT)
        {
            skip_whitespace(p);
            key = parse_string_raw(p);
            skip_whitespace(p);

            if (key == NULL || peek(p) != ':')
            {
                free(key);
                break;
            }

            p->position++;
        }

        json_value *item = parse_value(p, depth + 1);

        if (item == NULL)
        {
            free(key);
            break;
        }

        append_item(container, item, key);
        skip_whitespace(p);

        if (peek(p) == ',')
        {
            p->position++;
            continue;
        }

        if (peek(p) == close)
        {
            p->position++;
            return container;
        }

        break;
    }

    json_free(container);
    return NULL;
}

static json_value *parse_value(parser *p, int depth)
{
    if (depth > JSON_MAX_DEPTH)
    {
        return NULL;
    }

    skip_whitespace(p);

    switch (peek(p))
    {
    case '{':
        return parse_container(p, depth, JSON_OBJECT);
    case '[':
        return parse_container(p, depth, JSON_ARRAY);
    case '"':
    {
        char *text = parse_string_raw(p);

        if (text == NULL)
        {
            return NULL;
        }

        json_value *value = new_value(JSON_STRING);
        value->string = text;
        return value;
    }
    default:
        break;
    }

    if (consume_literal(p, "true"))
    {
        json_value *value = new_value(JSON_BOOL);
        value->boolean = 1;
        return value;
    }

    if (consume_literal(p, "false"))
    {
        return new_value(JSON_BOOL);
    }

    if (consume_literal(p, "null"))
    {
        return new_value(JSON_NULL);
    }

    return parse_number(p);
}

json_value *json_parse(const char *text, size_t length)
{
    parser p = {text, length, 0};
    json_value *value = parse_value(&p, 0);

    if (value == NULL)
    {
        return NULL;
    }

    skip_whitespace(&p);

    /* Trailing content means the document was not a single JSON value. */
    if (!at_end(&p))
    {
        json_free(value);
        return NULL;
    }

    return value;
}

void json_free(json_value *value)
{
    if (value == NULL)
    {
        return;
    }

    for (size_t i = 0; i < value->count; i++)
    {
        json_free(value->items[i]);

        if (value->keys != NULL)
        {
            free(value->keys[i]);
        }
    }

    free(value->items);
    free(value->keys);
    free(value->string);
    free(value);
}

const json_value *json_get(const json_value *object, const char *key)
{
    if (object == NULL || object->type != JSON_OBJECT)
    {
        return NULL;
    }

    for (size_t i = 0; i < object->count; i++)
    {
        if (strcmp(object->keys[i], key) == 0)
        {
            return object->items[i];
        }
    }

    return NULL;
}

const json_value *json_get_array(const json_value *object, const char *key)
{
    const json_value *value = json_get(object, key);
    return value != NULL && value->type == JSON_ARRAY ? value : NULL;
}

const json_value *json_get_object(const json_value *object, const char *key)
{
    const json_value *value = json_get(object, key);
    return value != NULL && value->type == JSON_OBJECT ? value : NULL;
}

const char *json_get_string(const json_value *object, const char *key)
{
    return json_string(json_get(object, key));
}

const json_value *json_at(const json_value *array, size_t index)
{
    if (array == NULL || array->type != JSON_ARRAY || index >= array->count)
    {
        return NULL;
    }

    return array->items[index];
}

const char *json_string(const json_value *value)
{
    return value != NULL && value->type == JSON_STRING ? value->string : NULL;
}

size_t json_count(const json_value *array)
{
    return array != NULL && array->type == JSON_ARRAY ? array->count : 0;
}
