#include "output/report.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "support/json.h"
#include "core/model.h"

/* STIX 2.1 bundle: observables (domain-name, ipv4-addr, ipv6-addr,
 * autonomous-system), the relationships between them, indicators for
 * registered lookalikes and reputation listings, a note with the signals
 * and a report that groups each domain's objects, which is how OpenCTI and
 * MISP file an import. */

#define STIX_NAMESPACE "\x00\xab\xed\xb4\xaa\x42\x46\x6c\x9c\x01\xfe\xd2\x33\x15\xa9\xb7"
#define ID_SIZE 80

/* SHA-1, for the name-based (version 5) UUIDs STIX gives observables. */
typedef struct
{
    uint32_t state[5];
    uint64_t length;
    unsigned char block[64];
    size_t used;
} sha1_context;

static uint32_t rotate(uint32_t value, int bits)
{
    return value << bits | value >> (32 - bits);
}

static void sha1_block(sha1_context *ctx, const unsigned char *block)
{
    uint32_t w[80];

    for (int i = 0; i < 16; i++)
    {
        w[i] = (uint32_t)block[i * 4] << 24 | (uint32_t)block[i * 4 + 1] << 16 | (uint32_t)block[i * 4 + 2] << 8 |
               block[i * 4 + 3];
    }

    for (int i = 16; i < 80; i++)
    {
        w[i] = rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3], e = ctx->state[4];

    for (int i = 0; i < 80; i++)
    {
        uint32_t f = i < 20 ? (b & c) | (~b & d) : i < 40 ? b ^ c ^ d : i < 60 ? (b & c) | (b & d) | (c & d) : b ^ c ^ d;
        uint32_t k = i < 20 ? 0x5a827999 : i < 40 ? 0x6ed9eba1 : i < 60 ? 0x8f1bbcdc : 0xca62c1d6;
        uint32_t temp = rotate(a, 5) + f + e + k + w[i];

        e = d;
        d = c;
        c = rotate(b, 30);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_update(sha1_context *ctx, const void *data, size_t length)
{
    const unsigned char *p = data;

    ctx->length += length;

    while (length > 0)
    {
        size_t take = 64 - ctx->used < length ? 64 - ctx->used : length;

        memcpy(ctx->block + ctx->used, p, take);
        ctx->used += take;
        p += take;
        length -= take;

        if (ctx->used == 64)
        {
            sha1_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha1(const void *a, size_t a_length, const void *b, size_t b_length, unsigned char digest[20])
{
    sha1_context ctx = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}, 0, {0}, 0};
    unsigned char padding[64] = {0x80};
    unsigned char bits[8];

    sha1_update(&ctx, a, a_length);
    sha1_update(&ctx, b, b_length);

    uint64_t total = ctx.length * 8;

    for (int i = 0; i < 8; i++)
    {
        bits[i] = (unsigned char)(total >> (56 - i * 8));
    }

    sha1_update(&ctx, padding, ctx.used < 56 ? 56 - ctx.used : 120 - ctx.used);
    sha1_update(&ctx, bits, 8);

    for (int i = 0; i < 5; i++)
    {
        digest[i * 4] = (unsigned char)(ctx.state[i] >> 24);
        digest[i * 4 + 1] = (unsigned char)(ctx.state[i] >> 16);
        digest[i * 4 + 2] = (unsigned char)(ctx.state[i] >> 8);
        digest[i * 4 + 3] = (unsigned char)ctx.state[i];
    }
}

static void format_uuid(const char *type, unsigned char bytes[16], int version, char *out)
{
    bytes[6] = (unsigned char)((bytes[6] & 0x0f) | (version << 4));
    bytes[8] = (unsigned char)((bytes[8] & 0x3f) | 0x80);
    snprintf(out, ID_SIZE, "%s--%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", type, bytes[0],
             bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10],
             bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
}

/* An observable's id is derived from its contributing properties, so the
 * same domain or address gets the same id in every bundle and imports merge
 * instead of piling up duplicates. `contributing` is their canonical JSON,
 * such as {"value":"example.com"}. */
static void observable_id(const char *type, const char *contributing, char *out)
{
    unsigned char digest[20];

    sha1(STIX_NAMESPACE, 16, contributing, strlen(contributing), digest);
    format_uuid(type, digest, 5, out);
}

static void value_id(const char *type, const char *value, char *out)
{
    char contributing[DOMAIN_SIZE + 16];

    snprintf(contributing, sizeof(contributing), "{\"value\":\"%s\"}", value);
    observable_id(type, contributing, out);
}

/* Other objects get random (version 4) ids. */
static void random_id(const char *type, char *out)
{
    unsigned char bytes[16];
    FILE *source = fopen("/dev/urandom", "rb");

    if (source == NULL || fread(bytes, 1, sizeof(bytes), source) != sizeof(bytes))
    {
        for (size_t i = 0; i < sizeof(bytes); i++)
        {
            bytes[i] = (unsigned char)rand();
        }
    }

    if (source != NULL)
    {
        fclose(source);
    }

    format_uuid(type, bytes, 4, out);
}

typedef struct
{
    FILE *out;
    int first;
    char now[32];
    char identity[ID_SIZE];
    string_list emitted; /* observable ids already in the bundle */
    string_list refs;    /* the objects of the domain being written */
} bundle;

/* Each object is one line of the "objects" array. */
static void begin_object(bundle *b, const char *type, const char *id)
{
    fprintf(b->out, "%s\n    {\"type\": \"%s\", \"spec_version\": \"2.1\", \"id\": \"%s\"", b->first ? "" : ",", type, id);
    b->first = 0;
    string_list_add(&b->refs, id);
}

static void put(bundle *b, const char *key, const char *value)
{
    fprintf(b->out, ", \"%s\": ", key);
    json_write_string(b->out, value);
}

static void put_common(bundle *b)
{
    put(b, "created", b->now);
    put(b, "modified", b->now);
    put(b, "created_by_ref", b->identity);
}

static void end_object(bundle *b)
{
    fputc('}', b->out);
}

/* A domain-name or IP observable, written once per bundle. Returns its id
 * in `id`. */
static void observable(bundle *b, const char *type, const char *value, char *id)
{
    value_id(type, value, id);

    if (string_list_contains(&b->emitted, id))
    {
        string_list_add_unique(&b->refs, id);
        return;
    }

    string_list_add(&b->emitted, id);
    begin_object(b, type, id);
    put(b, "value", value);
    end_object(b);
}

static void autonomous_system(bundle *b, const char *number, const char *name, char *id)
{
    char contributing[64];
    long asn = strtol(number, NULL, 10);

    snprintf(contributing, sizeof(contributing), "{\"number\":%ld}", asn);
    observable_id("autonomous-system", contributing, id);

    if (string_list_contains(&b->emitted, id))
    {
        string_list_add_unique(&b->refs, id);
        return;
    }

    string_list_add(&b->emitted, id);
    begin_object(b, "autonomous-system", id);
    fprintf(b->out, ", \"number\": %ld", asn);
    put(b, "name", name);
    end_object(b);
}

static void relationship(bundle *b, const char *type, const char *source, const char *target)
{
    char id[ID_SIZE];

    random_id("relationship", id);
    begin_object(b, "relationship", id);
    put_common(b);
    put(b, "relationship_type", type);
    put(b, "source_ref", source);
    put(b, "target_ref", target);
    end_object(b);
}

static const char *address_type(const char *ip)
{
    return strchr(ip, ':') != NULL ? "ipv6-addr" : "ipv4-addr";
}

/* An address, the network announcing it, and the links between them and
 * the name that resolves to it. */
static void resolution(bundle *b, const char *name_id, const char *ip, const char *asn, const char *as_name)
{
    char ip_id[ID_SIZE];

    observable(b, address_type(ip), ip, ip_id);
    relationship(b, "resolves-to", name_id, ip_id);

    if (asn != NULL && asn[0] != '\0')
    {
        char as_id[ID_SIZE];

        autonomous_system(b, asn, as_name, as_id);
        relationship(b, "belongs-to", ip_id, as_id);
    }
}

static void indicator(bundle *b, const char *name, const char *description, const char *indicator_type,
                      const char *domain)
{
    char id[ID_SIZE];
    char pattern[DOMAIN_SIZE + 32];

    snprintf(pattern, sizeof(pattern), "[domain-name:value = '%s']", domain);
    random_id("indicator", id);
    begin_object(b, "indicator", id);
    put_common(b);
    put(b, "name", name);
    put(b, "description", description);
    fprintf(b->out, ", \"indicator_types\": [\"%s\"]", indicator_type);
    put(b, "pattern", pattern);
    put(b, "pattern_type", "stix");
    put(b, "valid_from", b->now);
    end_object(b);
}

static const char *severity_name(severity level)
{
    static const char *const names[] = {"INFO", "LOW", "MEDIUM", "HIGH"};
    return names[level];
}

static void write_domain(bundle *b, const domain_report *report)
{
    char domain_id[ID_SIZE];
    char text[1024];

    string_list_free(&b->refs);
    observable(b, "domain-name", report->name, domain_id);

    if (report_has(report, MODULE_ADDRESSES))
    {
        for (size_t i = 0; i < report->address_count; i++)
        {
            const address_info *address = &report->addresses[i];
            int announced = address->asn_status == LOOKUP_OK && address->announced;

            resolution(b, domain_id, address->ip, announced ? address->asn : NULL, address->as_name);
        }
    }

    for (size_t i = 0; i < report->subdomains.count; i++)
    {
        const subdomain_info *sub = &report->subdomains.items[i];
        char sub_id[ID_SIZE];

        if (subdomain_state_of(sub) != SUBDOMAIN_ONLINE)
        {
            continue;
        }

        observable(b, "domain-name", sub->name, sub_id);

        if (sub->ip[0] != '\0')
        {
            resolution(b, sub_id, sub->ip, sub->asn, sub->as_name);
        }
    }

    for (size_t i = 0; i < report->lookalikes.count; i++)
    {
        const lookalike_info *item = &report->lookalikes.items[i];
        char lookalike_id[ID_SIZE];

        if (item->likely_defensive)
        {
            continue;
        }

        char description[512];

        observable(b, "domain-name", item->name, lookalike_id);
        snprintf(text, sizeof(text), "Lookalike of %s: %s", report->name, item->name);
        snprintf(description, sizeof(description), "Registered variant (%s) of %s%s%s%s.", item->technique,
                 report->name, item->has_mail ? "; it can receive mail" : "",
                 item->addresses.count > 0 ? "; it points to a server" : "", item->parked ? "; parked or for sale" : "");
        indicator(b, text, description, "anomalous-activity", item->name);
    }

    const reputation_info *rep = &report->reputation;

    if ((rep->threatfox_status == LOOKUP_OK && rep->threatfox_iocs > 0) ||
        (rep->urlhaus_status == LOOKUP_OK && rep->urlhaus_urls > 0))
    {
        snprintf(text, sizeof(text), "%s listed by threat intelligence", report->name);
        indicator(b, text, "Listed on ThreatFox or URLhaus (abuse.ch) when the report was made.", "malicious-activity",
                  report->name);
    }

    if (report->finding_count > 0)
    {
        char id[ID_SIZE];
        size_t length = 0;
        char *content = NULL;
        FILE *stream = open_memstream(&content, &length);

        for (size_t i = 0; i < report->finding_count; i++)
        {
            fprintf(stream, "%s[%s] %s", i > 0 ? "\n" : "", severity_name(report->findings[i].level),
                    report->findings[i].text);
        }

        fclose(stream);
        random_id("note", id);
        begin_object(b, "note", id);
        put_common(b);
        snprintf(text, sizeof(text), "domint signals for %s", report->name);
        put(b, "abstract", text);
        put(b, "content", content);
        fprintf(b->out, ", \"object_refs\": [\"%s\"]", domain_id);
        end_object(b);
        free(content);
    }

    /* The report goes last, listing everything written for this domain. */
    char report_id[ID_SIZE];
    string_list refs = b->refs;

    b->refs = (string_list){0};
    random_id("report", report_id);
    begin_object(b, "report", report_id);
    put_common(b);
    snprintf(text, sizeof(text), "domint: %s", report->name);
    put(b, "name", text);
    put(b, "published", b->now);
    fprintf(b->out, ", \"report_types\": [\"indicator\", \"observed-data\"], \"object_refs\": [");

    for (size_t i = 0; i < refs.count; i++)
    {
        fprintf(b->out, "%s\"%s\"", i > 0 ? ", " : "", refs.items[i]);
    }

    fputc(']', b->out);
    end_object(b);
    string_list_free(&refs);
}

void print_report_stix(FILE *out, const domain_report *reports, size_t count, const report_options *options)
{
    bundle b = {out, 1, "", "", {0}, {0}};
    char bundle_id[ID_SIZE];
    time_t now = time(NULL);
    struct tm parts;

    (void)options;
    gmtime_r(&now, &parts);
    strftime(b.now, sizeof(b.now), "%Y-%m-%dT%H:%M:%S.000Z", &parts);
    observable_id("identity", "{\"name\":\"domint\",\"identity_class\":\"system\"}", b.identity);
    random_id("bundle", bundle_id);

    fprintf(out, "{\n  \"type\": \"bundle\",\n  \"id\": \"%s\",\n  \"objects\": [", bundle_id);

    begin_object(&b, "identity", b.identity);
    put(&b, "created", b.now);
    put(&b, "modified", b.now);
    put(&b, "name", "domint");
    put(&b, "description", "Domain intelligence collected by domint (https://github.com/rudnikleandro/domint).");
    put(&b, "identity_class", "system");
    end_object(&b);

    for (size_t i = 0; i < count; i++)
    {
        write_domain(&b, &reports[i]);
    }

    fprintf(out, "\n  ]\n}\n");
    string_list_free(&b.emitted);
    string_list_free(&b.refs);
}
