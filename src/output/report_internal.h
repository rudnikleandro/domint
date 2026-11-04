#ifndef DOMINT_REPORT_INTERNAL_H
#define DOMINT_REPORT_INTERNAL_H

/* Shared by the report_*.c files; not part of the public API, which is
 * output/report.h. */

#include <stddef.h>
#include <stdio.h>

#include "core/model.h"

#define RULE "================================================================================"
#define LABEL_WIDTH 14
#define SUB_LABEL_WIDTH 12
#define KIND_WIDTH 22
#define WRAP_WIDTH 64
#define REPORT_WIDTH 80
#define TAG_WIDTH 9
#define SOURCE_INDENT 15
/* Names listed per group of unanswered subdomains without --full. */
#define CONCISE_SUBDOMAINS 20
#define REASON_WIDTH 24
#define MAX_NAME_WIDTH 28

/* Formatting primitives (report_format.c). */
const char *severity_tag(severity level);
void print_section(FILE *out, const char *title);
void print_field(FILE *out, const char *label, const char *value);
void print_sub_field(FILE *out, const char *label, const char *value);
void print_paragraph(FILE *out, int indent, const char *tag, const char *text);
void print_wrapped(FILE *out, int indent, int label_width, const char *label, const char *const *items, size_t count);
void print_list(FILE *out, const char *label, const char *const *items, size_t count);
void print_record_set(FILE *out, const char *label, const record_set *set);
void report_append(char *out, size_t size, const char *separator, const char *text);
int report_is_listed(const char *verdict);
int report_short_name(const char *name, const char *domain);
void network_label(const subdomain_info *sub, char *out, size_t size);

/* Detail sections (report_sections.c). */
void print_addresses(FILE *out, const domain_report *report);
void print_http(FILE *out, const domain_report *report);
void print_tls(FILE *out, const domain_report *report);
void print_dns(FILE *out, const domain_report *report);
void print_whois(FILE *out, const domain_report *report);
void print_reputation(FILE *out, const domain_report *report);
void print_lookalikes(FILE *out, const domain_report *report);
void print_sources(FILE *out, const domain_report *report);
void print_raw(FILE *out, const domain_report *report);
void describe_certificate(const tls_info *tls, char *out, size_t size);
void describe_reputation(const reputation_info *rep, char *out, size_t size);
void describe_lookalikes(const lookalike_list *list, char *out, size_t size);

/* Subdomains (report_subdomains.c). */
void print_subdomains(FILE *out, const domain_report *report, int full);
void print_all_subdomains(FILE *out, const domain_report *reports, size_t count, int full);

#endif
